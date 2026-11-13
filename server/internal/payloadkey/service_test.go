package payloadkey

import (
	"archive/zip"
	"authgo/internal/backupfile"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/db"
	"authgo/internal/model"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"gorm.io/gorm"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func database(t *testing.T) *gorm.DB {
	t.Helper()
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	t.Cleanup(func() { _ = pool.Close() })
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	return d
}
func seal(t *testing.T, p Payload, key, public []byte) Payload {
	t.Helper()
	a, e := p.aad()
	if e != nil {
		t.Fatal(e)
	}
	pub, e := ecdh.X25519().NewPublicKey(public)
	if e != nil {
		t.Fatal(e)
	}
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	shared, e := priv.ECDH(pub)
	if e != nil {
		t.Fatal(e)
	}
	a = append(a, priv.PublicKey().Bytes()...)
	salt := sha256.Sum256(a)
	kek, e := hkdf.Key(sha256.New, shared, salt[:], "authgo/payload/v1/wrap", 32)
	if e != nil {
		t.Fatal(e)
	}
	g, _ := gcm(kek)
	n := make([]byte, 12)
	if _, e = rand.Read(n); e != nil {
		t.Fatal(e)
	}
	enc := base64.RawURLEncoding.EncodeToString
	p.Envelope = Envelope{enc(priv.PublicKey().Bytes()), enc(n), enc(g.Seal(nil, n, key, a))}
	return p
}
func TestRotationIsolationAndBackupRestore(t *testing.T) {
	d := database(t)
	master := bytes.Repeat([]byte{3}, 32)
	box, _ := cryptoutil.NewCipher(master)
	s := New(d, box)
	p, v := vector(t)
	a := model.Application{Name: "payload", AppKey: p.AppKey}
	if e := d.Create(&a).Error; e != nil {
		t.Fatal(e)
	}
	private := unhex(t, field(t, v, "recipient_private_hex"))
	encrypted, e := box.Encrypt(private, aad(a.AppKey, p.KeyID))
	if e != nil {
		t.Fatal(e)
	}
	old := Key{AppID: a.ID, KeyID: p.KeyID, PrivateKeyEncrypted: encrypted, PublicKey: base64.RawURLEncoding.EncodeToString(unhex(t, field(t, v, "recipient_public_hex"))), IsCurrent: true, CreatedAt: time.Now().UTC()}
	if e = d.Create(&old).Error; e != nil {
		t.Fatal(e)
	}
	current, e := s.Rotate(context.Background(), a.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Open(d, a, p); e != nil {
		t.Fatal("old envelope lost on rotation", e)
	}
	q := p
	q.KeyID = current.KeyID
	pub, _ := b64(current.PublicKey)
	want := bytes.Repeat([]byte{5}, 32)
	q = seal(t, q, want, pub)
	if got, e := s.Open(d, a, q); e != nil || !bytes.Equal(got, want) {
		t.Fatal("new key not usable", e)
	}
	other := a
	other.ID++
	if _, e := s.Open(d, other, p); e != ErrInvalid {
		t.Fatal("cross-app accepted")
	}
	keys, e := s.List(context.Background(), a.ID)
	if e != nil || len(keys) != 2 || !keys[0].IsCurrent || keys[1].IsCurrent {
		t.Fatal("rotation state", e)
	}
	raw, _ := json.Marshal(keys)
	if strings.Contains(string(raw), "private") || bytes.Contains(raw, []byte(encrypted)) {
		t.Fatal("private data in API")
	}
	duplicate := old
	duplicate.ID = 0
	duplicate.KeyID = "other-key"
	duplicate.IsCurrent = true
	if e = d.Create(&duplicate).Error; e == nil {
		t.Fatal("multiple current keys accepted")
	}
	swapped := old
	swapped.KeyID = "swapped"
	if _, e = box.Decrypt(old.PrivateKeyEncrypted, aad(a.AppKey, swapped.KeyID)); e == nil {
		t.Fatal("key id not bound to at-rest encryption")
	}
	snapshot := filepath.Join(t.TempDir(), "snapshot.db")
	if e = d.Exec("VACUUM INTO ?", snapshot).Error; e != nil {
		t.Fatal(e)
	}
	bundle := filepath.Join(t.TempDir(), "backup.zip")
	if e = backupfile.Write(snapshot, bundle, master); e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(bundle)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	dir := t.TempDir()
	var restoredMaster []byte
	for _, f := range z.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		raw, e := io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
		switch f.Name {
		case "authgo.db":
			if e = os.WriteFile(filepath.Join(dir, "authgo.db"), raw, 0600); e != nil {
				t.Fatal(e)
			}
		case "master.key":
			restoredMaster, e = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	restored, e := db.Open(dir, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := restored.DB()
	defer pool.Close()
	restoredBox, _ := cryptoutil.NewCipher(restoredMaster)
	recovered := New(restored, restoredBox)
	if got, e := recovered.Open(restored, a, p); e != nil || !bytes.Equal(got, unhex(t, field(t, v, "content_key_hex"))) {
		t.Fatal("backup lost historic key", e)
	}
	if got, e := recovered.Open(restored, a, q); e != nil || !bytes.Equal(got, want) {
		t.Fatal("backup lost current key", e)
	}
}
