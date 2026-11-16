package backupfile

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPassword = "a backup password 2026"

func TestEncryptedStreamRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, chunkSize + 19, 2*chunkSize + 3} {
		raw := make([]byte, size)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		var encrypted, plain bytes.Buffer
		if err := Encrypt(&encrypted, bytes.NewReader(raw), testPassword); err != nil {
			t.Fatal(err)
		}
		length, err := EncryptedSize(int64(size))
		if err != nil || int64(encrypted.Len()) != length {
			t.Fatal("wrong encrypted length", length, err)
		}
		if err := Decrypt(&plain, bytes.NewReader(encrypted.Bytes()), testPassword); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, plain.Bytes()) {
			t.Fatal("round trip changed bytes")
		}
	}
	for _, password := range []string{"", strings.Repeat("字", 11)} {
		if ValidatePassword(password) == nil {
			t.Fatal("short password accepted")
		}
	}
	if err := ValidatePassword(strings.Repeat("字", 12)); err != nil {
		t.Fatal(err)
	}
}
func TestEncryptedBundleAtomicUnlockAndLegacyZIP(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 2*chunkSize+31)
	_, _ = rand.Read(raw)
	db, zipPath := filepath.Join(dir, "db"), filepath.Join(dir, "old.zip")
	if err := os.WriteFile(db, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Write(db, zipPath, bytes.Repeat([]byte{3}, 32)); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if err := Encrypt(&encrypted, bytes.NewReader(original), testPassword); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "backup.zip.enc")
	blob := encrypted.Bytes()
	cases := map[string][]byte{}
	for _, offset := range []int{16, 17, 33, 41, 46, headerSize, headerSize + 7, headerSize + 4 + chunkSize + 16 + 11} {
		changed := bytes.Clone(blob)
		changed[offset] ^= 1
		cases["tamper-"+string(rune('a'+len(cases)))] = changed
	}
	for _, size := range []int{1, headerSize - 1, headerSize + 3, len(blob) - 1, len(blob) - 20} {
		cases["truncate-"+string(rune('a'+len(cases)))] = blob[:size]
	}
	cases["trailing"] = append(bytes.Clone(blob), 1)
	for name, invalid := range cases {
		if err := os.WriteFile(source, invalid, 0600); err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(dir, name+".zip")
		if err := Unlock(source, destination, testPassword); err == nil {
			t.Fatal("damaged backup accepted", name)
		}
		if _, err := os.Stat(destination); !os.IsNotExist(err) {
			t.Fatal("failed restore published output", name, err)
		}
	}
	if err := os.WriteFile(source, blob, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Unlock(source, filepath.Join(dir, "wrong.zip"), "wrong password value"); err == nil || !strings.Contains(err.Error(), "备份密码错误") {
		t.Fatal(err)
	}
	for _, input := range []string{source, zipPath} {
		destination := filepath.Join(dir, filepath.Base(input)+".restored")
		if err := Unlock(input, destination, testPassword); err != nil {
			t.Fatal(err)
		}
		restored, err := os.ReadFile(destination)
		if err != nil || !bytes.Equal(restored, original) {
			t.Fatal("bundle bytes changed", err)
		}
		if err := Unlock(input, destination, testPassword); err == nil {
			t.Fatal("existing output overwritten")
		}
	}
	temps, _ := filepath.Glob(filepath.Join(dir, ".backup-unlock-*"))
	if len(temps) != 0 {
		t.Fatal("temporary plaintext retained", temps)
	}
}
func TestEncryptedStreamRejectsShortWriter(t *testing.T) {
	if err := Encrypt(shortWriter{}, strings.NewReader("data"), testPassword); err != io.ErrShortWrite {
		t.Fatal(err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
