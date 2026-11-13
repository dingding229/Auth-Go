package catalog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/db"
	"authgo/internal/model"
	"authgo/internal/response"

	"gorm.io/gorm"
)

type fixture struct {
	s      *Service
	db     *gorm.DB
	master []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	database, err := db.Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := database.DB()
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	s, err := NewService(database, key)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{s, database, key}
}
func ptr[T any](v T) *T { return &v }
func status(t *testing.T, err error, want int) {
	t.Helper()
	var safe *apperror.Error
	if !errors.As(err, &safe) || safe.Status != want {
		t.Fatalf("error=%v want=%d", err, want)
	}
}
func (f *fixture) app(t *testing.T, name string) ApplicationInfo {
	t.Helper()
	a, err := f.s.CreateApplication(context.Background(), ApplicationInput{Name: ptr(name)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func query(t *testing.T, values url.Values, sorts ...string) response.ListQuery {
	t.Helper()
	q, err := response.ParseList(values, sorts...)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestApplicationCredentialsAndRotations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.app(t, "测试应用")
	if a.NextCheckIn != 3600 || a.GraceHours != 72 || a.Status != "active" || a.PreviousPublicKey != "" {
		t.Fatal("defaults")
	}
	secret, err := f.s.RevealSecret(ctx, a.ID)
	if err != nil || len(secret) != 43 {
		t.Fatal("secret", err)
	}
	var stored model.Application
	if err := f.db.First(&stored, a.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored.AppSecretEncrypted, "v1:") || stored.AppSecretEncrypted == secret {
		t.Fatal("secret not encrypted")
	}
	private, err := f.s.cipher.Decrypt(stored.PrivateKeyEncrypted, aad(a.AppKey, "ed25519_private_key"))
	if err != nil || len(private) != 64 {
		t.Fatal("private key roundtrip", err)
	}
	public, _ := base64.StdEncoding.DecodeString(a.PublicKey)
	signature, err := cryptoutil.Sign(private, []byte("payload"))
	if err != nil || !cryptoutil.Verify(public, []byte("payload"), signature) {
		t.Fatal("stored keys inconsistent")
	}
	restarted, _ := NewService(f.db, f.master)
	recovered, err := restarted.RevealSecret(ctx, a.ID)
	if err != nil || recovered != secret {
		t.Fatal("restart decryption")
	}
	wrong, _ := NewService(f.db, bytes.Repeat([]byte{8}, 32))
	if _, err := wrong.RevealSecret(ctx, a.ID); err == nil {
		t.Fatal("wrong master accepted")
	}
	other := f.app(t, "另一应用")
	if err := f.db.Model(&model.Application{}).Where("id = ?", other.ID).Update("app_secret_encrypted", stored.AppSecretEncrypted).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RevealSecret(ctx, other.ID); err == nil {
		t.Fatal("cross-application ciphertext accepted")
	}
	if _, err := f.s.PublicKeyPEM(ctx, a.ID, true); err == nil {
		t.Fatal("unexpected previous key")
	}
	pem, err := f.s.PublicKeyPEM(ctx, a.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cryptoutil.ParsePublicKeyPEM(pem)
	if err != nil || !bytes.Equal(parsed, public) {
		t.Fatal("PEM differs")
	}
	rotated, err := f.s.RotateSecret(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	newSecret, err := f.s.RevealSecret(ctx, a.ID)
	if err != nil || secret == newSecret || rotated.AppKey != a.AppKey || rotated.PublicKey != a.PublicKey {
		t.Fatal("secret rotation")
	}
	oldMAC := cryptoutil.HMACSHA256([]byte(secret), []byte("body"))
	if cryptoutil.VerifyHMACSHA256([]byte(newSecret), []byte("body"), oldMAC) {
		t.Fatal("old secret still validates")
	}
	first, err := f.s.RotateKeyPair(ctx, a.ID)
	if err != nil || first.PreviousPublicKey != a.PublicKey || first.PublicKey == a.PublicKey {
		t.Fatal("key rotation", err)
	}
	second, err := f.s.RotateKeyPair(ctx, a.ID)
	if err != nil || second.PreviousPublicKey != first.PublicKey {
		t.Fatal("previous key not latest predecessor")
	}
	previousPEM, err := f.s.PublicKeyPEM(ctx, a.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	oldPublic, _ := cryptoutil.ParsePublicKeyPEM(previousPEM)
	expected, _ := base64.StdEncoding.DecodeString(first.PublicKey)
	if !bytes.Equal(oldPublic, expected) {
		t.Fatal("previous PEM mismatch")
	}
	f.db.First(&stored, a.ID)
	private, err = f.s.cipher.Decrypt(stored.PrivateKeyEncrypted, aad(a.AppKey, "ed25519_private_key"))
	if err != nil {
		t.Fatal(err)
	}
	currentPublic, _ := base64.StdEncoding.DecodeString(second.PublicKey)
	signature, _ = cryptoutil.Sign(private, []byte("current"))
	if !cryptoutil.Verify(currentPublic, []byte("current"), signature) {
		t.Fatal("rotated keys inconsistent")
	}
	encoded, _ := json.Marshal(second)
	for _, bad := range []string{secret, newSecret, stored.PrivateKeyEncrypted, "app_secret_encrypted", "private_key"} {
		if bytes.Contains(encoded, []byte(bad)) {
			t.Fatal("DTO leaked private credentials")
		}
	}
}

func TestApplicationCRUDValidationAndSearch(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	zero, err := f.s.CreateApplication(ctx, ApplicationInput{Name: ptr("100% 应用"), GraceHours: ptr(0)})
	if err != nil || zero.GraceHours != 0 {
		t.Fatal("explicit zero replaced with default", err)
	}
	f.app(t, "普通应用")
	updated, err := f.s.UpdateApplication(ctx, zero.ID, ApplicationInput{Status: ptr("disabled")})
	if err != nil || updated.Status != "disabled" || updated.GraceHours != 0 {
		t.Fatal("partial update/zero", err)
	}
	items, total, err := f.s.ListApplications(ctx, query(t, url.Values{"q": {"%"}, "sort_by": {"name"}, "sort_order": {"asc"}}, "name"), "")
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != zero.ID {
		t.Fatal("literal search", err)
	}
	_, total, err = f.s.ListApplications(ctx, query(t, url.Values{}, "name"), "disabled")
	if err != nil || total != 1 {
		t.Fatal("status filter")
	}
	for _, in := range []ApplicationInput{{Name: ptr("")}, {NextCheckIn: ptr(0)}, {GraceHours: ptr(-1)}, {}, {}, {Status: ptr("suspended")}} {
		_, err := f.s.UpdateApplication(ctx, zero.ID, in)
		status(t, err, 400)
	}
	_, err = f.s.UpdateApplication(ctx, zero.ID, ApplicationInput{})
	status(t, err, 400)
	if err := f.s.DeleteApplication(ctx, zero.ID); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.GetApplication(ctx, zero.ID)
	status(t, err, 404)
}

func TestDeleteApplicationCleansOnlyItsTemplatesAtomically(t *testing.T) {
	for _, hasLicense := range []bool{false, true} {
		name := "only configuration"
		if hasLicense {
			name = "license prevents cleanup"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			a := f.app(t, "目标软件")
			b := f.app(t, "其他软件")
			for _, row := range []struct{ id, app uint64 }{{7101, a.ID}, {7102, b.ID}} {
				if e := f.db.Exec(`INSERT INTO feature_templates(id,app_id,name,features) VALUES(?,?,'配置','{}')`, row.id, row.app).Error; e != nil {
					t.Fatal(e)
				}
				if e := f.db.Model(&model.Application{}).Where("id=?", row.app).Update("trial_template_id", row.id).Error; e != nil {
					t.Fatal(e)
				}
			}
			if hasLicense {
				if e := f.db.Create(&model.License{AppID: a.ID, Key: "retained-template-license", Features: model.JSONMap{}}).Error; e != nil {
					t.Fatal(e)
				}
			}
			err := f.s.DeleteApplication(ctx, a.ID)
			want := int64(0)
			if hasLicense {
				status(t, err, 409)
				want = 1
			} else if err != nil {
				t.Fatal(err)
			}
			var n int64
			for _, row := range []struct {
				table string
				id    uint64
				want  int64
			}{{"applications", a.ID, want}, {"feature_templates", 7101, want}, {"applications", b.ID, 1}, {"feature_templates", 7102, 1}} {
				if e := f.db.Table(row.table).Where("id=?", row.id).Count(&n).Error; e != nil {
					t.Fatal(e)
				}
				if n != row.want {
					t.Fatalf("%s %d count=%d want=%d", row.table, row.id, n, row.want)
				}
			}
			var other model.Application
			if e := f.db.First(&other, b.ID).Error; e != nil || other.TrialTemplateID == nil || *other.TrialTemplateID != 7102 {
				t.Fatal("other software configuration changed", other, e)
			}
			if hasLicense {
				var preserved model.Application
				if e := f.db.First(&preserved, a.ID).Error; e != nil || preserved.TrialTemplateID == nil || *preserved.TrialTemplateID != 7101 {
					t.Fatal("blocked delete changed trial template", preserved, e)
				}
			}
		})
	}
}
