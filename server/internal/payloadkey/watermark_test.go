package payloadkey

import (
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/internal/trial"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"gorm.io/gorm"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWatermarkSharedDerivationVectors(t *testing.T) {
	raw, e := os.ReadFile("../../../sdk/vectors/watermark.json")
	if e != nil {
		t.Fatal(e)
	}
	var root struct {
		Crypto struct {
			Private string `json:"private_hex"`
			Public  string `json:"public_hex"`
			Tag     string `json:"tag"`
			Cases   []struct {
				ID        string `json:"license_id"`
				Watermark string `json:"watermark"`
			} `json:"cases"`
		} `json:"crypto"`
	}
	if e = json.Unmarshal(raw, &root); e != nil {
		t.Fatal(e)
	}
	priv, e := hex.DecodeString(root.Crypto.Private)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := hex.DecodeString(root.Crypto.Public)
	if e != nil {
		t.Fatal(e)
	}
	scalar, e := ecdh.X25519().NewPrivateKey(priv)
	if e != nil || !bytes.Equal(scalar.PublicKey().Bytes(), pub) {
		t.Fatal("vector key pair", e)
	}
	tag, e := WatermarkTag(pub)
	if e != nil || tag != root.Crypto.Tag {
		t.Fatal("tag", e)
	}
	for _, v := range root.Crypto.Cases {
		id, e := strconv.ParseUint(v.ID, 10, 64)
		if e != nil {
			t.Fatal(e)
		}
		got, e := LicenseWatermark(priv, id)
		if e != nil || got != v.Watermark {
			t.Fatal("license id serialization/HKDF/HMAC", v.ID, e)
		}
	}
	if _, e = LicenseWatermark(priv, 0); e == nil {
		t.Fatal("zero license id accepted")
	}
	for _, size := range []int{0, 31, 33} {
		if _, e = LicenseWatermark(make([]byte, size), 1); e == nil {
			t.Fatal("private size", size)
		}
		if _, e = WatermarkTag(make([]byte, size)); e == nil {
			t.Fatal("public size", size)
		}
	}
}
func TestWatermarkTraceRotationScopeTrialNoSecretsNoNPlusOne(t *testing.T) {
	d := database(t)
	box, e := cryptoutil.NewCipher(bytes.Repeat([]byte{9}, 32))
	if e != nil {
		t.Fatal(e)
	}
	s := New(d, box)
	ctx := context.Background()
	app := model.Application{Name: "wm", AppKey: "wm-app"}
	other := model.Application{Name: "other", AppKey: "wm-other"}
	for _, a := range []*model.Application{&app, &other} {
		if e = d.Create(a).Error; e != nil {
			t.Fatal(e)
		}
	}
	empty, e := s.WatermarkTags(ctx, app.ID)
	if e != nil || len(empty) != 0 {
		t.Fatal("empty tags", e)
	}
	user := model.EndUser{Name: "watermark customer"}
	if e = d.Create(&user).Error; e != nil {
		t.Fatal(e)
	}
	licenses := []model.License{}
	for i := 0; i < 32; i++ {
		licenses = append(licenses, model.License{AppID: app.ID, UserID: &user.ID, Key: "DO_NOT_RETURN_KEY_" + strconv.Itoa(i)})
	}
	licenses[0].Type = "trial"
	licenses[0].Source = "self_trial"
	if e = d.Omit("Application", "User").Create(&licenses).Error; e != nil {
		t.Fatal(e)
	}
	claim := trial.Claim{AppID: app.ID, LicenseID: licenses[0].ID, IPKey: "203.0.113.3", InstanceID: strings.Repeat("a", 64), CreatedAt: time.Unix(1730000000, 0).UTC()}
	if e = d.Create(&claim).Error; e != nil {
		t.Fatal(e)
	}
	first, e := s.Rotate(ctx, app.ID)
	if e != nil {
		t.Fatal(e)
	}
	value, e := s.WatermarkForLicense(d, app, first.KeyID, licenses[0].ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Rotate(ctx, app.ID); e != nil {
		t.Fatal(e)
	}
	tags, e := s.WatermarkTags(ctx, app.ID)
	if e != nil || len(tags) != 2 || tags[0].KeyID != first.KeyID {
		t.Fatal("rotation history", e)
	}
	queries := 0
	if e = d.Callback().Query().Before("gorm:query").Register("wm_count", func(*gorm.DB) { queries++ }); e != nil {
		t.Fatal(e)
	}
	got, e := s.TraceWatermark(ctx, app.ID, value)
	d.Callback().Query().Remove("wm_count")
	if e != nil || !got.Found || got.LicenseID != licenses[0].ID || got.KeyID != first.KeyID || !got.IsTrial || got.UserName != user.Name || got.SourceIP != claim.IPKey || len(got.Sources) != 1 {
		t.Fatalf("trace metadata: %#v %v", got, e)
	}
	if queries > 5 {
		t.Fatal("N+1 queries", queries)
	}
	raw, _ := json.Marshal(got)
	if bytes.Contains(raw, []byte("DO_NOT_RETURN_KEY_")) || bytes.Contains(raw, []byte(value)) || bytes.Contains(raw, []byte("private")) {
		t.Fatal("sensitive trace response")
	}
	raw, _ = json.Marshal(tags)
	if bytes.Contains(raw, []byte("private")) || bytes.Contains(raw, []byte("public_key")) {
		t.Fatal("excess tag fields")
	}
	miss, e := s.TraceWatermark(ctx, other.ID, value)
	if e != nil || miss.Found {
		t.Fatal("cross-app trace", e)
	}
	if _, e = s.WatermarkForLicense(d, other, first.KeyID, licenses[0].ID); e == nil {
		t.Fatal("cross-app key")
	}
	if e = d.Delete(&licenses[0]).Error; e == nil {
		miss, e = s.TraceWatermark(ctx, app.ID, value)
		if e != nil || miss.Found {
			t.Fatal("deleted license matched", e)
		}
	} else {
		// Foreign-key protected licenses cannot be deleted until their source rows
		// are explicitly removed; this is not a skip or change to production rules.
		if e = d.Delete(&claim).Error; e != nil {
			t.Fatal(e)
		}
		if e = d.Delete(&licenses[0]).Error; e != nil {
			t.Fatal(e)
		}
		miss, e = s.TraceWatermark(ctx, app.ID, value)
		if e != nil || miss.Found {
			t.Fatal("deleted license matched", e)
		}
	}
	for _, bad := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), value + "\n"} {
		if _, e = s.TraceWatermark(ctx, app.ID, bad); e == nil {
			t.Fatal("invalid watermark accepted")
		}
	}
	if _, e = s.WatermarkTags(ctx, 999999); e == nil {
		t.Fatal("missing app accepted")
	}
}
