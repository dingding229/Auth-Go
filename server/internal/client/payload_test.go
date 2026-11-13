package client

import (
	"authgo/internal/code"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/licensekey"
	"authgo/internal/model"
	"authgo/internal/payloadkey"
	"authgo/internal/verify"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"gorm.io/gorm"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func payloadLP(a []byte, s string) []byte {
	return append(binary.BigEndian.AppendUint32(a, uint32(len(s))), s...)
}
func sealPayload(t *testing.T, p payloadkey.Payload, public string) payloadkey.Payload {
	t.Helper()
	raw, _ := base64.RawURLEncoding.DecodeString(p.Manifest)
	h := sha256.Sum256(raw)
	a := []byte("authgo-payload-envelope-v2\x00")
	for _, s := range []string{p.AppKey, p.Version, p.BuiltAt, p.KeyID, p.Config} {
		a = payloadLP(a, s)
	}
	a = append(a, h[:]...)
	pubraw, _ := base64.RawURLEncoding.DecodeString(public)
	pub, e := ecdh.X25519().NewPublicKey(pubraw)
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
	b, _ := aes.NewCipher(kek)
	g, _ := cipher.NewGCM(b)
	n := bytes.Repeat([]byte{9}, 12)
	enc := base64.RawURLEncoding.EncodeToString
	p.Envelope = payloadkey.Envelope{E: enc(priv.PublicKey().Bytes()), N: enc(n), C: enc(g.Seal(nil, n, bytes.Repeat([]byte{42}, 32), a))}
	return p
}

type unlockFixture struct {
	*loggingFixture
	p         payloadkey.Payload
	in        Input
	l         model.License
	recipient *ecdh.PrivateKey
	opened    *int
}

func newUnlockFixture(t *testing.T) *unlockFixture {
	t.Helper()
	f := newLoggingFixture(t, Options{IPBurst: 100, LicenseBurst: 100})
	ctx := context.Background()
	app, e := f.service.channel.EnsureApplication(ctx, f.app.ID)
	if e != nil {
		t.Fatal(e)
	}
	f.app = app
	var l model.License
	f.db.First(&l, "key=?", f.key)
	l.VerifyMethods = []string{"KEY", "FLOATING"}
	l.Type = "standard"
	if e = f.db.Save(&l).Error; e != nil {
		t.Fatal(e)
	}
	in := Input{LicenseKey: f.key, Device: strings.Repeat("a", 64), InstanceSession: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))}
	active := f.service.process(ctx, app, verify.Activate, "203.0.113.7", in, f.clock.now())
	if active.Code != code.OK {
		t.Fatal(active.Code)
	}
	in.ActivationToken = active.Data["activation_token"].(string)
	k, e := f.service.payloadKeys.Rotate(ctx, app.ID)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../../sdk/vectors/payload-envelope.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Payload payloadkey.Payload `json:"payload"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	p := v.Payload
	p.AppKey = app.AppKey
	p.KeyID = k.KeyID
	p.BuiltAt = f.clock.now().UTC().Format(time.RFC3339)
	configRaw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(p.Config, "authgo2."))
	var cfg map[string]any
	json.Unmarshal(configRaw, &cfg)
	cfg["app_key"] = app.AppKey
	configRaw, _ = json.Marshal(cfg)
	p.Config = "authgo2." + base64.RawURLEncoding.EncodeToString(configRaw)
	p = sealPayload(t, p, k.PublicKey)
	in.Payload, _ = json.Marshal(p)
	recipient, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	in.EphemeralPublicKey = base64.RawURLEncoding.EncodeToString(recipient.PublicKey().Bytes())
	opened := new(int)
	original := f.service.payloadOpen
	f.service.payloadOpen = func(tx *gorm.DB, a model.Application, p payloadkey.Payload) ([]byte, error) {
		*opened++
		return original(tx, a, p)
	}
	return &unlockFixture{f, p, in, l, recipient, opened}
}
func (f *unlockFixture) call(in Input) outcome {
	return f.service.processPolicyPayload(context.Background(), f.app, verify.Verify, "203.0.113.7", in, f.clock.now(), true, true)
}
func TestPayloadAuthorizationAndSeatPrecedeUnsealing(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(*unlockFixture, *Input)
	}{
		{"unknown", code.LicenseNotFound, func(f *unlockFixture, in *Input) { in.LicenseKey = "other" }},
		{"revoked", code.LicenseRevoked, func(f *unlockFixture, in *Input) {
			f.db.Model(&f.l).Update("status", "revoked")
			in.ActivationToken = "bad"
		}},
		{"expired", code.LicenseExpired, func(f *unlockFixture, in *Input) {
			f.db.Model(&f.l).Update("expires_at", f.clock.now())
			in.ActivationToken = "bad"
		}},
		{"not-started", code.LicenseNotStarted, func(f *unlockFixture, in *Input) { f.db.Model(&f.l).Update("starts_at", f.clock.now().Add(time.Hour)) }},
		{"disabled-app", code.AppDisabled, func(f *unlockFixture, in *Input) { f.db.Model(&f.app).Update("status", "disabled") }},
		{"invalid-token", code.ActivationInvalid, func(f *unlockFixture, in *Input) { in.ActivationToken = "bad" }},
		{"other-device", code.ActivationInvalid, func(f *unlockFixture, in *Input) { in.Device = strings.Repeat("b", 64) }},
		{"other-instance", code.InstanceReplaced, func(f *unlockFixture, in *Input) {
			in.InstanceSession = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
		}},
		{"lease-expired", code.LeaseExpired, func(f *unlockFixture, in *Input) {
			f.db.Model(&model.Activation{}).Where("license_id=? AND kind='floating'", f.l.ID).Update("lease_expires_at", f.clock.now())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newUnlockFixture(t)
			in := f.in
			tc.mutate(f, &in)
			out := f.call(in)
			if out.Code != tc.want || *f.opened != 0 {
				t.Fatalf("%s opens=%d want=%s", out.Code, *f.opened, tc.want)
			}
		})
	}
}
func TestPayloadTrialVersionAndMaintenance(t *testing.T) {
	for _, tc := range []struct {
		name, want      string
		bound           time.Duration
		disabled, trial bool
	}{
		{"no-limit", code.OK, 0, false, false}, {"before", code.OK, time.Second, false, false}, {"equal", code.OK, 0, false, false}, {"after", code.MaintenanceExpired, -time.Second, false, false}, {"disabled-before-maintenance", code.VersionDisabled, -time.Second, true, false}, {"trial", code.OK, time.Second, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newUnlockFixture(t)
			published := f.clock.now().Add(-time.Hour)
			if e := f.db.Create(&model.AppVersion{AppID: f.app.ID, Version: f.p.Version, PublishedAt: &published, Disabled: tc.disabled, Withdrawn: true, Source: "manual"}).Error; e != nil {
				t.Fatal(e)
			}
			if tc.name != "no-limit" {
				if e := f.db.Model(&f.l).Update("maintenance_until", f.clock.now().Add(tc.bound)).Error; e != nil {
					t.Fatal(e)
				}
			}
			if tc.trial {
				f.db.Model(&f.l).Update("type", "trial")
			}
			in := f.in
			in.Version = "999.0.0"
			out := f.call(in)
			if out.Code != tc.want {
				t.Fatal(out.Code, "want", tc.want)
			}
			if out.Code == code.OK {
				if out.Data["is_trial"] != tc.trial {
					t.Fatal("trial missing")
				}
				f.unwrap(t, out)
			}
			if out.Code == code.MaintenanceExpired {
				if _, ok := out.Data["latest_entitled_version"]; !ok {
					t.Fatal("missing recommendation")
				}
			}
		})
	}
}
func (f *unlockFixture) unwrap(t *testing.T, out outcome) {
	t.Helper()
	r := payloadkey.Envelope{E: out.Data["e"].(string), N: out.Data["n"].(string), C: out.Data["c"].(string)}
	pubraw, _ := base64.RawURLEncoding.DecodeString(r.E)
	pub, _ := ecdh.X25519().NewPublicKey(pubraw)
	shared, e := f.recipient.ECDH(pub)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(f.p.Manifest)
	h := sha256.Sum256(raw)
	a := []byte("authgo-payload-rewrap-v2\x00")
	for _, s := range []string{f.p.AppKey, f.p.Version, f.p.BuiltAt, f.p.KeyID} {
		a = payloadLP(a, s)
	}
	a = append(a, h[:]...)
	a = append(a, f.recipient.PublicKey().Bytes()...)
	challenge, _ := base64.RawURLEncoding.DecodeString(f.in.Challenge)
	a = append(a, challenge...)
	salt := sha256.Sum256(a)
	key, _ := hkdf.Key(sha256.New, shared, salt[:], "authgo/payload/v1/rewrap", 32)
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	n, _ := base64.RawURLEncoding.DecodeString(r.N)
	c, _ := base64.RawURLEncoding.DecodeString(r.C)
	got, e := g.Open(nil, n, c, a)
	if e != nil || !bytes.Equal(got, bytes.Repeat([]byte{42}, 32)) {
		t.Fatal("client failed to decrypt", e)
	}
}
func TestPayloadTamperingAndNoNewSeatOrTakeover(t *testing.T) {
	f := newUnlockFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*payloadkey.Payload)
	}{
		{"app", func(p *payloadkey.Payload) { p.AppKey = "other" }}, {"key", func(p *payloadkey.Payload) { p.KeyID = "other" }},
		{"version", func(p *payloadkey.Payload) { p.Version = "7.0.0" }}, {"built", func(p *payloadkey.Payload) { p.BuiltAt = "2026-11-08T00:00:00Z" }},
		{"config", func(p *payloadkey.Payload) {
			raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(p.Config, "authgo2."))
			raw = bytes.ReplaceAll(raw, []byte("https://"), []byte("https://other."))
			p.Config = "authgo2." + base64.RawURLEncoding.EncodeToString(raw)
		}},
		{"manifest", func(p *payloadkey.Payload) { p.Manifest = base64.RawURLEncoding.EncodeToString([]byte(`{"files":[]}`)) }},
		{"ciphertext", func(p *payloadkey.Payload) { p.Envelope.C = base64.RawURLEncoding.EncodeToString(make([]byte, 48)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := f.p
			tc.mutate(&p)
			in := f.in
			in.Payload, _ = json.Marshal(p)
			if out := f.call(in); out.Code != code.PayloadInvalid {
				t.Fatal(out.Code)
			}
		})
	}
	var before, after int64
	f.db.Model(&model.Activation{}).Where("license_id=?", f.l.ID).Count(&before)
	out := f.call(f.in)
	if out.Code != code.OK {
		t.Fatal(out.Code)
	}
	f.unwrap(t, out)
	f.db.Model(&model.Activation{}).Where("license_id=?", f.l.ID).Count(&after)
	if before != after {
		t.Fatal("unlock consumed seat")
	}
}
func (f *unlockFixture) signedUnlock(t *testing.T) Envelope {
	t.Helper()
	raw, _ := json.Marshal(f.in)
	f.seq++
	nonce := fmt.Sprintf("payload-nonce-%020d", f.seq)
	ts := strconv.FormatInt(f.clock.now().Unix(), 10)
	req := httptest.NewRequest("POST", "/api/v1/client/payload.unlock", bytes.NewReader(raw))
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Key", f.app.AppKey)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", cryptoutil.HMACSHA256([]byte(f.secret), SigningInput("payload.unlock", ts, nonce, raw)))
	w := httptest.NewRecorder()
	f.serve(t, w, req)
	var out Envelope
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	if out.Signature == nil {
		t.Fatal("unsigned unlock")
	}
	sig, _ := base64.StdEncoding.DecodeString(*out.Signature)
	pub, _ := base64.StdEncoding.DecodeString(f.app.PublicKey)
	signed, _ := cryptoutil.CanonicalJSON(map[string]any{"code": out.Code, "data": out.Data, "ts": out.TS})
	if !cryptoutil.Verify(pub, signed, sig) || out.Nonce != nonce || out.Data["request_nonce"] != nonce {
		t.Fatal("unlock response unauthenticated")
	}
	return out
}
func TestPayloadGatewayFixedRateAndSafeLogs(t *testing.T) {
	f := newUnlockFixture(t)
	f.service.ConfigureRateLimits(1000, 1000, 1000, 1000)
	f.db.Model(&f.l).Updates(map[string]any{"type": "trial", "source": "self_trial"})
	for i := 0; i < 4; i++ {
		out := f.signedUnlock(t)
		want := code.OK
		if i == 3 {
			want = code.RateLimited
		}
		if out.Code != want {
			t.Fatal(i, out.Code, want)
		}
	}
	if *f.opened != 3 {
		t.Fatal("limit after decryption", *f.opened)
	}
	f.clock.add(10 * time.Second)
	if out := f.signedUnlock(t); out.Code != code.OK {
		t.Fatal("fixed refill", out.Code)
	}
	f.drain(t)
	var logs []model.VerifyLog
	if e := f.db.Where("action=?", "payload.unlock").Find(&logs).Error; e != nil {
		t.Fatal(e)
	}
	if len(logs) == 0 {
		t.Fatal("no unlock logs")
	}
	for _, row := range logs {
		if row.Success && (row.LicenseID == nil || row.ClientVersion != f.p.Version) {
			t.Fatal("untraceable result")
		}
	}
	raw, _ := json.Marshal(logs)
	for _, secret := range []string{f.p.Config, f.p.Envelope.C, f.in.EphemeralPublicKey, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret in validation log")
		}
	}
}

func TestPayloadOtherSoftwareEnvelopeAndUnknownLicense(t *testing.T) {
	f := newUnlockFixture(t)
	other := model.Application{Name: "other", AppKey: "app_other"}
	if e := f.db.Create(&other).Error; e != nil {
		t.Fatal(e)
	}
	k, e := f.service.payloadKeys.Rotate(context.Background(), other.ID)
	if e != nil {
		t.Fatal(e)
	}
	p := f.p
	p.AppKey = other.AppKey
	p.KeyID = k.KeyID
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(p.Config, "authgo2."))
	var cfg map[string]any
	json.Unmarshal(raw, &cfg)
	cfg["app_key"] = other.AppKey
	raw, _ = json.Marshal(cfg)
	p.Config = "authgo2." + base64.RawURLEncoding.EncodeToString(raw)
	p = sealPayload(t, p, k.PublicKey)
	in := f.in
	in.Payload, _ = json.Marshal(p)
	if out := f.call(in); out.Code != code.PayloadInvalid {
		t.Fatal("cross-software envelope accepted", out.Code)
	}
	*f.opened = 0
	f.in.LicenseKey, e = licensekey.Generate("AUTH")
	if e != nil {
		t.Fatal(e)
	}
	if out := f.signedUnlock(t); out.Code != code.LicenseNotFound || *f.opened != 0 {
		t.Fatal("unknown license reached private key", out.Code)
	}
}

func TestPayloadBuildMaintenance(t *testing.T) {
	f := newUnlockFixture(t)
	if e := f.db.Model(&f.l).Updates(map[string]any{"maintenance_until": f.clock.now().Add(-time.Second)}).Error; e != nil {
		t.Fatal(e)
	}
	if out := f.call(f.in); out.Code != code.MaintenanceExpired {
		t.Fatal("build maintenance must reject expired entitlement", out.Code)
	}
	if e := f.db.Model(&f.l).Update("maintenance_until", f.clock.now()).Error; e != nil {
		t.Fatal(e)
	}
	if out := f.call(f.in); out.Code != code.OK {
		t.Fatal("maintenance decision incorrect", out.Code)
	}
}

func TestPayloadAnyPolicyCannotSkipFloatingLease(t *testing.T) {
	f := newUnlockFixture(t)
	if e := f.db.First(&f.l, f.l.ID).Error; e != nil {
		t.Fatal(e)
	}
	f.l.VerifyMethods = []string{"KEY", "FLOATING"}
	f.l.MatchMode = "any"
	if e := f.db.Save(&f.l).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.db.Model(&model.Activation{}).Where("license_id=? AND kind='floating'", f.l.ID).Update("lease_expires_at", f.clock.now()).Error; e != nil {
		t.Fatal(e)
	}
	if out := f.call(f.in); out.Code != code.LeaseExpired || *f.opened != 0 {
		t.Fatal("ANY policy bypassed floating seat", out.Code, *f.opened)
	}
}

func TestPayloadWatermarkResponseUsesAuthorizedIDAndPreviousKey(t *testing.T) {
	f := newUnlockFixture(t)
	out := f.call(f.in)
	if out.Code != code.OK {
		t.Fatal("unlock failed", out.Code)
	}
	watermark, ok := out.Data["watermark"].(string)
	if !ok || len(watermark) != 64 || watermark == strings.Repeat("0", 64) {
		t.Fatal("missing watermark in authenticated response data")
	}
	want, e := f.service.PayloadKeys().WatermarkForLicense(f.db, f.app, f.p.KeyID, f.l.ID)
	if e != nil || watermark != want {
		t.Fatal("watermark not bound to authorized license id", e)
	}
	f.unwrap(t, out)
	if _, e = f.service.PayloadKeys().Rotate(context.Background(), f.app.ID); e != nil {
		t.Fatal(e)
	}
	again := f.call(f.in)
	if again.Code != code.OK || again.Data["watermark"] != watermark {
		t.Fatal("old key id watermark changed on rotation")
	}
	other, e := f.service.PayloadKeys().WatermarkForLicense(f.db, f.app, f.p.KeyID, f.l.ID+1)
	if e != nil || other == watermark {
		t.Fatal("distinct license watermark unexpectedly equal", e)
	}
}
