package client

import (
	"authgo/internal/catalog"
	"authgo/internal/code"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	sdk "authgo/sdk"
	"authgo/sdk/wire"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func (f *loggingFixture) historyCall(t *testing.T, token string, options map[string]any, want string) Envelope {
	t.Helper()
	body := map[string]any{"license_key": f.key, "activation_token": token, "challenge": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	for k, v := range options {
		body[k] = v
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	f.seq++
	nonce := fmt.Sprintf("history-nonce-%020d", f.seq)
	ts := strconv.FormatInt(f.clock.now().Unix(), 10)
	req := httptest.NewRequest("POST", "/api/v1/client/versions", bytes.NewReader(raw))
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Key", f.app.AppKey)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", cryptoutil.HMACSHA256([]byte(f.secret), SigningInput("versions", ts, nonce, raw)))
	w := httptest.NewRecorder()
	f.serve(t, w, req)
	var out Envelope
	d := json.NewDecoder(w.Body)
	d.UseNumber()
	if err := d.Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Code != want {
		t.Fatalf("code=%s want=%s", out.Code, want)
	}
	if out.Signature == nil || out.Nonce != nonce || out.Data["request_nonce"] != nonce {
		t.Fatal("missing signature or nonce binding")
	}
	sig, _ := base64.StdEncoding.DecodeString(*out.Signature)
	pub, _ := base64.StdEncoding.DecodeString(f.app.PublicKey)
	canonical, err := wire.CanonicalJSON(map[string]any{"code": out.Code, "data": out.Data, "ts": out.TS})
	if err != nil || !cryptoutil.Verify(pub, canonical, sig) {
		t.Fatal("signature invalid")
	}
	return out
}

func TestVersionsPagingSchemaIsOperationSpecific(t *testing.T) {
	for _, body := range []string{`{"limit":1}`, `{"LIMIT":1}`, `{"before":""}`, `{"Before":""}`} {
		for _, operation := range []string{"verify", "update.check", "trial", "payload.unlock"} {
			var old Input
			if decode([]byte(body), operation, &old) {
				t.Errorf("accepted versions-only fields in %s", operation)
			}
		}
		var next Input
		if !decode([]byte(body), "versions", &next) {
			t.Error("rejected versions paging fields")
		}
	}
	for _, body := range []string{`{"limit":null}`, `{"limit":"50"}`, `{"limit":1.5}`, `{"before":null}`, `{"before":1}`, `{"unknown":1}`} {
		var in Input
		if decode([]byte(body), "versions", &in) {
			t.Errorf("accepted an invalid versions body: %s", body)
		}
	}
}

func TestVersionsGatewayAuthenticationPaginationAndEntitlement(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	now := f.clock.now()
	boundary := now.Add(-time.Hour)
	var lic model.License
	if err := f.db.First(&lic, "key=?", f.key).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(&lic).Update("maintenance_until", boundary).Error; err != nil {
		t.Fatal(err)
	}
	old := boundary.Add(-time.Hour)
	future := now.Add(time.Hour)
	rows := []model.AppVersion{
		{AppID: f.app.ID, Version: "1.0.0", Changelog: "first", PublishedAt: &old},
		{AppID: f.app.ID, Version: "1.1.0", Changelog: "same A", PublishedAt: &boundary, Mandatory: true},
		{AppID: f.app.ID, Version: "1.2.0", Changelog: "same B", PublishedAt: &boundary},
		{AppID: f.app.ID, Version: "1.3.0", Changelog: "outside", PublishedAt: &now},
		{AppID: f.app.ID, Version: "1.4.0", PublishedAt: &future},
		{AppID: f.app.ID, Version: "1.5.0"},
		{AppID: f.app.ID, Version: "1.6.0", PublishedAt: &now, Disabled: true},
		{AppID: f.app.ID, Version: "1.7.0", PublishedAt: &now, Withdrawn: true},
	}
	for i := range rows {
		if err := f.db.Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	catalogService, err := catalog.NewService(f.db, make([]byte, 32))
	if err != nil {
		t.Fatal("fixture catalog unavailable")
	}
	otherName := "other application"
	other, err := catalogService.CreateApplication(context.Background(), catalog.ApplicationInput{Name: &otherName})
	if err != nil {
		t.Fatal("other application setup failed")
	}
	if err := f.db.Create(&model.AppVersion{AppID: other.ID, Version: "9.0.0", PublishedAt: &now}).Error; err != nil {
		t.Fatal("other version setup failed")
	}
	f.historyCall(t, "", nil, code.ActivationInvalid)
	activation := f.signed(t, "activate", "", "", code.OK)
	token := activation.Data["activation_token"].(string)
	f.historyCall(t, token, map[string]any{"limit": 201}, code.InvalidRequest)
	f.historyCall(t, token, map[string]any{"limit": 0}, code.InvalidRequest)
	f.historyCall(t, token, map[string]any{"before": "not-a-cursor"}, code.InvalidRequest)
	got := []string{}
	entitled := []bool{}
	mandatory := []bool{}
	cursor := ""
	for page := 0; page < 4; page++ {
		opts := map[string]any{"limit": 2}
		if cursor != "" {
			opts["before"] = cursor
		}
		env := f.historyCall(t, token, opts, code.OK)
		items, ok := env.Data["items"].([]any)
		if !ok {
			t.Fatal("items type")
		}
		for _, v := range items {
			m := v.(map[string]any)
			got = append(got, m["version"].(string))
			entitled = append(entitled, m["entitled"].(bool))
			mandatory = append(mandatory, m["mandatory"].(bool))
		}
		cursor = env.Data["next_cursor"].(string)
		if cursor == "" {
			break
		}
	}
	if strings.Join(got, ",") != "1.3.0,1.2.0,1.1.0,1.0.0" {
		t.Fatalf("unexpected versions: %v", got)
	}
	if fmt.Sprint(entitled) != "[false true true true]" || fmt.Sprint(mandatory) != "[false false true false]" {
		t.Fatalf("wrong policy flags: %v %v", entitled, mandatory)
	}
	f.drain(t)
	var n int64
	if err := f.db.Model(&model.VerifyLog{}).Where("action = ? AND code = ?", "versions", code.OK).Count(&n).Error; err != nil || n < 2 {
		t.Fatalf("successful logs=%d err=%v", n, err)
	}
}

func TestVersionsDoesNotTakeOverOrRecreateFloatingSeat(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	ctx := context.Background()
	var lic model.License
	if err := f.db.First(&lic, "key=?", f.key).Error; err != nil {
		t.Fatal(err)
	}
	lic.VerifyMethods = []string{"KEY", "FLOATING"}
	if err := f.db.Save(&lic).Error; err != nil {
		t.Fatal(err)
	}
	app, err := f.service.channel.EnsureApplication(ctx, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	session := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, 16))
	other := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'b'}, 16))
	device := strings.Repeat("a", 64)
	input := Input{LicenseKey: f.key, Device: device, InstanceSession: session, Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	activated := f.service.process(ctx, app, "activate", "203.0.113.7", input, f.clock.now(), policyOptions{})
	if activated.Code != code.OK {
		t.Fatal("fixture activation failed", activated.Code)
	}
	input.ActivationToken = activated.Data["activation_token"].(string)
	f.historyCall(t, input.ActivationToken, map[string]any{"device_fingerprint": device, "instance_session": other}, code.InstanceReplaced)
	f.historyCall(t, input.ActivationToken, map[string]any{"device_fingerprint": device, "instance_session": session}, code.OK)
	if released := f.service.process(ctx, app, "release-seat", "203.0.113.7", input, f.clock.now(), policyOptions{}); released.Code != code.OK || released.Data["released"] != true {
		t.Fatal("fixture release failed", released.Code)
	}
	f.historyCall(t, input.ActivationToken, map[string]any{"device_fingerprint": device, "instance_session": session}, code.LeaseExpired)
	var seats int64
	if err := f.db.Model(&model.Activation{}).Where("license_id = ? AND kind = ?", lic.ID, model.ActivationFloating).Count(&seats).Error; err != nil || seats != 0 {
		t.Fatal("history recreated the released seat", seats, err)
	}
}

func TestVersionHistoryResponseSizeBoundAndCursor(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	now := f.clock.now()
	var lic model.License
	if err := f.db.First(&lic, "key=?", f.key).Error; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		v := model.AppVersion{AppID: f.app.ID, Version: fmt.Sprintf("1.0.%d", i), Changelog: strings.Repeat("\x01", 32768), PublishedAt: &now}
		if err := f.db.Create(&v).Error; err != nil {
			t.Fatal(err)
		}
	}
	limit := 200
	data, err := f.service.versionHistory(context.Background(), lic.ID, &limit, "", now)
	if err != nil {
		t.Fatal(err)
	}
	items := data["items"].([]historyItem)
	if len(items) == 0 || len(items) >= 30 || data["next_cursor"] == "" {
		t.Fatal("missing bounded pagination")
	}
	raw, err := json.Marshal(data)
	if err != nil || len(raw) > historyPageBytes+2048 {
		t.Fatal("oversized response", len(raw))
	}
}

// This exercises the actual Go SDK against the real local encrypted gateway.
func TestVersionsGoSDKRealGateway(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	if err := f.db.Model(&model.License{}).Where("key = ?", f.key).Update("features", model.JSONMap{}).Error; err != nil {
		t.Fatal("fixture setup failed")
	}
	f.clock.mu.Lock()
	f.clock.at = time.Now().UTC().Truncate(time.Second)
	f.clock.mu.Unlock()
	at := f.clock.now().Add(-time.Hour)
	for _, version := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		if err := f.db.Create(&model.AppVersion{AppID: f.app.ID, Version: version, PublishedAt: &at}).Error; err != nil {
			t.Fatal("insert version failed")
		}
	}
	gateway, err := f.service.channel.Current(context.Background())
	if err != nil {
		t.Fatal("gateway unavailable")
	}
	gatewayKey, err := wire.B64.DecodeString(gateway.PublicKey)
	if err != nil {
		t.Fatal("invalid test gateway")
	}
	public, err := base64.StdEncoding.DecodeString(f.app.PublicKey)
	if err != nil {
		t.Fatal("invalid test signing public key")
	}
	server := httptest.NewServer(f.router)
	defer server.Close()
	client := &sdk.Client{BaseURL: server.URL, AppKey: f.app.AppKey, AppSecret: f.secret, PublicKey: public, GatewayKey: gatewayKey, CacheDir: t.TempDir(), FingerprintFunc: func() (string, error) { return strings.Repeat("a", 64), nil }}
	if _, err := client.Activate(context.Background(), f.key, sdk.ActivateOptions{ClientVersion: "1.0.0"}); err != nil {
		t.Fatal("activation failed", err)
	}
	var versions []string
	cursor := ""
	for i := 0; i < 4; i++ {
		items, next, err := client.Versions(context.Background(), sdk.VersionsOptions{Limit: 2, Before: cursor})
		if err != nil {
			t.Fatal("history failed", err)
		}
		for _, item := range items {
			versions = append(versions, item.Version)
		}
		cursor = next
		if cursor == "" {
			break
		}
	}
	if strings.Join(versions, ",") != "1.2.0,1.1.0,1.0.0" {
		t.Fatal("wrong SDK history order", versions)
	}
}
