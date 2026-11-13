package httpserver

import (
	"authgo/internal/channel"
	"authgo/internal/client"
	"authgo/internal/code"
	"authgo/internal/model"
	"authgo/sdk/wire"
	"bytes"
	"context"
	"encoding/json"
	"gorm.io/gorm"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGatewayOnlyEncryptedSurfaceReplayAndTampering(t *testing.T) {
	f := newClientFixture(t, client.Options{IPBurst: 1000, LicenseBurst: 1000}, nil)
	keys, e := channel.New(f.db, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	k, _ := keys.Current(context.Background())
	pub, _ := wire.B64.DecodeString(k.PublicKey)
	nonce := 0
	makeRequest := func(op, token string) ([]byte, *wire.Session) {
		nonce++
		b, _ := json.Marshal(f.input(token))
		ts := "1793692800"
		n := strings.Repeat("n", 16) + strings.Repeat("a", nonce)
		in := wire.Inner{AppKey: f.app.AppKey, Op: op, Timestamp: ts, Nonce: n, Body: b, Signature: wire.MAC([]byte(f.secret), op, ts, n, b)}
		raw, _ := json.Marshal(in)
		r, session, e := wire.Encrypt(pub, raw)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ = json.Marshal(r)
		return raw, session
	}
	send := func(raw []byte) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/v1/client/gateway", bytes.NewReader(raw))
		r.RemoteAddr = "198.51.100.7:22"
		f.r.ServeHTTP(w, r)
		return w
	}
	request, s := makeRequest("activate", "")
	w := send(request)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, sensitive := range []string{f.license.Key, strings.Repeat("a", 64), `"op"`, `"OK"`, `"code"`, `"app_key"`} {
		if bytes.Contains(request, []byte(sensitive)) || bytes.Contains(w.Body.Bytes(), []byte(sensitive)) {
			t.Fatal("plaintext leak", sensitive)
		}
	}
	var response wire.Response
	json.Unmarshal(w.Body.Bytes(), &response)
	plain, e := s.DecryptResponse(response)
	if e != nil {
		t.Fatal(e)
	}
	var result client.Envelope
	json.Unmarshal(plain, &result)
	token := result.Data["activation_token"].(string)
	if result.Code != code.OK || result.Data["ticket"] == nil {
		t.Fatal(result)
	}
	// All standard actions occupy one identical 4096-byte plaintext bucket.
	for _, op := range []string{"activate", "verify", "heartbeat", "deactivate"} {
		raw, _ := makeRequest(op, token)
		if len(raw) != len(request) {
			t.Fatalf("different wire bucket %s: %d != %d", op, len(raw), len(request))
		}
	}
	replay := send(request)
	json.Unmarshal(replay.Body.Bytes(), &response)
	plain, e = s.DecryptResponse(response)
	if e != nil || !bytes.Contains(plain, []byte(code.ReplayDetected)) {
		t.Fatal("request replay", e, string(plain))
	}
	for _, edit := range []string{"k", "e", "n", "c"} {
		var r wire.Request
		json.Unmarshal(request, &r)
		switch edit {
		case "k":
			r.K = "0000000000000000"
		case "e":
			r.E = wire.B64.EncodeToString(make([]byte, 32))
		case "n":
			n, _ := wire.B64.DecodeString(r.N)
			n[0] ^= 1
			r.N = wire.B64.EncodeToString(n)
		case "c":
			ct, _ := wire.B64.DecodeString(r.C)
			ct[len(ct)-1] ^= 1
			r.C = wire.B64.EncodeToString(ct)
		}
		raw, _ := json.Marshal(r)
		bad := send(raw)
		if bad.Code != 400 || bad.Body.String() != `{"error":"invalid request"}` {
			t.Fatal(edit, bad.Code, bad.Body)
		}
	}
	for _, op := range []string{"activate", "verify", "heartbeat", "deactivate", "public-key", "announcement", "version"} {
		for _, method := range []string{"GET", "POST"} {
			w := httptest.NewRecorder()
			f.r.ServeHTTP(w, httptest.NewRequest(method, "/api/v1/client/"+op, nil))
			if w.Code != 404 {
				t.Fatal("old endpoint retained", op, method, w.Code)
			}
		}
	}
	for _, state := range []string{"suspended", "revoked"} {
		f.db.Model(&model.License{}).Where("id=?", f.license.ID).Update("status", state)
		raw, session := makeRequest("verify", token)
		w := send(raw)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		p, e := session.DecryptResponse(response)
		if e != nil || !bytes.Contains(p, []byte("LICENSE_"+strings.ToUpper(state))) {
			t.Fatal(string(p), e)
		}
		if bytes.Contains(p, []byte("unlock_seed")) {
			t.Fatal("unlock on refusal")
		}
	}
}
func TestGatewayRateLimitIsBeforeKeyLookupAndLogQueue(t *testing.T) {
	f := newClientFixture(t, client.Options{IPBurst: 1}, nil)
	var queries int
	f.db.Callback().Query().Before("gorm:query").Register("gateway-query", func(_ *gorm.DB) { queries++ })
	defer f.db.Callback().Query().Remove("gateway-query")
	for range 100 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/v1/client/gateway", strings.NewReader(`{}`))
		req.RemoteAddr = "192.0.2.1:1"
		f.r.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if queries > 1 {
		t.Fatal("CPU admission performs key lookups", queries)
	}
	f.drain(t)
	var n int64
	f.db.Model(&model.VerifyLog{}).Count(&n)
	if n > 2 || f.service.SampledLogRequests() < 98 {
		t.Fatal("garbage logging not sampled", n)
	}
}
func TestGatewayRotationOverlap(t *testing.T) {
	f := newClientFixture(t, client.Options{}, nil)
	keys, _ := channel.New(f.db, make([]byte, 32))
	old, _ := keys.Current(context.Background())
	next, e := keys.Rotate(context.Background(), time.Hour)
	if e != nil || old.ID == next.ID {
		t.Fatal(e)
	}
	if _, e := keys.Private(context.Background(), old.ID, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := keys.Private(context.Background(), old.ID, time.Now().Add(2*time.Hour)); e == nil {
		t.Fatal("expired key accepted")
	}
	var all []channel.Key
	f.db.Find(&all)
	for _, k := range all {
		if !strings.HasPrefix(k.PrivateEncrypted, "v1:") {
			t.Fatal("key not encrypted")
		}
	}
}
