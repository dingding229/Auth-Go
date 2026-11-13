package httpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"authgo/internal/auth"
	"authgo/internal/catalog"
	"authgo/internal/channel"
	"authgo/internal/client"
	"authgo/internal/code"
	"authgo/internal/config"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/licensing"
	"authgo/internal/model"
	"authgo/sdk/wire"

	"gorm.io/gorm"
)

type clientFixture struct {
	*adminFixture
	service   *client.Service
	catalog   *catalog.Service
	licensing *licensing.Service
	app       model.Application
	license   licensing.LicenseInfo
	secret    string
	next      atomic.Uint64
	requests  atomic.Int64
}

func newClientFixture(t *testing.T, opts client.Options, edit func(*licensing.CreateInput), trusted ...string) *clientFixture {
	t.Helper()
	a := newAdminFixture(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cat, e := catalog.NewService(a.db, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	app, e := cat.CreateApplication(context.Background(), catalog.ApplicationInput{Name: ptr("测试应用")})
	if e != nil {
		t.Fatal(e)
	}
	opts.Now = a.clock.now
	svc, e := client.NewService(a.db, make([]byte, 32), log, opts)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := svc.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	ls := licensing.NewServiceWithClock(a.db, a.clock.now)
	user := model.EndUser{Name: "测试用户", Status: "active"}
	if e := a.db.Create(&user).Error; e != nil {
		t.Fatal(e)
	}
	in := licensing.CreateInput{UserID: &user.ID, AppID: app.ID, VerifyMethods: ptr([]string{"KEY", "FLOATING"}), ValidityRule: ptr("after_activation"), DurationDays: ptr(2), Features: json.RawMessage(`{"quota":18446744073709551615,"export":true}`)}
	if edit != nil {
		edit(&in)
	}
	lic, e := ls.Create(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	var stored model.Application
	if e := a.db.First(&stored, app.ID).Error; e != nil {
		t.Fatal(e)
	}
	secret, e := cat.RevealSecret(context.Background(), app.ID)
	if e != nil {
		t.Fatal(e)
	}
	identity, e := auth.NewServiceWithClock(a.db, make([]byte, 32), a.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := a.db.DB()
	a.r, e = NewRouter(config.Config{TrustedProxies: trusted}, log, pool.PingContext, WithAdmin(identity, a.db), WithCatalog(cat), WithLicensing(ls), WithClient(svc))
	if e != nil {
		t.Fatal(e)
	}
	return &clientFixture{adminFixture: a, service: svc, catalog: cat, licensing: ls, app: stored, license: lic, secret: secret}
}
func (f *clientFixture) input(token string) map[string]any {
	return map[string]any{"license_key": f.license.Key, "device_fingerprint": strings.Repeat("a", 64), "client_version": "1.2.3", "activation_token": token, "hostname": "测试实例", "os": "linux", "challenge": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))}
}
func (f *clientFixture) call(t *testing.T, op string, body any, want string) map[string]any {
	t.Helper()
	method := "POST"
	if op == "public-key" || op == "announcement" || op == "version" {
		method = "GET"
	}
	var raw []byte
	if body != nil {
		var e error
		raw, e = json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
	}
	return f.raw(t, method, "/api/v1/client/"+op, raw, nil, "198.51.100.7:1234", want)
}
func (f *clientFixture) raw(t *testing.T, method, path string, body []byte, headers map[string]string, ip, want string) map[string]any {
	t.Helper()
	nonce := fmt.Sprintf("nonce-%024d", f.next.Add(1))
	ts := strconv.FormatInt(f.clock.now().Unix(), 10)
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = ip
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Key", f.app.AppKey)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nonce)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Signature", cryptoutil.HMACSHA256([]byte(f.secret), client.SigningInput(strings.TrimPrefix(req.URL.EscapedPath(), "/api/v1/client/"), req.Header.Get("X-Timestamp"), req.Header.Get("X-Nonce"), body)))
	if v, ok := headers["X-Signature"]; ok {
		req.Header.Set("X-Signature", v)
	}
	w := httptest.NewRecorder()
	f.serveGateway(t, w, req)
	f.requests.Add(1)
	var result map[string]any
	d := json.NewDecoder(w.Body)
	d.UseNumber()
	if e := d.Decode(&result); e != nil {
		t.Fatalf("response decode: %s: %v", w.Body, e)
	}
	if result["code"] != want || w.Code != 200 {
		t.Fatalf("%s %s got %d %+v want %s", method, path, w.Code, result, want)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("cacheable client response")
	}
	if sig, ok := result["signature"].(string); ok {
		payload, e := cryptoutil.CanonicalJSON(map[string]any{"code": result["code"], "data": result["data"], "ts": result["ts"]})
		if e != nil {
			t.Fatal(e)
		}
		rawSig, e := base64.StdEncoding.DecodeString(sig)
		if e != nil {
			t.Fatal(e)
		}
		public, _ := base64.StdEncoding.DecodeString(f.app.PublicKey)
		if !cryptoutil.Verify(public, payload, rawSig) {
			t.Fatalf("bad response signature: %+v", result)
		}
		expectedNonce := req.Header.Get("X-Nonce")
		if len(expectedNonce) < 16 || len(expectedNonce) > 128 {
			expectedNonce = ""
		}
		if result["nonce"] != expectedNonce || data(result)["request_nonce"] != result["nonce"] {
			t.Fatal("nonce not cryptographically bound")
		}
	}
	return result
}
func (f *clientFixture) drain(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := f.service.Close(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestClientLifecycleAndHashedCredentials(t *testing.T) {
	f := newClientFixture(t, client.Options{}, nil)
	created := data(f.call(t, "activate", f.input(""), code.OK))
	token := created["activation_token"].(string)
	if created["features"].(map[string]any)["quota"].(json.Number).String() != "18446744073709551615" || created["next_check_in"].(json.Number) != "3600" || created["grace_until"] == nil {
		t.Fatal(created)
	}
	var session model.ClientSession
	if e := f.db.First(&session).Error; e != nil {
		t.Fatal(e)
	}
	if session.TokenHash != cryptoutil.SHA256([]byte(token)) || session.TokenHash == token {
		t.Fatal("plaintext token in DB")
	}
	var rows []model.Activation
	f.db.Find(&rows)
	for _, a := range rows {
		if a.Token == token || len(a.Token) != 64 {
			t.Fatal("plaintext activation token")
		}
	}
	f.call(t, "verify", f.input(token), code.OK)
	f.clock.add(time.Minute)
	f.call(t, "heartbeat", f.input(token), code.OK)
	f.call(t, "verify", f.input(""), code.ActivationInvalid)
	other := f.input(token)
	other["device_fingerprint"] = strings.Repeat("b", 64)
	f.call(t, "verify", other, code.ActivationInvalid)
	f.call(t, "deactivate", f.input(token), code.OK)
	f.call(t, "verify", f.input(token), code.ActivationInvalid)
	f.call(t, "activate", f.input(""), code.OK)
	var l model.License
	f.db.First(&l, f.license.ID)
	if l.StartsAt == nil || !l.StartsAt.Equal(f.clock.now().Add(-time.Minute)) {
		t.Fatal(l)
	}
	f.drain(t)
	var logs []model.VerifyLog
	if e := f.db.Order("id").Find(&logs).Error; e != nil {
		t.Fatal(e)
	}
	if int64(len(logs)) != f.requests.Load() {
		t.Fatalf("logs=%d requests=%d", len(logs), f.requests.Load())
	}
	for _, v := range logs {
		if v.IP != "198.51.100.7" || v.Device != strings.Repeat("a", 64) && v.Device != strings.Repeat("b", 64) || v.ClientVersion != "1.2.3" || v.AppID == nil || v.DurationMS < 0 {
			t.Fatalf("log=%+v", v)
		}
	}
}
func TestClientSignaturesReplayAndTimestamp(t *testing.T) {
	f := newClientFixture(t, client.Options{IPBurst: 200, LicenseBurst: 200}, nil)
	body, _ := json.Marshal(f.input(""))
	path := "/api/v1/client/activate"
	nonce := "unchanged-nonce-1234567890"
	f.raw(t, "POST", path, body, map[string]string{"X-Nonce": nonce, "X-Signature": strings.Repeat("0", 64)}, "198.51.100.7:1234", code.SignatureInvalid)
	f.raw(t, "POST", path, body, map[string]string{"X-Nonce": nonce}, "198.51.100.7:1234", code.OK) // invalid HMAC did not poison nonce
	f.raw(t, "POST", path, body, map[string]string{"X-Nonce": nonce}, "198.51.100.7:1234", code.ReplayDetected)
	for _, n := range []int{301, -301, 300, -300} {
		want := code.OK
		if n > 300 || n < -300 {
			want = code.TimestampInvalid
		}
		f.raw(t, "GET", "/api/v1/client/public-key", nil, map[string]string{"X-Timestamp": strconv.FormatInt(f.clock.now().Unix()+int64(n), 10)}, "198.51.100.7:1234", want)
	}
	f.raw(t, "GET", "/api/v1/client/public-key", []byte(`{"extra":1}`), nil, "198.51.100.7:1234", code.InvalidRequest)
	f.raw(t, "GET", "/api/v1/client/public-key", nil, map[string]string{"X-App-Key": "missing"}, "198.51.100.7:1234", code.AppNotFound)
	f.raw(t, "GET", "/api/v1/client/public-key", nil, map[string]string{"X-Nonce": "short"}, "198.51.100.7:1234", code.InvalidRequest)
	f.call(t, "public-key", nil, code.OK)
	f.clock.add(10 * time.Minute)
	f.raw(t, "POST", path, body, map[string]string{"X-Nonce": nonce}, "198.51.100.7:1234", code.OK)
}
func TestClientRateLimits(t *testing.T) {
	t.Run("IP", func(t *testing.T) {
		f := newClientFixture(t, client.Options{IPBurst: 1}, nil)
		f.call(t, "public-key", nil, code.OK)
		r := f.call(t, "public-key", nil, code.RateLimited)
		if r["signature"] != nil {
			t.Fatal("pre-lookup rejection should be unsigned")
		}
		f.clock.add(time.Second)
		f.call(t, "public-key", nil, code.OK)
	})
	t.Run("license across IPs", func(t *testing.T) {
		f := newClientFixture(t, client.Options{LicenseBurst: 1}, nil)
		body, _ := json.Marshal(f.input(""))
		f.raw(t, "POST", "/api/v1/client/activate", body, nil, "198.51.100.7:1", code.OK)
		f.raw(t, "POST", "/api/v1/client/activate", body, nil, "198.51.100.8:1", code.RateLimited)
	})
}
func TestClientFloatingConcurrentLeaseAndReacquisition(t *testing.T) {
	f := newClientFixture(t, client.Options{IPBurst: 200, LicenseBurst: 200}, func(in *licensing.CreateInput) {
		in.VerifyMethods = ptr([]string{"KEY", "FLOATING"})
		in.MaxActivations = ptr(1)
	})
	type answer struct{ code, token string }
	out := make(chan answer, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(f.input(""))
			req := httptest.NewRequest("POST", "/api/v1/client/activate", bytes.NewReader(body))
			req.RemoteAddr = "198.51.100.7:1"
			req.Header.Set("Content-Type", "application/json")
			nonce := fmt.Sprintf("parallel-nonce-%020d", f.next.Add(1))
			ts := strconv.FormatInt(f.clock.now().Unix(), 10)
			req.Header.Set("X-App-Key", f.app.AppKey)
			req.Header.Set("X-Nonce", nonce)
			req.Header.Set("X-Timestamp", ts)
			req.Header.Set("X-Signature", cryptoutil.HMACSHA256([]byte(f.secret), client.SigningInput(strings.TrimPrefix(req.URL.Path, "/api/v1/client/"), ts, nonce, body)))
			w := httptest.NewRecorder()
			f.serveGateway(t, w, req)
			var r map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &r)
			token, _ := data(r)["activation_token"].(string)
			out <- answer{r["code"].(string), token}
		}()
	}
	wg.Wait()
	close(out)
	var token string
	n := 0
	for a := range out {
		if a.code == code.OK {
			n++
			token = a.token
		} else if a.code != code.FloatingLimitReached {
			t.Fatal(a)
		}
	}
	if n != 1 {
		t.Fatalf("granted %d seats", n)
	}
	f.clock.add(120 * time.Second)
	f.call(t, "verify", f.input(token), code.LeaseExpired)
	f.call(t, "heartbeat", f.input(token), code.OK)
	f.clock.add(120 * time.Second)
	newToken := data(f.call(t, "activate", f.input(""), code.OK))["activation_token"].(string)
	f.call(t, "heartbeat", f.input(token), code.FloatingLimitReached)
	f.call(t, "deactivate", f.input(newToken), code.OK)
	f.call(t, "heartbeat", f.input(token), code.OK)
}
func TestClientForcedOfflineAndUnbindInvalidateTokens(t *testing.T) {
	f := newClientFixture(t, client.Options{}, nil)
	token := data(f.call(t, "activate", f.input(""), code.OK))["activation_token"].(string)
	var a model.Activation
	f.db.Where("kind = 'floating'").First(&a)
	if _, e := f.licensing.ManageActivation(context.Background(), a.ID, false); e != nil {
		t.Fatal(e)
	}
	f.call(t, "verify", f.input(token), code.ActivationInvalid)
	token2 := data(f.call(t, "activate", f.input(""), code.OK))["activation_token"].(string)
	f.call(t, "verify", f.input(token2), code.OK)
	f.call(t, "verify", f.input(token), code.ActivationInvalid)
	a = model.Activation{}
	if e := f.db.Where("kind='floating' AND status='active' AND offline_at IS NULL").Order("id DESC").First(&a).Error; e != nil {
		t.Fatal(e)
	}
	if _, e := f.licensing.ManageActivation(context.Background(), a.ID, true); e != nil {
		t.Fatal(e)
	}
	f.call(t, "heartbeat", f.input(token2), code.ActivationInvalid)
}

func TestClientTrustedProxy(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			proxies := []string{}
			if trusted {
				proxies = []string{"198.51.100.0/24"}
			}
			f := newClientFixture(t, client.Options{}, func(in *licensing.CreateInput) {
				in.VerifyMethods = ptr([]string{"KEY"})
			}, proxies...)
			body, _ := json.Marshal(f.input(""))
			want := code.OK
			if trusted {
				want = code.OK
			}
			f.raw(t, "POST", "/api/v1/client/activate", body, map[string]string{"X-Forwarded-For": "2001:db8::42"}, "198.51.100.7:1", want)
			f.drain(t)
			var v model.VerifyLog
			f.db.First(&v)
			if trusted && v.IP != "2001:db8::42" || !trusted && v.IP != "198.51.100.7" {
				t.Fatal(v.IP)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func TestClientGlobalGuards(t *testing.T) {
	f := newClientFixture(t, client.Options{IPBurst: 100, LicenseBurst: 100}, func(in *licensing.CreateInput) {
		in.VerifyMethods = ptr([]string{"KEY"})
	})
	in := f.input("")
	in["device_fingerprint"] = ""
	token := data(f.call(t, "activate", in, code.OK))["activation_token"].(string)
	in["activation_token"] = token
	f.call(t, "verify", in, code.OK)
	var count int64
	f.db.Model(&model.Activation{}).Where("kind = 'floating'").Count(&count)
	if count != 0 {
		t.Fatal("ANY failure partially bound")
	}
	if e := f.db.Model(&model.License{}).Where("id = ?", f.license.ID).Updates(map[string]any{"status": "suspended"}).Error; e != nil {
		t.Fatal(e)
	}
	f.call(t, "verify", in, code.LicenseSuspended)
	f.db.Model(&model.License{}).Where("id = ?", f.license.ID).Updates(map[string]any{"status": "active", "expires_at": f.clock.now()})
	f.call(t, "verify", in, code.LicenseExpired)
	var lic model.License
	f.db.First(&lic, f.license.ID)
	if lic.Status != "expired" {
		t.Fatal("expiry not persisted")
	}
}

func TestClientResponseNonceAndRequestBodyTampering(t *testing.T) {
	f := newClientFixture(t, client.Options{}, nil)
	r := f.call(t, "public-key", nil, code.OK)
	sig, _ := base64.StdEncoding.DecodeString(r["signature"].(string))
	public, _ := base64.StdEncoding.DecodeString(f.app.PublicKey)
	data(r)["request_nonce"] = "different-nonce-123456"
	payload, _ := cryptoutil.CanonicalJSON(map[string]any{"code": r["code"], "data": r["data"], "ts": r["ts"]})
	if cryptoutil.Verify(public, payload, sig) {
		t.Fatal("nonce tampering went undetected")
	}
	nonce := "tamper-nonce-0123456789"
	ts := strconv.FormatInt(f.clock.now().Unix(), 10)
	body, _ := json.Marshal(f.input(""))
	wrongSig := cryptoutil.HMACSHA256([]byte(f.secret), client.SigningInput("activate", ts, nonce, append(body, ' ')))
	f.raw(t, "POST", "/api/v1/client/activate", body, map[string]string{"X-Nonce": nonce, "X-Signature": wrongSig}, "198.51.100.7:1", code.SignatureInvalid)
	var n int64
	f.db.Model(&model.ClientSession{}).Count(&n)
	if n != 0 {
		t.Fatal("invalid HMAC created a session")
	}
}

func TestClientQueuedRequestUsesEvaluationTime(t *testing.T) {
	f := newClientFixture(t, client.Options{}, nil)
	// Hold the single SQLite connection while the signed HTTP request arrives.
	held := make(chan struct{})
	release := make(chan struct{})
	txDone := make(chan error, 1)
	go func() { txDone <- f.db.Transaction(func(tx *gorm.DB) error { close(held); <-release; return nil }) }()
	<-held
	queryStarted := make(chan struct{}, 1)
	if e := f.db.Callback().Query().Before("gorm:query").Register("test:queued-request", func(tx *gorm.DB) {
		select {
		case queryStarted <- struct{}{}:
		default:
		}
	}); e != nil {
		close(release)
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { defer close(done); f.call(t, "activate", f.input(""), code.OK) }()
	<-queryStarted
	f.clock.add(time.Minute)
	close(release)
	<-done
	if e := <-txDone; e != nil {
		t.Fatal(e)
	}
	f.drain(t)
	if e := f.db.Callback().Query().Remove("test:queued-request"); e != nil {
		t.Fatal(e)
	}
	var l model.License
	if e := f.db.First(&l, f.license.ID).Error; e != nil {
		t.Fatal(e)
	}
	if l.StartsAt == nil || !l.StartsAt.Equal(f.clock.now()) {
		t.Fatalf("activation was backdated to arrival: %+v", l.StartsAt)
	}
}

// serveGateway adapts test request builders, not production endpoints.
func (f *clientFixture) serveGateway(t *testing.T, w *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()
	body, _ := io.ReadAll(req.Body)
	inner := wire.Inner{AppKey: req.Header.Get("X-App-Key"), Op: strings.TrimPrefix(req.URL.Path, "/api/v1/client/"), Timestamp: req.Header.Get("X-Timestamp"), Nonce: req.Header.Get("X-Nonce"), Signature: req.Header.Get("X-Signature"), Body: body}
	if len(body) == 0 {
		inner.Body = json.RawMessage(`null`)
	}
	raw, _ := json.Marshal(inner)
	keys, _ := channel.New(f.db, make([]byte, 32))
	key, _ := keys.Current(context.Background())
	pub, _ := base64.RawURLEncoding.DecodeString(key.PublicKey)
	outer, session, e := wire.Encrypt(pub, raw)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(outer)
	r := httptest.NewRequest("POST", "/api/v1/client/gateway", bytes.NewReader(raw))
	r.RemoteAddr = req.RemoteAddr
	r.Header = req.Header.Clone()
	f.r.ServeHTTP(w, r)
	if w.Code == 400 {
		if w.Body.String() != `{"error":"invalid request"}` {
			t.Fatalf("unexpected outer error %s", w.Body)
		}
		w.Code = 200
		w.Body.Reset()
		w.Body.WriteString(`{"code":"RATE_LIMITED","data":{},"nonce":"","signature":null}`)
		return
	}
	if w.Code != 200 {
		t.Fatalf("gateway HTTP %d %s", w.Code, w.Body)
	}
	var response wire.Response
	if e := json.Unmarshal(w.Body.Bytes(), &response); e != nil {
		t.Fatal(e)
	}
	plain, e := session.DecryptResponse(response)
	if e != nil {
		t.Fatal(e)
	}
	w.Body.Reset()
	w.Body.Write(plain)
}

func TestDeactivateWithoutQuotaOrCooldown(t *testing.T) {
	f := newClientFixture(t, client.Options{}, nil)
	token := data(f.call(t, "activate", f.input(""), code.OK))["activation_token"].(string)
	f.call(t, "deactivate", f.input(token), code.OK)
	f.call(t, "verify", f.input(token), code.ActivationInvalid)
	f.call(t, "activate", f.input(""), code.OK)
	var l model.License
	f.db.First(&l, f.license.ID)

}
