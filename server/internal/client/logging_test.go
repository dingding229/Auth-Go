package client

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
	"testing"
	"time"

	"authgo/internal/catalog"
	"authgo/internal/code"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/licensekey"
	"authgo/internal/model"
	"authgo/sdk/wire"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type logTestClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *logTestClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *logTestClock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.at = c.at.Add(d) }

type loggingFixture struct {
	db          *gorm.DB
	service     *Service
	router      *gin.Engine
	clock       *logTestClock
	app         model.Application
	secret, key string
	seq         uint64
}

func newLoggingFixture(t *testing.T, opts Options) *loggingFixture {
	t.Helper()
	database := testDB(t)
	cat, err := catalog.NewService(database, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	name := "尽力日志测试"
	info, err := cat.CreateApplication(context.Background(), catalog.ApplicationInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	var app model.Application
	if err := database.First(&app, info.ID).Error; err != nil {
		t.Fatal(err)
	}
	secret, err := cat.RevealSecret(context.Background(), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := licensekey.Generate("AUTH")
	if err != nil {
		t.Fatal(err)
	}
	l := model.License{AppID: app.ID, Key: key, Status: "unused", ValidityRule: "perpetual", VerifyMethods: []string{"KEY"}, MatchMode: "all", MaxActivations: 1}
	if err := database.Create(&l).Error; err != nil {
		t.Fatal(err)
	}
	clock := &logTestClock{at: time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)}
	opts.Now = clock.now
	service, err := NewService(database, make([]byte, 32), slog.New(slog.NewTextHandler(io.Discard, nil)), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	service.Register(r)
	return &loggingFixture{db: database, service: service, router: r, clock: clock, app: app, secret: secret, key: key}
}
func (f *loggingFixture) signed(t *testing.T, op, token, nonce, want string) Envelope {
	t.Helper()
	method := "POST"
	var raw []byte
	if op == "public-key" {
		method = "GET"
	} else {
		var err error
		raw, err = json.Marshal(Input{LicenseKey: f.key, ActivationToken: token, Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))})
		if err != nil {
			t.Fatal(err)
		}
	}
	if nonce == "" {
		f.seq++
		nonce = fmt.Sprintf("logging-nonce-%020d", f.seq)
	}
	ts := strconv.FormatInt(f.clock.now().Unix(), 10)
	path := "/api/v1/client/" + op
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Key", f.app.AppKey)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", cryptoutil.HMACSHA256([]byte(f.secret), SigningInput(op, ts, nonce, raw)))
	w := httptest.NewRecorder()
	f.serve(t, w, req)
	var result Envelope
	d := json.NewDecoder(w.Body)
	d.UseNumber()
	if err := d.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Code != want || w.Code != 200 {
		t.Fatalf("%s got %d %+v want %s", op, w.Code, result, want)
	}
	if result.Signature == nil {
		t.Fatalf("signed request returned unsigned result: %+v", result)
	}
	sig, err := base64.StdEncoding.DecodeString(*result.Signature)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(f.app.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cryptoutil.CanonicalJSON(map[string]any{"code": result.Code, "data": result.Data, "ts": result.TS})
	if err != nil {
		t.Fatal(err)
	}
	if !cryptoutil.Verify(pub, payload, sig) || result.Nonce != nonce || result.Data["request_nonce"] != nonce {
		t.Fatal("invalid response signature/nonce")
	}
	return result
}
func (f *loggingFixture) garbage(t *testing.T, ip, want string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/client/activate", strings.NewReader(`{"broken":`))
	req.RemoteAddr = ip
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.serve(t, w, req)
	var response Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != want || w.Code != 200 {
		t.Fatalf("got %d %s want %s", w.Code, w.Body, want)
	}
}
func (f *loggingFixture) drain(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.service.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
func awaitDropped(t *testing.T, s *Service, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.DroppedLogEntries() < want {
		if time.Now().After(deadline) {
			t.Fatalf("dropped=%d want=%d", s.DroppedLogEntries(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestFullLogQueueDoesNotChangeSignedAuthorization(t *testing.T) {
	f := newLoggingFixture(t, Options{LogCapacity: 1})
	// Occupy the complete logging budget without involving SQL/worker timing.
	release, ok := f.service.logs.reserve()
	if !ok {
		t.Fatal("cannot occupy log slot")
	}
	defer release(model.VerifyLog{Code: code.OK})
	token := f.signed(t, "activate", "", "", code.OK).Data["activation_token"].(string)
	f.signed(t, "verify", token, "", code.OK)
	f.signed(t, "heartbeat", token, "", code.OK)
	f.signed(t, "deactivate", token, "", code.OK)
	if got := f.service.DroppedLogEntries(); got != 4 {
		t.Fatalf("drop counter=%d", got)
	}
	if f.service.SampledLogRequests() != 0 {
		t.Fatal("successful requests were sampled")
	}
	var session model.ClientSession
	if err := f.db.First(&session).Error; err != nil {
		t.Fatal(err)
	}
	if session.RevokedAt == nil {
		t.Fatal("queue pressure prevented business commit")
	}
}
func TestNoisyRequestsAreSampled(t *testing.T) {
	t.Run("IP rate limit", func(t *testing.T) {
		f := newLoggingFixture(t, Options{IPBurst: 1})
		f.signed(t, "public-key", "", "", code.OK)
		const n = 1000
		for range n {
			f.garbage(t, "203.0.113.7:1234", code.RateLimited)
		}
		f.drain(t)
		var rows []model.VerifyLog
		if err := f.db.Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		rateLogs := 0
		for _, v := range rows {
			if v.Code == code.RateLimited {
				rateLogs++
			}
		}
		if len(rows) != 2 || rateLogs != 1 || f.service.SampledLogRequests() != n-1 || f.service.DroppedLogEntries() != 0 {
			t.Fatalf("logs=%d rate=%d sampled=%d dropped=%d", len(rows), rateLogs, f.service.SampledLogRequests(), f.service.DroppedLogEntries())
		}
	})
	t.Run("malformed requests per IP and minute", func(t *testing.T) {
		f := newLoggingFixture(t, Options{IPBurst: 2000})
		for range 1000 {
			f.garbage(t, "203.0.113.7:1234", code.InvalidRequest)
		}
		f.garbage(t, "203.0.113.8:1234", code.InvalidRequest)
		f.clock.add(time.Minute)
		f.garbage(t, "203.0.113.7:1234", code.InvalidRequest)
		// A legitimate request from the noisy IP still gets a full normal log.
		f.signed(t, "public-key", "", "", code.OK)
		f.drain(t)
		var rows []model.VerifyLog
		if err := f.db.Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if len(rows) != 4 || f.service.SampledLogRequests() != 999 || f.service.DroppedLogEntries() != 0 {
			t.Fatalf("logs=%d sampled=%d dropped=%d", len(rows), f.service.SampledLogRequests(), f.service.DroppedLogEntries())
		}
	})
}
func TestLogPersistenceFailureDoesNotDisableRequestsOrRecovery(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	if err := f.db.Migrator().DropTable(&model.VerifyLog{}); err != nil {
		t.Fatal(err)
	}
	token := f.signed(t, "activate", "", "", code.OK).Data["activation_token"].(string)
	awaitDropped(t, f.service, 1)
	f.signed(t, "verify", token, "", code.OK)
	awaitDropped(t, f.service, 2)
	if err := f.db.AutoMigrate(&model.VerifyLog{}); err != nil {
		t.Fatal(err)
	}
	f.signed(t, "heartbeat", token, "", code.OK)
	f.drain(t)
	var rows []model.VerifyLog
	if err := f.db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Action != "heartbeat" || f.service.DroppedLogEntries() != 2 {
		t.Fatalf("logs=%+v dropped=%d", rows, f.service.DroppedLogEntries())
	}
}
func TestLogDropWarningsAreRateLimited(t *testing.T) {
	var output bytes.Buffer
	w := newLogWriter(testDB(t), slog.New(slog.NewJSONHandler(&output, nil)), 1)
	held, ok := w.reserve()
	if !ok {
		t.Fatal("reserve")
	}
	for range 1000 {
		w.trySubmit(model.VerifyLog{Code: code.OK})
	}
	if w.dropped.Load() != 1000 || strings.Count(output.String(), "\n") != 10 {
		t.Fatalf("dropped=%d warnings=%d", w.dropped.Load(), strings.Count(output.String(), "\n"))
	}
	held(model.VerifyLog{Code: code.OK})
	if err := w.close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestFullNonceCacheRemainsFailClosed(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	if f.service.nonces.limit != 100000 {
		t.Fatal("default nonce capacity changed")
	}
	f.service.nonces.limit = 2
	first := "nonce-cache-first-0123456789"
	second := "nonce-cache-second-0123456789"
	f.signed(t, "activate", "", first, code.OK)
	f.signed(t, "activate", "", second, code.OK)
	f.signed(t, "activate", "", "nonce-cache-third-0123456789", code.RateLimited)
	// Full capacity must not evict a still-live entry and reopen replay.
	f.signed(t, "activate", "", first, code.ReplayDetected)
	if len(f.service.nonces.entries) != 2 {
		t.Fatal("unbounded nonce cache")
	}
	f.clock.add(10 * time.Minute)
	f.signed(t, "activate", "", "nonce-cache-after-0123456789", code.OK)
}

func (f *loggingFixture) serve(t *testing.T, w *httptest.ResponseRecorder, req *http.Request) {
	t.Helper()
	body, _ := io.ReadAll(req.Body)
	if !json.Valid(body) && len(body) > 0 { // preserve malformed inner JSON rather than malformed framing
		body = []byte(`{"broken":true}`)
	}
	inner := wire.Inner{AppKey: req.Header.Get("X-App-Key"), Op: strings.TrimPrefix(req.URL.Path, "/api/v1/client/"), Timestamp: req.Header.Get("X-Timestamp"), Nonce: req.Header.Get("X-Nonce"), Signature: req.Header.Get("X-Signature"), Body: body}
	if len(body) == 0 {
		inner.Body = []byte(`null`)
	}
	raw, _ := json.Marshal(inner)
	key, _ := f.service.channel.Current(context.Background())
	pub, _ := wire.B64.DecodeString(key.PublicKey)
	outer, session, e := wire.Encrypt(pub, raw)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(outer)
	r := httptest.NewRequest("POST", "/api/v1/client/gateway", bytes.NewReader(raw))
	r.RemoteAddr = req.RemoteAddr
	f.router.ServeHTTP(w, r)
	if w.Code == 400 {
		if w.Body.String() != `{"error":"invalid request"}` {
			t.Fatal(w.Body)
		}
		w.Code = 200
		w.Body.Reset()
		w.Body.WriteString(`{"code":"RATE_LIMITED"}`)
		return
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
