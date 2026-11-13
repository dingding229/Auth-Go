package sdk

import (
	"authgo/sdk/wire"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKey = "AUTH-RNMSQ-VSQQA-4S4NH-JDGCM"

type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *fakeClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *fakeClock) add(d time.Duration) { c.mu.Lock(); c.at = c.at.Add(d); c.mu.Unlock() }

type signedServer struct {
	payloadResponse func(json.RawMessage, map[string]any) string
	trial           bool
	responseCode    string
	gateway         *ecdh.PrivateKey
	floatingGrace   *time.Duration
	extensionDays   *int
	mu              sync.Mutex
	server          *httptest.Server
	pub             ed25519.PublicKey
	private         ed25519.PrivateKey
	clock           *fakeClock
	mode            string
	floating        bool
	expires         *time.Time
	counts          map[string]int
	nonces          map[string]bool
	last            []byte
}

func newSignedServer(t *testing.T) *signedServer {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s := &signedServer{pub: pub, private: priv, clock: &fakeClock{at: time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)}, counts: map[string]int{}, nonces: map[string]bool{}}
	s.gateway, _ = ecdh.X25519().GenerateKey(rand.Reader)
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	return s
}
func (s *signedServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	encrypted, _ := io.ReadAll(r.Body)
	var outerRequest wire.Request
	if json.Unmarshal(encrypted, &outerRequest) != nil || r.URL.Path != "/api/v1/client/gateway" {
		w.WriteHeader(400)
		return
	}
	plain, session, e := wire.Decrypt(s.gateway, outerRequest)
	if e != nil {
		w.WriteHeader(400)
		return
	}
	var inner wire.Inner
	if json.Unmarshal(plain, &inner) != nil {
		w.WriteHeader(400)
		return
	}
	raw := inner.Body
	op := inner.Op
	s.counts[op]++
	nonce := inner.Nonce
	ts := inner.Timestamp
	if op == "announcement" && string(raw) == "null" {
		raw = nil
	}
	if inner.AppKey != "app_test" || !hmac.Equal([]byte(inner.Signature), []byte(wire.MAC([]byte("secret-text"), op, ts, nonce, raw))) || len(nonce) < 16 || len(nonce) > 128 {
		w.WriteHeader(400)
		return
	}
	if s.nonces[nonce] {
		w.WriteHeader(409)
		return
	}
	s.nonces[nonce] = true
	if s.mode == "redirect" {
		w.Header().Set("Location", s.server.URL+"/redirected")
		w.WriteHeader(302)
		return
	}
	if s.mode == "replay-response" {
		_, _ = w.Write(s.last)
		return
	}
	now := s.clock.now()
	methods := []string{"KEY"}
	grace := now.Add(time.Hour)
	data := map[string]any{"request_nonce": nonce, "license_id": uint64(1), "status": "active", "features": map[string]any{"quota": json.Number("18446744073709551615"), "export": true}, "expires_at": s.expires, "starts_at": nil, "next_check_in": 10, "heartbeat_interval": 2, "grace_until": grace, "satisfied_methods": methods}
	if s.floating {
		lease := now.Add(4 * time.Second)
		data["satisfied_methods"] = []string{"KEY", "FLOATING"}
		data["lease_expires_at"] = lease
		data["grace_until"] = lease
		if s.floatingGrace != nil {
			data["grace_until"] = now.Add(*s.floatingGrace)
		}
	}
	if op == "activate" {
		data["activation_token"] = "act_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	}
	if op == "release-seat" {
		data = map[string]any{"request_nonce": nonce, "released": s.floating}
	}
	if op == "deactivate" {
		data = map[string]any{"request_nonce": nonce, "deactivated": true}
	}
	code := OK
	if s.responseCode != "" {
		code = s.responseCode
	}
	status := 200
	stamp := now.Unix()
	outer := nonce
	switch s.mode {
	case "user-disabled":
		code = UserDisabled
		status = 403
	case "suspended":
		code = LicenseSuspended
		status = 403
	case "503":
		code = InternalError
		status = 503
	case "old-ts":
		stamp -= 301
	case "future-ts":
		stamp += 301
	case "wrong-nonce":
		outer = "another-nonce"
		data["request_nonce"] = outer
	case "outer-nonce":
		outer = "another-nonce"
	}
	if op == "trial" {
		var in map[string]string
		_ = json.Unmarshal(raw, &in)
		data = map[string]any{"request_nonce": nonce, "license_key": testKey, "challenge": in["challenge"]}
		s.trial = true
	}
	if s.trial && op != "trial" {
		data["is_trial"] = true
		data["grace_until"] = now
	}
	if op != "trial" && op != "deactivate" && op != "release-seat" && op != "announcement" {
		var in map[string]string
		json.Unmarshal(raw, &in)
		seed := bytes.Repeat([]byte{7}, 32)
		features, _ := json.Marshal(data["features"])
		g := wire.Grant{IsTrial: s.trial, V: 2, AppKey: "app_test", Challenge: in["challenge"], LicenseID: 1, LicenseRef: sha([]byte("test-ref")), DeviceHash: sha([]byte(in["device_fingerprint"])), Status: "active", IssuedAt: now, ExpiresAt: s.expires, Features: features, NextCheckIn: 10, GraceUntil: data["grace_until"].(time.Time), Floating: s.floating, UnlockHash: sha(seed)}
		if s.floating {
			lease := now.Add(4 * time.Second)
			g.LeaseExpiresAt = &lease
		}
		switch s.mode {
		case "ticket-challenge":
			g.Challenge = wire.B64.EncodeToString(make([]byte, 32))
		case "ticket-device":
			g.DeviceHash = strings.Repeat("0", 64)
		case "ticket-old":
			g.IssuedAt = now.Add(-6 * time.Minute)
		}
		ticket, _ := wire.EncodeTicket(g, s.private)
		if s.mode == "ticket-signature" {
			ticket += "!"
		}
		data["ticket"] = ticket
		data["unlock_seed"] = wire.B64.EncodeToString(seed)
	}
	if op == "announcement" {
		data = map[string]any{"request_nonce": data["request_nonce"], "items": []map[string]any{{"id": 1, "app_id": 1, "title": "中文公告", "content": "已发布", "created_at": now, "updated_at": now, "published_at": now, "expires_at": nil}}}
	}
	if op == "payload.unlock" && code == OK && s.payloadResponse != nil {
		if value := s.payloadResponse(raw, data); value != "" {
			code = value
		}
	}
	signed, _ := canonicalJSON(map[string]any{"code": code, "data": data, "ts": stamp})
	signature := ed25519.Sign(s.private, signed)
	if s.mode == "bad-signature" {
		signature[0] ^= 1
	}
	sig := base64.StdEncoding.EncodeToString(signature)
	if s.mode == "tamper" {
		data["features"] = map[string]any{"export": false}
	}
	if s.mode == "watermark-tamper" && op == "payload.unlock" && code == OK {
		// Change only the valid watermark after signing, before response encryption.
		data["watermark"] = strings.Repeat("2a", 32)
	}
	var signatureValue any = sig
	if s.mode == "unsigned" {
		signatureValue = nil
	}
	message := map[string]any{"code": code, "message": "操作结果", "data": data, "signature": signatureValue, "ts": stamp, "nonce": outer}
	body, _ := json.Marshal(message)
	if s.mode == "duplicate" {
		body = []byte(strings.TrimSuffix(string(body), "}") + `,"code":"OK"}`)
	}
	if s.mode == "large" {
		body = bytes.Repeat([]byte("x"), maxResponse+1)
	}
	if s.mode == "malformed" {
		body = []byte(`{"code":`)
	}
	if s.mode == "wrong-encryption-key" {
		session.ResponseKey = bytes.Repeat([]byte{99}, 32)
	}
	outerResponse, _ := session.EncryptResponse(body)
	body, _ = json.Marshal(outerResponse)
	if s.mode == "" {
		s.last = append([]byte(nil), body...)
	}
	_ = status
	w.WriteHeader(200)
	_, _ = w.Write(body)
}
func (s *signedServer) client(t *testing.T) *Client {
	t.Helper()
	return &Client{GatewayKey: s.gateway.PublicKey().Bytes(), BaseURL: s.server.URL, AppKey: "app_test", AppSecret: "secret-text", PublicKey: append(ed25519.PublicKey(nil), s.pub...), CacheDir: t.TempDir(), FingerprintFunc: func() (string, error) { return strings.Repeat("a", 64), nil }, now: s.clock.now}
}
func (s *signedServer) set(mode string) { s.mu.Lock(); s.mode = mode; s.mu.Unlock() }

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func unavailable() *http.Client {
	return &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("unavailable")}
	})}
}
func activate(t *testing.T, c *Client) *Result {
	t.Helper()
	r, e := c.Activate(context.Background(), testKey, ActivateOptions{ClientVersion: "1.2.3"})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestOnlineLifecycleEncryptionAndRestartGrace(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	first := activate(t, c)
	if first.Offline || first.Features["quota"].(json.Number) != "18446744073709551615" || first.ActivationToken == "" {
		t.Fatal(first)
	}
	if _, e := c.Verify(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Heartbeat(context.Background()); e != nil {
		t.Fatal(e)
	}
	files, e := filepath.Glob(filepath.Join(c.CacheDir, "*.cache"))
	if e != nil || len(files) != 1 {
		t.Fatal(files, e)
	}
	raw, e := os.ReadFile(files[0])
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{testKey, first.ActivationToken, "secret-text", "activation_token", "18446744073709551615"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("plaintext credential in cache")
		}
	}
	info, _ := os.Stat(files[0])
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatal("unsafe cache permissions")
	}
	c.HTTPClient = unavailable()
	cached, e := c.Verify(context.Background())
	if e != nil || !cached.Offline || cached.Source != "cache" {
		t.Fatal(cached, e)
	}
	restored := s.client(t)
	restored.CacheDir = c.CacheDir
	restored.HTTPClient = unavailable()
	cached, e = restored.Verify(context.Background())
	if e != nil || !cached.Offline {
		t.Fatal(cached, e)
	}
	// Neither fallback nor a restart extends signed grace.
	s.clock.add(time.Hour)
	if r, e := restored.Verify(context.Background()); r != nil || !errors.Is(e, ErrGraceExpired) {
		t.Fatal(r, e)
	}
}
func TestUntrustedResponsesUseGraceNeverOnline(t *testing.T) {
	cases := []struct {
		mode string
		want error
	}{{"bad-signature", ErrResponseSignatureInvalid}, {"tamper", ErrResponseSignatureInvalid}, {"unsigned", ErrResponseSignatureInvalid}, {"old-ts", ErrResponseTimestampInvalid}, {"future-ts", ErrResponseTimestampInvalid}, {"wrong-nonce", ErrResponseNonceInvalid}, {"outer-nonce", ErrResponseNonceInvalid}, {"replay-response", ErrResponseInvalid}, {"wrong-encryption-key", ErrResponseInvalid}, {"duplicate", ErrResponseInvalid}, {"malformed", ErrResponseInvalid}, {"large", ErrResponseInvalid}, {"redirect", ErrResponseInvalid}, {"503", ErrInternalError}}
	for _, tt := range cases {
		t.Run(tt.mode, func(t *testing.T) {
			s := newSignedServer(t)
			c := s.client(t)
			activate(t, c)
			ticket := c.state.Proof.Envelope
			s.set(tt.mode)
			r, e := c.Verify(context.Background())
			if e != nil || r.Status != "grace" || !r.Offline || !strings.Contains(r.Reason, tt.want.(*Error).Code) {
				t.Fatalf("expected grace, got err=%v", e)
			}
			assertProofPreserved(t, s, c, ticket)
			assertOriginalWithoutProof(t, c, tt.want)
			s.set("")
			c.HTTPClient = nil
			if r, e := c.Verify(context.Background()); e != nil || r.Status != "online" {
				t.Fatal("online recovery", e)
			}
		})
	}
}
func TestCacheTamperingAndSignatureRevalidation(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	path := c.cachePath()
	raw, _ := os.ReadFile(path)
	raw[len(raw)-4] ^= 1
	os.WriteFile(path, raw, 0600)
	fresh := s.client(t)
	fresh.CacheDir = c.CacheDir
	fresh.HTTPClient = unavailable()
	if _, e := fresh.Verify(context.Background()); !errors.Is(e, ErrCacheInvalid) {
		t.Fatal(e)
	}
	// Knowing the symmetric app secret is not sufficient to forge grant features.
	activate(t, c)
	gcm, aad, _ := c.cacheCipher()
	raw, _ = os.ReadFile(path)
	ciphertext, _ := decodeURL(strings.TrimPrefix(string(raw), cachePrefix))
	plain, e := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], aad)
	if e != nil {
		t.Fatal(e)
	}
	plain = bytes.ReplaceAll(plain, []byte("18446744073709551615"), []byte("18446744073709551614"))
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	forged := gcm.Seal(nonce, nonce, plain, aad)
	os.WriteFile(path, []byte(cachePrefix+base64.RawURLEncoding.EncodeToString(forged)), 0600)
	fresh = s.client(t)
	fresh.CacheDir = c.CacheDir
	fresh.HTTPClient = unavailable()
	if _, e := fresh.Verify(context.Background()); !errors.Is(e, ErrCacheInvalid) {
		t.Fatal(e)
	}
}
func TestExpiryLeaseAndCancellationNeverExtendGrace(t *testing.T) {
	t.Run("license expiry", func(t *testing.T) {
		s := newSignedServer(t)
		end := s.clock.now().Add(time.Second)
		s.expires = &end
		c := s.client(t)
		activate(t, c)
		c.HTTPClient = unavailable()
		s.clock.add(time.Second)
		if _, e := c.Verify(context.Background()); !errors.Is(e, ErrLicenseExpired) {
			t.Fatal(e)
		}
	})
	t.Run("floating lease", func(t *testing.T) {
		s := newSignedServer(t)
		s.floating = true
		c := s.client(t)
		activate(t, c)
		c.HTTPClient = unavailable()
		s.clock.add(4 * time.Second)
		if _, e := c.Heartbeat(context.Background()); !errors.Is(e, ErrGraceExpired) {
			t.Fatal(e)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		s := newSignedServer(t)
		c := s.client(t)
		activate(t, c)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if r, e := c.Verify(ctx); r != nil || !errors.Is(e, context.Canceled) {
			t.Fatal(r, e)
		}
		c.HTTPClient = unavailable()
		if r, e := c.Verify(context.Background()); e != nil || !r.Offline {
			t.Fatal(r, e)
		}
	})
	t.Run("TLS security failure", func(t *testing.T) {
		s := newSignedServer(t)
		c := s.client(t)
		activate(t, c)
		c.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) { return nil, x509.UnknownAuthorityError{} })}
		if r, e := c.Verify(context.Background()); e != nil || r.Status != "grace" || !strings.Contains(r.Reason, ResponseInvalid) {
			t.Fatal("TLS fallback", e)
		}
	})
	t.Run("deactivation loss", func(t *testing.T) {
		s := newSignedServer(t)
		c := s.client(t)
		activate(t, c)
		c.HTTPClient = unavailable()
		if e := c.Deactivate(context.Background()); e == nil {
			t.Fatal("false unbind success")
		}
		if r, e := c.Verify(context.Background()); e != nil || r.Status != "grace" || c.state.Refused {
			t.Fatal("failed unbind lost grant", e)
		}
	})
}
func TestTLSProtocolAlertsUseGrace(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	c.HTTPClient = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return nil, &net.OpError{Op: "remote error", Net: "tcp", Err: errors.New("tls protocol alert")}
	})}
	if r, e := c.Verify(context.Background()); e != nil || r.Status != "grace" || !strings.Contains(r.Reason, ResponseInvalid) {
		t.Fatal("TLS fallback", e)
	}
}
func TestRestartAfterDeactivationWithExpectedKey(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	if e := c.Deactivate(context.Background()); e != nil {
		t.Fatal(e)
	}
	fresh := s.client(t)
	fresh.CacheDir = c.CacheDir
	fresh.ExpectedLicenseKey = testKey
	if _, e := fresh.Verify(context.Background()); !errors.Is(e, ErrNotActivated) {
		t.Fatal(e)
	}
}

func TestErrorsAndKeyValidation(t *testing.T) {
	if e := validateKey(testKey); e != nil {
		t.Fatal(e)
	}
	for _, k := range []string{"bad", testKey[:len(testKey)-1] + "2", strings.ToLower(testKey)} {
		if e := validateKey(k); !errors.Is(e, ErrInvalidLicenseKey) {
			t.Fatal(k, e)
		}
	}
	var typedNil *Error
	if errors.Is(failure(LicenseExpired, "expired", nil), typedNil) {
		t.Fatal("nil target matched")
	}
	e := &Error{Code: LicenseExpired, Err: context.DeadlineExceeded}
	if !errors.Is(e, ErrLicenseExpired) || !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
}
func TestHKDFRFC5869(t *testing.T) {
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	actual := hkdfSHA256(bytes.Repeat([]byte{0x0b}, 22), salt, info, 42)
	if hex.EncodeToString(actual) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
		t.Fatal(hex.EncodeToString(actual))
	}
}
func TestAutomaticVerifyHeartbeatAndCallbackReentrancy(t *testing.T) {
	s := newSignedServer(t)
	s.floating = true
	c := s.client(t)
	activate(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := 0
	c.wait = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		waits++
		if waits > 8 {
			cancel()
			return ctx.Err()
		}
		s.clock.add(d)
		return nil
	}
	callbacks := 0
	err := c.StartAutoCheck(ctx, func(r *Result, e error) {
		callbacks++
		if e != nil {
			t.Error(e)
		}
		if err := c.Validate(r.Ticket()); err != nil {
			t.Error(err)
		}
	})
	if !errors.Is(err, context.Canceled) || callbacks < 4 || s.counts["verify"] < 2 || s.counts["heartbeat"] < 3 {
		t.Fatal(err, callbacks, s.counts)
	}
}
