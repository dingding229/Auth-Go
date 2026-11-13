package sdk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func configFor(s *signedServer) string {
	b, _ := json.Marshal(map[string]any{"url": s.server.URL, "app_key": "app_test", "app_secret": "secret-text", "public_key": base64.StdEncoding.EncodeToString(s.pub), "gateway_key": base64.RawURLEncoding.EncodeToString(s.gateway.PublicKey().Bytes())})
	return "authgo2." + base64.RawURLEncoding.EncodeToString(b)
}
func TestNewConfiguration(t *testing.T) {
	s := newSignedServer(t)
	c, e := New(configFor(s), WithCacheDir(""))
	if e != nil || c.AppSecret != "secret-text" || c.CacheDir != "" {
		t.Fatal(e)
	}
	for _, v := range []string{"", "authgo2.secret-text", "authgo2." + base64.RawURLEncoding.EncodeToString([]byte(`{"url":"secret-text"}`)), strings.Repeat("secret-text", 1000)} {
		_, e := New(v)
		if e == nil || strings.Contains(e.Error(), "secret-text") {
			t.Fatalf("leak or accepted: %v", e)
		}
	}
}
func TestCheckFlow(t *testing.T) {
	s := newSignedServer(t)
	c, e := New(configFor(s), WithCacheDir(t.TempDir()), WithFingerprint(func() (string, error) { return strings.Repeat("a", 64), nil }))
	if e != nil {
		t.Fatal(e)
	}
	c.now = s.clock.now
	ctx := context.Background()
	if _, e = c.Check(ctx, testKey); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Check(ctx, testKey); e != nil {
		t.Fatal(e)
	}
	if s.counts["activate"] != 1 || s.counts["verify"] != 1 {
		t.Fatal(s.counts)
	}
	c.HTTPClient = unavailable()
	if r, e := c.Check(ctx, testKey); e != nil || !r.Offline {
		t.Fatal(r, e)
	}
	c.HTTPClient = s.server.Client()
	s.mode = "suspended"
	if _, e = c.Check(ctx, testKey); e == nil {
		t.Fatal("business refusal used grace")
	}
	s.mode = ""
	if _, e = c.Check(ctx, testKey); e != nil {
		t.Fatal(e)
	}
	// A different valid prefix changes the checksum, use a generated checksum.
	p := strings.Split(testKey, "-")
	p[0] = "TEST"
	alphabet := "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	body := p[1] + p[2] + p[3] + p[4][:4]
	check := len(p[0]) % 32
	for _, r := range p[0] + body {
		check = (check*17 + strings.IndexRune(alphabet, r)) % 32
	}
	p[4] = p[4][:4] + string(alphabet[check])
	other := strings.Join(p, "-")
	if _, e = c.Check(ctx, other); e != nil {
		t.Fatal(e)
	}
	if s.counts["activate"] != 2 {
		t.Fatal(s.counts)
	}
	c.HTTPClient = unavailable()
	if _, e = c.Check(ctx, testKey); e == nil {
		t.Fatal("old key grace used on switch")
	}
}

func TestCheckInvalidCacheRequiresFreshActivation(t *testing.T) {
	s := newSignedServer(t)
	dir := t.TempDir()
	opts := []Option{WithCacheDir(dir), WithFingerprint(func() (string, error) { return strings.Repeat("a", 64), nil })}
	c, e := New(configFor(s), opts...)
	if e != nil {
		t.Fatal(e)
	}
	c.now = s.clock.now
	if _, e = c.Check(context.Background(), testKey); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.cachePath(), []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	fresh, e := New(configFor(s), opts...)
	if e != nil {
		t.Fatal(e)
	}
	fresh.now = s.clock.now
	if _, e = fresh.Check(context.Background(), testKey); e != nil {
		t.Fatal(e)
	}
	if s.counts["activate"] != 2 {
		t.Fatal("did not repair through online activation")
	}
	if e = os.WriteFile(c.cachePath(), []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	offline, e := New(configFor(s), append(opts, WithHTTPClient(unavailable()))...)
	if e != nil {
		t.Fatal(e)
	}
	offline.now = s.clock.now
	if r, e := offline.Check(context.Background(), testKey); e == nil || r != nil {
		t.Fatal("invalid cache granted grace")
	}
}

func TestCheckUserDisabledNotGrace(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	ctx := context.Background()
	if _, e := c.Check(ctx, testKey); e != nil {
		t.Fatal(e)
	}
	s.mode = "user-disabled"
	if r, e := c.Check(ctx, testKey); r != nil || !errors.Is(e, ErrUserDisabled) {
		t.Fatal(r, e)
	}
	s.mode = ""
	if _, e := c.Check(ctx, testKey); e != nil {
		t.Fatal(e)
	}
	s.mode = "user-disabled"
	c.Check(ctx, testKey)
	c.HTTPClient = unavailable()
	if r, e := c.Check(ctx, testKey); r != nil || e == nil {
		t.Fatal("business refusal used grace")
	}
}

func TestInvalidConfigurationDoesNotLeakSecrets(t *testing.T) {
	_, e := New("authgo2.SECRET-NEVER-LOG")
	if e == nil || !strings.Contains(e.Error(), "请在后台重新复制接入配置") || strings.Contains(e.Error(), "SECRET") {
		t.Fatal(e)
	}
}
func TestNewPreservesDeploymentPrefix(t *testing.T) {
	s := newSignedServer(t)
	for _, path := range []string{"", "/api/v1/client", "/auth", "/auth/", "/auth/api/v1/client"} {
		t.Run(path, func(t *testing.T) {
			raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(configFor(s), "authgo2."))
			var data map[string]any
			json.Unmarshal(raw, &data)
			data["url"] = s.server.URL + path
			raw, _ = json.Marshal(data)
			c, e := New("authgo2."+base64.RawURLEncoding.EncodeToString(raw), WithCacheDir(""))
			expected := s.server.URL + "/api/v1/client"
			if strings.HasPrefix(path, "/auth") {
				expected = s.server.URL + "/auth/api/v1/client"
			}
			if e != nil || c.endpoint != expected {
				t.Fatal("endpoint lost prefix", c, e)
			}
		})
	}
}
