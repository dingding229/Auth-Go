package sdk

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPublicKeyAndFingerprintHelpers(t *testing.T) {
	s := newSignedServer(t)
	b64 := base64.StdEncoding.EncodeToString(s.pub)
	key, e := ParsePublicKey(b64)
	if e != nil || string(key) != string(s.pub) {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(s.pub)
	if e != nil {
		t.Fatal(e)
	}
	text := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	key, e = ParsePublicKey(string(text))
	if e != nil || string(key) != string(s.pub) {
		t.Fatal(e)
	}
	for _, v := range []string{"bad", base64.StdEncoding.EncodeToString(make([]byte, 31)), string(text) + "extra"} {
		if _, e := ParsePublicKey(v); !errors.Is(e, ErrInvalidConfig) {
			t.Fatal(e)
		}
	}
	a, e := hashIdentity(" UUID ", "02:00:00:00:00:01", "Intel  CPU")
	if e != nil || !validFingerprint(a) {
		t.Fatal(a, e)
	}
	b, e := hashIdentity("uuid", "02:00:00:00:00:01", "intel cpu")
	if e != nil || a != b {
		t.Fatal("unstable normalization")
	}
	items := []net.Interface{{Index: 1, Name: "lo", Flags: net.FlagLoopback | net.FlagUp}, {Index: 3, Name: "wifi", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 3}}, {Index: 2, Name: "eth", Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 2}}}
	if mac, e := primaryMAC(items, "wifi"); e != nil || mac != "02:00:00:00:00:03" {
		t.Fatal(mac, e)
	}
	if mac, e := primaryMAC(items, "2"); e != nil || mac != "02:00:00:00:00:02" {
		t.Fatal(mac, e)
	}
	if _, e := primaryMAC(nil, ""); e == nil {
		t.Fatal("no NIC accepted")
	}
	if _, e := hashIdentity("", "bad", ""); !errors.Is(e, ErrFingerprintUnavailable) {
		t.Fatal(e)
	}
}
func TestConfigurationAndCacheWarnings(t *testing.T) {
	s := newSignedServer(t)
	for _, bad := range []string{"https://user:password@example.com", "https://example.com?x=1", "https://example.com/#x", "https://example.com/auth/../other", "http://example.com"} {
		c := s.client(t)
		c.BaseURL = bad
		if _, e := c.Activate(context.Background(), testKey, ActivateOptions{}); !errors.Is(e, ErrInvalidConfig) {
			t.Fatal(bad, e)
		}
	}
	c := s.client(t)
	target := filepath.Join(t.TempDir(), "not-a-directory")
	os.WriteFile(target, []byte("file"), 0600)
	c.CacheDir = target
	r, e := c.Activate(context.Background(), testKey, ActivateOptions{})
	if e != nil || r.CacheWarning == nil {
		t.Fatal(r, e)
	}
	// A callback override is valid without any online credentials.
	local := &Client{FingerprintFunc: func() (string, error) { return strings.Repeat("f", 64), nil }}
	if _, e := local.identity(""); e != nil {
		t.Fatal(e)
	}
}
func TestCacheCannotMoveToAnotherDeviceEvenWithAppSecret(t *testing.T) {
	s := newSignedServer(t)
	a := s.client(t)
	activate(t, a)
	raw, _ := os.ReadFile(a.cachePath())
	source, aad, _ := a.cacheCipher()
	blob, _ := decodeURL(strings.TrimPrefix(string(raw), cachePrefix))
	plain, e := source.Open(nil, blob[:source.NonceSize()], blob[source.NonceSize():], aad)
	if e != nil {
		t.Fatal(e)
	}
	b := s.client(t)
	b.FingerprintFunc = func() (string, error) { return strings.Repeat("b", 64), nil }
	if e := b.online(""); e != nil {
		t.Fatal(e)
	}
	// Re-encryption is possible for a malicious client holding app_secret, but
	// the server-signed nonce still binds the original device/request context.
	target, targetAAD, _ := b.cacheCipher()
	nonce := make([]byte, target.NonceSize())
	rand.Read(nonce)
	forged := target.Seal(nonce, nonce, plain, targetAAD)
	os.MkdirAll(b.CacheDir, 0700)
	os.WriteFile(b.cachePath(), []byte(cachePrefix+base64.RawURLEncoding.EncodeToString(forged)), 0600)
	b.HTTPClient = unavailable()
	if r, e := b.Verify(context.Background()); r != nil || !errors.Is(e, ErrCacheInvalid) {
		t.Fatal("cross-device cache accepted", r, e)
	}
}
func TestDuplicateAutoLoopAndCancel(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	c.wait = func(ctx context.Context, d time.Duration) error { close(entered); <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { done <- c.StartAutoCheck(ctx, nil) }()
	<-entered
	if e := c.StartAutoCheck(context.Background(), nil); !errors.Is(e, ErrAutoCheckRunning) {
		t.Fatal(e)
	}
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
