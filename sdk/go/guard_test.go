package sdk

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuardLifecycleAndConcurrentCopies(t *testing.T) {
	s := newSignedServer(t)
	changed := make(chan error, 16)
	options := []Option{WithCacheDir(t.TempDir()), WithFingerprint(func() (string, error) { return strings.Repeat("a", 64), nil }), func(c *Client) { c.now = s.clock.now }}
	g, e := StartGuard(context.Background(), GuardOptions{Config: configFor(s), License: testKey, Version: "1.2.3", SDKOptions: options, OnChange: func(_ *Result, e error) { changed <- e }})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close(context.Background())
	if g.Result() == nil || g.Err() != nil {
		t.Fatal("missing initial result")
	}
	if e := g.Require(""); e != nil {
		t.Fatal(e)
	}
	if e := g.Require("export"); e != nil {
		t.Fatal(e)
	}
	if e := g.Require("missing"); !errors.Is(e, ErrInvalidPolicy) {
		t.Fatal(e)
	}
	r := g.Result()
	r.Features["mutated"] = true
	r.SatisfiedMethods[0] = "bad"
	if g.Result().Features["mutated"] != nil || g.Result().SatisfiedMethods[0] == "bad" {
		t.Fatal("not a copy")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				g.Result()
				g.Err()
				_ = g.Require("")
			}
		}()
	}
	wg.Wait()
	if e := g.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := g.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := g.Require(""); !errors.Is(e, ErrNotActivated) {
		t.Fatal(e)
	}
}

func TestGuardGraceRecoveryAndRefusal(t *testing.T) {
	s := newSignedServer(t)
	changes := make(chan *Result, 32)
	wake := make(chan struct{})
	opts := []Option{WithCacheDir(t.TempDir()), WithFingerprint(func() (string, error) { return strings.Repeat("a", 64), nil }), func(c *Client) {
		c.now = s.clock.now
		c.wait = func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wake:
				return nil
			}
		}
	}}
	g, e := StartGuard(context.Background(), GuardOptions{Config: configFor(s), License: testKey, SDKOptions: opts, OnChange: func(r *Result, _ error) { changes <- r }})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close(context.Background())
	next := func() *Result {
		t.Helper()
		select {
		case r := <-changes:
			return r
		case <-time.After(3 * time.Second):
			t.Fatal("missing callback")
			return nil
		}
	}
	_ = next()
	s.mu.Lock()
	s.mode = ""
	s.responseCode = InternalError
	s.mu.Unlock()
	s.clock.add(time.Hour / 4)
	wake <- struct{}{}
	if r := next(); r == nil || r.Availability != "grace" {
		t.Fatal(r)
	}
	select {
	case <-g.Done():
		t.Fatal("grace closed Done")
	default:
	}
	s.mu.Lock()
	s.responseCode = ""
	s.mu.Unlock()
	s.clock.add(time.Hour / 4)
	wake <- struct{}{}
	if r := next(); r == nil || r.Availability != "online" {
		t.Fatal(r)
	}
	s.mu.Lock()
	s.responseCode = LicenseRevoked
	s.mu.Unlock()
	s.clock.add(time.Hour / 4)
	wake <- struct{}{}
	_ = next()
	select {
	case <-g.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("refusal did not close Done")
	}
	if !errors.Is(g.Err(), ErrLicenseRevoked) || !errors.Is(g.Require(""), ErrLicenseRevoked) {
		t.Fatal(g.Err())
	}
}
func TestGuardRejectsMissingConfigAndInitialFailure(t *testing.T) {
	t.Setenv("AUTHGO_CONFIG", "authgo2.attacker")
	if _, e := StartGuard(context.Background(), GuardOptions{}); !errors.Is(e, ErrInvalidConfig) {
		t.Fatal(e)
	}
	s := newSignedServer(t)
	if _, e := StartGuard(context.Background(), GuardOptions{Config: configFor(s), License: "abc"}); !errors.Is(e, ErrInvalidLicenseKey) {
		t.Fatal(e)
	}
}

func TestGuardCloseDeadlinePreservesProof(t *testing.T) {
	s := newSignedServer(t)
	s.floating = true
	var block atomic.Bool
	transport := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if block.Load() {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	notified := make(chan struct{}, 1)
	g, e := StartGuard(context.Background(), GuardOptions{Config: configFor(s), License: testKey, SDKOptions: []Option{
		WithHTTPClient(transport), WithCacheDir(t.TempDir()), WithFingerprint(func() (string, error) { return strings.Repeat("a", 64), nil }), func(c *Client) { c.now = s.clock.now },
	}, OnChange: func(_ *Result, _ error) {
		select {
		case notified <- struct{}{}:
		default:
		}
	}})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-notified:
	case <-time.After(3 * time.Second):
		t.Fatal("auto did not start")
	}
	block.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if e := g.Close(ctx); e == nil || time.Since(started) > time.Second {
		t.Fatal("Close ignored caller deadline", e)
	}
	g.client.mu.Lock()
	defer g.client.mu.Unlock()
	if g.client.state.Refused || g.client.state.Proof == nil {
		t.Fatal("failed release removed proof")
	}
}

func TestGuardRequireChecksSignedTicketAndExpiry(t *testing.T) {
	s := newSignedServer(t)
	end := s.clock.now().Add(time.Second)
	s.expires = &end
	notified := make(chan struct{}, 1)
	g, e := StartGuard(context.Background(), GuardOptions{Config: configFor(s), License: testKey, OnChange: func(_ *Result, _ error) {
		select {
		case notified <- struct{}{}:
		default:
		}
	}, SDKOptions: []Option{WithCacheDir(t.TempDir()), WithFingerprint(func() (string, error) { return strings.Repeat("a", 64), nil }), func(c *Client) { c.now = s.clock.now }}})
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close(context.Background())
	select {
	case <-notified:
	case <-time.After(3 * time.Second):
		t.Fatal("auto did not start")
	}
	g.mu.Lock()
	saved := g.result.ticket
	g.result.ticket = "invalid"
	g.mu.Unlock()
	if e := g.Require(""); !errors.Is(e, ErrResponseSignatureInvalid) {
		t.Fatal(e)
	}
	g.mu.Lock()
	g.result.ticket = saved
	g.mu.Unlock()
	s.clock.add(2 * time.Second)
	if e := g.Require(""); !errors.Is(e, ErrLicenseExpired) {
		t.Fatal(e)
	}
}
