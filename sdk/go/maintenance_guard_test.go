package sdk

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceGuardStartupAndFinalFailure(t *testing.T) {
	s := newSignedServer(t)
	opts := func() []Option {
		return []Option{WithCacheDir(t.TempDir()), WithFingerprint(func() (string, error) { return strings.Repeat("a", 64), nil }), func(c *Client) { c.now = s.clock.now }}
	}
	s.mu.Lock()
	s.responseCode = MaintenanceExpired
	s.mu.Unlock()
	if _, err := StartGuard(context.Background(), GuardOptions{Config: configFor(s), License: testKey, SDKOptions: opts()}); !errors.Is(err, ErrMaintenanceExpired) {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.responseCode = ""
	s.mu.Unlock()
	changes := make(chan *Result, 4)
	wake := make(chan struct{})
	options := append(opts(), func(c *Client) {
		c.now = s.clock.now
		c.wait = func(ctx context.Context, delay time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wake:
				s.clock.add(delay)
				return nil
			}
		}
	})
	guard, err := StartGuard(context.Background(), GuardOptions{Config: configFor(s), License: testKey, SDKOptions: options, OnChange: func(r *Result, _ error) { changes <- r }})
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close(context.Background())
	select {
	case <-changes:
	case <-time.After(3 * time.Second):
		t.Fatal("no initial check")
	}
	s.mu.Lock()
	s.responseCode = MaintenanceExpired
	s.mu.Unlock()
	select {
	case wake <- struct{}{}:
	case <-time.After(3 * time.Second):
		t.Fatal("guard did not wait for next check")
	}
	select {
	case <-guard.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("maintenance refusal did not complete guard")
	}
	if !errors.Is(guard.Err(), ErrMaintenanceExpired) || !errors.Is(guard.Require(""), ErrMaintenanceExpired) {
		t.Fatal(guard.Err())
	}
}
func TestMaintenanceResultSnapshotDoesNotShareTimePointer(t *testing.T) {
	at := time.Now()
	want := at
	r := &Result{MaintenanceUntil: &at, LatestEntitledVersion: "1.0.0"}
	snapshot := cloneResult(r)
	*snapshot.MaintenanceUntil = at.Add(time.Hour)
	if !r.MaintenanceUntil.Equal(want) || snapshot.LatestEntitledVersion != "1.0.0" {
		t.Fatal("mutable maintenance snapshot")
	}
}
