package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// A candidate key never inherits the old grant, but failure cannot revoke it.
func TestLicenseKeyCandidateFailurePreservesActivation(t *testing.T) {
	raw, err := os.ReadFile("../vectors/license-key.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Key   string
			Valid bool
		}
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	candidate := vectors.Cases[0].Key
	for _, entry := range []string{"check", "activate"} {
		for _, input := range []string{"abc", candidate} {
			t.Run(entry+"/"+input, func(t *testing.T) {
				s := newSignedServer(t)
				dir := t.TempDir()
				opts := []Option{WithCacheDir(dir), WithFingerprint(func() (string, error) { return strings.Repeat("a", 64), nil })}
				c, err := New(configFor(s), opts...)
				if err != nil {
					t.Fatal(err)
				}
				c.now = s.clock.now
				ctx := context.Background()
				if _, err = c.Check(ctx, testKey); err != nil {
					t.Fatal(err)
				}
				previous := c.state
				previousTicket, previousUntil := c.onlineTicket, c.onlineUntil
				data, err := os.ReadFile(c.cachePath())
				if err != nil {
					t.Fatal(err)
				}
				beforeRequests := s.counts["activate"]
				s.responseCode = LicenseNotFound
				if entry == "check" {
					_, err = c.Check(ctx, input)
				} else {
					_, err = c.Activate(ctx, input, ActivateOptions{})
				}
				want := ErrLicenseNotFound
				if input == "abc" {
					want = ErrInvalidLicenseKey
				}
				if !errors.Is(err, want) {
					t.Fatal(err)
				}
				if input == "abc" && s.counts["activate"] != beforeRequests {
					t.Fatal("invalid key sent over network")
				}
				if c.state.Refused || c.state.Proof == nil || !reflect.DeepEqual(c.state, previous) || c.onlineTicket != previousTicket || c.onlineUntil != previousUntil {
					t.Fatal("previous activation changed")
				}
				after, err := os.ReadFile(c.cachePath())
				if err != nil || !bytes.Equal(data, after) {
					t.Fatal("persisted cache changed", err)
				}
				// A fresh Client must still restore the original proof and enter grace.
				fresh, err := New(configFor(s), opts...)
				if err != nil {
					t.Fatal(err)
				}
				fresh.now = s.clock.now
				fresh.HTTPClient = unavailable()
				r, err := fresh.Check(ctx, testKey)
				if err != nil || r.Availability != "grace" || fresh.state.Refused {
					t.Fatal(r, err)
				}
				s.responseCode = ""
				fresh.HTTPClient = s.server.Client()
				r, err = fresh.Check(ctx, testKey)
				if err != nil || r.Availability != "online" {
					t.Fatal(r, err)
				}
			})
		}
	}
}
