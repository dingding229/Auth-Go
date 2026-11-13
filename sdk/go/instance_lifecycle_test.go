package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFloatingOutageGraceAndExpiryPriority(t *testing.T) {
	{
		t.Run("grace window", func(t *testing.T) {
			s := newSignedServer(t)
			s.floating = true
			duration := time.Hour
			s.floatingGrace = &duration
			c := s.client(t)
			r := activate(t, c)
			s.clock.add(5 * time.Second)
			if e := c.Validate(r.Ticket()); !errors.Is(e, ErrLeaseExpired) {
				t.Fatal("online validation ignored expired lease", e)
			}
			c.HTTPClient = unavailable()
			r, e := c.Heartbeat(context.Background())
			if e != nil || r.Status != "grace" || !r.Offline || len(r.Features) == 0 {
				t.Fatal(r, e)
			}
			if e = c.Validate(r.Ticket()); e != nil {
				t.Fatal("floating grace ticket invalid", e)
			}
			restored := s.client(t)
			restored.CacheDir = c.CacheDir
			restored.HTTPClient = unavailable()
			if r, e := restored.Verify(context.Background()); e != nil || r.Status != "grace" {
				t.Fatal("restart grace", r, e)
			}
			s.clock.add(time.Hour)
			if r, e := restored.Heartbeat(context.Background()); r != nil || !errors.Is(e, ErrGraceExpired) {
				t.Fatal("expired grace or extended", r, e)
			}
		})
	}
	t.Run("zero", func(t *testing.T) {
		s := newSignedServer(t)
		s.floating = true
		d := time.Duration(0)
		s.floatingGrace = &d
		c := s.client(t)
		activate(t, c)
		c.HTTPClient = unavailable()
		if _, e := c.Heartbeat(context.Background()); !errors.Is(e, ErrGraceExpired) {
			t.Fatal(e)
		}
	})
	t.Run("expired", func(t *testing.T) {
		s := newSignedServer(t)
		s.floating = true
		d := time.Hour
		s.floatingGrace = &d
		end := s.clock.now().Add(3 * time.Second)
		s.expires = &end
		c := s.client(t)
		activate(t, c)
		s.clock.add(4 * time.Second)
		c.HTTPClient = unavailable()
		if _, e := c.Heartbeat(context.Background()); !errors.Is(e, ErrLicenseExpired) {
			t.Fatal(e)
		}
	})
	t.Run("temporary then recovery and refusal", func(t *testing.T) {
		s := newSignedServer(t)
		s.floating = true
		d := time.Hour
		s.floatingGrace = &d
		c := s.client(t)
		activate(t, c)
		s.clock.add(5 * time.Second)
		s.mu.Lock()
		s.responseCode = InternalError
		s.mu.Unlock()
		if r, e := c.Heartbeat(context.Background()); e != nil || r.Status != "grace" {
			t.Fatal(r, e)
		}
		s.mu.Lock()
		s.responseCode = ""
		s.mu.Unlock()
		if r, e := c.Heartbeat(context.Background()); e != nil || r.Status != "online" {
			t.Fatal(r, e)
		}
		s.mu.Lock()
		s.responseCode = FloatingLimitReached
		s.mu.Unlock()
		if _, e := c.Heartbeat(context.Background()); !errors.Is(e, ErrFloatingLimitReached) || c.state.Proof != nil {
			t.Fatal(e)
		}
	})
}
func TestInstanceReplacedNeverClearsOrFallsBack(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	before, e := os.ReadFile(c.cachePath())
	if e != nil {
		t.Fatal(e)
	}
	ticket := c.state.Proof.Envelope
	s.mu.Lock()
	s.responseCode = InstanceReplaced
	s.mu.Unlock()
	if r, e := c.Verify(context.Background()); r != nil || !errors.Is(e, ErrInstanceReplaced) || c.state.Refused || c.state.Proof == nil {
		t.Fatal(r, e)
	}
	after, _ := os.ReadFile(c.cachePath())
	if string(before) != string(after) || string(ticket) != string(c.state.Proof.Envelope) {
		t.Fatal("replacement changed local cache")
	}
	c.HTTPClient = unavailable()
	if r, e := c.Verify(context.Background()); r != nil || !errors.Is(e, ErrInstanceReplaced) {
		t.Fatal("replaced process used grace", r, e)
	}
	sameProcess := s.client(t)
	sameProcess.CacheDir = c.CacheDir
	sameProcess.HTTPClient = unavailable()
	if r, e := sameProcess.Verify(context.Background()); r != nil || !errors.Is(e, ErrInstanceReplaced) {
		t.Fatal("new Client forgot process refusal", e)
	}
	restored := s.client(t)
	restored.instanceSession = strings.Repeat("A", 22) // Simulate a different process, not merely another Client object.
	restored.CacheDir = c.CacheDir
	restored.HTTPClient = unavailable()
	if r, e := restored.Verify(context.Background()); e != nil || r.Status != "grace" {
		t.Fatal("replacement destroyed restart proof", r, e)
	}
}
func TestReleaseSeatKeepsProofAndNeverUnbindsDevices(t *testing.T) {
	for _, floating := range []bool{false, true} {
		s := newSignedServer(t)
		s.floating = floating
		c := s.client(t)
		activate(t, c)
		before, _ := os.ReadFile(c.cachePath())
		if e := c.ReleaseSeat(context.Background()); e != nil {
			t.Fatal(e)
		}
		after, _ := os.ReadFile(c.cachePath())
		if string(before) != string(after) || c.state.Refused {
			t.Fatal("release changed cache")
		}
		s.mu.Lock()
		n := s.counts["release-seat"]
		deactivated := s.counts["deactivate"]
		s.mu.Unlock()
		if deactivated != 0 || floating && n != 1 || !floating && n != 0 {
			t.Fatal("wrong release action", n, deactivated)
		}
		if floating {
			c.HTTPClient = unavailable()
			if e := c.ReleaseSeat(context.Background()); e == nil {
				t.Fatal("release ignored network error")
			}
			if r, e := c.Verify(context.Background()); e != nil || r.Status != "grace" {
				t.Fatal(r, e)
			}
		}
	}
}
func TestProcessSessionIsNotPersisted(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	if len(c.instanceSession) != 22 {
		t.Fatal("not 16 bytes")
	}
	raw, _ := os.ReadFile(c.cachePath())
	g, a, _ := c.cacheCipher()
	ct, _ := decodeURL(strings.TrimPrefix(string(raw), cachePrefix))
	plain, e := g.Open(nil, ct[:12], ct[12:], a)
	if e != nil || strings.Contains(string(plain), "instance_session") || strings.Contains(string(plain), c.instanceSession) {
		t.Fatal("process ID persisted", e)
	}
}
func TestFloatingAutoCheckDoesNotStopOrSpinAtExpiredLease(t *testing.T) {
	s := newSignedServer(t)
	s.floating = true
	d := time.Hour
	s.floatingGrace = &d
	c := s.client(t)
	activate(t, c)
	c.HTTPClient = unavailable()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := 0
	c.wait = func(ctx context.Context, delay time.Duration) error {
		if delay <= 0 {
			t.Fatal("busy loop", delay)
		}
		waits++
		s.clock.add(delay)
		if waits >= 5 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if e := c.StartAutoCheck(ctx, func(r *Result, e error) {
		if e == nil && r.Status != "grace" {
			t.Fatal("outage returned online", r)
		}
	}); !errors.Is(e, context.Canceled) || waits < 5 {
		t.Fatal(e, waits)
	}
}

func TestInstanceSessionVectors(t *testing.T) {
	raw, e := os.ReadFile("../vectors/instance-session.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Cases []struct {
			Name, Fault, Expected      string
			Now, Lease, Grace, Expires int64
		} `json:"-"`
		Floating []struct {
			Name     string  `json:"name"`
			Fault    *string `json:"fault"`
			Now      int64   `json:"now"`
			Lease    int64   `json:"lease_expires_at"`
			Grace    int64   `json:"grace_until"`
			Expires  int64   `json:"expires_at"`
			Expected string  `json:"expected"`
		} `json:"floating_cases"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for _, tc := range v.Floating {
		t.Run(tc.Name, func(t *testing.T) {
			s := newSignedServer(t)
			s.clock.at = time.Unix(100, 0).UTC()
			s.floating = true
			duration := time.Duration(tc.Grace-100) * time.Second
			s.floatingGrace = &duration
			end := time.Unix(tc.Expires, 0).UTC()
			s.expires = &end
			c := s.client(t)
			r := activate(t, c)
			s.clock.add(time.Duration(tc.Now-100) * time.Second)
			if tc.Fault == nil {
				e = r.validAt(s.clock.now())
			} else {
				c.HTTPClient = unavailable()
				r, e = c.Heartbeat(context.Background())
			}
			if tc.Expected == "grace" {
				if e != nil || r == nil || r.Status != "grace" {
					t.Fatal(r, e)
				}
			} else if !errors.Is(e, &Error{Code: tc.Expected}) {
				t.Fatal(tc.Expected, e)
			}
		})
	}
}
func TestReleaseSeatRefusalsUseAuthenticatedPolicy(t *testing.T) {
	for _, code := range []string{InstanceReplaced, LicenseRevoked, VersionDisabled, MaintenanceExpired, "UNKNOWN_RELEASE_ERROR"} {
		t.Run(code, func(t *testing.T) {
			s := newSignedServer(t)
			s.floating = true
			c := s.client(t)
			activate(t, c)
			before, _ := os.ReadFile(c.cachePath())
			proof := c.state.Proof.Envelope
			s.mu.Lock()
			s.responseCode = code
			s.mu.Unlock()
			if e := c.ReleaseSeat(context.Background()); !errors.Is(e, &Error{Code: code}) {
				t.Fatal(e)
			}
			after, _ := os.ReadFile(c.cachePath())
			if code == InstanceReplaced {
				if string(before) != string(after) || c.state.Refused || c.state.Proof == nil || string(proof) != string(c.state.Proof.Envelope) {
					t.Fatal("replacement changed cache")
				}
			} else if c.state.Proof != nil || !c.state.Refused {
				t.Fatal("authenticated release refusal was ignored")
			}
		})
	}
}
func TestInstanceErrorClassificationVectors(t *testing.T) {
	raw, e := os.ReadFile("../vectors/error-classification.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Cases []struct {
			Authenticated bool   `json:"authenticated"`
			Code          string `json:"code"`
			Clear         bool   `json:"clear_cache"`
			AllowGrace    bool   `json:"allow_grace"`
		} `json:"instance_cases"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for _, tc := range v.Cases {
		var e error = &Error{Code: tc.Code}
		if tc.Authenticated {
			e = &authenticatedServerError{original: &Error{Code: tc.Code}}
		}
		if (explicitRefusal(e) && !isInstanceReplaced(e)) != tc.Clear || !explicitRefusal(e) != tc.AllowGrace {
			t.Fatal(tc)
		}
	}
}

func TestUntrustedInstanceReplacedCannotStopProcess(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	proof := string(c.state.Proof.Envelope)
	s.mu.Lock()
	s.responseCode = InstanceReplaced
	s.mode = "unsigned"
	s.mu.Unlock()
	if r, e := c.Verify(context.Background()); e != nil || r.Status != "grace" || c.replacedKey != "" || c.state.Refused || string(c.state.Proof.Envelope) != proof {
		t.Fatal("unsigned replacement was trusted", e)
	}
}

func TestFloatingFirstActivationWithoutProofStillFails(t *testing.T) {
	s := newSignedServer(t)
	s.floating = true
	c := s.client(t)
	c.HTTPClient = unavailable()
	if r, e := c.Check(context.Background(), testKey); r != nil || !errors.Is(e, ErrNetworkError) {
		t.Fatal("no-proof activation was granted", e)
	}
}
