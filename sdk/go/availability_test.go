package sdk

import (
	"authgo/sdk/wire"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTicketChallengeDeviceAndForgery(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	r := activate(t, c)
	if e := c.Validate(r.Ticket()); e != nil {
		t.Fatal(e)
	}
	grant, _ := wire.DecodeTicket(string(r.Ticket()), s.pub)
	for _, field := range []string{"device", "signature", "expired"} {
		g := grant
		switch field {
		case "device":
			g.DeviceHash = strings.Repeat("0", 64)
		case "expired":
			end := s.clock.now()
			g.ExpiresAt = &end
		}
		ticket, _ := wire.EncodeTicket(g, s.private)
		if field == "signature" {
			ticket = string(ticket[:len(ticket)-1]) + "!"
		}
		if e := c.Validate(Ticket(ticket)); e == nil {
			t.Fatal("invalid ticket", field)
		}
	}
	// Only a fresh challenge can satisfy a new online check, even with a valid ticket signature.
	for _, mode := range []string{"ticket-challenge", "ticket-device", "ticket-signature", "ticket-old"} {
		c := s.client(t)
		s.set("")
		activate(t, c)
		s.set(mode)
		if r, e := c.Verify(context.Background()); e != nil || r.Status != "grace" {
			t.Fatal("invalid ticket must only use cached grace", mode, e)
		}
	}
}
func TestAvailabilityStopsForGraceExpiryRollbackRecovery(t *testing.T) {
	{
		t.Run("grace window", func(t *testing.T) {
			s := newSignedServer(t)
			c := s.client(t)
			online := activate(t, c)
			if online.Status != "online" {
				t.Fatal(online)
			}
			c.HTTPClient = unavailable()
			r, e := c.Verify(context.Background())
			if e != nil || r.Status != "grace" || !r.Offline || r.RemainingSeconds < 1 {
				t.Fatal(r, e)
			}
			s.clock.add(2 * time.Hour)
			r, e = c.Verify(context.Background())
			if !errors.Is(e, ErrGraceExpired) {
				t.Fatal("expired grace must stop", e)
			}
			c.HTTPClient = nil
			r, e = c.Verify(context.Background())
			if e != nil || r.Status != "online" || r.Offline {
				t.Fatal(r, e)
			}
			s.set("suspended")
			c.HTTPClient = nil
			if _, e = c.Verify(context.Background()); !errors.Is(e, ErrLicenseSuspended) {
				t.Fatal(e)
			}
			c.HTTPClient = unavailable()
			if _, e = c.Verify(context.Background()); e == nil {
				t.Fatal("business refusal used offline")
			}
		})
	}
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	s.clock.add(-5 * time.Minute)
	c.HTTPClient = unavailable()
	if _, e := c.Verify(context.Background()); e != nil {
		t.Fatal("5m skew", e)
	}
	s.clock.add(-time.Second)
	if _, e := c.Verify(context.Background()); !errors.Is(e, ErrClockRollback) {
		t.Fatal(e)
	}
	fresh := s.client(t)
	fresh.CacheDir = c.CacheDir
	fresh.HTTPClient = unavailable()
	if _, e := fresh.Verify(context.Background()); !errors.Is(e, ErrClockRollback) {
		t.Fatal("restart rollback", e)
	}
	c.HTTPClient = nil
	if _, e := c.Verify(context.Background()); e != nil {
		t.Fatal("online recovery", e)
	}
	c.HTTPClient = unavailable()
	if _, e := c.Verify(context.Background()); e != nil {
		t.Fatal("rollback watermark not recovered", e)
	}
}
func TestGraceNeverBypassesExpiryOrBadCache(t *testing.T) {
	s := newSignedServer(t)
	end := s.clock.now().Add(2 * time.Hour)
	s.expires = &end
	c := s.client(t)
	activate(t, c)
	c.HTTPClient = unavailable()
	s.clock.add(3 * time.Hour)
	if _, e := c.Verify(context.Background()); !errors.Is(e, ErrLicenseExpired) {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(c.cachePath())
	raw[len(raw)-1] ^= 1
	os.WriteFile(c.cachePath(), raw, 0600)
	fresh := s.client(t)
	fresh.CacheDir = c.CacheDir
	fresh.HTTPClient = unavailable()
	if _, e := fresh.Check(context.Background(), testKey); e == nil {
		t.Fatal("tampered cache granted")
	}
}

var sentinelTime = time.Unix(1, 0).UTC()

func TestExpiredGracePersistsWatermarkAcrossRestart(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	activate(t, c)
	c.HTTPClient = unavailable()
	s.clock.add(2 * time.Hour)
	if _, e := c.Verify(context.Background()); !errors.Is(e, ErrGraceExpired) {
		t.Fatal(e)
	}
	s.clock.add(-110 * time.Minute)
	fresh := s.client(t)
	fresh.CacheDir = c.CacheDir
	fresh.HTTPClient = unavailable()
	if _, e := fresh.Verify(context.Background()); !errors.Is(e, ErrClockRollback) {
		t.Fatal("stopped observation forgotten", e)
	}
}
