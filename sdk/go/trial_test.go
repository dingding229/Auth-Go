package sdk

import (
	"context"
	"errors"
	"testing"
)

func TestGuardTrialSignedKeyCacheAndNoGrace(t *testing.T) {
	s := newSignedServer(t)
	c := s.client(t)
	if _, e := c.Check(context.Background(), ""); !errors.Is(e, ErrInvalidLicenseKey) {
		t.Fatal(e)
	}
	if s.counts["trial"] != 0 {
		t.Fatal("low-level check requested trial")
	}
	r, e := c.guardCheck(context.Background(), "")
	if e != nil || !r.IsTrial {
		t.Fatal(r, e)
	}
	if c.state.TrialKey != testKey || s.counts["trial"] != 1 {
		t.Fatal("trial not persisted")
	}
	fresh := s.client(t)
	fresh.CacheDir = c.CacheDir
	r, e = fresh.guardCheck(context.Background(), "")
	if e != nil || !r.IsTrial || s.counts["trial"] != 1 {
		t.Fatal("restart requested trial again", r, e)
	}
	fresh.HTTPClient = unavailable()
	if _, e = fresh.Verify(context.Background()); !errors.Is(e, ErrGraceExpired) {
		t.Fatal("trial used grace", e)
	}
	if c.state.Refused {
		t.Fatal("outage became refusal")
	}
}
func TestGuardTrialDoesNotUseUnauthenticatedKey(t *testing.T) {
	s := newSignedServer(t)
	s.set("bad-signature")
	c := s.client(t)
	if _, e := c.guardCheck(context.Background(), ""); !errors.Is(e, ErrResponseSignatureInvalid) {
		t.Fatal(e)
	}
	if c.state.TrialKey != "" || c.state.Key != "" {
		t.Fatal("untrusted key persisted")
	}
}
