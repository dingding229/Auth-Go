package portal

import (
	"strings"
	"sync"
	"testing"
	"time"

	"authgo/internal/model"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTScopedAudienceExpiryAndTamper(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	s := &Service{now: func() time.Time { return now }, tokenKey: []byte(strings.Repeat("t", 32)), codeKey: []byte(strings.Repeat("c", 32))}
	id := identity{License: model.License{Base: model.Base{ID: 42}, Key: "license-key"}, App: model.Application{Base: model.Base{ID: 7}}}
	token, e := s.token(id)
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.parse(token)
	if e != nil || c.Subject != "42" || !c.ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatal(c, e)
	}
	forged := *c
	forged.Audience = jwt.ClaimStrings{"authgo-admin-access"}
	bad, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, forged).SignedString(s.tokenKey)
	if _, e := s.parse(bad); e == nil {
		t.Fatal("wrong audience")
	}
	bad, _ = jwt.NewWithClaims(jwt.SigningMethodHS512, c).SignedString(s.tokenKey)
	if _, e := s.parse(bad); e == nil {
		t.Fatal("wrong algorithm")
	}
	parts := strings.Split(token, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	if _, e := s.parse(strings.Join(parts, ".")); e == nil {
		t.Fatal("tampered token")
	}
	now = now.Add(TokenTTL)
	if _, e := s.parse(token); e == nil {
		t.Fatal("expiry equality accepted")
	}
}
func TestBoundedLocksAndConcurrentLimiter(t *testing.T) {
	now := time.Now()
	s := newSecurity()
	if s.locked("key", now) {
		t.Fatal("locked early")
	}
	for i := 1; i <= 5; i++ {
		if s.failed("key", now) != (i == 5) {
			t.Fatal(i)
		}
	}
	if !s.locked("key", now.Add(15*time.Minute-time.Nanosecond)) || s.locked("key", now.Add(15*time.Minute)) {
		t.Fatal("lock boundary")
	}
	for i := 0; i < 10000; i++ {
		s.failures[string(rune(i+1))] = failure{until: now.Add(time.Hour)}
	}
	if !s.locked("overflow", now) {
		t.Fatal("capacity admitted")
	}
	l := newLimiter(1, 1)
	var mu sync.Mutex
	allowed := 0
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.allow("ip", now) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 1 {
		t.Fatal(allowed)
	}
	if !l.allow("ip", now.Add(time.Second)) {
		t.Fatal("bucket did not refill")
	}
	for raw, want := range map[string]string{"203.0.113.1": "203.0.*.*", "::ffff:192.0.2.1": "192.0.*.*", "2001:db8:abcd:1234::a": "2001:db8:abcd::/48", "not-an-ip": ""} {
		if MaskIP(raw) != want {
			t.Fatal(raw, MaskIP(raw))
		}
	}
}
