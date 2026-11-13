package auth

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLoginSourceIPv6AndMappedIPv4(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, e := f.s.Login(ctx, "owner", "bad", "", fmt.Sprintf("2001:db8:1:1::%x", i))
		status := 401
		if i == 4 {
			status = 429
		}
		wantStatus(t, e, status)
	}
	_, e := f.s.Login(ctx, "owner", "initial-password", "", "2001:db8:1:1::ffff")
	wantStatus(t, e, 429)
	if _, e := f.s.Login(ctx, "owner", "initial-password", "", "2001:db8:1:2::1"); e != nil {
		t.Fatal("different /64 blocked", e)
	}
	if loginKey("owner", "::ffff:192.0.2.1") != loginKey("owner", "192.0.2.1") {
		t.Fatal("mapped IPv4 splits budget")
	}
}
func TestLoginAccountBudgetAcrossSourcesAndRecovery(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		_, e := f.s.Login(ctx, "owner", "bad", "", fmt.Sprintf("192.0.2.%d", i+1))
		status := 401
		if i == 19 {
			status = 429
		}
		wantStatus(t, e, status)
	}
	f.clock.add(14 * time.Minute)
	_, e := f.s.Login(ctx, "owner", "initial-password", "", "203.0.113.1")
	wantStatus(t, e, 429)
	_, e = f.s.Login(ctx, "other", "bad", "", "203.0.113.1")
	wantStatus(t, e, 401)
	f.clock.add(time.Minute)
	if _, e = f.s.Login(ctx, "owner", "initial-password", "", "203.0.113.2"); e != nil {
		t.Fatal("blocked requests extended window", e)
	}
	if _, ok := f.s.account.entries["owner"]; ok {
		t.Fatal("success did not clear account failures")
	}
	for i := 0; i < 3; i++ {
		_, e = f.s.Login(ctx, "owner", "bad", "", fmt.Sprintf("198.51.100.%d", i))
		wantStatus(t, e, 401)
	}
	if _, e = f.s.Login(ctx, "owner", "initial-password", "", "203.0.113.3"); e != nil {
		t.Fatal(e)
	}
	if len(f.s.account.entries) != 1 {
		t.Fatal("successful login budget retained", f.s.account.entries)
	} // only other remains
}
func TestAccountBudgetConcurrentAndBounded(t *testing.T) {
	clock := &testClock{value: time.Now()}
	l := NewLoginLimiter(clock.now)
	var wg sync.WaitGroup
	admitted := 0
	var mu sync.Mutex
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := l.gate("owner")
			defer unlock()
			if l.accountAllowed("owner") {
				l.accountFailed("owner")
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 20 {
		t.Fatal("parallel sources bypassed budget", admitted)
	}
	for i := 0; i < 10100; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); l.accountAllowed(fmt.Sprint(i)) }(i)
	}
	wg.Wait()
	if len(l.entries) != 10000 {
		t.Fatal("unbounded account map", len(l.entries))
	}
	clock.add(15 * time.Minute)
	if !l.accountAllowed("owner") {
		t.Fatal("budget did not recover")
	}
}

func TestLoginAccountBudgetSerializesRotatingSources(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 36; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := f.s.Login(context.Background(), "owner", "bad", "", fmt.Sprintf("192.0.2.%d", i+1))
			if e == nil {
				t.Error("invalid password accepted")
			}
		}(i)
	}
	wg.Wait()
	if failures := f.s.account.entries["owner"].count; failures != 20 {
		t.Fatal("concurrent sources exceeded account failure budget", failures)
	}
}
