package auth

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterConcurrentAndBounded(t *testing.T) {
	clock := &testClock{value: time.Now()}
	l := NewLoginLimiter(clock.now)
	key := loginKey("owner", "127.0.0.1")
	var wg sync.WaitGroup
	var passed atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			unlock := l.gate(key)
			defer unlock()
			if l.allowed(key) {
				passed.Add(1)
				l.failed(key)
			}
		})
	}
	wg.Wait()
	if passed.Load() != 5 || l.allowed(key) {
		t.Fatal("parallel lockout bypass")
	}
	clock.add(15 * time.Minute)
	if !l.allowed(key) {
		t.Fatal("lock not expired")
	}
	l.failed(key)
	l.succeeded(key)
	if !l.allowed(key) {
		t.Fatal("success did not reset")
	}
	l.succeeded(key)
	for i := 0; i < 10000; i++ {
		k := fmt.Sprint(i)
		if !l.allowed(k) {
			t.Fatal("unexpected capacity rejection")
		}
		l.failed(k)
	}
	if l.allowed("new-user") {
		t.Fatal("unbounded failure entries")
	}
	clock.add(16 * time.Minute)
	if !l.allowed("new-user") || len(l.entries) != 1 {
		t.Fatal("expired entries not reclaimed")
	}
}

func TestTOTPVectorAndWindow(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // RFC 6238 SHA1 test secret.
	for _, seconds := range []int64{29, 59, 89} {
		step, err := verifyTOTP(secret, "287082", time.Unix(seconds, 0), 0)
		if err != nil || step != 1 {
			t.Fatalf("RFC/window %d: %d %v", seconds, step, err)
		}
	}
	for _, test := range []struct {
		code string
		at   int64
		last int64
	}{{"287082", 119, 0}, {"287082", 59, 1}, {"invalid", 59, 0}, {"12345a", 59, 0}} {
		if _, err := verifyTOTP(secret, test.code, time.Unix(test.at, 0), test.last); err == nil {
			t.Fatal("invalid/replayed TOTP accepted")
		}
	}
}

func TestLimiterCapacityAdmissionIsAtomic(t *testing.T) {
	l := NewLoginLimiter(time.Now)
	for i := 0; i < 9999; i++ {
		if !l.allowed(fmt.Sprint(i)) {
			t.Fatal("initial admission failed")
		}
	}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Go(func() {
			if l.allowed(fmt.Sprintf("new-%d", i)) {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 1 || len(l.entries) != 10000 {
		t.Fatalf("admitted=%d size=%d", admitted.Load(), len(l.entries))
	}
}
