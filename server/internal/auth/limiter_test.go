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
	l := newLoginLimiter(clock.now)
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

func TestLimiterCapacityAdmissionIsAtomic(t *testing.T) {
	l := newLoginLimiter(time.Now)
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
