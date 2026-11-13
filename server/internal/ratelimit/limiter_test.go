package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	l := Tokens(2, 2, 2, true)
	now := time.Unix(1000, 0)
	for i := 0; i < 2; i++ {
		if !l.Allow("one", now) {
			t.Fatal("burst", i)
		}
	}
	if l.Allow("one", now) {
		t.Fatal("third request admitted")
	}
	if l.Allow("one", now.Add(499*time.Millisecond)) || !l.Allow("one", now.Add(500*time.Millisecond)) {
		t.Fatal("fractional refill")
	}
	if !l.Allow("two", now) || l.Allow("three", now) {
		t.Fatal("key isolation or capacity")
	}
	if !l.Allow("three", now.Add(2*time.Hour)) {
		t.Fatal("idle entries not removed")
	}
}
func TestConfigureAndConcurrency(t *testing.T) {
	l := Tokens(1, 20, 10000, false)
	now := time.Now()
	if !l.Allow("ip", now) {
		t.Fatal("initial budget")
	}
	l.Configure(2, 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("ip", now) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 1 {
		t.Fatal("burst", allowed)
	}
	if l.Allow("ip", now.Add(499*time.Millisecond)) || !l.Allow("ip", now.Add(500*time.Millisecond)) {
		t.Fatal("configured refill")
	}
}
func TestWindowBoundaryAndCapacity(t *testing.T) {
	now := time.Unix(1000, 0)
	l := Window(10, 2, time.Minute, RejectNew)
	for range 10 {
		if !l.Allow("one", now) {
			t.Fatal("window burst")
		}
	}
	if l.Allow("one", now.Add(59*time.Second)) {
		t.Fatal("window reset too early")
	}
	if !l.Allow("two", now) || l.Allow("three", now) {
		t.Fatal("capacity")
	}
	if !l.Allow("one", now.Add(time.Minute)) || !l.Allow("three", now.Add(time.Minute)) {
		t.Fatal("window boundary cleanup")
	}
}
func TestFullRateLimitBucketsEvictOldest(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	l := Window(30, 10000, time.Minute, EvictOldest)
	for i := 0; i < 10000; i++ {
		l.entries[fmt.Sprintf("source-%d", i)] = entry{at: now.Add(-30 * time.Second), tokens: 0}
	}
	l.entries["source-0"] = entry{at: now.Add(-50 * time.Second), tokens: 0}
	if !l.Allow("new-source", now) || l.Len() != 10000 {
		t.Fatal("new source denied or limit exceeded")
	}
	if _, ok := l.entries["source-0"]; ok {
		t.Fatal("oldest bucket retained")
	}
	if l.Allow("source-1", now) {
		t.Fatal("existing source limit was reset")
	}
}

func TestCapacityAndExpiryBoundaries(t *testing.T) {
	now := time.Unix(1000, 0)
	if Window(1, 0, time.Minute, EvictOldest).Allow("ip", now) {
		t.Fatal("zero capacity admitted")
	}
	for _, offset := range []time.Duration{time.Hour, time.Hour + time.Nanosecond} {
		l := Tokens(1, 1, 1, true)
		l.Allow("one", now)
		if got := l.Allow("other", now.Add(offset)); got != (offset > time.Hour) {
			t.Fatal("idle expiry boundary", offset, got)
		}
	}
}
