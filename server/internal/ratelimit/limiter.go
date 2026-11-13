// Package ratelimit provides bounded per-key request budgets.
package ratelimit

import (
	"sync"
	"time"
)

type Overflow uint8

const (
	RejectNew Overflow = iota
	EvictOldest
)

type Options struct {
	Rate            float64
	Burst, Capacity int
	// Window preserves fixed-window budgets; zero selects token replenishment.
	Window                 time.Duration
	IdleTTL, SweepInterval time.Duration
	SweepOnFull            bool
	Overflow               Overflow
}
type entry struct {
	tokens float64
	at     time.Time
}
type Limiter struct {
	mu      sync.Mutex
	options Options
	entries map[string]entry
	swept   time.Time
}

func New(options Options) *Limiter { return &Limiter{options: options, entries: map[string]entry{}} }
func Tokens(rate float64, burst, capacity int, sweepOnFull bool) *Limiter {
	return New(Options{Rate: rate, Burst: burst, Capacity: capacity, IdleTTL: time.Hour, SweepInterval: time.Minute, SweepOnFull: sweepOnFull})
}
func Window(burst, capacity int, duration time.Duration, overflow Overflow) *Limiter {
	return New(Options{Burst: burst, Capacity: capacity, Window: duration, IdleTTL: duration, Overflow: overflow})
}
func (l *Limiter) sweep(now time.Time) {
	for key, value := range l.entries {
		elapsed := now.Sub(value.at)
		if l.options.Window > 0 && elapsed >= l.options.IdleTTL || l.options.Window == 0 && elapsed > l.options.IdleTTL {
			delete(l.entries, key)
		}
	}
	l.swept = now
}
func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	o := l.options
	if o.Capacity <= 0 {
		return false
	}
	b, exists := l.entries[key]
	full := !exists && len(l.entries) >= o.Capacity
	if (!o.SweepOnFull || full) && (l.swept.IsZero() || now.Sub(l.swept) >= o.SweepInterval) {
		l.sweep(now)
		b, exists = l.entries[key]
	}
	if !exists {
		if len(l.entries) >= o.Capacity {
			if o.Overflow == RejectNew {
				return false
			}
			var oldestKey string
			var oldest time.Time
			for k, v := range l.entries {
				if oldest.IsZero() || v.at.Before(oldest) {
					oldestKey, oldest = k, v.at
				}
			}
			delete(l.entries, oldestKey)
		}
		b = entry{tokens: float64(o.Burst), at: now}
	}
	if o.Window == 0 {
		if elapsed := now.Sub(b.at).Seconds(); elapsed > 0 {
			b.tokens = min(float64(o.Burst), b.tokens+elapsed*o.Rate)
		}
		b.at = now
	}
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	l.entries[key] = b
	return allowed
}
func (l *Limiter) Configure(rate float64, burst int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.options.Rate, l.options.Burst = rate, burst
	for key, value := range l.entries {
		if value.tokens > float64(burst) {
			value.tokens = float64(burst)
			l.entries[key] = value
		}
	}
}
func (l *Limiter) Len() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.entries) }
