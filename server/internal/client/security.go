package client

import (
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/netpolicy"
	"encoding/base64"
	"strconv"
	"sync"
	"time"
)

// SigningInput is v2: the authenticated action, timestamp, nonce and raw body hash.
func SigningInput(op, timestamp, nonce string, body []byte) []byte {
	return []byte(op + timestamp + nonce + cryptoutil.SHA256(body))
}
func validTimestamp(raw string, now time.Time) bool {
	n, err := strconv.ParseInt(raw, 10, 64)
	return err == nil && strconv.FormatInt(n, 10) == raw && n >= now.Unix()-300 && n <= now.Unix()+300
}
func validNonce(raw string) bool {
	if len(raw) < 16 || len(raw) > 128 {
		return false
	}
	for _, c := range []byte(raw) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

type nonceCache struct {
	lastSweep time.Time
	mu        sync.Mutex
	entries   map[string]time.Time
	limit     int
}

// checkAndAdd runs only after a valid HMAC. False is replay or capacity exhaustion.
func (c *nonceCache) checkAndAdd(key string, now time.Time) (replay, full bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if end, ok := c.entries[key]; ok {
		if now.Before(end) {
			return true, false
		}
		delete(c.entries, key)
	}
	if len(c.entries) >= c.limit && (c.lastSweep.IsZero() || now.Sub(c.lastSweep) >= time.Second) {
		c.lastSweep = now
		for k, end := range c.entries {
			if !now.Before(end) {
				delete(c.entries, k)
			}
		}
	}
	if len(c.entries) >= c.limit {
		return false, true
	}
	c.entries[key] = now.Add(10 * time.Minute)
	return false, false
}

type bucket struct {
	tokens float64
	at     time.Time
}
type limiter struct {
	lastSweep time.Time
	mu        sync.Mutex
	entries   map[string]bucket
	rate      float64
	burst     int
	limit     int
}

func newLimiter(rate float64, burst, limit int) *limiter {
	return &limiter{entries: map[string]bucket{}, rate: rate, burst: burst, limit: limit}
}
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.limit && (l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= time.Minute) {
			l.lastSweep = now
			for k, v := range l.entries {
				if now.Sub(v.at) > time.Hour {
					delete(l.entries, k)
				}
			}
		}
		if len(l.entries) >= l.limit {
			return false
		}
		b = bucket{float64(l.burst), now}
	}
	if elapsed := now.Sub(b.at).Seconds(); elapsed > 0 {
		b.tokens = min(float64(l.burst), b.tokens+elapsed*l.rate)
	}
	b.at = now
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	l.entries[key] = b
	return allowed
}

func (l *limiter) configure(rate float64, burst int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = rate
	l.burst = burst
	for k, v := range l.entries {
		if v.tokens > float64(burst) {
			v.tokens = float64(burst)
			l.entries[k] = v
		}
	}
}

// Group IPv6 privacy addresses by network; IPv4 retains one bucket per address.
func ipLimitKey(raw string) string { return netpolicy.SourceKey(raw) }

func validInstanceSession(raw string) bool {
	if raw == "" {
		return true
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(raw)
	return e == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == raw
}
