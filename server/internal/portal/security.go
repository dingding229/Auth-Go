package portal

import (
	"crypto/sha256"
	"sync"
	"time"
)

type failure struct {
	count int
	until time.Time
}
type otp struct {
	hash, credentials string
	expires           time.Time
	attempts          int
	ready             bool
}
type security struct {
	mu        sync.Mutex
	gates     [64]sync.Mutex
	failures  map[string]failure
	codes     map[string]otp
	cooldowns map[string]time.Time
	swept     time.Time
}

func newSecurity() *security {
	return &security{failures: map[string]failure{}, codes: map[string]otp{}, cooldowns: map[string]time.Time{}}
}
func (s *security) gate(key string) func() {
	sum := sha256.Sum256([]byte(key))
	m := &s.gates[int(sum[0])%64]
	m.Lock()
	return m.Unlock
}
func (s *security) sweep(now time.Time) {
	if now.Sub(s.swept) < time.Minute {
		return
	}
	s.swept = now
	for k, v := range s.failures {
		if !now.Before(v.until) {
			delete(s.failures, k)
		}
	}
	for k, v := range s.codes {
		if !now.Before(v.expires) {
			delete(s.codes, k)
		}
	}
	for k, v := range s.cooldowns {
		if !now.Before(v) {
			delete(s.cooldowns, k)
		}
	}
}
func (s *security) locked(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	f, ok := s.failures[key]
	if ok && !now.Before(f.until) {
		delete(s.failures, key)
		ok = false
	}
	if ok {
		return f.count >= 5
	}
	if len(s.failures) >= 10000 {
		return true
	}
	s.failures[key] = failure{until: now.Add(15 * time.Minute)}
	return false
}
func (s *security) failed(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.failures[key]
	v.count++
	if v.count >= 5 {
		v.until = now.Add(15 * time.Minute)
	}
	s.failures[key] = v
	return v.count >= 5
}
func (s *security) success(key string) { s.mu.Lock(); delete(s.failures, key); s.mu.Unlock() }
