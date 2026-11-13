package auth

import (
	"authgo/internal/netpolicy"
	"crypto/sha256"
	"sync"
	"time"
)

type loginFailure struct {
	count       int
	expires     time.Time
	lockedUntil time.Time
}

// LoginLimiter bounds memory and never evicts active locks to admit new names.
// Striped gates serialize attempts including password checks, so parallel
// requests cannot all pass a preflight check before the fifth failure locks.
type LoginLimiter struct {
	mu        sync.Mutex
	entries   map[string]loginFailure
	gates     [64]sync.Mutex
	now       func() time.Time
	lastSweep time.Time
}

func NewLoginLimiter(now func() time.Time) *LoginLimiter {
	return &LoginLimiter{entries: make(map[string]loginFailure), now: now}
}
func loginKey(username, ip string) string { return username + "\x00" + netpolicy.SourceKey(ip) }
func (l *LoginLimiter) gate(key string) func() {
	hash := sha256.Sum256([]byte(key))
	m := &l.gates[int(hash[0])%len(l.gates)]
	m.Lock()
	return m.Unlock
}
func (l *LoginLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= time.Minute {
		for k, v := range l.entries {
			if !now.Before(v.expires) && !now.Before(v.lockedUntil) {
				delete(l.entries, k)
			}
		}
		l.lastSweep = now
	}
	v, ok := l.entries[key]
	if ok && now.Before(v.lockedUntil) {
		return false
	}
	if ok && !now.Before(v.expires) {
		delete(l.entries, key)
		ok = false
	}
	if ok {
		return true
	}
	if len(l.entries) >= 10000 {
		return false
	}
	// Reserve under the same mutex: distinct names racing through bcrypt must
	// not oversubscribe the memory bound after their admission checks.
	l.entries[key] = loginFailure{expires: now.Add(15 * time.Minute)}
	return true
}
func (l *LoginLimiter) failed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	v, exists := l.entries[key]
	if !exists && len(l.entries) >= 10000 {
		return true
	}
	if v.count == 0 || !now.Before(v.expires) {
		v = loginFailure{expires: now.Add(15 * time.Minute)}
	}
	v.count++
	if v.count >= 5 {
		v.lockedUntil = now.Add(15 * time.Minute)
		v.expires = v.lockedUntil
	}
	l.entries[key] = v
	return v.count >= 5
}
func (l *LoginLimiter) succeeded(key string) { l.mu.Lock(); delete(l.entries, key); l.mu.Unlock() }

// Account failures across sources have a fixed window, not a sliding permanent
// lock. Twenty failures delay further attempts until the existing 15m window
// ends. Blocked requests never extend it; a successful login clears the budget.
func (l *LoginLimiter) accountAllowed(username string) bool {
	if !l.allowed(username) {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.entries[username].count < 20
}
func (l *LoginLimiter) accountFailed(username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	v, ok := l.entries[username]
	if !ok {
		return true
	}
	if !now.Before(v.expires) {
		v = loginFailure{expires: now.Add(15 * time.Minute)}
	}
	v.count++
	l.entries[username] = v
	return v.count >= 20
}
