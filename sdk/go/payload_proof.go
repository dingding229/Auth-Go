package sdk

import (
	"authgo/sdk/wire"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const payloadProofPrefix = "AUTHGO-PAYLOAD-PROOF-v1."

// Only the launcher and protected applications maintain the language-neutral
// evidence. No language's private licensing cache is part of this format.
func (c *Client) protectedEvidence() bool { return c.stubMode || os.Getenv("AUTHGO_PROTECTED") == "1" }
func (c *Client) payloadProofPath() string {
	return filepath.Join(c.CacheDir, "authgo-payload-proof-v1-"+sha([]byte(c.cacheIdentity()))+".cache")
}
func payloadProofMAC(identity, fingerprint, ticket string) []byte {
	key := wire.HKDF([]byte(fingerprint), nil, []byte("authgo/payload-proof/key/v1\x00"+identity), 32)
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("authgo-payload-proof-v1\x00" + ticket))
	return mac.Sum(nil)
}
func atomicPayloadFile(path string, raw []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return errors.New("nonregular cache")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".authgo-payload-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e == nil {
		e = closed
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func (c *Client) savePayloadProof(r *Result) {
	if !c.protectedEvidence() || r == nil || r.Source != "online" || c.CacheDir == "" || c.memoryCache {
		return
	}
	g, e := c.validateTicket(r.ticket, true)
	if e != nil {
		return
	}
	if g.IsTrial || !g.GraceUntil.After(g.IssuedAt) {
		c.clearPayloadKeys()
		return
	}
	raw := payloadProofPrefix + payloadB64.EncodeToString([]byte(r.ticket)) + "." + payloadB64.EncodeToString(payloadProofMAC(c.cacheIdentity(), c.fingerprint, r.ticket))
	_ = atomicPayloadFile(c.payloadProofPath(), []byte(raw))
}

// protectedCachedKey returns K||WM. The independent proof structure is current;
// loadPayloadKey enforces authenticated material length.
func (c *Client) protectedCachedKey(p Payload) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.CacheDir == "" || c.memoryCache || !c.protectedEvidence() {
		return nil, failure(CacheUnavailable, "没有启动授权证据", nil)
	}
	st, e := os.Lstat(c.payloadProofPath())
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > maxCacheSize {
		return nil, failure(CacheInvalid, "启动授权证据不可用", e)
	}
	f, e := os.Open(c.payloadProofPath())
	if e != nil {
		return nil, e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) {
		return nil, failure(CacheInvalid, "启动授权证据已变化", e)
	}
	raw, e := io.ReadAll(io.LimitReader(f, maxCacheSize+1))
	if e != nil || len(raw) > maxCacheSize {
		return nil, failure(CacheInvalid, "启动授权证据无效", e)
	}
	parts := strings.Split(strings.TrimPrefix(string(raw), payloadProofPrefix), ".")
	if !strings.HasPrefix(string(raw), payloadProofPrefix) || len(parts) != 2 {
		return nil, failure(CacheInvalid, "启动授权证据格式无效", nil)
	}
	ticket, e := payloadB64.DecodeString(parts[0])
	if e != nil {
		return nil, failure(CacheInvalid, "启动授权证据编码无效", e)
	}
	mac, e := payloadB64.DecodeString(parts[1])
	if e != nil || !hmac.Equal(mac, payloadProofMAC(c.cacheIdentity(), c.fingerprint, string(ticket))) {
		return nil, failure(CacheInvalid, "启动授权证据实例不符", nil)
	}
	g, e := c.validateTicket(string(ticket), true)
	if e != nil {
		return nil, e
	}
	if e = c.payloadProofPeriod(g); e != nil {
		return nil, e
	}
	c.payloadNoCache = false
	return c.loadPayloadKey(p, &Result{ticket: string(ticket), IsTrial: g.IsTrial})
}
func (c *Client) payloadProofPeriod(g wire.Grant) error {
	now := c.clock()
	if g.IsTrial || !g.GraceUntil.After(g.IssuedAt) || !now.Before(g.GraceUntil) || g.IssuedAt.After(now.Add(5*time.Minute)) {
		return failure(GraceExpired, "启动授权证据不在宽限期内", nil)
	}
	if g.StartsAt != nil && now.Before(*g.StartsAt) {
		return failure(LicenseNotStarted, "授权尚未生效", nil)
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		return failure(LicenseExpired, "授权已到期", nil)
	}
	return nil
}
