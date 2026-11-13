package sdk

import (
	"authgo/sdk/wire"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const payloadCachePrefix = "AUTHGO-PAYLOAD-CACHE-v2."

func payloadCacheFilePrefix(p Payload) string {
	return payloadCachePrefix
}
func payloadMaterialSize(p Payload) int { return 64 }
func validPayloadMaterial(p Payload, material []byte) bool {
	return p.V == 2 && len(material) == payloadMaterialSize(p) && payloadNonzero(material[32:])
}

func payloadCacheLabel(p Payload, fingerprint string) ([]byte, error) {
	bind, e := p.PayloadBinding()
	if e != nil {
		return nil, e
	}
	raw, e := payloadB64.DecodeString(p.Manifest)
	if e != nil {
		return nil, e
	}
	hash := sha256.Sum256(raw)
	label := []byte("authgo-payload-cache-v2\x00")
	for _, s := range []string{p.AppKey, fingerprint, p.KeyID, p.Version} {
		label = payloadLP(label, s)
	}
	label = append(label, hash[:]...)
	return append(label, bind...), nil
}
func (c *Client) payloadCacheBase() string {
	return c.payloadCacheBaseVersion(2)
}
func (c *Client) payloadCacheBaseVersion(version int) string {
	return "authgo-payload-v2-" + sha([]byte(c.cacheIdentity())) + "-"
}
func (c *Client) payloadCacheMaterial(p Payload, r *Result) (string, cipher.AEAD, []byte, error) {
	if c.payloadNoCache || r == nil || r.IsTrial || c.CacheDir == "" || c.memoryCache || r.Source == "offline" {
		return "", nil, nil, failure(CacheUnavailable, "此授权不允许内容密钥缓存", nil)
	}
	g, e := c.validateTicket(r.ticket, true)
	if e != nil {
		return "", nil, nil, e
	}
	now := c.clock()
	if !g.GraceUntil.After(g.IssuedAt) || !now.Before(g.GraceUntil) || g.IsTrial {
		return "", nil, nil, failure(GraceExpired, "内容密钥宽限期已结束", nil)
	}
	if e = c.payloadProofPeriod(g); e != nil {
		return "", nil, nil, e
	}
	label, e := payloadCacheLabel(p, c.fingerprint)
	if e != nil {
		return "", nil, nil, e
	}
	hashSeed, e := hex.DecodeString(g.UnlockHash)
	if e != nil || len(hashSeed) != 32 {
		return "", nil, nil, failure(CacheInvalid, "票据解锁绑定无效", e)
	}
	key := wire.ResourceKey(hashSeed, string(label))
	defer clear(key)
	block, _ := aes.NewCipher(key)
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return "", nil, nil, e
	}
	h := sha256.Sum256(label)
	aad := append([]byte("authgo-payload-cache-file-v2\x00"), h[:]...)
	aad = binary.BigEndian.AppendUint64(aad, g.LicenseID)
	path := filepath.Join(c.CacheDir, c.payloadCacheBaseVersion(p.V)+hex.EncodeToString(h[:])+".cache")
	return path, aead, aad, nil
}
func (c *Client) savePayloadKey(p Payload, r *Result, key []byte) {
	if !validPayloadMaterial(p, key) {
		return
	}
	path, g, aad, e := c.payloadCacheMaterial(p, r)
	if e != nil {
		return
	}
	n := make([]byte, 12)
	if _, e = rand.Read(n); e != nil {
		return
	}
	encoded := []byte(payloadCacheFilePrefix(p) + payloadB64.EncodeToString(g.Seal(n, n, key, aad)))
	if os.MkdirAll(c.CacheDir, 0700) != nil {
		return
	}
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return
	}
	f, e := os.CreateTemp(c.CacheDir, ".authgo-payload-*.tmp")
	if e != nil {
		return
	}
	defer os.Remove(f.Name())
	e = f.Chmod(0600)
	if e == nil {
		_, e = f.Write(encoded)
	}
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e != nil || closed != nil {
		return
	}
	_ = os.Rename(f.Name(), path)
}
func (c *Client) loadPayloadKey(p Payload, r *Result) ([]byte, error) {
	path, g, aad, e := c.payloadCacheMaterial(p, r)
	if e != nil {
		return nil, e
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 256 {
		return nil, failure(CacheUnavailable, "没有可用的内容密钥缓存", nil)
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, failure(CacheUnavailable, "无法读取内容密钥缓存", nil)
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) {
		return nil, failure(CacheInvalid, "内容密钥缓存已变化", nil)
	}
	prefix := payloadCacheFilePrefix(p)
	raw, e := io.ReadAll(io.LimitReader(f, 257))
	if e != nil || len(raw) > 256 || !strings.HasPrefix(string(raw), prefix) {
		return nil, failure(CacheInvalid, "内容密钥缓存格式无效", nil)
	}
	ct, e := payloadB64.DecodeString(string(raw[len(prefix):]))
	if e != nil || len(ct) != 12+payloadMaterialSize(p)+16 {
		return nil, failure(CacheInvalid, "内容密钥缓存格式无效", nil)
	}
	key, e := g.Open(nil, ct[:12], ct[12:], aad)
	if e != nil || !validPayloadMaterial(p, key) {
		clear(key)
		return nil, failure(CacheInvalid, "内容密钥缓存认证失败", nil)
	}
	return key, nil
}
func (c *Client) clearPayloadKeys() {
	if c.CacheDir == "" || c.fingerprint == "" || c.endpoint == "" {
		return
	}
	if c.protectedEvidence() {
		_ = os.Remove(c.payloadProofPath())
	}
	entries, e := os.ReadDir(c.CacheDir)
	if e != nil {
		return
	}
	prefix := c.payloadCacheBase()
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".cache") {
			_ = os.Remove(filepath.Join(c.CacheDir, entry.Name()))
		}
	}
}

// Called under the existing client mutex only after licensing operations.
func (c *Client) recordPayloadResult(result *Result, err error) {
	if err != nil && explicitRefusal(err) && c.protectedEvidence() {
		c.clearPayloadKeys()
	}
	if err != nil || result == nil {
		return
	}
	c.savePayloadProof(result)
	c.payloadReady = true
	g, e := c.validateTicket(result.ticket, true)
	c.payloadNoCache = e != nil || g.IsTrial || !g.GraceUntil.After(g.IssuedAt)
	if c.payloadNoCache {
		c.clearPayloadKeys()
	}
}
