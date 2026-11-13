package sdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxCacheSize = 12 * 1024 * 1024 // bounded encrypted authenticated session cache
const cachePrefix = "AUTHGO-CACHE-v1."

// hkdfSHA256 is RFC5869 extract/expand implemented with standard-library HMAC.
func hkdfSHA256(ikm, salt, info []byte, size int) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(ikm)
	prk := extract.Sum(nil)
	var out, last []byte
	for counter := byte(1); len(out) < size; counter++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(last)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{counter})
		last = expand.Sum(nil)
		out = append(out, last...)
	}
	return out[:size]
}
func (c *Client) cacheIdentity() string {
	return c.endpoint + "\x00" + c.AppKey + "\x00" + c.fingerprint + "\x00" + sha(c.PublicKey)
}
func (c *Client) cachePath() string {
	if c.CacheDir == "" || c.memoryCache {
		return ""
	}
	return filepath.Join(c.CacheDir, "authgo-v1-"+sha([]byte(c.cacheIdentity()))+".cache")
}
func (c *Client) cacheCipher() (cipher.AEAD, []byte, error) {
	aad := []byte("authgo/sdk/cache/v1\x00" + c.cacheIdentity())
	salt := sha256.Sum256([]byte("authgo/sdk/cache/salt/v1\x00" + c.AppKey + "\x00" + c.fingerprint))
	key := hkdfSHA256([]byte(c.AppSecret), salt[:], []byte("authgo/sdk/cache/aes-gcm/v1"), 32)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, nil, e
	}
	gcm, e := cipher.NewGCM(block)
	return gcm, aad, e
}
func (c *Client) persist() error {
	path := c.cachePath()
	if path == "" {
		return nil
	}
	raw, e := json.Marshal(c.state)
	if e != nil {
		return failure(CacheUnavailable, "无法编码本地缓存", e)
	}
	gcm, aad, e := c.cacheCipher()
	if e != nil {
		return failure(CacheUnavailable, "无法初始化缓存加密", e)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return failure(CacheUnavailable, "无法生成缓存随机数", e)
	}
	ciphertext := gcm.Seal(nonce, nonce, raw, aad)
	encoded := []byte(cachePrefix + base64.RawURLEncoding.EncodeToString(ciphertext))
	if e := os.MkdirAll(c.CacheDir, 0700); e != nil {
		return failure(CacheUnavailable, "无法创建缓存目录", e)
	}
	// Never follow a pre-existing cache file symlink on either read or write.
	if stat, e := os.Lstat(path); e == nil && !stat.Mode().IsRegular() {
		return failure(CacheUnavailable, "缓存目标不是普通文件", nil)
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return failure(CacheUnavailable, "无法检查缓存目标", e)
	}
	file, e := os.CreateTemp(c.CacheDir, ".authgo-*.tmp")
	if e != nil {
		return failure(CacheUnavailable, "无法创建缓存文件", e)
	}
	temp := file.Name()
	defer os.Remove(temp)
	if e = file.Chmod(0600); e == nil {
		_, e = file.Write(encoded)
	}
	if e == nil {
		e = file.Sync()
	}
	closeErr := file.Close()
	if e == nil {
		e = closeErr
	}
	if e == nil {
		e = os.Rename(temp, path)
	}
	if e != nil {
		_ = c.removeCache()
		return failure(CacheUnavailable, "无法原子保存缓存", e)
	}
	return nil
}
func (c *Client) removeCache() error {
	path := c.cachePath()
	if path == "" {
		return nil
	}
	e := os.Remove(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	return e
}
func (c *Client) restore() error {
	if c.cacheLoaded {
		return nil
	}
	c.cacheLoaded = true
	path := c.cachePath()
	if path == "" {
		return nil
	}
	stat, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || !stat.Mode().IsRegular() || stat.Size() > maxCacheSize {
		return failure(CacheInvalid, "本地缓存文件不可用", e)
	}
	file, e := os.Open(path)
	if e != nil {
		return failure(CacheInvalid, "无法打开本地缓存", e)
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, maxCacheSize+1))
	if e != nil || len(raw) > maxCacheSize || !strings.HasPrefix(string(raw), cachePrefix) {
		return failure(CacheInvalid, "缓存格式或长度无效", e)
	}
	ciphertext, e := decodeURL(string(raw[len(cachePrefix):]))
	if e != nil {
		return failure(CacheInvalid, "缓存编码无效", e)
	}
	gcm, aad, e := c.cacheCipher()
	if e != nil || len(ciphertext) < gcm.NonceSize()+gcm.Overhead() {
		return failure(CacheInvalid, "缓存密文无效", e)
	}
	plain, e := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], aad)
	if e != nil {
		return failure(CacheInvalid, "缓存解密或完整性校验失败", e)
	}
	var saved sessionState
	if e := strictJSON(plain, &saved); e != nil || saved.Version != 1 || saved.ObservedAt <= 0 {
		return failure(CacheInvalid, "缓存结构或时钟状态无效", e)
	}
	if saved.Key != "" {
		if e := validateKey(saved.Key); e != nil {
			return failure(CacheInvalid, "缓存授权码无效", e)
		}
	}
	if saved.Token != "" && !validToken(saved.Token) || saved.Proof != nil && saved.Token == "" {
		return failure(CacheInvalid, "缓存激活凭据无效", nil)
	}
	if c.ExpectedLicenseKey != "" && saved.Key != "" && saved.Key != c.ExpectedLicenseKey {
		return failure(CacheInvalid, "缓存与预期授权码不符", nil)
	}
	if e := validateOptions(saved.Options); e != nil {
		return failure(CacheInvalid, "缓存上下文无效", e)
	}
	c.state = saved
	if saved.Proof != nil {
		if verified, e := c.cachedResult(); e != nil || saved.Proof.Operation == "activate" && verified.ActivationToken != saved.Token {
			c.state = sessionState{}
			return failure(CacheInvalid, "缓存签名证据或实例指纹上下文无效", e)
		}
	}
	return nil
}
func (c *Client) cachedResult() (*Result, error) {
	if c.state.Proof == nil {
		return nil, failure(CacheUnavailable, "没有成功验证的缓存", nil)
	}
	proof := c.state.Proof
	switch proof.Operation {
	case "activate", "verify", "heartbeat":
	default:
		return nil, failure(CacheInvalid, "缓存操作类型无效", nil)
	}
	var wire envelope
	if e := strictJSON(proof.Envelope, &wire, "code", "message", "data", "signature", "ts", "nonce"); e != nil {
		return nil, failure(CacheInvalid, "缓存响应无效", e)
	}
	return c.authenticate(proof.Envelope, wire.Nonce, proof.Operation, false, 200)
}
