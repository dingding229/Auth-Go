package sdk

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Option customizes New. Client configuration must not change after first use.
type Option func(*Client)

func WithCacheDir(path string) Option {
	return func(c *Client) { c.CacheDir = path; c.cacheDirSet = true }
}
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.HTTPClient = h } }
func WithFingerprint(f func() (string, error)) Option {
	return func(c *Client) { c.FingerprintFunc = f }
}
func WithClientVersion(version string) Option {
	return func(c *Client) { c.defaultOptions.ClientVersion = version }
}

// WithInsecureHTTP is for explicitly trusted private development networks only.
func WithInsecureHTTP() Option { return func(c *Client) { c.AllowInsecureHTTP = true } }

// New parses a developer-pinned authgo2 configuration compiled into the program.
// Configuration may be public; never load its trust roots from environment/files.
// AppSecret is not caller identity. Never log configuration, license keys or tokens.
func New(config string, options ...Option) (*Client, error) {
	invalid := func() (*Client, error) {
		return nil, failure(InvalidConfig, "请在后台重新复制接入配置", nil)
	}
	if len(config) > 32768 || !strings.HasPrefix(config, "authgo2.") {
		return invalid()
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(config, "authgo2."))
	if e != nil {
		return invalid()
	}
	var data struct {
		URL        string `json:"url"`
		AppKey     string `json:"app_key"`
		AppSecret  string `json:"app_secret"`
		PublicKey  string `json:"public_key"`
		GatewayKey string `json:"gateway_key"`
	}
	if e = strictJSON(raw, &data); e != nil {
		return invalid()
	}
	pub, e := ParsePublicKey(data.PublicKey)
	if e != nil {
		return invalid()
	}
	gateway, e := decodeURL(data.GatewayKey)
	if e != nil || len(gateway) != 32 {
		return invalid()
	}
	c := &Client{GatewayKey: gateway, BaseURL: data.URL, AppKey: data.AppKey, AppSecret: data.AppSecret, PublicKey: pub}
	// Cache identity is hashed, so even unusual application identifiers cannot
	// escape the per-user directory or expose secrets in a filename.
	for _, opt := range options {
		if opt != nil {
			opt(c)
		}
	}
	container := detectContainer(os.ReadFile, os.Getenv)
	if !c.cacheDirSet {
		if dir := os.Getenv("AUTHGO_CACHE_DIR"); dir != "" {
			c.CacheDir = dir
		} else if container {
			c.CacheDir = "/var/lib/authgo"
		} else {
			root, err := os.UserCacheDir()
			if err != nil {
				return nil, failure(InvalidConfig, "无法确定用户缓存目录，请用WithCacheDir指定", nil)
			}
			c.CacheDir = filepath.Join(root, "authgo", sha([]byte(data.AppKey)))
		}
	}
	if c.FingerprintFunc == nil {
		if id := os.Getenv("AUTHGO_INSTANCE_ID"); id != "" {
			c.FingerprintFunc = func() (string, error) { return instanceFingerprint(id), nil }
		} else if container {
			c.FingerprintFunc = func() (string, error) {
				id, err := containerIdentity(c.CacheDir)
				if id == "" {
					return "", failure(FingerprintUnavailable, "无法生成实例标识", err)
				}
				if err != nil {
					c.memoryCache = true
					c.cacheWarning = failure(CacheUnavailable, "此实例重启后是新实例，没有断连宽限", nil)
				}
				return instanceFingerprint(id), nil
			}
		}
	}
	if e = c.validateEndpoint(); e != nil {
		return invalid()
	}
	if e = validateOptions(requestOptions{Version: c.defaultOptions.ClientVersion}); e != nil {
		return invalid()
	}
	return c, nil
}

// Check activates on first use, otherwise verifies the same activation.
// An explicit server refusal is never replaced with a new activation or grace.
func (c *Client) Check(ctx context.Context, key string) (result *Result, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { c.recordPayloadResult(result, err) }()
	if e := validateKey(key); e != nil {
		return nil, e
	}
	if c.ExpectedLicenseKey != "" && c.ExpectedLicenseKey != key {
		return nil, failure(InvalidLicenseKey, "授权码与预期值不同", nil)
	}
	if e := c.online(""); e != nil {
		return nil, e
	}
	if e := c.restore(); e != nil {
		if !errors.Is(e, ErrCacheInvalid) {
			return nil, e
		}
		// An invalid cache is never evidence. Recover only through a fresh signed
		// activation; network failure cannot grant grace from corrupt bytes.
		c.state = sessionState{Version: 1, ObservedAt: max64(c.state.ObservedAt, c.clock().Unix())}
		if err := c.removeCache(); err != nil {
			return nil, failure(CacheUnavailable, "无法清理无效缓存", nil)
		}
	}
	sameContext := (c.defaultOptions.ClientVersion == "" || c.defaultOptions.ClientVersion == c.state.Options.Version)
	if c.state.Key == key && sameContext && validToken(c.state.Token) {
		return c.checkLocked(ctx, "verify")
	}
	// Candidate activation is transactional: failure must not revoke a different key.
	return c.activateLocked(ctx, key, c.defaultOptions)
}
