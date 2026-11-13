package sdk

import (
	"authgo/sdk/wire"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Client owns one device identity and one current activation. Configuration
// fields are immutable after first use; methods on the same Client are serialized.
type Client struct {
	BaseURL            string
	AppKey             string
	AppSecret          string
	PublicKey          ed25519.PublicKey
	GatewayKey         []byte
	CacheDir           string
	HTTPClient         *http.Client
	FingerprintFunc    func() (string, error)
	ExpectedLicenseKey string
	AllowInsecureHTTP  bool

	payloadNoCache        bool
	stubMode              bool
	payloadReady          bool
	replacedKey           string
	instanceSession       string
	offlineTicket         string
	offlineUntil          time.Time
	onlineTicket          string
	onlineUntil           time.Time
	mu                    sync.Mutex
	fingerprint, endpoint string
	state                 sessionState
	cacheLoaded           bool
	cacheDirSet           bool
	memoryCache           bool
	cacheWarning          error
	autoRunning           bool
	defaultOptions        ActivateOptions
	now                   func() time.Time
	wait                  func(context.Context, time.Duration) error
}
type ActivateOptions struct {
	Fingerprint   string
	ClientVersion string
	Hostname      string
	OS            string
}
type Result struct {
	IsTrial               bool       `json:"is_trial,omitempty"`
	MaintenanceUntil      *time.Time `json:"maintenance_until,omitempty"`
	LatestEntitledVersion string     `json:"latest_entitled_version,omitempty"`
	guard                 func() error
	LicenseID             uint64         `json:"license_id"`
	Status                string         `json:"status"`
	Type                  string         `json:"type,omitempty"`
	Features              map[string]any `json:"features"`
	StartsAt              *time.Time     `json:"starts_at"`
	ExpiresAt             *time.Time     `json:"expires_at"`
	NextCheckIn           int            `json:"next_check_in"`
	HeartbeatInterval     int            `json:"heartbeat_interval"`
	GraceUntil            time.Time      `json:"grace_until"`
	LeaseExpiresAt        *time.Time     `json:"lease_expires_at,omitempty"`
	SatisfiedMethods      []string       `json:"satisfied_methods"`
	ActivationToken       string         `json:"-"`
	Offline               bool           `json:"offline"`
	Source                string         `json:"source"`
	usableUntil           time.Time
	clock                 func() time.Time
	ticket                string
	unlockSeed            []byte
	Availability          string `json:"availability"`
	RemainingSeconds      int64  `json:"remaining_seconds"`
	Reason                string `json:"reason"`
	CacheWarning          error  `json:"-"`
}
type requestOptions struct {
	Version  string `json:"client_version"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}
type sessionState struct {
	TrialKey   string         `json:"trial_key,omitempty"`
	Refused    bool           `json:"refused"`
	Version    int            `json:"version"`
	Key        string         `json:"key"`
	Token      string         `json:"token"`
	Options    requestOptions `json:"options"`
	Proof      *evidence      `json:"proof"`
	ObservedAt int64          `json:"observed_at"`
}
type evidence struct {
	Operation string          `json:"operation"`
	Envelope  json.RawMessage `json:"envelope"`
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}
func (c *Client) identity(override string) (string, error) {
	if c.fingerprint != "" {
		if override != "" && !strings.EqualFold(override, c.fingerprint) {
			return "", failure(InvalidConfig, "同一 Client 不能切换设备指纹，请创建独立实例", nil)
		}
		return c.fingerprint, nil
	}
	fp := override
	var e error
	if fp == "" {
		if c.FingerprintFunc != nil {
			fp, e = c.FingerprintFunc()
		} else {
			fp, e = Fingerprint()
		}
	}
	if e != nil {
		return "", e
	}
	if !validFingerprint(fp) {
		return "", failure(FingerprintUnavailable, "设备指纹必须为64位SHA256十六进制", nil)
	}
	c.fingerprint = strings.ToLower(fp)
	return c.fingerprint, nil
}
func (c *Client) validateEndpoint() error {
	if len(c.GatewayKey) != 32 {
		return failure(InvalidConfig, "请在后台重新复制接入配置", nil)
	}
	if len(c.PublicKey) != ed25519.PublicKeySize || c.AppKey == "" || len(c.AppKey) > 128 || c.AppSecret == "" || len(c.AppSecret) > 1024 {
		return failure(InvalidConfig, "必须提供有效应用凭据和可信 Ed25519 公钥", nil)
	}
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return failure(InvalidConfig, "BaseURL 必须为无凭据、查询或片段的服务地址", e)
	}
	p := strings.TrimSuffix(u.Path, "/")
	if strings.Contains(p, "//") {
		return failure(InvalidConfig, "BaseURL 路径无效", nil)
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return failure(InvalidConfig, "BaseURL 路径无效", nil)
		}
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !c.AllowInsecureHTTP && !(ip != nil && ip.IsLoopback() || strings.EqualFold(u.Hostname(), "localhost")) {
			return failure(InvalidConfig, "生产服务必须使用 HTTPS；本机回环 HTTP 可用于开发", nil)
		}
	}
	u.Path = p
	if !strings.HasSuffix(p, "/api/v1/client") {
		u.Path += "/api/v1/client"
	}
	u.Host = strings.ToLower(u.Host)
	endpoint := strings.TrimSuffix(u.String(), "/")
	if c.endpoint != "" && c.endpoint != endpoint {
		return failure(InvalidConfig, "使用后不能更换服务地址", nil)
	}
	c.endpoint = endpoint
	return nil
}
func (c *Client) online(override string) error {
	if err := c.validateEndpoint(); err != nil {
		return err
	}
	_, err := c.identity(override)
	return err
}
func (c *Client) Activate(ctx context.Context, key string, opts ActivateOptions) (result *Result, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { c.recordPayloadResult(result, err) }()
	return c.activateLocked(ctx, key, opts)
}
func (c *Client) activateLocked(ctx context.Context, key string, opts ActivateOptions) (*Result, error) {
	if c.replacedKey != "" && c.replacedKey == key {
		return nil, failure(InstanceReplaced, "此进程已被接管，请退出", nil)
	}
	if e := validateKey(key); e != nil {
		return nil, e
	}
	if c.ExpectedLicenseKey != "" && c.ExpectedLicenseKey != key {
		return nil, failure(InvalidLicenseKey, "授权码与预期值不同", nil)
	}
	if e := c.online(opts.Fingerprint); e != nil {
		return nil, e
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if c.processReplaced(key) {
		return nil, failure(InstanceReplaced, "此进程已被接管，请退出", nil)
	}
	// Preserve application-wide clock/sequence watermarks for explicit Activate,
	// not only for the higher-level Check entry point. Bad grants never survive.
	if !c.cacheLoaded {
		if e := c.restore(); e != nil {
			if !errors.Is(e, ErrCacheInvalid) {
				return nil, e
			}
			c.state.Proof = nil
			// This is an ONLINE activation, not a fallback. A broken cache path
			// must not suppress a fresh authenticated grant; persist reports
			// CacheWarning afterward and no corrupt proof is ever reused.
			_ = c.removeCache()
		}
	}
	if opts.Hostname == "" {
		opts.Hostname, _ = os.Hostname()
	}
	if opts.OS == "" {
		opts.OS = runtime.GOOS + "/" + runtime.GOARCH
	}
	options := requestOptions{Version: opts.ClientVersion, Hostname: opts.Hostname, OS: opts.OS}
	if e := validateOptions(options); e != nil {
		return nil, e
	}
	previous := c.state
	sameContext := previous.Key == key && previous.Options.Version == options.Version
	previousTicket, previousUntil := c.onlineTicket, c.onlineUntil
	c.state = sessionState{TrialKey: c.state.TrialKey, Version: 1, Key: key, Options: options, ObservedAt: max64(c.state.ObservedAt, c.clock().Unix())}
	c.cacheLoaded = true
	c.onlineUntil = time.Time{}
	failActivation := func(err error) (*Result, error) {
		if explicitRefusal(err) {
			c.clearPayloadKeys()
		}
		if isInstanceReplaced(err) {
			c.state = previous
			c.rememberReplacement(key)
			c.onlineTicket = previousTicket
			c.onlineUntil = time.Time{}
			c.offlineTicket = ""
			return nil, err
		}
		if previous.Key != key {
			c.state = previous
			c.onlineTicket, c.onlineUntil = previousTicket, previousUntil
			return nil, err
		}
		if explicitRefusal(err) {

			return nil, errors.Join(err, c.invalidate())
		}
		if sameContext {
			c.state = previous
		}
		return nil, errors.Join(err, c.persist())
	}
	result, raw, _, e := c.exchange(ctx, "activate")
	if e != nil {
		return failActivation(e)
	}
	if !validToken(result.ActivationToken) {
		return failActivation(failure(ResponseInvalid, "激活响应缺少有效凭据", nil))
	}
	c.state.Token = result.ActivationToken
	c.remember("activate", raw)
	result.CacheWarning = errors.Join(c.cacheWarning, c.persist())
	return result, nil
}
func (c *Client) Verify(ctx context.Context) (*Result, error)    { return c.check(ctx, "verify") }
func (c *Client) Heartbeat(ctx context.Context) (*Result, error) { return c.check(ctx, "heartbeat") }
func (c *Client) check(ctx context.Context, op string) (result *Result, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { c.recordPayloadResult(result, err) }()
	return c.checkLocked(ctx, op)
}
func (c *Client) checkLocked(ctx context.Context, op string) (*Result, error) {
	if c.replacedKey != "" && c.replacedKey == c.state.Key {
		return nil, failure(InstanceReplaced, "此进程已被接管，请退出", nil)
	}
	if e := c.online(""); e != nil {
		return nil, e
	}
	if e := c.restore(); e != nil {
		return nil, e
	}
	if c.processReplaced(c.state.Key) {
		return nil, failure(InstanceReplaced, "此进程已被接管，请退出", nil)
	}
	if c.state.Key == "" || !validToken(c.state.Token) {
		return nil, failure(NotActivated, "尚未激活或没有可恢复的激活凭据", nil)
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if op == "verify" {
		if cached, e := c.cachedResult(); e == nil && cached.floating() && cached.LeaseExpiresAt != nil && !c.clock().Before(*cached.LeaseExpiresAt) {
			op = "heartbeat"
		}
	}
	result, raw, recoverable, e := c.exchange(ctx, op)
	if e != nil {
		// A caller cancellation racing an already authenticated refusal must
		// not resurrect a grant that the server explicitly rejected.
		if explicitRefusal(e) {
			c.offlineTicket = ""
			c.offlineUntil = time.Time{}
			if isInstanceReplaced(e) {
				c.rememberReplacement(c.state.Key)
				return nil, e
			}
			return nil, errors.Join(e, c.invalidate())
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if recoverable {
			c.onlineUntil = time.Time{}
			return c.fallback(ctx, e)
		}
		return nil, e
	}
	c.remember(op, raw)
	result.CacheWarning = errors.Join(c.cacheWarning, c.persist())
	return result, nil
}
func (c *Client) Deactivate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.online(""); e != nil {
		return e
	}
	if e := c.restore(); e != nil {
		return e
	}
	if !validToken(c.state.Token) {
		return failure(NotActivated, "尚未激活", nil)
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	// A failed/unauthenticated acknowledgement is not proof of an unbind.
	_, _, _, e := c.exchange(ctx, "deactivate")
	if e != nil {
		return e
	}
	clearErr := c.invalidate()
	c.payloadReady = false
	c.clearPayloadKeys()
	c.state = sessionState{Version: 1, Refused: true, ObservedAt: max64(c.state.ObservedAt, c.clock().Unix())}
	return errors.Join(clearErr, c.persist())
}
func (c *Client) remember(op string, raw []byte) {
	c.replacedKey = ""
	c.offlineTicket = ""
	c.offlineUntil = time.Time{}
	c.state.Refused = false
	c.state.Proof = &evidence{op, append(json.RawMessage(nil), raw...)}
	c.state.ObservedAt = c.clock().Unix()
	var env envelope
	if json.Unmarshal(raw, &env) == nil {
		c.state.ObservedAt = max64(c.state.ObservedAt, env.TS)
		var data struct {
			Ticket string `json:"ticket"`
		}
		if json.Unmarshal(env.Data, &data) == nil {
			if g, e := wire.DecodeTicket(data.Ticket, c.PublicKey); e == nil {
				c.onlineTicket = data.Ticket
				c.onlineUntil = g.IssuedAt.Add(time.Duration(g.NextCheckIn) * time.Second)
			}
		}
	}
}
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func (c *Client) invalidate() error {
	c.payloadReady = false
	c.clearPayloadKeys()
	c.offlineTicket = ""
	c.offlineUntil = time.Time{}
	c.onlineUntil = time.Time{}
	c.state.Refused = true
	c.state.Proof = nil
	c.state.ObservedAt = max64(c.state.ObservedAt, c.clock().Unix())
	if e := c.persist(); e != nil {
		return errors.Join(e, c.removeCache())
	}
	return nil
}

func validToken(value string) bool {
	if len(value) != 47 || !strings.HasPrefix(value, "act_") {
		return false
	}
	_, e := decodeURL(value[4:])
	return e == nil
}
func validateKey(key string) error {
	const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	p := strings.Split(key, "-")
	if len(p) != 5 || len(p[0]) < 1 || len(p[0]) > 16 {
		return failure(InvalidLicenseKey, "授权码格式无效", nil)
	}
	for i, v := range p {
		if i > 0 && len(v) != 5 {
			return failure(InvalidLicenseKey, "授权码分组长度无效", nil)
		}
		for _, r := range v {
			if !strings.ContainsRune(alphabet, r) {
				return failure(InvalidLicenseKey, "授权码字符无效", nil)
			}
		}
	}
	data := p[1] + p[2] + p[3] + p[4][:4]
	check := len(p[0]) % 32
	for _, r := range p[0] + data {
		check = (check*17 + strings.IndexRune(alphabet, r)) % 32
	}
	if p[4][4] != alphabet[check] {
		return failure(InvalidLicenseKey, "授权码校验位无效", nil)
	}
	return nil
}
func validateOptions(o requestOptions) error {
	for _, item := range []struct {
		v string
		n int
	}{{o.Version, 128}, {o.Hostname, 128}, {o.OS, 64}} {
		if !cleanText(item.v, item.n) {
			return failure(InvalidRequest, "激活选项长度或字符无效", nil)
		}
	}
	return nil
}
func cleanText(value string, max int) bool {
	if len(value) > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ParsePublicKey accepts the Base64 raw key returned by Auth Go or PKIX PEM.
// Keys still need to be distributed through a separately trusted channel.
func ParsePublicKey(value string) (ed25519.PublicKey, error) { return parsePublicKey(value) }
