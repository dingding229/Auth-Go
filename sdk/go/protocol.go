package sdk

import (
	"authgo/sdk/wire"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResponse = 1024 * 1024

type envelope struct {
	Code      string          `json:"code"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data"`
	Signature *string         `json:"signature"`
	TS        int64           `json:"ts"`
	Nonce     string          `json:"nonce"`
}

// The fixed empty domain component preserves the signed nonce context of old
// KEY/FLOATING caches; no public binding option or domain request is consumed.
func (c *Client) contextHash(op string) string {
	tokenHash := ""
	if op != "activate" {
		tokenHash = sha([]byte(c.state.Token))
	}
	raw, _ := canonicalJSON(map[string]any{"endpoint": c.endpoint, "app_key": c.AppKey, "license_key": c.state.Key, "fingerprint": c.fingerprint, "domain": "", "client_version": c.state.Options.Version, "operation": op, "token_hash": tokenHash})
	return sha(raw)
}
func (c *Client) exchange(ctx context.Context, op string) (*Result, []byte, bool, error) {
	var instance string
	if op != "deactivate" {
		var e error
		instance, e = c.instance()
		if e != nil {
			return nil, nil, false, e
		}
	}
	challenge := make([]byte, 32)
	if _, e := rand.Read(challenge); e != nil {
		return nil, nil, false, e
	}
	challengeText := base64.RawURLEncoding.EncodeToString(challenge)
	bodyFields := map[string]any{"license_key": c.state.Key, "activation_token": c.state.Token, "device_fingerprint": c.fingerprint, "client_version": c.state.Options.Version, "hostname": c.state.Options.Hostname, "os": c.state.Options.OS, "challenge": challengeText}
	if op != "deactivate" {
		bodyFields["instance_session"] = instance
	}
	body, e := json.Marshal(bodyFields)
	if e != nil {
		return nil, nil, false, e
	}
	raw, nonce, recoverable, e := c.exchangeRaw(ctx, op, body)
	if e != nil {
		return nil, nil, recoverable, e
	}
	result, e := c.authenticate(raw, nonce, op, true, 200)
	if e == nil && op != "deactivate" && op != "release-seat" {
		var grant wire.Grant
		grant, e = c.validateTicket(result.ticket, false)
		if e == nil && grant.Challenge != challengeText {
			e = failure(ResponseNonceInvalid, "票据挑战不匹配", nil)
		}
	}
	if e != nil {
		return nil, raw, !explicitRefusal(e), e
	}
	return result, raw, false, nil
}

// exchangeRaw authenticates the encrypted channel framing; callers must still
// verify the signed inner envelope before treating any server code as trusted.
func (c *Client) exchangeRaw(ctx context.Context, op string, body []byte) ([]byte, string, bool, error) {
	random := make([]byte, 32)
	if _, e := rand.Read(random); e != nil {
		return nil, "", false, failure(InternalError, "无法生成随机 nonce", e)
	}
	nonce := c.contextHash(op) + "_" + base64.RawURLEncoding.EncodeToString(random)
	ts := strconv.FormatInt(c.clock().Unix(), 10)
	inner := wire.Inner{AppKey: c.AppKey, Op: op, Timestamp: ts, Nonce: nonce, Body: body, Signature: wire.MAC([]byte(c.AppSecret), op, ts, nonce, body)}
	plain, e := json.Marshal(inner)
	if e != nil {
		return nil, "", false, e
	}
	encrypted, session, e := wire.Encrypt(c.GatewayKey, plain)
	if e != nil {
		return nil, "", false, failure(InvalidConfig, "接入配置无效", nil)
	}
	transportBody, e := json.Marshal(encrypted)
	if e != nil {
		return nil, "", false, e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/gateway", bytes.NewReader(transportBody))
	if e != nil {
		return nil, "", false, failure(InvalidConfig, "服务地址无效", nil)
	}
	req.Header.Set("Content-Type", "application/json")
	var httpClient http.Client
	if c.HTTPClient != nil {
		httpClient = *c.HTTPClient
	}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = 10 * time.Second
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return failure(ResponseInvalid, "不允许重定向客户端请求", nil)
	}
	response, e := httpClient.Do(req)
	if e != nil {
		if response != nil {
			response.Body.Close()
		}
		if ctx.Err() != nil {
			return nil, "", false, ctx.Err()
		}
		if retryableNetwork(e) {
			return nil, "", true, failure(NetworkError, "连接授权服务失败", e)
		}
		return nil, "", true, failure(ResponseInvalid, "连接安全或请求策略校验失败", e)
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if e != nil || len(raw) > maxResponse {
		return nil, "", true, failure(ResponseInvalid, "授权响应不完整或过大", e)
	}
	if response.StatusCode != 200 {
		return nil, "", true, &Error{Code: ResponseInvalid, Message: "加密信道被拒绝", HTTPStatus: response.StatusCode}
	}
	var outer wire.Response
	if e = strictJSON(raw, &outer, "n", "c"); e != nil {
		return nil, "", true, failure(ResponseInvalid, "加密响应格式无效", nil)
	}
	raw, e = session.DecryptResponse(outer)
	if e != nil {
		return nil, "", true, failure(ResponseInvalid, "加密响应校验失败", nil)
	}
	return raw, nonce, false, nil
}
func retryableNetwork(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var sdkErr *Error
	if errors.As(err, &sdkErr) {
		return false
	}
	var cert *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &cert) || errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return false
	}
	var record tls.RecordHeaderError
	var alert tls.AlertError
	if errors.As(err, &record) || errors.As(err, &alert) {
		return false
	}
	var operation *net.OpError
	if errors.As(err, &operation) && (operation.Op == "local error" || operation.Op == "remote error") {
		return false
	}
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
func strictJSON(raw []byte, dst any, fields ...string) error {
	canonical, e := canonicalizeJSON(raw)
	if e != nil {
		return e
	}
	if len(fields) > 0 {
		var m map[string]json.RawMessage
		if e := json.Unmarshal(canonical, &m); e != nil || len(m) != len(fields) {
			return errors.New("JSON 字段不完整")
		}
		for _, k := range fields {
			if _, ok := m[k]; !ok {
				return errors.New("JSON 缺少字段")
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}
func (c *Client) authenticateEnvelope(raw []byte, nonce, op string, fresh bool, httpStatus int) (envelope, map[string]json.RawMessage, error) {
	var wire envelope
	if e := strictJSON(raw, &wire, "code", "message", "data", "signature", "ts", "nonce"); e != nil || wire.Code == "" || len(wire.Code) > 128 {
		return envelope{}, nil, failure(ResponseInvalid, "授权响应格式无效", e)
	}
	if wire.Signature == nil {
		return envelope{}, nil, &Error{Code: ResponseSignatureInvalid, Message: "服务端响应没有可信签名", HTTPStatus: httpStatus}
	}
	signature, e := base64.StdEncoding.Strict().DecodeString(*wire.Signature)
	signed, e2 := canonicalJSON(map[string]any{"code": wire.Code, "data": wire.Data, "ts": wire.TS})
	if e != nil || e2 != nil || !ed25519.Verify(c.PublicKey, signed, signature) {
		return envelope{}, nil, &Error{Code: ResponseSignatureInvalid, Message: "授权响应验签失败", HTTPStatus: httpStatus}
	}
	var data map[string]json.RawMessage
	if e := json.Unmarshal(wire.Data, &data); e != nil {
		return envelope{}, nil, failure(ResponseInvalid, "授权 data 不是对象", e)
	}
	var echoed string
	if e := json.Unmarshal(data["request_nonce"], &echoed); e != nil || echoed != nonce || wire.Nonce != nonce {
		return envelope{}, nil, failure(ResponseNonceInvalid, "响应 nonce 与本次请求不符", e)
	}
	if !strings.HasPrefix(nonce, c.contextHash(op)+"_") {
		return envelope{}, nil, failure(ResponseNonceInvalid, "响应上下文与本机激活不符", nil)
	}
	now := c.clock().Unix()
	if wire.TS <= 0 || fresh && (wire.TS > now+300 || wire.TS < now-300) {
		return envelope{}, nil, failure(ResponseTimestampInvalid, "响应时间戳不在可信窗口内", nil)
	}
	if wire.Code != OK {
		original := &Error{Code: wire.Code, Message: wire.Message, HTTPStatus: httpStatus}
		_ = json.Unmarshal(data["latest_entitled_version"], &original.LatestEntitledVersion)
		if wire.Code == VersionDisabled {
			_ = json.Unmarshal(data["latest_version"], &original.LatestVersion)
		}
		return envelope{}, nil, &authenticatedServerError{original: original}
	}
	if fresh && httpStatus != 200 {
		return envelope{}, nil, failure(ResponseInvalid, "成功响应 HTTP 状态不符", nil)
	}
	return wire, data, nil
}
func (c *Client) authenticate(raw []byte, nonce, op string, fresh bool, httpStatus int) (*Result, error) {
	wire, data, e := c.authenticateEnvelope(raw, nonce, op, fresh, httpStatus)
	if e != nil {
		return nil, e
	}
	if op == "release-seat" {
		var yes bool
		if e := json.Unmarshal(data["released"], &yes); e != nil {
			return nil, failure(ResponseInvalid, "释放响应无效", e)
		}
		return &Result{Status: "released", Source: "online"}, nil
	}
	if op == "deactivate" {
		var yes bool
		if e := json.Unmarshal(data["deactivated"], &yes); e != nil || !yes {
			return nil, failure(ResponseInvalid, "解绑响应无效", e)
		}
		return &Result{Status: "deactivated", Source: "online"}, nil
	}
	for _, k := range []string{"license_id", "status", "expires_at", "features", "next_check_in", "grace_until", "heartbeat_interval", "satisfied_methods"} {
		if _, ok := data[k]; !ok {
			return nil, failure(ResponseInvalid, "授权结果缺少必需字段", nil)
		}
	}
	var result Result
	// Result omits request_nonce/activation_token from its public JSON encoding;
	// decode known grant fields without accepting them as proof of identity.
	decoder := json.NewDecoder(bytes.NewReader(wire.Data))
	decoder.UseNumber()
	if e := decoder.Decode(&result); e != nil {
		return nil, failure(ResponseInvalid, "授权数据类型无效", e)
	}
	if value, ok := data["activation_token"]; ok {
		if e := json.Unmarshal(value, &result.ActivationToken); e != nil {
			return nil, failure(ResponseInvalid, "激活凭据类型无效", e)
		}
	}
	if result.LicenseID == 0 || result.LicenseID > 1<<63-1 || result.Status != "active" || result.Features == nil || result.NextCheckIn < 1 || result.NextCheckIn > 86400 || result.HeartbeatInterval < 1 || result.HeartbeatInterval > 3600 || result.GraceUntil.IsZero() {
		return nil, failure(ResponseInvalid, "授权结果字段无效", nil)
	}

	methods := map[string]bool{}
	for _, m := range result.SatisfiedMethods {
		switch m {
		case "KEY", "FLOATING":
		default:
			return nil, failure(ResponseInvalid, "未知验证方式", nil)
		}
		if methods[m] {
			return nil, failure(ResponseInvalid, "验证方式重复", nil)
		}
		methods[m] = true
	}
	if !methods["KEY"] || methods["FLOATING"] && result.LeaseExpiresAt == nil {
		return nil, failure(ResponseInvalid, "授权验证方式或租约无效", nil)
	}
	if fresh {
		if e := result.validAt(c.clock()); e != nil {
			return nil, e
		}
	}
	if e := json.Unmarshal(data["ticket"], &result.ticket); e != nil {
		return nil, failure(ResponseInvalid, "缺少验证票据", nil)
	}
	var seedText string
	if e := json.Unmarshal(data["unlock_seed"], &seedText); e != nil {
		return nil, failure(ResponseInvalid, "缺少授权数据", nil)
	}
	seed, e := decodeURL(seedText)
	if e != nil || len(seed) != 32 {
		return nil, failure(ResponseInvalid, "授权数据无效", nil)
	}
	result.unlockSeed = seed
	grant, e := c.validateTicket(result.ticket, !fresh)
	if e != nil {
		return nil, e
	}
	result.IsTrial = grant.IsTrial
	if grant.LicenseID != result.LicenseID || grant.UnlockHash != sha(seed) || grant.NextCheckIn != result.NextCheckIn {
		return nil, failure(ResponseInvalid, "票据与授权响应不符", nil)
	}
	result.guard = func() error { return c.Validate(result.Ticket()) }
	result.Availability = "online"
	result.Status = "online"
	result.usableUntil = grant.GraceUntil
	if fresh {
		onlineEnd := grant.IssuedAt.Add(time.Duration(grant.NextCheckIn) * time.Second)
		if onlineEnd.After(result.usableUntil) {
			result.usableUntil = onlineEnd
		}
		for _, end := range []*time.Time{grant.ExpiresAt, grant.LeaseExpiresAt} {
			if end != nil && result.usableUntil.After(*end) {
				result.usableUntil = *end
			}
		}
	}
	result.clock = c.clock
	result.Offline = false
	result.Source = "online"
	return &result, nil
}
func (r *Result) floating() bool {
	for _, m := range r.SatisfiedMethods {
		if m == "FLOATING" {
			return true
		}
	}
	return false
}
func (r *Result) validPeriodAt(now time.Time) error {
	if r.StartsAt != nil && now.Before(*r.StartsAt) {
		return failure(LicenseNotStarted, "授权尚未开始", nil)
	}
	if r.ExpiresAt != nil && !now.Before(*r.ExpiresAt) {
		return failure(LicenseExpired, "授权已到期", nil)
	}
	return nil
}
func (r *Result) validAt(now time.Time) error {
	if e := r.validPeriodAt(now); e != nil {
		return e
	}
	if r.floating() && (r.LeaseExpiresAt == nil || !now.Before(*r.LeaseExpiresAt)) {
		return failure(LeaseExpired, "浮动席位租约已到期", nil)
	}
	return nil
}
func sha(raw []byte) string { value := sha256.Sum256(raw); return hex.EncodeToString(value[:]) }
func decodeURL(value string) ([]byte, error) {
	raw, e := base64.RawURLEncoding.Strict().DecodeString(value)
	if e != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, errors.New("Base64URL 无效")
	}
	return raw, nil
}
func parsePublicKey(value string) (ed25519.PublicKey, error) {
	if strings.HasPrefix(strings.TrimSpace(value), "-----BEGIN") {
		block, rest := pem.Decode([]byte(value))
		if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, failure(InvalidConfig, "公钥 PEM 无效", nil)
		}
		parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
		if e != nil {
			return nil, failure(InvalidConfig, "公钥无效", e)
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, failure(InvalidConfig, "公钥不是 Ed25519", nil)
		}
		return append(ed25519.PublicKey(nil), key...), nil
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(value)
	if e != nil || len(raw) != 32 {
		return nil, failure(InvalidConfig, "公钥必须为标准 Base64 编码的32字节 Ed25519 公钥", e)
	}
	return ed25519.PublicKey(raw), nil
}
