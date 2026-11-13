package client

import (
	"authgo/internal/code"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/sdk/wire"
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io"
)

// Gateway always limits IP before parsing/ECDH. No decryption oracle details.
func (s *Service) Gateway(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	bad := func() {
		s.recordVerifyLog(model.VerifyLog{CreatedAt: s.now().UTC(), IP: c.ClientIP(), Action: "gateway", Code: code.InvalidRequest, Reason: code.Describe(code.InvalidRequest).Message}, true)
		c.Data(400, "application/json", []byte(`{"error":"invalid request"}`))
	}
	now := s.now().UTC()
	if !s.ip.allow(ipLimitKey(c.ClientIP()), now) {
		s.recordVerifyLog(model.VerifyLog{CreatedAt: now, IP: c.ClientIP(), Action: "gateway", Code: code.RateLimited, Reason: code.Describe(code.RateLimited).Message}, true)
		c.Data(400, "application/json", []byte(`{"error":"invalid request"}`))
		return
	}
	raw, e := io.ReadAll(io.LimitReader(c.Request.Body, 65537))
	if e != nil || len(raw) > 65536 || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
		bad()
		return
	}
	var r wire.Request
	if _, e := cryptoutil.CanonicalizeJSON(raw); e != nil {
		bad()
		return
	}
	decoderOuter := json.NewDecoder(bytes.NewReader(raw))
	decoderOuter.DisallowUnknownFields()
	if decoderOuter.Decode(&r) != nil {
		bad()
		return
	}
	key, e := s.channel.Private(c.Request.Context(), r.K, now)
	if e != nil {
		bad()
		return
	}
	plain, session, e := wire.Decrypt(key, r)
	if e != nil {
		bad()
		return
	}
	c.Set("gateway_session", session)
	invalidInner := func() {
		s.recordVerifyLog(model.VerifyLog{CreatedAt: s.now().UTC(), IP: c.ClientIP(), Action: "gateway", Code: code.InvalidRequest, Reason: code.Describe(code.InvalidRequest).Message}, true)
		s.reply(c, denied(code.InvalidRequest), nil, now, "")
	}

	if _, e := cryptoutil.CanonicalizeJSON(plain); e != nil {
		invalidInner()
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(plain, &fields) != nil || len(fields) != 6 {
		invalidInner()
		return
	}
	var inner wire.Inner
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&inner); e != nil {
		invalidInner()
		return
	}
	switch inner.Op {
	case "activate", "verify", "heartbeat", "deactivate", "release-seat", "public-key", "announcement", "version", "update.check", "trial", "payload.unlock":
	default:
		invalidInner()
		return
	}
	if string(inner.Body) == "null" {
		inner.Body = nil
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(inner.Body))

	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("X-App-Key", inner.AppKey)
	c.Request.Header.Set("X-Timestamp", inner.Timestamp)
	c.Request.Header.Set("X-Nonce", inner.Nonce)
	c.Request.Header.Set("X-Signature", inner.Signature)
	s.handleAction(inner.Op)(c)
}
