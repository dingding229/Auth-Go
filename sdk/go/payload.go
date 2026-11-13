package sdk

import (
	"authgo/sdk/wire"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// UnlockPayload requires a successful Check/Activate/Verify on this Client.
// It never activates implicitly. The returned 32-byte content key belongs to
// the caller, which must clear it after use. No plaintext content key is persisted.
func (c *Client) UnlockPayload(ctx context.Context, p Payload) ([]byte, error) {
	material, err := c.unlockPayloadMaterial(ctx, p)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	key := make([]byte, 32)
	copy(key, material[:32])
	return key, nil
}

// The protected loader alone receives K||WM for v2. The watermark is scoped to
// this response's signed license/challenge, never stored in an unbound map.
func (c *Client) unlockPayloadMaterial(ctx context.Context, p Payload) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.payloadReady || c.state.Refused || c.state.Proof == nil || c.processReplaced(c.state.Key) {
		return nil, failure(NotActivated, "请先完成授权校验", nil)
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > 65536 {
		return nil, payloadInvalid
	}
	if _, e = ParsePayload(raw); e != nil || p.AppKey != c.AppKey {
		return nil, payloadInvalid
	}
	result, e := c.cachedResult()
	if e != nil {
		return nil, e
	}
	if e = result.validPeriodAt(c.clock()); e != nil {
		return nil, e
	}
	if c.clock().Unix()+300 < c.state.ObservedAt {
		return nil, failure(ClockRollback, "检测到本地时钟回退", nil)
	}
	// A successful offline Check already attempted the primary. Do not repeat
	// that network timeout before using the same authenticated grace cache.
	if c.offlineTicket == result.ticket && c.onlineUntil.IsZero() {
		return c.loadPayloadKey(p, result)
	}
	instance, e := c.instance()
	if e != nil {
		return nil, e
	}
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, failure(InternalError, "无法生成临时密钥", nil)
	}
	challenge := make([]byte, 32)
	if _, e = rand.Read(challenge); e != nil {
		return nil, failure(InternalError, "无法生成挑战", nil)
	}
	body, e := json.Marshal(map[string]any{"license_key": c.state.Key, "activation_token": c.state.Token, "device_fingerprint": c.fingerprint, "instance_session": instance, "payload": p, "ephemeral_public_key": wire.B64.EncodeToString(private.PublicKey().Bytes()), "challenge": wire.B64.EncodeToString(challenge)})
	if e != nil {
		return nil, payloadInvalid
	}
	reply, nonce, recoverable, e := c.exchangeRaw(ctx, "payload.unlock", body)
	if e == nil {
		var data map[string]json.RawMessage
		_, data, e = c.authenticateEnvelope(reply, nonce, "payload.unlock", true, 200)
		if e == nil {
			fresh, err := c.authenticate(reply, nonce, "payload.unlock", true, 200)
			if err != nil {
				return nil, err
			}
			grant, err := c.validateTicket(fresh.ticket, false)
			if err != nil || grant.Challenge != wire.B64.EncodeToString(challenge) || fresh.LicenseID != result.LicenseID {
				return nil, failure(ResponseInvalid, "解锁票据上下文不符", nil)
			}
			if grant.IsTrial || !grant.GraceUntil.After(grant.IssuedAt) {
				c.payloadNoCache = true
				c.clearPayloadKeys()
			}
			var watermark []byte
			if p.V == 2 {
				watermark, err = payloadResponseWatermark(data["watermark"])
				if err != nil {
					return nil, err // terminal: do not fall back to cached material
				}
				defer clear(watermark)
			}
			var wrapped PayloadEnvelope
			for name, target := range map[string]*string{"e": &wrapped.E, "n": &wrapped.N, "c": &wrapped.C} {
				if json.Unmarshal(data[name], target) != nil {
					e = failure(ResponseInvalid, "内容密钥响应无效", nil)
					break
				}
			}
			if e == nil {
				key, err := unwrapPayload(p, wrapped, private, challenge)
				if err != nil {
					return nil, err
				}
				if p.V == 2 {
					material := make([]byte, 64)
					copy(material, key)
					copy(material[32:], watermark)
					clear(key)
					key = material
				}
				// Only this freshly authenticated signed grant can update the
				// launcher evidence; network failures never extend its grace.
				c.savePayloadKey(p, fresh, key)
				c.savePayloadProof(fresh)
				return key, nil
			}
		}
		recoverable = !explicitRefusal(e)
	}
	if explicitRefusal(e) {
		c.payloadReady = false
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
		if key, err := c.loadPayloadKey(p, result); err == nil {
			return key, nil
		}
	}
	return nil, e
}
func payloadRewrapAAD(p Payload, ephemeral, challenge []byte) ([]byte, error) {
	if len(ephemeral) != 32 || len(challenge) != 32 {
		return nil, payloadInvalid
	}
	manifest, e := payloadB64.DecodeString(p.Manifest)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(manifest)
	if p.V != 2 {
		return nil, payloadInvalid
	}
	a := []byte("authgo-payload-rewrap-v2\x00")
	for _, s := range []string{p.AppKey, p.Version, p.BuiltAt, p.KeyID} {
		a = payloadLP(a, s)
	}
	a = append(a, h[:]...)
	a = append(a, ephemeral...)
	return append(a, challenge...), nil
}
func unwrapPayload(p Payload, r PayloadEnvelope, private *ecdh.PrivateKey, challenge []byte) ([]byte, error) {
	invalid := func() ([]byte, error) { return nil, failure(ResponseInvalid, "内容密钥响应认证失败", nil) }
	ep, e := payloadB64.DecodeString(r.E)
	if e != nil || len(ep) != 32 {
		return invalid()
	}
	pub, e := ecdh.X25519().NewPublicKey(ep)
	if e != nil {
		return invalid()
	}
	shared, e := private.ECDH(pub)
	if e != nil {
		return invalid()
	}
	defer clear(shared)
	aad, e := payloadRewrapAAD(p, private.PublicKey().Bytes(), challenge)
	if e != nil {
		return invalid()
	}
	salt := sha256.Sum256(aad)
	key := wire.HKDF(shared, salt[:], []byte("authgo/payload/v1/rewrap"), 32)
	defer clear(key)
	n, e := payloadB64.DecodeString(r.N)
	if e != nil || len(n) != 12 {
		return invalid()
	}
	ct, e := payloadB64.DecodeString(r.C)
	if e != nil || len(ct) != 48 {
		return invalid()
	}
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	out, e := g.Open(nil, n, ct, aad)
	if e != nil || len(out) != 32 {
		return invalid()
	}
	return out, nil
}
