package sdk

import (
	"authgo/sdk/wire"
	"context"
	"crypto/rand"
	"encoding/json"
)

// guardCheck is intentionally private: low-level Check never requests a trial.
func (c *Client) guardCheck(ctx context.Context, key string) (*Result, error) {
	if key != "" {
		return c.Check(ctx, key)
	}
	c.mu.Lock()
	if e := c.online(""); e != nil {
		c.mu.Unlock()
		return nil, e
	}
	if e := c.restore(); e != nil {
		c.mu.Unlock()
		return nil, e
	}
	key = c.state.TrialKey
	if key == "" {
		challenge := make([]byte, 32)
		if _, e := rand.Read(challenge); e != nil {
			c.mu.Unlock()
			return nil, e
		}
		body, _ := json.Marshal(map[string]string{"device_fingerprint": c.fingerprint, "challenge": wire.B64.EncodeToString(challenge)})
		raw, nonce, _, e := c.exchangeRaw(ctx, "trial", body)
		var data map[string]json.RawMessage
		if e == nil {
			_, data, e = c.authenticateEnvelope(raw, nonce, "trial", true, 200)
		}
		var echoed string
		if e == nil {
			e = json.Unmarshal(data["challenge"], &echoed)
			if e == nil && echoed != wire.B64.EncodeToString(challenge) {
				e = failure(ResponseNonceInvalid, "试用响应挑战不匹配", nil)
			}
		}
		if e == nil {
			e = json.Unmarshal(data["license_key"], &key)
		}
		if e == nil {
			e = validateKey(key)
		}
		if e != nil {
			if explicitRefusal(e) && c.protectedEvidence() {
				c.clearPayloadKeys()
			}
			c.mu.Unlock()
			return nil, e
		}
		c.state.TrialKey = key
		c.state.Version = 1
		c.state.ObservedAt = max64(c.state.ObservedAt, c.clock().Unix())
		c.cacheWarning = c.persist()
	}
	c.mu.Unlock()
	r, e := c.Check(ctx, key)
	return r, e
}
