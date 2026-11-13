package sdk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"runtime"
	"time"
)

type Update struct {
	DockerImage           string     `json:"docker_image"`
	DockerPull            string     `json:"docker_pull"`
	MaintenanceUntil      *time.Time `json:"maintenance_until,omitempty"`
	LatestEntitledVersion string     `json:"latest_entitled_version,omitempty"`
	RenewalRequired       bool       `json:"renewal_required,omitempty"`
	Available             bool       `json:"available"`
	Version               string     `json:"version"`
	Changelog             string     `json:"changelog"`
	Mandatory             bool       `json:"mandatory"`
	PublishedAt           *time.Time `json:"published_at"`
}

func (c *Client) updateRequest(ctx context.Context, op string, extra map[string]any) (map[string]json.RawMessage, error) {
	if e := c.online(""); e != nil {
		return nil, e
	}
	if e := c.restore(); e != nil {
		return nil, e
	}
	if c.state.Key == "" || !validToken(c.state.Token) {
		return nil, failure(NotActivated, "请先激活授权再检查更新", nil)
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	challenge := make([]byte, 32)
	if _, e := rand.Read(challenge); e != nil {
		return nil, e
	}
	body := map[string]any{"license_key": c.state.Key, "activation_token": c.state.Token, "device_fingerprint": c.fingerprint, "client_version": c.state.Options.Version, "hostname": c.state.Options.Hostname, "os": runtime.GOOS, "challenge": encodeURL(challenge)}
	for k, v := range extra {
		body[k] = v
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	encrypted, nonce, _, e := c.exchangeRaw(ctx, op, raw)
	if e != nil {
		return nil, e
	}
	_, data, e := c.authenticateEnvelope(encrypted, nonce, op, true, 200)
	if e != nil {
		return nil, e
	}
	return data, nil
}
func encodeURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// CheckUpdate requires a current online activation; it never reports cached news
// as a successful update check. No outcome (including an authenticated refusal)
// may mutate the licensing ticket, cache or Refused flag.
func (c *Client) CheckUpdate(ctx context.Context, currentVersion string) (*Update, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, e := c.updateRequest(ctx, "update.check", map[string]any{"current_version": currentVersion, "client_version": currentVersion})
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(data)
	if e != nil {
		return nil, e
	}
	var out Update
	if e = json.Unmarshal(raw, &out); e != nil {
		return nil, failure(ResponseInvalid, "更新响应无效", nil)
	}
	if out.Available {
		if out.Version == "" || out.PublishedAt == nil {
			return nil, failure(ResponseInvalid, "更新信息不完整", nil)
		}

	}
	return &out, nil
}
