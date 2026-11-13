package sdk

import (
	"context"
	"encoding/json"
	"time"
)

// Announcement is published software news, not a license grant.
type Announcement struct {
	ID          uint64     `json:"id"`
	AppID       uint64     `json:"app_id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Title       string     `json:"title"`
	Content     string     `json:"content"`
	PublishedAt *time.Time `json:"published_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// Announcements authenticates news over the gateway without activation, device
// collection, cache reads/writes, fallback, or changes to a license session.
func (c *Client) Announcements(ctx context.Context) ([]Announcement, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.validateEndpoint(); e != nil {
		return nil, e
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	raw, nonce, _, e := c.exchangeRaw(ctx, "announcement", nil)
	if e != nil {
		return nil, e
	}
	_, data, e := c.authenticateEnvelope(raw, nonce, "announcement", true, 200)
	if e != nil {
		return nil, e
	}
	var items []Announcement
	if e := json.Unmarshal(data["items"], &items); e != nil || items == nil {
		return nil, failure(ResponseInvalid, "公告响应格式无效", e)
	}
	return items, nil
}
