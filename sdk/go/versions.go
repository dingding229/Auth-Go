package sdk

import (
	"context"
	"encoding/json"
	"time"
)

// VersionInfo is a published version, not an authorization ticket.
type VersionInfo struct {
	Version     string     `json:"version"`
	Changelog   string     `json:"changelog"`
	PublishedAt *time.Time `json:"published_at"`
	Mandatory   bool       `json:"mandatory"`
	Entitled    bool       `json:"entitled"`
}

// VersionsOptions requests at most Limit results (0 uses the server default).
// Before is the opaque next cursor returned by a previous call.
type VersionsOptions struct {
	Limit  int
	Before string
}

// Versions fetches authenticated, published release history without changing the
// cached license proof. It requires an online, active license session.
func (c *Client) Versions(ctx context.Context, opts VersionsOptions) ([]VersionInfo, string, error) {
	if opts.Limit < 0 || opts.Limit > 200 || len(opts.Before) > 256 {
		return nil, "", failure(InvalidRequest, "版本历史分页参数无效", nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	extra := map[string]any{}
	if opts.Limit != 0 {
		extra["limit"] = opts.Limit
	}
	if opts.Before != "" {
		extra["before"] = opts.Before
	}
	data, err := c.updateRequest(ctx, "versions", extra)
	if err != nil {
		return nil, "", err
	}
	return decodeVersions(data, opts.Limit)
}

func decodeVersions(data map[string]json.RawMessage, limit int) ([]VersionInfo, string, error) {
	var items []struct {
		Version     *string    `json:"version"`
		Changelog   *string    `json:"changelog"`
		PublishedAt *time.Time `json:"published_at"`
		Mandatory   *bool      `json:"mandatory"`
		Entitled    *bool      `json:"entitled"`
	}
	var next *string
	if err := json.Unmarshal(data["items"], &items); err != nil || items == nil || len(items) > 200 || (limit != 0 && len(items) > limit) {
		return nil, "", failure(ResponseInvalid, "版本历史响应无效", err)
	}
	if err := json.Unmarshal(data["next_cursor"], &next); err != nil || next == nil || len(*next) > 256 || (len(items) == 0 && *next != "") {
		return nil, "", failure(ResponseInvalid, "版本历史游标无效", err)
	}
	out := make([]VersionInfo, 0, len(items))
	for _, item := range items {
		if item.Version == nil || *item.Version == "" || item.Changelog == nil || item.PublishedAt == nil || item.Mandatory == nil || item.Entitled == nil {
			return nil, "", failure(ResponseInvalid, "版本历史条目不完整", nil)
		}
		out = append(out, VersionInfo{Version: *item.Version, Changelog: *item.Changelog, PublishedAt: item.PublishedAt, Mandatory: *item.Mandatory, Entitled: *item.Entitled})
	}
	return out, *next, nil
}
