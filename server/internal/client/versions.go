package client

import (
	"authgo/internal/apperror"
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/Masterminds/semver/v3"
)

// History pages are additionally bounded by encoded JSON size so the gateway's
// encrypted response fits the SDK's 1 MiB response limit, even with escaped text.
const historyPageBytes = 384 * 1024

type historyCursor struct {
	PublishedAt time.Time `json:"t"`
	ID          uint64    `json:"i"`
}

type historyItem struct {
	Version     string     `json:"version"`
	Changelog   string     `json:"changelog"`
	PublishedAt *time.Time `json:"published_at"`
	Mandatory   bool       `json:"mandatory"`
	Entitled    bool       `json:"entitled"`
}

func decodeHistoryCursor(value string) (historyCursor, error) {
	var c historyCursor
	if len(value) > 256 || value == "" {
		return c, errors.New("invalid cursor")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || json.Unmarshal(b, &c) != nil || c.ID == 0 || c.ID > math.MaxInt64 || c.PublishedAt.IsZero() {
		return historyCursor{}, errors.New("invalid cursor")
	}
	return c, nil
}
func validHistoryCursor(value string) bool {
	if value == "" {
		return true
	}
	_, err := decodeHistoryCursor(value)
	return err == nil
}
func encodeHistoryCursor(v model.AppVersion) string {
	b, _ := json.Marshal(historyCursor{PublishedAt: v.PublishedAt.UTC(), ID: v.ID})
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Service) versionHistory(ctx context.Context, licenseID uint64, limit *int, before string, now time.Time) (map[string]any, error) {
	license, app, err := s.updates.ValidateLicense(ctx, licenseID)
	if err != nil {
		return nil, err
	}
	n := 50
	if limit != nil {
		n = *limit
	}
	if n < 1 || n > 200 || !validHistoryCursor(before) {
		return nil, apperror.Invalid("版本历史分页参数无效")
	}
	q := s.db.WithContext(ctx).Where("app_id = ? AND disabled = ? AND withdrawn = ? AND published_at IS NOT NULL AND published_at <= ?", app.ID, false, false, now)
	if before != "" {
		cursor, err := decodeHistoryCursor(before)
		if err != nil {
			return nil, err
		}
		q = q.Where("(published_at < ? OR (published_at = ? AND id < ?))", cursor.PublishedAt, cursor.PublishedAt, cursor.ID)
	}
	var rows []model.AppVersion
	if err := q.Order("published_at DESC, id DESC").Limit(n + 1).Find(&rows).Error; err != nil {
		return nil, err
	}
	items := make([]historyItem, 0, n)
	used := 0
	for _, row := range rows {
		if len(items) == n {
			break
		}
		// LatestEntitledVersion ignores versions which are not strict SemVer.
		_, semverErr := semver.StrictNewVersion(row.Version)
		item := historyItem{Version: row.Version, Changelog: row.Changelog, PublishedAt: row.PublishedAt, Mandatory: row.Mandatory, Entitled: semverErr == nil && maintenance.Allows(license, row)}
		raw, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if used+len(raw)+1 > historyPageBytes {
			if len(items) == 0 {
				return nil, errors.New("version history item exceeds response limit")
			}
			break
		}
		used += len(raw) + 1
		items = append(items, item)
	}
	next := ""
	if len(items) < len(rows) {
		next = encodeHistoryCursor(rows[len(items)-1])
	}
	return map[string]any{"items": items, "next_cursor": next}, nil
}
