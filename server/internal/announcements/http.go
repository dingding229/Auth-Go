// Package announcements serves bounded, unsigned public software news.
package announcements

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"authgo/internal/netpolicy"
	"authgo/internal/ratelimit"
	"authgo/internal/response"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strconv"
	"time"
)

const MaxResponseBytes = 256 << 10
const MaxItems = 20

type Item struct {
	ID          uint64     `json:"id"`
	Title       string     `json:"title"`
	Content     string     `json:"content"`
	Level       string     `json:"level" enums:"info,warning,critical"`
	PublishedAt *time.Time `json:"published_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}
type Service struct {
	db      *gorm.DB
	now     func() time.Time
	limiter *ratelimit.Limiter
}

func New(db *gorm.DB) *Service {
	return &Service{db: db, now: time.Now, limiter: ratelimit.Window(30, 10000, time.Minute, ratelimit.EvictOldest)}
}
func envelope(items []Item) map[string]any {
	return map[string]any{"code": "OK", "message": "操作成功", "data": map[string]any{"items": items}, "signature": nil}
}
func (s *Service) Register(r *gin.Engine) { r.GET("/api/v1/public/announcements", s.list) }
func (s *Service) list(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	if !s.limiter.Allow(netpolicy.SourceKey(c.ClientIP()), s.now()) {
		c.Header("Cache-Control", "no-store")
		response.Fail(c, apperror.New(429, "RATE_LIMITED", "公告查询过于频繁，请稍后重试"))
		return
	}
	key := c.Query("app_key")
	rows := []model.Announcement{}
	if len(key) > 0 && len(key) <= 256 {
		now := s.now().UTC()
		if e := s.db.WithContext(c.Request.Context()).Table("announcements").Select("announcements.*").Joins("JOIN applications ON applications.id=announcements.app_id").Where("applications.app_key=? AND applications.status='active' AND announcements.published_at IS NOT NULL AND announcements.published_at<=? AND (announcements.expires_at IS NULL OR announcements.expires_at>?)", key, now, now).Order("announcements.published_at DESC, announcements.id DESC").Limit(MaxItems).Find(&rows).Error; e != nil {
			response.Fail(c, e)
			return
		}
	}
	items := []Item{}
	body, _ := json.Marshal(envelope(items))
	for _, v := range rows {
		next := append(items, Item{v.ID, v.Title, v.Content, v.Level, v.PublishedAt, v.ExpiresAt})
		encoded, e := json.Marshal(envelope(next))
		if e != nil {
			response.Fail(c, e)
			return
		}
		if len(encoded) > MaxResponseBytes {
			break
		}
		items = next
		body = encoded
	}
	maxAge := 60
	for _, item := range items {
		if item.ExpiresAt != nil {
			ttl := int(item.ExpiresAt.Sub(s.now()).Seconds())
			if ttl < maxAge {
				maxAge = ttl
			}
		}
	}
	if maxAge < 0 {
		maxAge = 0
	}
	c.Header("Cache-Control", "public, max-age="+strconv.Itoa(maxAge))
	c.Data(200, "application/json; charset=utf-8", body)
}
