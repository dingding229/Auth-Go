package sharing

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strconv"
	"time"
)

func rowJSON(v any) (string, error) { b, e := json.Marshal(v); return string(b), e }

type View struct {
	Available     bool       `json:"available"`
	Reason        string     `json:"reason,omitempty"`
	Countries     []Country  `json:"countries"`
	ASNs          []ASN      `json:"asns"`
	InstanceCount int64      `json:"instance_count"`
	Flagged       bool       `json:"flagged"`
	Ignored       bool       `json:"ignored"`
	FlaggedAt     *time.Time `json:"flagged_at"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	IgnoredUntil  *time.Time `json:"ignored_until"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

func (s *Service) Get(ctx context.Context, id uint64) (View, error) {
	out := View{Available: s.Available(), Countries: []Country{}, ASNs: []ASN{}}
	var l model.License
	if e := s.db.WithContext(ctx).Select("id").First(&l, id).Error; e != nil {
		if errors.Is(e, gorm.ErrRecordNotFound) {
			return out, apperror.NotFound()
		}
		return out, e
	}
	var row Summary
	e := s.db.WithContext(ctx).First(&row, "license_id=?", id).Error
	if e != nil && !errors.Is(e, gorm.ErrRecordNotFound) {
		return out, e
	}
	if e == nil {
		out.Countries = row.Countries
		out.ASNs = row.ASNs
		out.InstanceCount = row.InstanceCount
		out.FlaggedAt = row.FlaggedAt
		out.LastSeenAt = row.LastSeenAt
		out.IgnoredUntil = row.IgnoredUntil
		out.UpdatedAt = &row.UpdatedAt
	}
	now := s.now().UTC()
	out.Ignored = out.IgnoredUntil != nil && now.Before(*out.IgnoredUntil)
	out.Flagged = out.Available && out.FlaggedAt != nil && !out.Ignored && (out.IgnoredUntil == nil || !row.UpdatedAt.Before(*out.IgnoredUntil))
	if !out.Available {
		out.Reason = "需要先在系统设置启用 IP 库"
	}
	return out, nil
}
func (s *Service) Ignore(ctx context.Context, id uint64) (View, error) {
	if !s.Available() {
		return View{}, apperror.New(409, "SHARING_UNAVAILABLE", "需要先在系统设置启用 IP 库")
	}
	until := s.now().UTC().Add(30 * 24 * time.Hour)
	result := s.db.WithContext(ctx).Model(&Summary{}).Where("license_id=? AND flagged_at IS NOT NULL", id).UpdateColumn("ignored_until", until)
	if result.Error != nil {
		return View{}, result.Error
	}
	if result.RowsAffected == 0 {
		if _, e := s.Get(ctx, id); e != nil {
			return View{}, e
		}
		return View{}, apperror.New(409, "SHARING_NOT_FLAGGED", "当前没有需要忽略的共享提示")
	}
	return s.Get(ctx, id)
}
func (s *Service) Register(r *gin.Engine, identity *auth.Service) {
	root := r.Group("/api/v1/admin/licenses", middleware.Authenticate(identity))
	readID := func(c *gin.Context) (uint64, bool) {
		id, e := strconv.ParseUint(c.Param("id"), 10, 64)
		if e != nil || id == 0 {
			response.Fail(c, apperror.Invalid("授权编号无效"))
			return 0, false
		}
		return id, true
	}
	root.GET("/:id/sharing", func(c *gin.Context) {
		id, ok := readID(c)
		if !ok {
			return
		}
		v, e := s.Get(c.Request.Context(), id)
		if e != nil {
			response.Fail(c, e)
			return
		}
		response.Success(c, v)
	})
	root.POST("/:id/sharing/ignore", middleware.Action("license.sharing.ignore", "license"), func(c *gin.Context) {
		id, ok := readID(c)
		if !ok {
			return
		}
		v, e := s.Ignore(c.Request.Context(), id)
		if e != nil {
			response.Fail(c, e)
			return
		}
		response.Success(c, v)
	})
}
