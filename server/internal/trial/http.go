package trial

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/maintenance"
	"authgo/internal/middleware"
	"authgo/internal/model"
	"authgo/internal/response"
	featuretemplate "authgo/internal/template"
	"context"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strconv"
	"time"
)

type Settings struct {
	TemplateID *uint64 `json:"trial_template_id"`
	Enabled    bool    `json:"trial_enabled"`
	Days       int     `json:"trial_days"`
}
type ConvertInput struct {
	maintenance.Input
	UserID         uint64     `json:"user_id"`
	Type           string     `json:"type"`
	Days           *int       `json:"days"`
	ExpiresAt      *time.Time `json:"expires_at"`
	MaxActivations *int       `json:"max_activations"`
}

func (s *Service) Convert(ctx context.Context, id uint64, in ConvertInput) (model.License, error) {
	var out model.License
	now := s.now().UTC()
	kind := in.Type
	if kind == "" {
		kind = "standard"
	}
	if kind != "standard" && kind != "subscription" && kind != "perpetual" && kind != "floating" {
		return out, apperror.Invalid("请选择正式授权类型")
	}
	if in.UserID == 0 {
		return out, apperror.Invalid("请选择用户")
	}
	if in.MaxActivations != nil && (*in.MaxActivations < 1 || *in.MaxActivations > 1000000) {
		return out, apperror.Invalid("实例数必须为1至1000000")
	}
	at, set, err := in.Input.Resolve(now)
	if err != nil {
		return out, err
	}
	var expires *time.Time
	if kind != "perpetual" {
		if (in.Days == nil) == (in.ExpiresAt == nil) {
			return out, apperror.Invalid("有效天数和到期时间必须填写且只能填写一个")
		}
		if in.Days != nil {
			if *in.Days < 1 || *in.Days > 36500 {
				return out, apperror.Invalid("有效天数必须为1至36500")
			}
			v := now.AddDate(0, 0, *in.Days)
			expires = &v
		} else {
			v := in.ExpiresAt.UTC()
			expires = &v
		}
		if !expires.After(now) || expires.Year() > 9999 {
			return out, apperror.Invalid("请选择未来的授权到期时间")
		}
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&out, id).Error; err != nil {
			return err
		}
		if out.Type != "trial" || out.Status == "revoked" {
			return apperror.New(409, "INVALID_TRANSITION", "此授权不能转正")
		}
		var user model.EndUser
		if err := tx.First(&user, in.UserID).Error; err != nil || user.Status != "active" {
			return apperror.Invalid("请选择正常用户")
		}
		values := map[string]any{"user_id": in.UserID, "type": kind, "converted_at": now, "expires_at": expires, "duration_days": 0, "validity_rule": "fixed_expiry"}
		if kind == "perpetual" {
			values["validity_rule"] = "perpetual"
		}
		if out.Status == "expired" {
			values["status"] = "active"
		}
		if in.MaxActivations != nil {
			values["max_activations"] = *in.MaxActivations
		}
		if set {
			values["maintenance_until"] = at
		}
		if err := tx.Model(&out).Updates(values).Error; err != nil {
			return err
		}
		return tx.First(&out, id).Error
	})
	return out, err
}
func (s *Service) Register(r *gin.Engine, identity *auth.Service) {
	root := r.Group("/api/v1/admin", middleware.Authenticate(identity))
	wrap := func(fn func(*gin.Context, uint64) (any, error)) gin.HandlerFunc {
		return func(c *gin.Context) {
			id, e := strconv.ParseUint(c.Param("id"), 10, 64)
			if e != nil || id == 0 {
				response.Fail(c, apperror.Invalid("编号无效"))
				return
			}
			v, e := fn(c, id)
			if e != nil {
				if errors.Is(e, gorm.ErrRecordNotFound) {
					e = apperror.NotFound()
				}
				response.Fail(c, e)
				return
			}
			response.Success(c, v)
		}
	}
	root.GET("/applications/:id/trial", wrap(func(c *gin.Context, id uint64) (any, error) {
		var a model.Application
		e := s.db.WithContext(c.Request.Context()).First(&a, id).Error
		return Settings{TemplateID: a.TrialTemplateID, Enabled: a.TrialEnabled, Days: a.TrialDays}, e
	}))
	root.PATCH("/applications/:id/trial", middleware.Action("trial.settings", "application"), wrap(func(c *gin.Context, id uint64) (any, error) {
		var in struct {
			Enabled    *bool           `json:"trial_enabled"`
			Days       *int            `json:"trial_days"`
			TemplateID json.RawMessage `json:"trial_template_id"`
		}
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		var result Settings
		e := s.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
			var a model.Application
			if e := tx.First(&a, id).Error; e != nil {
				if errors.Is(e, gorm.ErrRecordNotFound) {
					return apperror.NotFound()
				}
				return e
			}
			if in.Enabled != nil {
				a.TrialEnabled = *in.Enabled
			}
			if in.Days != nil {
				a.TrialDays = *in.Days
			}
			if a.TrialDays < 1 || a.TrialDays > 365 {
				return apperror.Invalid("试用天数必须为1至365")
			}
			if len(in.TemplateID) > 0 {
				var selected *uint64
				if json.Unmarshal(in.TemplateID, &selected) != nil {
					return apperror.Invalid("试用功能模板无效")
				}
				if selected != nil {
					if _, e := featuretemplate.Find(tx, id, *selected); e != nil {
						return e
					}
				}
				a.TrialTemplateID = selected
			}
			if e := tx.Model(&a).Updates(map[string]any{"trial_enabled": a.TrialEnabled, "trial_days": a.TrialDays, "trial_template_id": a.TrialTemplateID}).Error; e != nil {
				return e
			}
			result = Settings{TemplateID: a.TrialTemplateID, Enabled: a.TrialEnabled, Days: a.TrialDays}
			return nil
		})
		return result, e
	}))
	root.GET("/licenses/:id/trial", wrap(func(c *gin.Context, id uint64) (any, error) {
		var rows []Claim
		e := s.db.WithContext(c.Request.Context()).Where("license_id=?", id).Order("id").Find(&rows).Error
		out := make([]gin.H, 0, len(rows))
		for _, row := range rows {
			out = append(out, gin.H{"ip": row.IPKey, "instance_id": row.InstanceID, "created_at": row.CreatedAt})
		}
		return gin.H{"items": out}, e
	}))
	root.POST("/licenses/:id/convert", middleware.Action("trial.convert", "license"), wrap(func(c *gin.Context, id uint64) (any, error) {
		var in ConvertInput
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		l, e := s.Convert(c.Request.Context(), id, in)
		return gin.H{"id": l.ID, "type": l.Type, "converted_at": l.ConvertedAt}, e
	}))
	root.GET("/trials/stats", func(c *gin.Context) {
		var total, converted int64
		q := s.db.WithContext(c.Request.Context()).Model(&model.License{}).Where("source='self_trial'")
		if e := q.Count(&total).Error; e != nil {
			response.Fail(c, e)
			return
		}
		if e := q.Where("converted_at IS NOT NULL").Count(&converted).Error; e != nil {
			response.Fail(c, e)
			return
		}
		response.Success(c, gin.H{"trial_count": total, "converted_count": converted})
	})
}
