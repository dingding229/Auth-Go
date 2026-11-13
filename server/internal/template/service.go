// Package template manages independent, copy-on-issue feature templates.
package template

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"authgo/internal/response"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"strings"
	"time"
	"unicode/utf8"
)

type Template struct {
	model.Base
	AppID                  uint64
	Name                   string
	Features               model.JSONMap `gorm:"type:text"`
	DefaultMaxActivations  *int
	DefaultDays            *int
	DefaultMaintenanceDays *int
}

func (Template) TableName() string { return "feature_templates" }

type Info struct {
	ID                     uint64        `json:"id"`
	AppID                  uint64        `json:"app_id"`
	Name                   string        `json:"name"`
	Features               model.JSONMap `json:"features"`
	DefaultMaxActivations  *int          `json:"default_max_activations"`
	DefaultDays            *int          `json:"default_days"`
	DefaultMaintenanceDays *int          `json:"default_maintenance_days"`
	CreatedAt              time.Time     `json:"created_at"`
	UpdatedAt              time.Time     `json:"updated_at"`
}

func info(t Template) Info {
	return Info{t.ID, t.AppID, t.Name, t.Features, t.DefaultMaxActivations, t.DefaultDays, t.DefaultMaintenanceDays, t.CreatedAt, t.UpdatedAt}
}

type Input struct {
	Name                   *string         `json:"name"`
	Features               json.RawMessage `json:"features" swaggertype:"object"`
	DefaultMaxActivations  json.RawMessage `json:"default_max_activations" swaggertype:"integer"`
	DefaultDays            json.RawMessage `json:"default_days" swaggertype:"integer"`
	DefaultMaintenanceDays json.RawMessage `json:"default_maintenance_days" swaggertype:"integer"`
}
type Service struct{ db *gorm.DB }

func New(db *gorm.DB) *Service { return &Service{db} }
func application(tx *gorm.DB, appID uint64) error {
	var a model.Application
	e := tx.Select("id").First(&a, appID).Error
	if errors.Is(e, gorm.ErrRecordNotFound) {
		return apperror.NotFound()
	}
	return e
}
func Find(tx *gorm.DB, appID, id uint64) (Template, error) {
	var t Template
	e := tx.Where("app_id=? AND id=?", appID, id).First(&t).Error
	if errors.Is(e, gorm.ErrRecordNotFound) {
		return t, apperror.NotFound()
	}
	return t, e
}
func nullableInt(raw json.RawMessage, target **int, min, max int) error {
	if len(raw) == 0 {
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		*target = nil
		return nil
	}
	var n int
	if json.Unmarshal(raw, &n) != nil || n < min || n > max {
		return apperror.Invalid("模板默认值超出允许范围")
	}
	*target = &n
	return nil
}
func apply(t Template, in Input) (Template, error) {
	if in.Name != nil {
		t.Name = strings.TrimSpace(*in.Name)
	}
	if utf8.RuneCountInString(t.Name) < 1 || utf8.RuneCountInString(t.Name) > 64 {
		return t, apperror.Invalid("模板名称必须为1至64个字符")
	}
	if len(in.Features) > 0 {
		raw := bytes.TrimSpace(in.Features)
		if len(raw) == 0 || raw[0] != '{' || t.Features.Scan(raw) != nil || t.Features == nil {
			return t, apperror.Invalid("功能项必须是JSON对象")
		}
	}
	if t.Features == nil {
		return t, apperror.Invalid("请填写功能项JSON对象")
	}
	if e := nullableInt(in.DefaultMaxActivations, &t.DefaultMaxActivations, 1, 1000000); e != nil {
		return t, e
	}
	if e := nullableInt(in.DefaultDays, &t.DefaultDays, 1, 36500); e != nil {
		return t, e
	}
	if e := nullableInt(in.DefaultMaintenanceDays, &t.DefaultMaintenanceDays, 0, 36500); e != nil {
		return t, e
	}
	return t, nil
}
func (s *Service) List(ctx context.Context, appID uint64, p response.Page) ([]Info, int64, error) {
	tx := s.db.WithContext(ctx)
	if e := application(tx, appID); e != nil {
		return nil, 0, e
	}
	var total int64
	var items []Template
	q := tx.Model(&Template{}).Where("app_id=?", appID)
	if e := q.Count(&total).Error; e != nil {
		return nil, 0, e
	}
	if e := q.Order("id DESC").Offset(p.Offset()).Limit(p.Size).Find(&items).Error; e != nil {
		return nil, 0, e
	}
	out := make([]Info, 0, len(items))
	for _, t := range items {
		out = append(out, info(t))
	}
	return out, total, nil
}
func (s *Service) Save(ctx context.Context, appID, id uint64, in Input) (Info, error) {
	var out Template
	e := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := application(tx, appID); e != nil {
			return e
		}
		var e error
		out = Template{AppID: appID}
		if id != 0 {
			out, e = Find(tx, appID, id)
			if e != nil {
				return e
			}
		}
		out, e = apply(out, in)
		if e != nil {
			return e
		}
		var count int64
		if e = tx.Model(&Template{}).Where("app_id=? AND name=? AND id<>?", appID, out.Name, id).Count(&count).Error; e != nil {
			return e
		}
		if count > 0 {
			return apperror.New(409, "CONFLICT", "此软件已有同名功能模板")
		}
		return tx.Save(&out).Error
	})
	return info(out), e
}
func (s *Service) Delete(ctx context.Context, appID, id uint64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		t, e := Find(tx, appID, id)
		if e != nil {
			return e
		}
		var count int64
		if e = tx.Model(&model.Application{}).Where("trial_template_id=?", id).Count(&count).Error; e != nil {
			return e
		}
		if count > 0 {
			return apperror.New(409, "CONFLICT", "此模板正用于试用，请先在试用设置中更换")
		}
		return tx.Delete(&t).Error
	})
}
