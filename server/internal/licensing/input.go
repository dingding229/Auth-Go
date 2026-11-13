package licensing

import (
	"authgo/internal/apperror"
	"authgo/internal/licensekey"
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"math"
	"time"
)

type CreateInput struct {
	maintenance.Input
	UserID         *uint64         `json:"user_id"`
	AppID          uint64          `json:"app_id"`
	Prefix         string          `json:"prefix"`
	Type           *string         `json:"type"`
	VerifyMethods  *[]string       `json:"verify_methods"`
	MatchMode      *string         `json:"match_mode"`
	MaxActivations *int            `json:"max_activations"`
	Features       json.RawMessage `json:"features" swaggertype:"object"`
	ValidityRule   *string         `json:"validity_rule"`
	StartsAt       *time.Time      `json:"starts_at"`
	ExpiresAt      *time.Time      `json:"expires_at"`
	DurationDays   *int            `json:"duration_days"`
	PortalPassword *string         `json:"portal_password"`
	Note           *string         `json:"note"`
	Metadata       json.RawMessage `json:"metadata" swaggertype:"object"`
}
type BatchInput struct {
	CreateInput
	Count int `json:"count"`
}

func (s *Service) prepare(ctx context.Context, in CreateInput) (model.License, string, error) {
	l := model.License{AppID: in.AppID, Type: "standard", Status: "unused", VerifyMethods: []string{"KEY", "FLOATING"}, MatchMode: "all", MaxActivations: 1, ValidityRule: "perpetual", Features: model.JSONMap{}, Metadata: model.JSONMap{}}
	if in.AppID == 0 || in.AppID > math.MaxInt64 {
		return l, "", apperror.Invalid("app_id 必须为有效的正整数")
	}
	at, _, err := in.Input.Resolve(s.now())
	if err != nil {
		return l, "", err
	}
	l.MaintenanceUntil = at
	prefix, err := licensekey.Prefix(in.Prefix)
	if err != nil {
		return l, "", apperror.Invalid(err.Error())
	}
	tx := s.db.WithContext(ctx)
	var app model.Application
	if err := tx.First(&app, in.AppID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return l, "", apperror.New(404, "NOT_FOUND", "软件不存在")
		}
		return l, "", err
	}

	if in.UserID != nil {
		if *in.UserID == 0 {
			return l, "", apperror.Invalid("user_id须为正整数或null")
		}
		var u model.EndUser
		if err := tx.First(&u, *in.UserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return l, "", apperror.Invalid("所选用户不存在")
			}
			return l, "", err
		}
		l.UserID = in.UserID
		l.User = &u
	}
	if in.Type != nil {
		l.Type = *in.Type
	}
	if in.VerifyMethods != nil {
		l.VerifyMethods = append([]string{}, (*in.VerifyMethods)...)
	}
	if in.MatchMode != nil {
		l.MatchMode = *in.MatchMode
	}
	if in.MaxActivations != nil {
		l.MaxActivations = *in.MaxActivations
	}
	if in.ValidityRule != nil {
		l.ValidityRule = *in.ValidityRule
	}
	if in.DurationDays != nil {
		l.DurationDays = *in.DurationDays
	}
	l.StartsAt = in.StartsAt
	l.ExpiresAt = in.ExpiresAt
	if in.ExpiresAt != nil && in.ValidityRule == nil {
		l.ValidityRule = "fixed_expiry"
		l.DurationDays = 0
	}
	if in.Note != nil {
		l.Note = *in.Note
	}
	l.Features, err = parseMap(in.Features, l.Features)
	if err != nil {
		return l, "", err
	}
	if l.Features == nil {
		l.Features = model.JSONMap{}
	}
	l.Metadata, err = parseMap(in.Metadata, l.Metadata)
	if err != nil {
		return l, "", err
	}
	switch l.Type {
	case "trial", "standard", "subscription", "perpetual", "floating":
	default:
		return l, "", apperror.Invalid("授权类型无效")
	}
	seen := map[string]bool{}
	for _, method := range l.VerifyMethods {
		switch method {
		case "KEY", "FLOATING":
		default:
			return l, "", apperror.Invalid("验证方式无效，v1 不支持 USER")
		}
		if seen[method] {
			return l, "", apperror.Invalid("验证方式不能重复")
		}
		seen[method] = true
	}
	if !seen["KEY"] {
		return l, "", apperror.Invalid("必须包含 KEY 验证方式")
	}
	if l.MatchMode != "all" && l.MatchMode != "any" {
		return l, "", apperror.Invalid("match_mode 必须为 all 或 any")
	}
	if l.MaxActivations < 1 || l.MaxActivations > 1000000 {
		return l, "", apperror.Invalid("max_activations 必须为 1 至 1000000")
	}
	if len(l.Note) > 4096 {
		return l, "", apperror.Invalid("备注过长")
	}
	now := s.now().UTC()
	switch l.ValidityRule {
	case "perpetual":
		if l.DurationDays != 0 || l.ExpiresAt != nil {
			return l, "", apperror.Invalid("永久授权不能设置有效天数或到期日")
		}
	case "fixed_days":
		if l.DurationDays < 1 || l.DurationDays > 36500 || l.ExpiresAt != nil {
			return l, "", apperror.Invalid("固定天数须为 1 至 36500 且不能同时指定到期日")
		}
		expires := now.AddDate(0, 0, l.DurationDays)
		l.ExpiresAt = &expires
	case "after_activation":
		if l.DurationDays < 1 || l.DurationDays > 36500 || l.ExpiresAt != nil || l.StartsAt != nil {
			return l, "", apperror.Invalid("激活后计时须为 1 至 36500 天，且不能提前设置起止时间")
		}
	case "fixed_expiry":
		if l.ExpiresAt == nil || l.DurationDays != 0 {
			return l, "", apperror.Invalid("固定到期规则必须提供 expires_at 且 duration_days 为 0")
		}
	default:
		return l, "", apperror.Invalid("有效期规则无效")
	}
	if l.Type == "perpetual" && l.ValidityRule != "perpetual" {
		return l, "", apperror.Invalid("perpetual 类型只能使用永久规则")
	}
	if l.ExpiresAt != nil {
		t := l.ExpiresAt.UTC()
		if t.Year() < 1 || t.Year() > 9999 {
			return l, "", apperror.Invalid("到期日超出可表示范围")
		}
		l.ExpiresAt = &t
		if !t.After(now) {
			return l, "", apperror.Invalid("到期日必须晚于当前时间")
		}
		if l.StartsAt != nil && !l.StartsAt.Before(t) {
			return l, "", apperror.Invalid("开始时间必须早于到期时间")
		}
	}
	if l.StartsAt != nil {
		t := l.StartsAt.UTC()
		if t.Year() < 1 || t.Year() > 9999 {
			return l, "", apperror.Invalid("开始时间超出可表示范围")
		}
		l.StartsAt = &t
	}
	if in.PortalPassword != nil && *in.PortalPassword != "" {
		if len(*in.PortalPassword) < 8 || len(*in.PortalPassword) > 72 {
			return l, "", apperror.Invalid("用户中心查询密码须为 8 至 72 字节")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*in.PortalPassword), bcrypt.DefaultCost)
		if err != nil {
			return l, "", err
		}
		l.PortalPasswordHash = string(hash)
	}
	return l, prefix, nil
}

// AssignmentInput changes the owner. An explicit null makes a license inventory.
type AssignmentInput struct {
	UserID *uint64 `json:"user_id"`
}

func (s *Service) Assign(ctx context.Context, id uint64, in AssignmentInput) (LicenseInfo, error) {
	var l model.License
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var e error
		l, e = findLicense(tx, id)
		if e != nil {
			return e
		}
		if in.UserID != nil {
			if *in.UserID == 0 {
				return apperror.Invalid("用户编号无效")
			}
			var u model.EndUser
			if e := tx.First(&u, *in.UserID).Error; e != nil {
				if errors.Is(e, gorm.ErrRecordNotFound) {
					return apperror.Invalid("用户不存在")
				}
				return e
			}
			l.User = &u
		} else {
			l.User = nil
		}
		l.UserID = in.UserID
		return tx.Model(&model.License{}).Where("id=?", l.ID).Update("user_id", in.UserID).Error
	})
	return info(l), err
}
