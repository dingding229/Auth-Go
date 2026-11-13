// Package updater contains Docker update authorization and the existing poll preference only.
package updater

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"context"
	"encoding/json"
	"errors"
	"github.com/Masterminds/semver/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
)

type Settings struct {
	PollMinutes int `json:"poll_minutes"`
}
type Service struct {
	db  *gorm.DB
	now func() time.Time
}

func New(d *gorm.DB, _ []byte, now func() time.Time) (*Service, error) {
	if now == nil {
		now = time.Now
	}
	return &Service{d, now}, nil
}
func (s *Service) CurrentSettings() (Settings, error) {
	v := Settings{10}
	var r model.Setting
	e := s.db.First(&r, "key=?", "docker.poll.v1").Error
	if errors.Is(e, gorm.ErrRecordNotFound) {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	e = json.Unmarshal([]byte(r.Value), &v)
	return v, e
}
func (s *Service) SaveSettings(ctx context.Context, v Settings) error {
	if v.PollMinutes < 5 || v.PollMinutes > 1440 {
		return apperror.Invalid("轮询间隔须为5至1440分钟")
	}
	raw, _ := json.Marshal(v)
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&model.Setting{Key: "docker.poll.v1", Value: string(raw)}).Error
}
func (s *Service) ValidateLicense(ctx context.Context, id uint64) (model.License, model.Application, error) {
	var l model.License
	var a model.Application
	refuse := func(c string) error { return apperror.New(403, c, "授权不可用于更新") }
	if e := s.db.WithContext(ctx).Preload("User").First(&l, id).Error; e != nil {
		if errors.Is(e, gorm.ErrRecordNotFound) {
			return l, a, refuse("LICENSE_NOT_FOUND")
		}
		return l, a, e
	}
	if e := s.db.WithContext(ctx).First(&a, l.AppID).Error; e != nil {
		return l, a, e
	}
	if a.Status != "active" {
		return l, a, refuse("APP_DISABLED")
	}
	if l.UserID != nil && (l.User == nil || l.User.Status != "active") {
		return l, a, refuse("USER_DISABLED")
	}
	if l.Status != "active" && l.Status != "unused" {
		c := "LICENSE_NOT_ACTIVATED"
		if l.Status == "revoked" {
			c = "LICENSE_REVOKED"
		}
		if l.Status == "suspended" {
			c = "LICENSE_SUSPENDED"
		}
		return l, a, refuse(c)
	}
	if l.StartsAt != nil && s.now().Before(*l.StartsAt) {
		return l, a, refuse("LICENSE_NOT_STARTED")
	}
	if l.ExpiresAt != nil && !s.now().Before(*l.ExpiresAt) {
		return l, a, refuse("LICENSE_EXPIRED")
	}
	return l, a, nil
}
func VersionAllowed(_ model.Application, _ model.License, v string) bool {
	_, e := semver.StrictNewVersion(v)
	return e == nil
}
