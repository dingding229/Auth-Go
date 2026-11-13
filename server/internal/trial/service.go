// Package trial issues rate-limited anonymous trials and manages conversion.
package trial

import (
	"authgo/internal/apperror"
	"authgo/internal/code"
	"authgo/internal/licensekey"
	"authgo/internal/model"
	"authgo/internal/ratelimit"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"net/netip"
	"regexp"
	"time"
)

type Claim struct {
	ID         uint64 `gorm:"primaryKey"`
	AppID      uint64
	IPKey      string
	InstanceID string
	LicenseID  uint64
	CreatedAt  time.Time
}

func (Claim) TableName() string { return "trial_claims" }

type Service struct {
	db      *gorm.DB
	now     func() time.Time
	limiter *ratelimit.Limiter
}

func New(db *gorm.DB, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, now: now, limiter: ratelimit.Window(10, 50000, time.Minute, ratelimit.RejectNew)}
}
func IPKey(raw string) (string, error) {
	a, e := netip.ParseAddr(raw)
	if e != nil || a.Zone() != "" {
		return "", apperror.Invalid("客户端IP无效")
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String(), nil
	}
	return netip.PrefixFrom(a, 64).Masked().String(), nil
}

var instancePattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func failure(c string) error { d := code.Describe(c); return apperror.New(d.Status, c, d.Message) }
func (s *Service) Acquire(ctx context.Context, appID uint64, ip, instance string) (model.License, error) {
	var out model.License
	key, err := IPKey(ip)
	if err != nil {
		return out, err
	}
	if !instancePattern.MatchString(instance) {
		return out, apperror.Invalid("实例标识无效")
	}
	now := s.now().UTC()
	if !s.limiter.Allow(fmt.Sprintf("%d:%s", appID, key), now) {
		return out, failure(code.RateLimited)
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var a model.Application
		if err := tx.First(&a, appID).Error; err != nil {
			return err
		}
		var old Claim
		err := tx.Where("app_id=? AND instance_id=?", appID, instance).First(&old).Error
		if err == nil {
			return tx.First(&out, old.LicenseID).Error
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if a.Status != model.StatusActive || !a.TrialEnabled {
			return failure(code.TrialDisabled)
		}
		// Alias rows retain the original issue date; rebuilding cannot extend the IP window.
		err = tx.Where("app_id=? AND ip_key=? AND created_at>?", appID, key, now.AddDate(0, 0, -30)).Order("created_at DESC, id DESC").First(&old).Error
		if err == nil {
			if err := tx.First(&out, old.LicenseID).Error; err != nil {
				return err
			}
			if out.Type != model.LicenseTrial || out.ConvertedAt != nil || out.Status == "revoked" {
				return failure(code.TrialIPLimit)
			}
			return tx.Create(&Claim{AppID: appID, IPKey: key, InstanceID: instance, LicenseID: out.ID, CreatedAt: old.CreatedAt}).Error
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var count int64
		day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		if err := tx.Model(&model.License{}).Where("source=? AND created_at>=? AND created_at<?", "self_trial", day, day.AddDate(0, 0, 1)).Count(&count).Error; err != nil {
			return err
		}
		if count >= 100 {
			return failure(code.TrialQuotaExceeded)
		}
		licenseKey, err := licensekey.Generate("AUTH")
		if err != nil {
			return err
		}
		days := 14
		var setting model.Setting
		if e := tx.First(&setting, "key=?", "system.v1").Error; e == nil {
			v := struct {
				TrialDays int `json:"trial_days"`
			}{14}
			if e = json.Unmarshal([]byte(setting.Value), &v); e != nil {
				return e
			}
			if v.TrialDays < 1 || v.TrialDays > 365 {
				return apperror.Invalid("试用天数必须为1至365")
			}
			days = v.TrialDays
		} else if !errors.Is(e, gorm.ErrRecordNotFound) {
			return e
		}
		end := now.AddDate(0, 0, days)
		out = model.License{AppID: appID, Key: licenseKey, Type: model.LicenseTrial, Status: model.StatusUnused, Source: "self_trial", VerifyMethods: []string{"KEY", "FLOATING"}, MatchMode: "all", MaxActivations: 1, ValidityRule: "fixed_expiry", ExpiresAt: &end, Features: model.JSONMap{}, Metadata: model.JSONMap{}}
		out.CreatedAt = now
		if err := tx.Omit("User", "Application").Create(&out).Error; err != nil {
			return err
		}
		return tx.Create(&Claim{AppID: appID, IPKey: key, InstanceID: instance, LicenseID: out.ID, CreatedAt: now}).Error
	})
	return out, err
}

// ConvertOnActivation retires the previous anonymous trial only after a formal
// activation has passed policy. It runs inside that activation's transaction.
func ConvertOnActivation(tx *gorm.DB, l model.License, instance string, now time.Time) error {
	if l.Type == model.LicenseTrial || instance == "" {
		return nil
	}
	var claims []Claim
	if err := tx.Where("app_id=? AND instance_id=? AND license_id<>?", l.AppID, instance, l.ID).Find(&claims).Error; err != nil {
		return err
	}
	for _, c := range claims {
		var old model.License
		if err := tx.First(&old, c.LicenseID).Error; err != nil {
			return err
		}
		if old.Source != "self_trial" || old.Type != model.LicenseTrial || old.ConvertedAt != nil {
			continue
		}
		if err := tx.Model(&old).Updates(map[string]any{"converted_at": now, "status": "revoked"}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Activation{}).Where("license_id=? AND status='active'", old.ID).Updates(map[string]any{"status": "revoked", "offline_at": now, "lease_expires_at": now, "token": gorm.Expr("'converted_' || id")}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.ClientSession{}).Where("license_id=? AND revoked_at IS NULL", old.ID).Update("revoked_at", now).Error; err != nil {
			return err
		}
	}
	return nil
}
