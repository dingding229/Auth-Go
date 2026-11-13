// Package trial issues rate-limited anonymous trials and manages conversion.
package trial

import (
	"authgo/internal/apperror"
	"authgo/internal/code"
	"authgo/internal/licensekey"
	"authgo/internal/model"
	featuretemplate "authgo/internal/template"
	"context"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"net/netip"
	"regexp"
	"sync"
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

type bucket struct {
	Start time.Time
	Count int
}
type Service struct {
	db      *gorm.DB
	now     func() time.Time
	mu      sync.Mutex
	buckets map[string]bucket
}

func New(db *gorm.DB, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, now: now, buckets: map[string]bucket{}}
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
func (s *Service) allow(ip string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.buckets {
		if now.Sub(v.Start) >= time.Minute {
			delete(s.buckets, k)
		}
	}
	b := s.buckets[ip]
	if b.Start.IsZero() {
		if len(s.buckets) >= 50000 {
			return false
		}
		b.Start = now
	}
	if b.Count >= 10 {
		return false
	}
	b.Count++
	s.buckets[ip] = b
	return true
}
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
	if !s.allow(fmt.Sprintf("%d:%s", appID, key), now) {
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
		if a.Status != "active" || !a.TrialEnabled {
			return failure(code.TrialDisabled)
		}
		// Alias rows retain the original issue date; rebuilding cannot extend the IP window.
		err = tx.Where("app_id=? AND ip_key=? AND created_at>?", appID, key, now.AddDate(0, 0, -30)).Order("created_at DESC, id DESC").First(&old).Error
		if err == nil {
			if err := tx.First(&out, old.LicenseID).Error; err != nil {
				return err
			}
			if out.Type != "trial" || out.ConvertedAt != nil || out.Status == "revoked" {
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
		features := model.JSONMap{}
		if a.TrialTemplateID != nil {
			t, e := featuretemplate.Find(tx, a.ID, *a.TrialTemplateID)
			if e != nil {
				return e
			}
			features = t.Features
		}
		end := now.AddDate(0, 0, a.TrialDays)
		out = model.License{AppID: appID, Key: licenseKey, Type: "trial", Status: "unused", Source: "self_trial", VerifyMethods: []string{"KEY", "FLOATING"}, MatchMode: "all", MaxActivations: 1, ValidityRule: "fixed_expiry", ExpiresAt: &end, Features: features, Metadata: model.JSONMap{}}
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
	if l.Type == "trial" || instance == "" {
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
		if old.Source != "self_trial" || old.Type != "trial" || old.ConvertedAt != nil {
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
