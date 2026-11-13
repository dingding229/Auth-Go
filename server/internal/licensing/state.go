package licensing

import (
	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"context"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"time"
)

// Transition is the status graph only. Renewing unused/suspended changes dates,
// not activation/suspension status. No management activate endpoint is exposed.
func Transition(status, action string) (string, error) {
	if !validStatus(status) || status == "revoked" {
		return "", transitionError()
	}
	switch action {
	case "suspend":
		if status == "unused" || status == "active" || status == "expired" {
			return "suspended", nil
		}
	case "resume":
		if status == "suspended" {
			return "active", nil
		}
	case "revoke":
		return "revoked", nil
	case "renew":
		if status == "expired" {
			return "active", nil
		}
		return status, nil
	case "expire":
		if status == "active" {
			return "expired", nil
		}
	}
	return "", transitionError()
}

type RenewInput struct {
	maintenance.Input
	Days      *int       `json:"days"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (s *Service) ChangeState(ctx context.Context, id uint64, action string) (LicenseInfo, error) {
	var result model.License
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		l, err := findLicense(tx, id)
		if err != nil {
			return err
		}
		next, err := Transition(l.Status, action)
		if err != nil {
			return err
		}
		if action != "suspend" && action != "resume" && action != "revoke" {
			return transitionError()
		}
		if action == "resume" && l.ExpiresAt != nil && !l.ExpiresAt.After(s.now()) {
			return apperror.New(409, "LICENSE_EXPIRED", "授权已到期，请先续期再恢复")
		}
		if err := tx.Model(&model.License{}).Where("id = ?", id).Update("status", next).Error; err != nil {
			return err
		}
		if action == "revoke" {
			suffix, err := cryptoutil.RandomString(18)
			if err != nil {
				return err
			}
			now := s.now().UTC()
			if err := tx.Model(&model.Activation{}).Where("license_id = ? AND status = ?", id, "active").Updates(map[string]any{"status": "revoked", "token": gorm.Expr("'revoked_' || id || '_' || ?", suffix), "offline_at": now, "lease_expires_at": now}).Error; err != nil {
				return err
			}
		}
		result, err = findLicense(tx, id)
		return err
	})

	return info(result), err
}
func (s *Service) Renew(ctx context.Context, id uint64, in RenewInput) (LicenseInfo, error) {
	if (in.Days == nil) == (in.ExpiresAt == nil) {
		return LicenseInfo{}, apperror.Invalid("days 和 expires_at 必须且只能提供一个")
	}
	if in.Days != nil && (*in.Days < 1 || *in.Days > 36500) {
		return LicenseInfo{}, apperror.Invalid("续期天数必须为 1 至 36500")
	}
	var result model.License
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		l, err := findLicense(tx, id)
		if err != nil {
			return err
		}
		next, err := Transition(l.Status, "renew")
		if err != nil {
			return err
		}
		if l.ValidityRule == "perpetual" || l.Type == "perpetual" {
			return apperror.New(409, "INVALID_TRANSITION", "永久授权无需续期")
		}
		values := map[string]any{"status": next}
		now := s.now().UTC()
		at, set, e := in.Input.Resolve(now)
		if e != nil {
			return e
		}
		if set {
			values["maintenance_until"] = at
		}
		if l.ValidityRule == "after_activation" && l.StartsAt == nil && l.ExpiresAt == nil && in.Days != nil {
			days := l.DurationDays + *in.Days
			if days > 36500 {
				return apperror.Invalid("累计有效天数不得超过 36500")
			}
			values["duration_days"] = days
		} else {
			var expires time.Time
			if in.ExpiresAt != nil {
				expires = in.ExpiresAt.UTC()
			} else {
				base := now
				if l.ExpiresAt != nil && l.ExpiresAt.After(base) {
					base = *l.ExpiresAt
				}
				expires = base.AddDate(0, 0, *in.Days)
			}
			if expires.Year() < 1 || expires.Year() > 9999 {
				return apperror.Invalid("到期日超出可表示范围")
			}
			if !expires.After(now) || l.ExpiresAt != nil && !expires.After(*l.ExpiresAt) {
				return apperror.Invalid("新到期日必须晚于当前时间及原到期日")
			}
			if l.StartsAt != nil && !expires.After(*l.StartsAt) {
				return apperror.Invalid("新到期日必须晚于开始时间")
			}
			values["expires_at"] = expires
			values["validity_rule"] = "fixed_expiry"
			values["duration_days"] = 0
		}
		if err := tx.Model(&model.License{}).Where("id = ?", id).Updates(values).Error; err != nil {
			return err
		}
		result, err = findLicense(tx, id)
		return err
	})
	return info(result), err
}
func (s *Service) SetPortalPassword(ctx context.Context, id uint64, password string) error {
	hash := ""
	if password != "" {
		if len(password) < 8 || len(password) > 72 {
			return apperror.Invalid("用户中心密码须为 8 至 72 字节，空字符串表示清除")
		}
		encoded, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		hash = string(encoded)
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		l, err := findLicense(tx, id)
		if err != nil {
			return err
		}
		if l.Status == "revoked" {
			return transitionError()
		}
		return tx.Model(&model.License{}).Where("id = ?", id).Update("portal_password_hash", hash).Error
	})
}
