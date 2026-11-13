package auth

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"context"
	"errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"time"
)

// Six digits, 30s steps, ±1 step clock skew. Accepted steps are persisted and
// cannot be replayed, including across login, enable and disable operations.
func verifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, error) {
	if len(code) != 6 {
		return 0, errors.New("动态验证码无效")
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, errors.New("动态验证码无效")
		}
	}
	step := now.Unix() / 30
	for _, delta := range []int64{0, -1, 1} {
		candidate := step + delta
		if candidate <= lastStep {
			continue
		}
		ok, err := totp.ValidateCustom(code, secret, time.Unix(candidate*30, 0), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && ok {
			return candidate, nil
		}
	}
	return 0, errors.New("动态验证码无效或已使用")
}

type TOTPSetup struct {
	Secret    string    `json:"secret"`
	URI       string    `json:"otpauth_uri"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) SetupTOTP(ctx context.Context, p Principal, password string) (*TOTPSetup, error) {
	var result *TOTPSetup
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		a, err := s.activeAdmin(tx, p.AdminID)
		if err != nil {
			return err
		}
		if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(password)) != nil {
			return invalidCredentials()
		}
		if a.TOTPEnabled {
			return apperror.Conflict("双重验证已启用，请先停用")
		}
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "Auth Go", AccountName: a.Username, Period: 30, SecretSize: 20, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			return err
		}
		encrypted, err := s.crypto.seal(key.Secret(), totpAAD(a.ID, "pending"))
		if err != nil {
			return err
		}
		expires := s.now().UTC().Add(10 * time.Minute)
		if err := tx.Model(&a).Updates(map[string]any{"pending_totp_secret": encrypted, "pending_totp_expires_at": expires}).Error; err != nil {
			return err
		}
		result = &TOTPSetup{key.Secret(), key.URL(), expires}
		return nil
	})
	return result, err
}
func (s *Service) EnableTOTP(ctx context.Context, p Principal, code string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		a, err := s.activeAdmin(tx, p.AdminID)
		if err != nil {
			return err
		}
		if a.TOTPEnabled {
			return apperror.Conflict("双重验证已启用")
		}
		if a.PendingTOTPSecret == "" || a.PendingTOTPExpiresAt == nil || !s.now().Before(*a.PendingTOTPExpiresAt) {
			return apperror.Invalid("请先生成有效的双重验证密钥")
		}
		secret, err := s.crypto.open(a.PendingTOTPSecret, totpAAD(a.ID, "pending"))
		if err != nil {
			return err
		}
		step, err := verifyTOTP(secret, code, s.now(), 0)
		if err != nil {
			return apperror.Invalid("动态验证码无效")
		}
		encrypted, err := s.crypto.seal(secret, totpAAD(a.ID, "active"))
		if err != nil {
			return err
		}
		if err := tx.Model(&a).Updates(map[string]any{"totp_enabled": true, "totp_secret": encrypted, "last_totp_step": step, "pending_totp_secret": "", "pending_totp_expires_at": nil}).Error; err != nil {
			return err
		}
		return s.invalidate(tx, a.ID)
	})
}
func (s *Service) DisableTOTP(ctx context.Context, p Principal, password, code string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		a, err := s.activeAdmin(tx, p.AdminID)
		if err != nil {
			return err
		}
		if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(password)) != nil {
			return invalidCredentials()
		}
		if !a.TOTPEnabled {
			return apperror.Conflict("双重验证尚未启用")
		}
		secret, err := s.crypto.open(a.TOTPSecret, totpAAD(a.ID, "active"))
		if err != nil {
			return err
		}
		if _, err := verifyTOTP(secret, code, s.now(), a.LastTOTPStep); err != nil {
			return apperror.Invalid("动态验证码无效或已使用")
		}
		if err := tx.Model(&model.Admin{}).Where("id = ?", a.ID).Updates(map[string]any{"totp_enabled": false, "totp_secret": "", "last_totp_step": 0, "pending_totp_secret": "", "pending_totp_expires_at": nil}).Error; err != nil {
			return err
		}
		return s.invalidate(tx, a.ID)
	})
}
