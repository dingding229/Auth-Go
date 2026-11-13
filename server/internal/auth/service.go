// Package auth implements administrator single-administrator session authentication.
package auth

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"context"
	"crypto/subtle"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Principal struct {
	AdminID   uint64
	Username  string
	SessionID string
}

type AdminInfo struct {
	ID          uint64     `json:"id"`
	Username    string     `json:"username"`
	TOTPEnabled bool       `json:"totp_enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func info(a model.Admin) AdminInfo {
	return AdminInfo{a.ID, a.Username, a.TOTPEnabled, a.CreatedAt, a.UpdatedAt, a.LastLoginAt}
}

type TokenPair struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	ExpiresIn        int64     `json:"expires_in"`
	RefreshExpiresIn int64     `json:"refresh_expires_in"`
	Admin            AdminInfo `json:"admin"`
	SessionID        string    `json:"-"`
}

func (p TokenPair) Principal() Principal {
	return Principal{AdminID: p.Admin.ID, Username: p.Admin.Username, SessionID: p.SessionID}
}

type Service struct {
	db        *gorm.DB
	crypto    *Crypto
	now       func() time.Time
	limiter   *LoginLimiter
	account   *LoginLimiter
	dummyHash []byte
}

func NewService(database *gorm.DB, master []byte) (*Service, error) {
	return NewServiceWithClock(database, master, time.Now)
}
func NewServiceWithClock(database *gorm.DB, master []byte, now func() time.Time) (*Service, error) {
	crypto, err := NewCrypto(master, now)
	if err != nil {
		return nil, err
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte("authgo-unknown-account-dummy"), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Service{db: database, crypto: crypto, now: now, limiter: NewLoginLimiter(now), account: NewLoginLimiter(now), dummyHash: dummy}, nil
}
func (s *Service) activeAdmin(tx *gorm.DB, id uint64) (model.Admin, error) {
	var a model.Admin
	if err := tx.First(&a, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return a, apperror.Unauthorized()
		}
		return a, err
	}
	return a, nil
}
func (s *Service) Me(ctx context.Context, p Principal) (AdminInfo, error) {
	a, err := s.activeAdmin(s.db.WithContext(ctx), p.AdminID)
	if err != nil {
		return AdminInfo{}, err
	}
	result := info(a)
	return result, nil
}
func invalidCredentials() error {
	return apperror.New(http.StatusUnauthorized, "INVALID_CREDENTIALS", "用户名、密码或动态验证码不正确")
}
func locked() error {
	return apperror.New(http.StatusTooManyRequests, "LOGIN_LOCKED", "登录失败次数过多，请在 15 分钟后重试")
}

func (s *Service) Login(ctx context.Context, username, password, code, ip string) (*TokenPair, error) {
	if strings.TrimSpace(username) == "" || len(username) > 128 || len(password) == 0 || len(password) > 72 {
		return nil, apperror.Invalid("用户名或密码长度无效")
	}
	key := loginKey(username, ip)
	unlock := s.account.gate(username)
	defer unlock()
	if !s.account.accountAllowed(username) {
		return nil, locked()
	}
	sourceUnlock := s.limiter.gate(key)
	defer sourceUnlock()
	if !s.limiter.allowed(key) {
		return nil, locked()
	}
	fail := func() (*TokenPair, error) {
		sourceLocked := s.limiter.failed(key)
		accountDelayed := s.account.accountFailed(username)
		if sourceLocked || accountDelayed {
			return nil, locked()
		}
		return nil, invalidCredentials()
	}
	var a model.Admin
	err := s.db.WithContext(ctx).Where("username = ?", username).First(&a).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	hash := s.dummyHash
	if err == nil {
		hash = []byte(a.PasswordHash)
	}
	passwordOK := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	if err != nil || !passwordOK {
		return fail()
	}
	var step int64
	if a.TOTPEnabled {
		secret, err := s.crypto.open(a.TOTPSecret, totpAAD(a.ID, "active"))
		if err != nil {
			return nil, err
		}
		step, err = verifyTOTP(secret, code, s.now(), a.LastTOTPStep)
		if err != nil {
			return fail()
		}
	}
	var pair *TokenPair
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		current, err := s.activeAdmin(tx, a.ID)
		if err != nil {
			return err
		}
		if current.AuthVersion != a.AuthVersion || current.PasswordHash != a.PasswordHash {
			return invalidCredentials()
		}
		if a.TOTPEnabled {
			res := tx.Model(&model.Admin{}).Where("id = ? AND auth_version = ? AND last_totp_step < ? AND totp_enabled = ?", a.ID, a.AuthVersion, step, true).Update("last_totp_step", step)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return invalidCredentials()
			}
		}
		now := s.now().UTC()
		if err := tx.Model(&current).Update("last_login_at", now).Error; err != nil {
			return err
		}
		current.LastLoginAt = &now
		sid, err := randomToken(24)
		if err != nil {
			return err
		}
		pair, err = s.pair(current, sid, now.Add(RefreshTTL))
		if err != nil {
			return err
		}
		return tx.Create(&model.AdminSession{ID: sid, AdminID: a.ID, TokenHash: hashToken(pair.RefreshToken), AuthVersion: a.AuthVersion, ExpiresAt: now.Add(RefreshTTL)}).Error
	})
	if err != nil {
		var safe *apperror.Error
		if errors.As(err, &safe) && safe.Status == 401 {
			return fail()
		}
		return nil, err
	}
	s.limiter.succeeded(key)
	s.account.succeeded(username)
	return pair, nil
}
func (s *Service) pair(a model.Admin, sid string, refreshExpiry time.Time) (*TokenPair, error) {
	access, err := s.crypto.sign(a.ID, sid, a.AuthVersion, "access", s.now().Add(AccessTTL))
	if err != nil {
		return nil, err
	}
	refresh, err := s.crypto.sign(a.ID, sid, a.AuthVersion, "refresh", refreshExpiry)
	if err != nil {
		return nil, err
	}
	return &TokenPair{access, refresh, "Bearer", int64(AccessTTL / time.Second), int64(refreshExpiry.Sub(s.now()) / time.Second), info(a), sid}, nil
}
func (s *Service) session(tx *gorm.DB, claims *Claims) (model.AdminSession, model.Admin, error) {
	var session model.AdminSession
	if err := tx.First(&session, "id = ?", claims.SessionID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return session, model.Admin{}, apperror.Unauthorized()
		}
		return session, model.Admin{}, err
	}
	id, _ := strconv.ParseUint(claims.Subject, 10, 63)
	if session.AdminID != id || session.RevokedAt != nil || !s.now().Before(session.ExpiresAt) || session.AuthVersion != claims.Version {
		return session, model.Admin{}, apperror.Unauthorized()
	}
	a, err := s.activeAdmin(tx, id)
	if err != nil {
		return session, a, err
	}
	if a.AuthVersion != claims.Version {
		return session, a, apperror.Unauthorized()
	}
	return session, a, nil
}
func (s *Service) Refresh(ctx context.Context, raw string) (*TokenPair, error) {
	claims, err := s.crypto.Parse(raw, "refresh")
	if err != nil {
		return nil, apperror.Unauthorized()
	}
	var pair *TokenPair
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		session, a, err := s.session(tx, claims)
		if err != nil {
			return err
		}
		hash := hashToken(raw)
		if subtle.ConstantTimeCompare([]byte(session.TokenHash), []byte(hash)) != 1 {
			return apperror.Unauthorized()
		}
		pair, err = s.pair(a, session.ID, session.ExpiresAt)
		if err != nil {
			return err
		}
		res := tx.Model(&model.AdminSession{}).Where("id = ? AND token_hash = ? AND revoked_at IS NULL", session.ID, hash).Update("token_hash", hashToken(pair.RefreshToken))
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return apperror.Unauthorized()
		}
		return nil
	})
	return pair, err
}
func (s *Service) Authenticate(ctx context.Context, raw string) (Principal, error) {
	claims, err := s.crypto.Parse(raw, "access")
	if err != nil {
		return Principal{}, apperror.Unauthorized()
	}
	session, a, err := s.session(s.db.WithContext(ctx), claims)
	if err != nil {
		return Principal{}, err
	}
	return Principal{AdminID: a.ID, Username: a.Username, SessionID: session.ID}, nil
}
func (s *Service) Logout(ctx context.Context, p Principal) error {
	now := s.now().UTC()
	return s.db.WithContext(ctx).Model(&model.AdminSession{}).Where("id = ? AND admin_id = ? AND revoked_at IS NULL", p.SessionID, p.AdminID).Update("revoked_at", now).Error
}
func validPassword(password string) error {
	if len(password) < 8 || len(password) > 72 {
		return apperror.Invalid("密码长度必须为 8 至 72 字节")
	}
	return nil
}
func (s *Service) invalidate(tx *gorm.DB, id uint64) error {
	now := s.now().UTC()
	if err := tx.Model(&model.Admin{}).Where("id = ?", id).Updates(map[string]any{"auth_version": gorm.Expr("auth_version + 1"), "pending_totp_secret": "", "pending_totp_expires_at": nil}).Error; err != nil {
		return err
	}
	if err := tx.Model(&model.AdminSession{}).Where("admin_id = ? AND revoked_at IS NULL", id).Update("revoked_at", now).Error; err != nil {
		return err
	}
	return nil
}
func (s *Service) ChangePassword(ctx context.Context, p Principal, oldPassword, newPassword string) error {
	if err := validPassword(newPassword); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		a, err := s.activeAdmin(tx, p.AdminID)
		if err != nil {
			return err
		}
		if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(oldPassword)) != nil {
			return invalidCredentials()
		}
		if err := tx.Model(&a).Update("password_hash", string(hash)).Error; err != nil {
			return err
		}
		return s.invalidate(tx, a.ID)
	})
}
