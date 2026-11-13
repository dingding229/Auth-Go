package bootstrap

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"strings"
	"sync"
	"time"
	"unicode"
)

type Setup struct {
	mu       sync.Mutex
	db       *gorm.DB
	hash     [32]byte
	active   bool
	now      func() time.Time
	attempts map[string]setupAttempts
}
type setupAttempts struct {
	Count int
	Until time.Time
}

func NewSetup(database *gorm.DB) (*Setup, string, error) {
	s := &Setup{db: database, now: time.Now, attempts: map[string]setupAttempts{}}
	initialized, err := s.Initialized(context.Background())
	if err != nil || initialized {
		return s, "", err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, "", err
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	s.hash = sha256.Sum256([]byte(token))
	s.active = true
	return s, token, nil
}
func (s *Setup) Initialized(ctx context.Context) (bool, error) {
	var n int64
	err := s.db.WithContext(ctx).Model(&model.Admin{}).Count(&n).Error
	return n > 0, err
}
func (s *Setup) Available(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return false, nil
	}
	done, err := s.Initialized(ctx)
	return !done, err
}
func unavailable() error {
	return apperror.New(404, "SETUP_UNAVAILABLE", "初始化入口已关闭，请使用管理员账号登录")
}

// Complete consumes the token only after committing the account and optional
// initial session together. The callback may not commit the transaction itself.
func (s *Setup) Complete(ctx context.Context, token, username, password, ip string, session func(*gorm.DB, model.Admin) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return unavailable()
	}
	initialized, err := s.Initialized(ctx)
	if err != nil {
		return err
	}
	if initialized {
		s.active = false
		s.hash = [32]byte{}
		return unavailable()
	}
	now := s.now()
	for key, v := range s.attempts {
		if !now.Before(v.Until) {
			delete(s.attempts, key)
		}
	}
	v := s.attempts[ip]
	if v.Count >= 5 || len(s.attempts) >= 10000 && v.Count == 0 {
		return apperror.New(429, "RATE_LIMITED", "初始化请求过于频繁，请稍后再试")
	}
	if v.Count == 0 {
		v.Until = now.Add(time.Minute)
	}
	v.Count++
	s.attempts[ip] = v
	candidate := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(candidate[:], s.hash[:]) != 1 {
		return apperror.New(401, "SETUP_TOKEN_INVALID", "初始化令牌无效，请从当前服务日志重新获取链接")
	}
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 128 || strings.IndexFunc(username, unicode.IsControl) >= 0 {
		return apperror.Invalid("管理员用户名无效")
	}
	if len(password) < 8 || len(password) > 72 {
		return apperror.Invalid("密码长度必须为8至72字节")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.Admin{}).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return unavailable()
		}
		admin := model.Admin{Username: username, PasswordHash: string(hash)}
		if err := tx.Create(&admin).Error; err != nil {
			return err
		}
		if session != nil {
			return session(tx, admin)
		}
		return nil
	})
	if err == nil {
		s.active = false
		s.hash = [32]byte{}
		s.attempts = nil
	}
	return err
}
