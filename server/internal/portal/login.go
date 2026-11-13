package portal

import (
	"authgo/internal/apperror"
	codes "authgo/internal/code"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/licensekey"
	"authgo/internal/mailer"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"math/big"
	"strings"
	"time"
)

type LoginInput struct {
	LicenseKey string `json:"license_key"`
	Code       string `json:"code"`
	Password   string `json:"password"`
}

func (s *Service) LoginOptions() map[string]any {
	methods := []string{"password"}
	enabled := s.notifications.Current().SMTP.Enabled
	if enabled {
		methods = append([]string{"email_code"}, methods...)
	}
	return map[string]any{"methods": methods, "smtp_configured": enabled, "code_expires_in": 600, "email_cooldown_seconds": 60, "token_expires_in": 7200}
}
func (s *Service) checkKey(key string) error {
	if licensekey.Validate(key) != nil {
		return credentialsError()
	}
	if !s.license.allow(cryptoutil.SHA256([]byte(key)), s.now()) {
		return rateError()
	}
	return nil
}
func (s *Service) SendCode(ctx context.Context, key, email, ip string) error {
	if e := s.checkKey(key); e != nil {
		return e
	}
	guard := cryptoutil.SHA256([]byte(key + "\x00" + ip))
	defer s.security.gate(guard)()
	if s.security.locked(guard, s.now()) {
		return lockedError()
	}
	fail := func() error {
		if s.security.failed(guard, s.now()) {
			return lockedError()
		}
		return credentialsError()
	}
	email = strings.ToLower(strings.TrimSpace(email))
	id, e := s.identity(ctx, s.db.Where("key=?", key))
	if e != nil {
		if _, ok := e.(*apperror.Error); ok {
			return fail()
		}
		return e
	}
	if _, e := mailer.Address(email); e != nil || email != id.Email {
		return fail()
	}
	if !s.notifications.Current().SMTP.Enabled {
		return apperror.New(409, "SMTP_NOT_CONFIGURED", "SMTP 尚未启用，请使用查询密码")
	}
	n, e := rand.Int(rand.Reader, big.NewInt(1000000))
	if e != nil {
		return e
	}
	code := fmt.Sprintf("%06d", n.Int64())
	now := s.now().UTC()
	mapKey := cryptoutil.SHA256([]byte(key))
	emailKey := cryptoutil.SHA256([]byte(email))
	s.security.mu.Lock()
	s.security.sweep(now)
	if until, ok := s.security.cooldowns[emailKey]; ok && now.Before(until) {
		s.security.mu.Unlock()
		return apperror.New(429, codes.CodeCooldown, "同一邮箱发送验证码需间隔60秒")
	}
	if len(s.security.codes) >= 10000 || len(s.security.cooldowns) >= 10000 {
		s.security.mu.Unlock()
		return rateError()
	}
	challenge := otp{hash: s.codeHash(key, code), credentials: s.credential(id), expires: now.Add(CodeTTL)}
	s.security.codes[mapKey] = challenge
	s.security.cooldowns[emailKey] = now.Add(time.Minute)
	s.security.mu.Unlock()
	e = s.notifications.SendPortalCode(ctx, email, code, challenge.expires)
	s.security.mu.Lock()
	defer s.security.mu.Unlock()
	if current, ok := s.security.codes[mapKey]; ok && current.hash == challenge.hash {
		if e != nil {
			delete(s.security.codes, mapKey)
		} else {
			current.ready = true
			s.security.codes[mapKey] = current
		}
	}
	if e != nil {
		return apperror.New(502, "SMTP_SEND_FAILED", "验证码邮件发送失败，请稍后重试")
	}
	return nil
}
func (s *Service) codeHash(key, code string) string {
	return cryptoutil.HMACSHA256(s.codeKey, []byte(key+"\x00"+code))
}
func (s *Service) Login(ctx context.Context, in LoginInput, ip string) (identity, string, error) {
	var empty identity
	if e := s.checkKey(in.LicenseKey); e != nil {
		return empty, "", e
	}
	guard := cryptoutil.SHA256([]byte(in.LicenseKey + "\x00" + ip))
	defer s.security.gate(guard)()
	if s.security.locked(guard, s.now()) {
		return empty, "", lockedError()
	}
	fail := func() (identity, string, error) {
		if s.security.failed(guard, s.now()) {
			return empty, "", lockedError()
		}
		return empty, "", credentialsError()
	}
	if (in.Code == "") == (in.Password == "") {
		return fail()
	}
	id, e := s.identity(ctx, s.db.Where("key=?", in.LicenseKey))
	if e != nil {
		if _, ok := e.(*apperror.Error); ok {
			_ = bcrypt.CompareHashAndPassword(s.dummy, []byte(in.Password))
			return fail()
		}
		return empty, "", e
	}
	valid := false
	if in.Password != "" {
		hash := []byte(id.License.PortalPasswordHash)
		if len(hash) == 0 {
			hash = s.dummy
		}
		valid = bcrypt.CompareHashAndPassword(hash, []byte(in.Password)) == nil && id.License.PortalPasswordHash != ""
	} else if s.notifications.Current().SMTP.Enabled {
		s.security.mu.Lock()
		mapKey := cryptoutil.SHA256([]byte(in.LicenseKey))
		v, ok := s.security.codes[mapKey]
		if ok && v.ready && s.now().Before(v.expires) && v.credentials == s.credential(id) {
			valid = len(in.Code) == 6 && subtle.ConstantTimeCompare([]byte(v.hash), []byte(s.codeHash(in.LicenseKey, in.Code))) == 1
			if valid {
				delete(s.security.codes, mapKey)
			} else {
				v.attempts++
				if v.attempts >= 5 {
					delete(s.security.codes, mapKey)
				} else {
					s.security.codes[mapKey] = v
				}
			}
		}
		s.security.mu.Unlock()
	}
	if !valid {
		return fail()
	}
	if e := s.signing(&id); e != nil {
		return empty, "", e
	}
	token, e := s.token(id)
	if e != nil {
		return empty, "", e
	}
	s.security.success(guard)
	return id, token, nil
}
