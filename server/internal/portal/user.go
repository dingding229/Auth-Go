package portal

import (
	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/enduser"
	"authgo/internal/mailer"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"math/big"
	"strconv"
	"strings"
	"time"
)

func (s *Service) userCredential(u model.EndUser) string {
	return cryptoutil.HMACSHA256(s.codeKey, []byte(fmt.Sprintf("user|%d|%s|%s|%s|%d", u.ID, u.Email, u.PortalPasswordHash, u.Status, u.AuthVersion)))
}
func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }
func (s *Service) userForEmail(ctx context.Context, email string) (model.EndUser, error) {
	var u model.EndUser
	e := s.db.WithContext(ctx).Where("email=? AND email<>''", email).First(&u).Error
	return u, e
}
func (s *Service) userKey(email string) string { return "user:" + email }
func (s *Service) SendUserCode(ctx context.Context, email, ip string) error {
	email = normalizeEmail(email)
	if _, e := mailer.Address(email); e != nil {
		return credentialsError()
	}
	key := s.userKey(email)
	if !s.license.allow(cryptoutil.SHA256([]byte(key)), s.now()) {
		return rateError()
	}
	defer s.security.gate(key + "\x00" + ip)()
	if !s.notifications.Current().SMTP.Enabled {
		return apperror.New(409, "SMTP_NOT_CONFIGURED", "邮箱验证码暂不可用，请使用用户中心密码")
	}
	now := s.now().UTC()
	mapKey := cryptoutil.SHA256([]byte(key))
	emailKey := cryptoutil.SHA256([]byte(email))
	s.security.mu.Lock()
	s.security.sweep(now)
	if until, ok := s.security.cooldowns[emailKey]; ok && now.Before(until) {
		s.security.mu.Unlock()
		return apperror.New(429, "CODE_COOLDOWN", "同一邮箱发送验证码需间隔60秒")
	}
	if len(s.security.codes) >= 10000 || len(s.security.cooldowns) >= 10000 {
		s.security.mu.Unlock()
		return rateError()
	}
	s.security.cooldowns[emailKey] = now.Add(time.Minute)
	s.security.mu.Unlock()
	n, e := rand.Int(rand.Reader, big.NewInt(1000000))
	if e != nil {
		return e
	}
	code := fmt.Sprintf("%06d", n.Int64())
	u, e := s.userForEmail(ctx, email)
	if e != nil && e != gorm.ErrRecordNotFound {
		return e
	}
	// Unknown and disabled identities receive exactly the same acknowledgement
	// and cooldown. No challenge is usable without the current credential HMAC.
	credential := "unusable"
	eligible := e == nil && u.Status == "active"
	if eligible {
		credential = s.userCredential(u)
	}
	challenge := otp{hash: s.codeHash(key, code), credentials: credential, expires: now.Add(CodeTTL), ready: false}
	s.security.mu.Lock()
	s.security.codes[mapKey] = challenge
	s.security.mu.Unlock()
	// Acknowledge before SMTP I/O for every address, so return latency and mail
	// errors do not disclose whether an account exists. At most eight sends run.
	if eligible {
		select {
		case s.codeWorkers <- struct{}{}:
			go func() {
				defer func() { <-s.codeWorkers }()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				err := s.notifications.SendPortalCode(ctx, email, code, challenge.expires)
				s.security.mu.Lock()
				defer s.security.mu.Unlock()
				if v, ok := s.security.codes[mapKey]; ok && v.hash == challenge.hash {
					if err != nil {
						delete(s.security.codes, mapKey)
					} else {
						v.ready = true
						s.security.codes[mapKey] = v
					}
				}
			}()
		default:
			s.security.mu.Lock()
			delete(s.security.codes, mapKey)
			s.security.mu.Unlock()
		}
	}
	return nil
}

type UserLoginInput struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

func (s *Service) UserLogin(ctx context.Context, in UserLoginInput, ip string) (identity, string, error) {
	empty := identity{}
	email := normalizeEmail(in.Email)
	if len(email) > 254 {
		return empty, "", credentialsError()
	}
	key := s.userKey(email)
	if !s.license.allow(cryptoutil.SHA256([]byte(key)), s.now()) {
		return empty, "", rateError()
	}
	guard := cryptoutil.SHA256([]byte(key + "\x00" + ip))
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
	u, e := s.userForEmail(ctx, email)
	if e != nil && e != gorm.ErrRecordNotFound {
		return empty, "", e
	}
	hash := s.dummy
	if u.PortalPasswordHash != "" {
		hash = []byte(u.PortalPasswordHash)
	}
	passwordOK := false
	if in.Password != "" {
		passwordOK = bcrypt.CompareHashAndPassword(hash, []byte(in.Password)) == nil
	}
	valid := false
	if (in.Code == "") != (in.Password == "") && u.ID != 0 && u.Status == "active" {
		if in.Password != "" {
			valid = passwordOK && u.PortalPasswordHash != ""
		} else if s.notifications.Current().SMTP.Enabled {
			mapKey := cryptoutil.SHA256([]byte(key))
			s.security.mu.Lock()
			v, ok := s.security.codes[mapKey]
			if ok && v.ready && s.now().Before(v.expires) && v.credentials == s.userCredential(u) {
				valid = len(in.Code) == 6 && subtle.ConstantTimeCompare([]byte(v.hash), []byte(s.codeHash(key, in.Code))) == 1
				v.attempts++
				if valid || v.attempts >= 5 {
					delete(s.security.codes, mapKey)
				} else {
					s.security.codes[mapKey] = v
				}
			}
			s.security.mu.Unlock()
		}
	}
	if !valid {
		return fail()
	}
	id := identity{User: &u, UserScope: true, Email: u.Email}
	token, e := s.token(id)
	if e != nil {
		return empty, "", e
	}
	s.security.success(guard)
	return id, token, nil
}
func (s *Service) registerUserLogin(root *gin.RouterGroup) {
	root.POST("/user/login/code", func(c *gin.Context) {
		var in struct {
			Email string `json:"email"`
		}
		if e := response.BindJSON(c, &in); e != nil {
			s.reply(c, nil, nil, e)
			return
		}
		e := s.SendUserCode(c.Request.Context(), in.Email, c.ClientIP())
		s.reply(c, nil, gin.H{"expires_in": 600, "message": "如该邮箱可用于登录，将收到验证码"}, e)
	})
	root.POST("/user/login", func(c *gin.Context) {
		var in UserLoginInput
		if e := response.BindJSON(c, &in); e != nil {
			s.reply(c, nil, nil, e)
			return
		}
		id, token, e := s.UserLogin(c.Request.Context(), in, c.ClientIP())
		if e != nil {
			s.reply(c, nil, nil, e)
			return
		}
		s.reply(c, &id, gin.H{"portal_token": token, "scope": "user", "expires_in": 7200}, nil)
	})
}
func (s *Service) registerUserCenter(root *gin.RouterGroup) {
	wrap := func(fn func(*gin.Context, identity) (any, error)) gin.HandlerFunc {
		return func(c *gin.Context) {
			id := c.MustGet("portal_identity").(identity)
			if !id.UserScope {
				s.reply(c, &id, nil, unauthorized())
				return
			}
			v, e := fn(c, id)
			s.reply(c, &id, v, e)
		}
	}
	root.GET("/user", wrap(func(c *gin.Context, id identity) (any, error) {
		var n, instances int64
		var next struct{ ExpiresAt *time.Time }
		tx := s.db.WithContext(c.Request.Context())
		if e := tx.Model(&model.License{}).Where("user_id=?", id.User.ID).Count(&n).Error; e != nil {
			return nil, e
		}
		if e := tx.Model(&model.Activation{}).Where("status='active' AND kind='floating' AND license_id IN (SELECT id FROM licenses WHERE user_id=?)", id.User.ID).Count(&instances).Error; e != nil {
			return nil, e
		}
		if e := tx.Model(&model.License{}).Select("expires_at").Where("user_id=? AND expires_at>? AND status IN ?", id.User.ID, s.now(), []string{"active", "unused"}).Order("expires_at").Limit(1).Scan(&next).Error; e != nil {
			return nil, e
		}
		var onlineCount int64
		if e := tx.Model(&model.Activation{}).Where("kind='floating' AND status='active' AND offline_at IS NULL AND lease_expires_at>? AND license_id IN (SELECT id FROM licenses WHERE user_id=?)", s.now(), id.User.ID).Count(&onlineCount).Error; e != nil {
			return nil, e
		}
		return gin.H{"id": id.User.ID, "name": id.User.Name, "email": id.User.Email, "license_count": n, "instances_total": instances, "online_instances": onlineCount, "next_expires_at": next.ExpiresAt, "selected_license_id": id.License.ID}, nil
	}))
	root.GET("/licenses", s.userOnly(s.userLicenses))
	root.POST("/switch", wrap(func(c *gin.Context, id identity) (any, error) {
		var in struct {
			LicenseID uint64 `json:"license_id"`
		}
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		selected, e := s.ownedIdentity(c.Request.Context(), id.User.ID, in.LicenseID)
		if e != nil {
			return nil, apperror.NotFound()
		}
		selected.UserScope = true
		if e = s.signing(&selected); e != nil {
			return nil, e
		}
		token, e := s.token(selected)
		if e != nil {
			return nil, e
		}
		view, e := s.licenseView(c.Request.Context(), selected)
		return gin.H{"portal_token": token, "license": view}, e
	}))
	root.POST("/user/instances/:id/release-seat", wrap(func(c *gin.Context, id identity) (any, error) {
		aid, e := strconv.ParseUint(c.Param("id"), 10, 63)
		if e != nil || aid == 0 {
			return nil, apperror.Invalid("实例编号无效")
		}
		var a model.Activation
		if e = s.db.WithContext(c.Request.Context()).Where("id=? AND license_id IN (SELECT id FROM licenses WHERE user_id=?)", aid, id.User.ID).First(&a).Error; e != nil {
			return nil, apperror.NotFound()
		}
		return gin.H{"released": true}, s.entitlements.ReleaseSelf(c.Request.Context(), a.LicenseID, aid, id.User.ID)
	}))
	root.POST("/password", wrap(func(c *gin.Context, id identity) (any, error) {
		guard := "password:" + strconv.FormatUint(id.User.ID, 10) + ":" + c.ClientIP()
		defer s.security.gate(guard)()
		if s.security.locked(guard, s.now()) {
			return nil, lockedError()
		}

		var in struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
			Code        string `json:"code"`
		}
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		valid := id.User.PortalPasswordHash != "" && bcrypt.CompareHashAndPassword([]byte(id.User.PortalPasswordHash), []byte(in.OldPassword)) == nil
		if !valid && s.notifications.Current().SMTP.Enabled {
			key := s.userKey(id.User.Email)
			mapKey := cryptoutil.SHA256([]byte(key))
			s.security.mu.Lock()
			v, ok := s.security.codes[mapKey]
			valid = ok && v.ready && s.now().Before(v.expires) && v.credentials == s.userCredential(*id.User) && len(in.Code) == 6 && subtle.ConstantTimeCompare([]byte(v.hash), []byte(s.codeHash(key, in.Code))) == 1
			if ok {
				v.attempts++
				if valid || v.attempts >= 5 {
					delete(s.security.codes, mapKey)
				} else {
					s.security.codes[mapKey] = v
				}
			}
			s.security.mu.Unlock()
		}
		if !valid {
			if s.security.failed(guard, s.now()) {
				return nil, lockedError()
			}
			return nil, credentialsError()
		}
		s.security.success(guard)
		if in.NewPassword == "" {
			return nil, apperror.Invalid("新密码不能为空")
		}
		hash, e := enduser.HashPassword(in.NewPassword)
		if e != nil {
			return nil, e
		}
		e = s.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
			var current model.EndUser
			if e := tx.First(&current, id.User.ID).Error; e != nil {
				return e
			}
			if s.userCredential(current) != s.userCredential(*id.User) {
				return unauthorized()
			}
			return tx.Model(&current).Updates(map[string]any{"portal_password_hash": hash, "auth_version": current.AuthVersion + 1}).Error
		})
		return gin.H{"reauthenticate": true}, e
	}))
}
