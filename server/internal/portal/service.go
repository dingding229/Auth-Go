// Package portal implements license-scoped end-user access, separate from admin/client credentials.
package portal

import (
	"authgo/internal/apperror"
	"authgo/internal/automation"
	"authgo/internal/code"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/dockerhub"
	"authgo/internal/ipinfo"
	"authgo/internal/model"
	entitlements "authgo/internal/service"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"strconv"
	"strings"
	"time"
)

const TokenTTL = 2 * time.Hour
const CodeTTL = 10 * time.Minute
const audience = "authgo-portal"

type Options struct {
	Now                                                 func() time.Time
	IPRate, LicenseRate, SessionRate, SessionIPRate     float64
	IPBurst, LicenseBurst, SessionBurst, SessionIPBurst int
}
type Service struct {
	deploymentGuide                 string
	hub                             *dockerhub.Service
	ipinfo                          *ipinfo.Service
	db                              *gorm.DB
	notifications                   *automation.Service
	entitlements                    *entitlements.Service
	cipher                          *cryptoutil.Cipher
	tokenKey, codeKey               []byte
	dummy                           []byte
	now                             func() time.Time
	ip, license, session, sessionIP *limiter
	security                        *security
	codeWorkers                     chan struct{}
}

func New(database *gorm.DB, master []byte, notifications *automation.Service, grants *entitlements.Service, opts Options) (*Service, error) {
	if notifications == nil || grants == nil {
		return nil, errors.New("用户中心需要通知与授权服务")
	}
	box, e := cryptoutil.NewCipher(master)
	if e != nil {
		return nil, e
	}
	key, e := hkdf.Key(sha256.New, master, nil, "authgo/portal/access/v1", 32)
	if e != nil {
		return nil, e
	}
	otpKey, e := hkdf.Key(sha256.New, master, nil, "authgo/portal/otp/v1", 32)
	if e != nil {
		return nil, e
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.IPRate <= 0 {
		opts.IPRate = 5
	}
	if opts.IPBurst <= 0 {
		opts.IPBurst = 30
	}
	if opts.LicenseRate <= 0 {
		opts.LicenseRate = 2
	}
	if opts.LicenseBurst <= 0 {
		opts.LicenseBurst = 10
	}
	if opts.SessionRate <= 0 {
		opts.SessionRate = 10
	}
	if opts.SessionBurst <= 0 {
		opts.SessionBurst = 60
	}
	if opts.SessionIPRate <= 0 {
		opts.SessionIPRate = 20
	}
	if opts.SessionIPBurst <= 0 {
		opts.SessionIPBurst = 120
	}
	dummy, e := bcrypt.GenerateFromPassword([]byte("authgo-unusable-dummy-password"), bcrypt.DefaultCost)
	if e != nil {
		return nil, e
	}
	return &Service{hub: notifications.DockerHub(), db: database, notifications: notifications, entitlements: grants, cipher: box, tokenKey: key, codeKey: otpKey, dummy: dummy, now: opts.Now, ip: newLimiter(opts.IPRate, opts.IPBurst), license: newLimiter(opts.LicenseRate, opts.LicenseBurst), session: newLimiter(opts.SessionRate, opts.SessionBurst), sessionIP: newLimiter(opts.SessionIPRate, opts.SessionIPBurst), security: newSecurity(), codeWorkers: make(chan struct{}, 8)}, nil
}

type identity struct {
	License   model.License
	App       model.Application
	Email     string
	Private   ed25519.PrivateKey
	User      *model.EndUser
	UserScope bool
}

func (s *Service) identity(ctx context.Context, query *gorm.DB) (identity, error) {
	var id identity
	if e := query.WithContext(ctx).Preload("User").First(&id.License).Error; e != nil {
		if errors.Is(e, gorm.ErrRecordNotFound) {
			return id, unauthorized()
		}
		return id, e
	}
	if e := s.db.WithContext(ctx).First(&id.App, id.License.AppID).Error; e != nil {
		return id, e
	}
	id.User = id.License.User
	if id.User != nil {
		id.Email = strings.ToLower(strings.TrimSpace(id.User.Email))
		if id.User.Status != "active" {
			return id, unauthorized()
		}
	}
	return id, nil
}
func (s *Service) credential(id identity) string {
	if id.UserScope {
		return s.userCredential(*id.User)
	}
	userCredential := "inventory"
	if id.User != nil {
		userCredential = s.userCredential(*id.User)
	}
	return cryptoutil.HMACSHA256(s.codeKey, []byte(fmt.Sprintf("license|%d|%d|%s|%s|%s", id.License.ID, id.App.ID, id.License.Key, id.License.PortalPasswordHash, userCredential)))
}

// Key material is prepared before writes so a signing failure cannot turn a committed write into an unsigned success.
func (s *Service) signing(id *identity) error {
	raw, e := s.cipher.Decrypt(id.App.PrivateKeyEncrypted, []byte("application:"+id.App.AppKey+":ed25519_private_key"))
	if e != nil {
		return e
	}
	pub, e := base64.StdEncoding.DecodeString(id.App.PublicKey)
	if e != nil {
		return e
	}
	proof, e := cryptoutil.Sign(raw, []byte("authgo/portal/key-check"))
	if e != nil || !cryptoutil.Verify(pub, []byte("authgo/portal/key-check"), proof) {
		return errors.New("用户中心软件签名密钥不可用")
	}
	id.Private = ed25519.PrivateKey(raw)
	return nil
}

type claims struct {
	Scope       string `json:"scope,omitempty"`
	Selected    uint64 `json:"selected,omitempty"`
	Credentials string `json:"cred"`
	KeyHash     string `json:"kh"`
	jwt.RegisteredClaims
}

func (s *Service) token(id identity) (string, error) {
	jti, e := cryptoutil.RandomString(24)
	if e != nil {
		return "", e
	}
	now := s.now().UTC()
	c := claims{Credentials: s.credential(id), KeyHash: cryptoutil.SHA256([]byte(id.License.Key)), RegisteredClaims: jwt.RegisteredClaims{Issuer: "authgo", Audience: jwt.ClaimStrings{audience}, Subject: strconv.FormatUint(id.License.ID, 10), ID: jti, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(TokenTTL))}}
	if id.UserScope {
		c.Scope = "user"
		c.Subject = strconv.FormatUint(id.User.ID, 10)
		c.Selected = id.License.ID
		c.KeyHash = cryptoutil.SHA256([]byte("user:" + c.Subject))
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(s.tokenKey)
}
func (s *Service) parse(raw string) (*claims, error) {
	if len(raw) > 8192 {
		return nil, unauthorized()
	}
	c := new(claims)
	t, e := jwt.ParseWithClaims(raw, c, func(*jwt.Token) (any, error) { return s.tokenKey, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("authgo"), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(s.now))
	if e != nil || !t.Valid || c.ID == "" || c.IssuedAt == nil || c.Credentials == "" || len(c.KeyHash) != 64 || c.ExpiresAt.Sub(c.IssuedAt.Time) > TokenTTL {
		return nil, unauthorized()
	}
	if c.Scope != "" && c.Scope != "user" {
		return nil, unauthorized()
	}
	if id, e := strconv.ParseUint(c.Subject, 10, 63); e != nil || id == 0 {
		return nil, unauthorized()
	}
	return c, nil
}
func unauthorized() error {
	return apperror.New(401, code.PortalUnauthorized, "用户中心登录凭据无效或已过期")
}
func credentialsError() error {
	return apperror.New(401, "INVALID_CREDENTIALS", "登录凭据不正确")
}
func lockedError() error {
	return apperror.New(429, "LOGIN_LOCKED", "登录失败过多，请15分钟后重试")
}
func rateError() error { return apperror.New(429, "RATE_LIMITED", "用户中心请求过于频繁") }

func (s *Service) SetIPInfo(v *ipinfo.Service) { s.ipinfo = v }
