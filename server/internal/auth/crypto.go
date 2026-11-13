package auth

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"strconv"
	"time"
)

const AccessTTL = 15 * time.Minute
const RefreshTTL = 7 * 24 * time.Hour

// Access and refresh use different HKDF contexts and audiences. Every request
// validates the current administrator, session and credential version.
type Claims struct {
	SessionID string `json:"sid"`
	Version   uint64 `json:"ver"`
	jwt.RegisteredClaims
}

type Crypto struct {
	accessKey, refreshKey []byte
	now                   func() time.Time
}

func newCrypto(master []byte, now func() time.Time) (*Crypto, error) {
	if len(master) != 32 {
		return nil, errors.New("主密钥必须为 32 字节")
	}
	derive := func(label string) ([]byte, error) {
		return hkdf.Key(sha256.New, master, nil, "authgo/admin/"+label+"/v1", 32)
	}
	access, err := derive("access")
	if err != nil {
		return nil, err
	}
	refresh, err := derive("refresh")
	if err != nil {
		return nil, err
	}
	return &Crypto{access, refresh, now}, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
func (c *Crypto) sign(adminID uint64, sid string, version uint64, kind string, expires time.Time) (string, error) {
	id, err := randomToken(24)
	if err != nil {
		return "", err
	}
	claims := Claims{SessionID: sid, Version: version, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "authgo", Subject: strconv.FormatUint(adminID, 10), Audience: jwt.ClaimStrings{"authgo-admin-" + kind},
		ExpiresAt: jwt.NewNumericDate(expires), IssuedAt: jwt.NewNumericDate(c.now()), ID: id,
	}}
	key := c.accessKey
	if kind == "refresh" {
		key = c.refreshKey
	} else if kind != "access" {
		return "", errors.New("未知令牌类型")
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
}
func (c *Crypto) Parse(raw, kind string) (*Claims, error) {
	key := c.accessKey
	if kind == "refresh" {
		key = c.refreshKey
	} else if kind != "access" {
		return nil, errors.New("未知令牌类型")
	}
	claims := new(Claims)
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("authgo"), jwt.WithAudience("authgo-admin-"+kind),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(c.now))
	if err != nil || !token.Valid {
		return nil, errors.New("无效令牌")
	}
	id, err := strconv.ParseUint(claims.Subject, 10, 63)
	if err != nil || id == 0 || claims.SessionID == "" || claims.ID == "" || claims.IssuedAt == nil {
		return nil, errors.New("无效令牌声明")
	}
	return claims, nil
}
