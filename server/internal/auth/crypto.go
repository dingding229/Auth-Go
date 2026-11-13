package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	box                   cipher.AEAD
	now                   func() time.Time
}

func NewCrypto(master []byte, now func() time.Time) (*Crypto, error) {
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
	secret, err := derive("totp-encryption")
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	box, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Crypto{access, refresh, box, now}, nil
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
func (c *Crypto) seal(secret, aad string) (string, error) {
	nonce := make([]byte, c.box.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return "v1:" + base64.RawStdEncoding.EncodeToString(c.box.Seal(nonce, nonce, []byte(secret), []byte(aad))), nil
}
func (c *Crypto) open(value, aad string) (string, error) {
	if len(value) < 3 || value[:3] != "v1:" {
		return "", errors.New("无效密文版本")
	}
	b, err := base64.RawStdEncoding.DecodeString(value[3:])
	if err != nil || len(b) < c.box.NonceSize() {
		return "", errors.New("无效密文")
	}
	plain, err := c.box.Open(nil, b[:c.box.NonceSize()], b[c.box.NonceSize():], []byte(aad))
	if err != nil {
		return "", errors.New("密文校验失败")
	}
	return string(plain), nil
}
func totpAAD(adminID uint64, purpose string) string {
	return fmt.Sprintf("admin:%d:totp:%s", adminID, purpose)
}

// CheckEncryptedSecret verifies an existing TOTP ciphertext without exposing its plaintext.
// Used only by the read-only startup master-key check, before migrations/backups.
func (c *Crypto) CheckEncryptedSecret(value, aad string) error {
	_, err := c.open(value, aad)
	return err
}
