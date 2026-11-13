package auth

import (
	"bytes"
	"github.com/golang-jwt/jwt/v5"
	"testing"
	"time"
)

func TestJWTValidation(t *testing.T) {
	now := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{1}, 32)
	crypto, err := newCrypto(key, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(crypto.accessKey, key) || bytes.Equal(crypto.accessKey, crypto.refreshKey) {
		t.Fatal("HKDF key separation failed")
	}
	for _, kind := range []string{"access", "refresh"} {
		raw, err := crypto.sign(7, "session-id", 3, kind, now.Add(AccessTTL))
		if err != nil {
			t.Fatal(err)
		}
		claims, err := crypto.Parse(raw, kind)
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject != "7" || claims.Version != 3 || claims.SessionID != "session-id" || claims.ExpiresAt.Unix()-claims.IssuedAt.Unix() != 900 {
			t.Fatalf("claims: %+v", claims)
		}
		other := "refresh"
		if kind == "refresh" {
			other = "access"
		}
		if _, err := crypto.Parse(raw, other); err == nil {
			t.Fatal("access/refresh confused")
		}
		restarted, _ := newCrypto(key, func() time.Time { return now })
		if _, err := restarted.Parse(raw, kind); err != nil {
			t.Fatal("HKDF unstable", err)
		}
		wrong, _ := newCrypto(bytes.Repeat([]byte{2}, 32), func() time.Time { return now })
		if _, err := wrong.Parse(raw, kind); err == nil {
			t.Fatal("wrong master accepted")
		}
		now = now.Add(AccessTTL)
		if _, err := crypto.Parse(raw, kind); err == nil {
			t.Fatal("expired token accepted")
		}
		now = now.Add(-AccessTTL)
	}
	base := Claims{SessionID: "sid", RegisteredClaims: jwt.RegisteredClaims{Issuer: "authgo", Subject: "1", Audience: jwt.ClaimStrings{"authgo-admin-access"}, ID: "jti", IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute))}}
	for _, name := range []string{"issuer", "audience", "expiry", "iat", "future-iat", "subject", "sid", "jti", "algorithm"} {
		t.Run(name, func(t *testing.T) {
			c := base
			method := jwt.SigningMethodHS256
			switch name {
			case "issuer":
				c.Issuer = "other"
			case "audience":
				c.Audience = jwt.ClaimStrings{"other"}
			case "expiry":
				c.ExpiresAt = nil
			case "iat":
				c.IssuedAt = nil
			case "future-iat":
				c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute))
			case "subject":
				c.Subject = "0"
			case "sid":
				c.SessionID = ""
			case "jti":
				c.ID = ""
			case "algorithm":
				method = jwt.SigningMethodHS384
			}
			raw, err := jwt.NewWithClaims(method, c).SignedString(crypto.accessKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := crypto.Parse(raw, "access"); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
	if _, err := newCrypto([]byte("short"), time.Now); err == nil {
		t.Fatal("short master accepted")
	}
}
