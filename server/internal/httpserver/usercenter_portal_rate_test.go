package httpserver

import (
	"authgo/internal/enduser"
	"authgo/internal/portal"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"testing"
	"time"
)

func usercenterRateRequest(t *testing.T, f *portalFixture, method, path, token string, body any, ip string, status int, code string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, "/api/v1/portal"+path, bytes.NewReader(raw))
	request.RemoteAddr = ip
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	f.r.ServeHTTP(response, request)
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != status || result["code"] != code {
		t.Fatalf("%s %s status=%d code=%v want %d %s", method, path, response.Code, result["code"], status, code)
	}
	return result
}

func TestAuthenticatedNavigationFortyRequestsWithinOneClockSecond(t *testing.T) {
	// Frozen server time is stricter than a one-second burst: no bucket can refill.
	f := newPortalFixture(t, portal.Options{IPBurst: 30, LicenseBurst: 10}, nil)
	token := userPassword(t, f)
	now := f.clock.now()
	for i := 0; i < 40; i++ {
		method, path, body := "GET", "/user", any(nil)
		switch i % 5 {
		case 1:
			path = "/user/updates"
		case 2:
			path = fmt.Sprintf("/licenses/%d", f.license.ID)
		case 3:
			method, path, body = "POST", "/switch", gin.H{"license_id": f.license.ID}
		case 4:
			path = "/licenses"
		}
		usercenterRateRequest(t, f, method, path, token, body, "198.51.100.8:1234", 200, "OK")
	}
	if !f.clock.now().Equal(now) {
		t.Fatal("server clock advanced")
	}
}

func TestAnonymousLoginRoutesKeepThirtyRequestIPBurst(t *testing.T) {
	for _, path := range []string{"/login", "/login/code", "/user/login", "/user/login/code"} {
		t.Run(path, func(t *testing.T) {
			f := newPortalFixture(t, portal.Options{IPBurst: 30, LicenseBurst: 10}, nil)
			// Invalid JSON shape avoids account/password buckets; even a Bearer header
			// cannot move a public login request into the authenticated IP budget.
			for i := 0; i < 30; i++ {
				usercenterRateRequest(t, f, "POST", path, "not-a-session", "invalid-object", "198.51.100.8:1234", 400, "INVALID_REQUEST")
			}
			usercenterRateRequest(t, f, "POST", path, "not-a-session", "invalid-object", "198.51.100.8:1234", 429, "RATE_LIMITED")
			f.clock.add(200 * time.Millisecond)
			usercenterRateRequest(t, f, "POST", path, "", "invalid-object", "198.51.100.8:1234", 400, "INVALID_REQUEST")
		})
	}
}

func TestLoginIdentityKeepsTenRequestBurstAcrossIPsAndCodeRoutes(t *testing.T) {
	t.Run("license", func(t *testing.T) {
		f := newPortalFixture(t, portal.Options{IPBurst: 30, LicenseBurst: 10}, nil)
		body := gin.H{"license_key": f.license.Key, "password": "portal-password123"}
		for i := 0; i < 10; i++ {
			usercenterRateRequest(t, f, "POST", "/login", "", body, fmt.Sprintf("198.51.100.%d:1234", i+1), 200, "OK")
		}
		usercenterRateRequest(t, f, "POST", "/login", "", body, "198.51.100.50:1234", 429, "RATE_LIMITED")
		usercenterRateRequest(t, f, "POST", "/login/code", "", gin.H{"license_key": f.license.Key, "email": "user@example.com"}, "198.51.100.51:1234", 429, "RATE_LIMITED")
		f.clock.add(500 * time.Millisecond)
		usercenterRateRequest(t, f, "POST", "/login", "", body, "198.51.100.50:1234", 200, "OK")
	})
	t.Run("email", func(t *testing.T) {
		f := newPortalFixture(t, portal.Options{IPBurst: 30, LicenseBurst: 10}, nil)
		_ = userPassword(t, f)
		body := gin.H{"email": "user@example.com", "password": "user-password123"}
		for i := 1; i < 10; i++ {
			usercenterRateRequest(t, f, "POST", "/user/login", "", body, fmt.Sprintf("198.51.100.%d:1234", i+10), 200, "OK")
		}
		usercenterRateRequest(t, f, "POST", "/user/login", "", body, "198.51.100.50:1234", 429, "RATE_LIMITED")
		usercenterRateRequest(t, f, "POST", "/user/login/code", "", gin.H{"email": "user@example.com"}, "198.51.100.51:1234", 429, "RATE_LIMITED")
		f.clock.add(500 * time.Millisecond)
		usercenterRateRequest(t, f, "POST", "/user/login", "", body, "198.51.100.50:1234", 200, "OK")
	})
}

func TestSessionBudgetsAreIndependentBetweenUsersAndSharedAcrossOwnTokens(t *testing.T) {
	f := newPortalFixture(t, portal.Options{IPBurst: 30, LicenseBurst: 10}, nil)
	first := userPassword(t, f)
	second := data(f.p(t, "POST", "/user/login", "", gin.H{"email": "user@example.com", "password": "user-password123"}, "OK"))["portal_token"].(string)
	_, err := (enduser.Service{DB: f.db}).Create(context.Background(), enduser.Input{Name: ptr("other"), Email: ptr("other@example.com"), PortalPassword: ptr("other-password123")})
	if err != nil {
		t.Fatal(err)
	}
	other := data(f.p(t, "POST", "/user/login", "", gin.H{"email": "other@example.com", "password": "other-password123"}, "OK"))["portal_token"].(string)
	for i := 0; i < 60; i++ {
		usercenterRateRequest(t, f, "GET", "/user", first, nil, "198.51.100.8:1234", 200, "OK")
	}
	usercenterRateRequest(t, f, "GET", "/user", first, nil, "198.51.100.8:1234", 429, "RATE_LIMITED")
	usercenterRateRequest(t, f, "GET", "/user", second, nil, "198.51.100.9:1234", 429, "RATE_LIMITED")
	for i := 0; i < 40; i++ {
		usercenterRateRequest(t, f, "GET", "/user", other, nil, "198.51.100.8:1234", 200, "OK")
	}
	f.clock.add(100 * time.Millisecond)
	usercenterRateRequest(t, f, "GET", "/user", first, nil, "198.51.100.8:1234", 200, "OK")
}

func TestAuthenticatedIPBudgetAllowsThreeUsersFortyRequests(t *testing.T) {
	f := newPortalFixture(t, portal.Options{IPBurst: 30, LicenseBurst: 10}, nil)
	tokens := []string{userPassword(t, f)}
	for i := 0; i < 2; i++ {
		email := fmt.Sprintf("nat-%d@example.com", i)
		_, err := (enduser.Service{DB: f.db}).Create(context.Background(), enduser.Input{Name: ptr("NAT user"), Email: &email, PortalPassword: ptr("nat-password123")})
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, data(f.p(t, "POST", "/user/login", "", gin.H{"email": email, "password": "nat-password123"}, "OK"))["portal_token"].(string))
	}
	for _, token := range tokens {
		for i := 0; i < 40; i++ {
			usercenterRateRequest(t, f, "GET", "/user", token, nil, "198.51.100.8:1234", 200, "OK")
		}
	}
	usercenterRateRequest(t, f, "GET", "/user", tokens[0], nil, "198.51.100.8:1234", 429, "RATE_LIMITED")
	usercenterRateRequest(t, f, "GET", "/user", tokens[0], nil, "198.51.100.9:1234", 200, "OK")
	f.clock.add(50 * time.Millisecond)
	usercenterRateRequest(t, f, "GET", "/user", tokens[1], nil, "198.51.100.8:1234", 200, "OK")
}
