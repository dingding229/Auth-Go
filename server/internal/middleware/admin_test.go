package middleware

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"testing"
)

func TestAnonymousAdminSourceBudgetIPv6AndBoundedMemory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.SetTrustedProxies(nil)
	r.Use(AdminRequests(nil))
	r.POST("/api/v1/admin/auth/login", func(c *gin.Context) { c.Status(204) })
	request := func(path, source string) int {
		t.Helper()
		q := httptest.NewRequest("POST", path, nil)
		q.RemoteAddr = source
		q.Header.Set("X-Forwarded-For", "203.0.113.8")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		return w.Code
	}
	for i := 0; i < 30; i++ {
		if code := request("/api/v1/admin/auth/login", fmt.Sprintf("[2001:db8:1:1::%x]:1000", i)); code != 204 {
			t.Fatal(i, code)
		}
	}
	if code := request("/api/v1/admin/auth/login", "[2001:db8:1:1::ff]:1000"); code != 429 {
		t.Fatal("IPv6/source split login budget", code)
	}
	// Unknown paths cannot advertise the management namespace via a special
	// rate-limit status or cache header, even after that source is exhausted.
	if code := request("/api/v1/admin/missing", "[2001:db8:1:1::ff]:1000"); code != 404 {
		t.Fatal(code)
	}
	if code := request("/api/v1/admin/auth/login", "[2001:db8:1:2::1]:1000"); code != 204 {
		t.Fatal("different source blocked", code)
	}
	// Missing routes with bearer never invoke identity (nil would panic).
	q := httptest.NewRequest("POST", "/api/v1/admin/not-found", nil)
	q.RemoteAddr = "192.0.2.1:1234"
	q.Header.Set("Authorization", "Bearer opaque")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	// Fill the map with fresh sources: admission, not eviction, bounds memory.
	for i := 0; i < 10050; i++ {
		code := request("/api/v1/admin/auth/login", fmt.Sprintf("[2001:db8:%x::1]:1000", i+10))
		if i >= 10000 && code != 429 {
			t.Fatal("source map exceeds cap", i, code)
		}
	}
}
