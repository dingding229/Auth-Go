package httpserver

import (
	"authgo/internal/config"
	"bytes"
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRouter(t *testing.T) {
	router, err := NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Static fallback is covered independently in webui.TestRoutes; API misses
	// must keep the existing JSON contract regardless of frontend build state.
	for _, p := range []string{"/api/unknown", "/swagger", "/api/v1/admin/status"} {
		for _, method := range []string{"GET", "HEAD"} {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(method, p, nil))
			if w.Code != 404 || !strings.Contains(w.Header().Get("Content-Type"), "application/json") || w.Header().Get("Content-Security-Policy") != "" {
				t.Fatal(method, p, w.Code, w.Body.String())
			}
			if method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("unexpected HEAD error body")
			}
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestHealthFailureAndProxyTrust(t *testing.T) {
	for _, tc := range []struct {
		proxies []string
		wantIP  string
	}{{nil, "203.0.113.9"}, {[]string{"10.0.0.0/8"}, "203.0.113.9"}, {[]string{"192.168.0.0/16"}, "10.0.0.1"}} {
		var logs bytes.Buffer
		router, err := NewRouter(config.Config{TrustedProxies: tc.proxies}, slog.New(slog.NewJSONHandler(&logs, nil)), func(context.Context) error { return errors.New("private database error") })
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/healthz?secret=do-not-log", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.9")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != 503 || strings.Contains(w.Body.String(), "private") {
			t.Fatalf("health: %d %s", w.Code, w.Body)
		}
		if !strings.Contains(logs.String(), tc.wantIP) || strings.Contains(logs.String(), "do-not-log") {
			t.Fatalf("logs: %s", logs.String())
		}
	}
}

func TestRecoveryDoesNotExposePanic(t *testing.T) {
	var logs bytes.Buffer
	router, err := NewRouter(config.Config{}, slog.New(slog.NewJSONHandler(&logs, nil)), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	router.GET("/panic-test", func(c *gin.Context) { panic("secret-panic-value") })
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic-test", nil))
	if w.Code != 500 || strings.Contains(w.Body.String()+logs.String(), "secret-panic-value") {
		t.Fatalf("panic leaked or failed: %d", w.Code)
	}
}
