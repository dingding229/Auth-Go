package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"authgo/internal/adminpath"
	"authgo/internal/automation"
	"authgo/internal/config"

	"github.com/gin-gonic/gin"
)

func TestRouterBodyCeiling(t *testing.T) {
	r, err := NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/missing", "/api/v1/admin/system/ip-info/city", "/api/v1/admin/system/ip-info/asn"} {
		limit := int64(32 << 20)
		if path != "/api/v1/missing" {
			limit = 513 << 20
		}
		req := httptest.NewRequest("POST", path, nil)
		req.ContentLength = limit + 1
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 413 {
			t.Fatal(path, w.Code)
		}
	}
}

func TestRouterForwardedAuthority(t *testing.T) {
	for _, runtime := range []bool{false, true} {
		for _, trusted := range []bool{false, true} {
			var r *adminpath.Router
			if runtime {
				f, s := automationFixture(t)
				r = f.r
				if trusted {
					_, err := s.UpdateSettings(context.Background(), automation.SettingsInput{TrustedProxies: ptr([]string{"10.0.0.0/8"})})
					if err != nil {
						t.Fatal(err)
					}
				}
			} else {
				cfg := config.Config{}
				if trusted {
					cfg.TrustedProxies = []string{"10.0.0.0/8"}
				}
				var err error
				r, err = NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
			}
			r.GET("/proxy-probe", func(c *gin.Context) {
				wantIP, wantHost, wantProto := "10.0.0.2", "actual.example", "http"
				if trusted {
					wantIP, wantHost, wantProto = "203.0.113.9", "public.example:8443", "https"
				}
				if c.ClientIP() != wantIP || c.Request.Host != wantHost || c.Request.URL.Scheme != wantProto {
					t.Fatalf("runtime=%v trusted=%v: ip=%s host=%s proto=%s", runtime, trusted, c.ClientIP(), c.Request.Host, c.Request.URL.Scheme)
				}
				c.Status(204)
			})
			req := httptest.NewRequest("GET", "http://actual.example/proxy-probe", nil)
			req.RemoteAddr = "10.0.0.2:1234"
			req.Header.Set("X-Forwarded-For", "203.0.113.9")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "public.example:8443")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != 204 {
				t.Fatal(w.Code)
			}
		}
	}
}
