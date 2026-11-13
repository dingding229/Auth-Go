package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
)

func TestRoutes(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	register(r, fstest.MapFS{
		"index.html":           {Data: []byte("<!doctype html><div id=app></div>")},
		"assets/app.js":        {Data: []byte("console.log('real asset')")},
		"favicon.svg":          {Data: []byte("<svg></svg>")},
		".well-known/site.txt": {Data: []byte("existing static file")},
	}, func(c *gin.Context) { c.JSON(404, gin.H{"code": "NOT_FOUND"}) })
	for _, tc := range []struct {
		method, path             string
		code                     int
		cache, referrer, content string
	}{
		{"GET", "/admin/login", 200, "no-cache", "strict-origin-when-cross-origin", "text/html"},
		{"GET", "/admin/setup?token=secret", 200, "no-store", "no-referrer", "text/html"},
		{"HEAD", "/admin/setup", 200, "no-store", "no-referrer", "text/html"},
		{"GET", "/assets/app.js", 200, "public, max-age=31536000, immutable", "strict-origin-when-cross-origin", "javascript"},
		{"HEAD", "/assets/app.js", 200, "public, max-age=31536000, immutable", "strict-origin-when-cross-origin", "javascript"},
		{"GET", "/assets/missing.js", 404, "", "", "application/json"},
		{"GET", "/favicon.svg", 200, "no-cache", "strict-origin-when-cross-origin", "image/svg+xml"},
		{"GET", "/.well-known/site.txt", 200, "no-cache", "strict-origin-when-cross-origin", "text/plain"},
		{"GET", "/assets/../index.html", 404, "", "", "application/json"},
		{"POST", "/admin/login", 405, "no-cache", "strict-origin-when-cross-origin", ""},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.code || w.Header().Get("Cache-Control") != tc.cache || w.Header().Get("Referrer-Policy") != tc.referrer {
				t.Fatalf("%d %v", w.Code, w.Header())
			}
			if !strings.Contains(w.Header().Get("Content-Type"), tc.content) {
				t.Fatal(w.Header())
			}
			for name, want := range map[string]string{"Content-Security-Policy": csp, "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"} {
				if tc.code == 404 {
					if w.Header().Get(name) != "" {
						t.Fatal("missing route reveals UI headers", name, w.Header())
					}
				} else if w.Header().Get(name) != want {
					t.Fatal(name, w.Header())
				}
			}
			if tc.method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD body", w.Body.String())
			}
			if tc.method == "POST" && w.Header().Get("Allow") != "GET, HEAD" {
				t.Fatal("missing Allow")
			}
		})
	}
	for _, p := range []string{"/api", "/api/unknown", "/api/v1/不存在", "/swagger", "/swagger/disabled", "/healthz"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 404 || !strings.Contains(w.Body.String(), "NOT_FOUND") || w.Header().Get("Content-Security-Policy") != "" || w.Header().Get("Cache-Control") != "" {
			t.Fatal(p, w.Code, w.Header(), w.Body.String())
		}
	}
}

func TestMissingIndexFailsClosed(t *testing.T) {
	r := gin.New()
	register(r, fstest.MapFS{}, func(c *gin.Context) { c.Status(404) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal(w.Code)
	}
}
