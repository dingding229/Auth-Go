// Package webui owns embedded frontend routing. API routes and headers stay backend-owned.
package webui

import (
	"bytes"
	"embed"
	"encoding/json"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"authgo/internal/adminpath"
	"github.com/gin-gonic/gin"
)

//go:embed all:dist
var embedded embed.FS

const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"

func Register(r *gin.Engine, apiNotFound gin.HandlerFunc) {
	files, _ := fs.Sub(embedded, "dist")
	register(r, files, apiNotFound)
}
func register(r *gin.Engine, files fs.FS, apiNotFound gin.HandlerFunc) {
	serve := func(c *gin.Context) {
		p := c.Request.URL.Path
		name := strings.TrimPrefix(p, "/")
		valid := fs.ValidPath(name) && !strings.Contains(name, "\\")
		var raw []byte
		var err error
		if valid && name != "placeholder.txt" && p != "/admin/setup" {
			raw, err = fs.ReadFile(files, name)
		} else {
			err = fs.ErrNotExist
		}
		if strings.HasPrefix(p, "/api/") || p == "/api" || p == "/swagger" || strings.HasPrefix(p, "/swagger/") || p == "/healthz" || strings.HasPrefix(p, "/healthz/") {
			apiNotFound(c)
			return
		}
		if err != nil {
			if !knownPage(p) {
				apiNotFound(c)
				return
			}
			name = "index.html"
			raw, err = fs.ReadFile(files, name)
			if err != nil {
				c.Status(http.StatusServiceUnavailable)
				return
			}
		}
		c.Header("Cache-Control", "no-cache")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Header("Content-Security-Policy", csp)
		if strings.HasPrefix(p, "/assets/") {
			c.Header("Cache-Control", "public, max-age=31536000, immutable")
		}
		if p == "/admin/setup" {
			c.Header("Cache-Control", "no-store")
			c.Header("Referrer-Policy", "no-referrer")
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Header("Allow", "GET, HEAD")
			c.Status(http.StatusMethodNotAllowed)
			return
		}
		if name == "index.html" {
			base := ""
			if p == "/admin" || strings.HasPrefix(p, "/admin/") {
				base = adminpath.Path(c.Request)
			}
			state, _ := json.Marshal(struct {
				AdminPath string `json:"admin_path"`
			}{base})
			tag := append([]byte(`<script id="authgo-runtime" type="application/json">`), state...)
			tag = append(tag, []byte("</script>")...)
			if bytes.Contains(raw, []byte("</head>")) {
				raw = bytes.Replace(raw, []byte("</head>"), append(tag, []byte("</head>")...), 1)
			} else {
				raw = append(tag, raw...)
			}
		}
		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			contentType = http.DetectContentType(raw)
		}
		c.Header("Content-Type", contentType)
		c.Status(http.StatusOK)
		http.ServeContent(c.Writer, c.Request, name, time.Time{}, bytes.NewReader(raw))
	}
	// Register the asset namespace even in a source-only build. The live route
	// table is also the source of reserved management root names.
	r.GET("/assets/*file", serve)
	r.HEAD("/assets/*file", serve)
	r.NoRoute(serve)
}
