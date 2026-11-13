package httpserver

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/automation"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

const backupDownloadRoute = "/api/v1/admin/system/backups/:name"

func WithAutomation(s *automation.Service) Option { return func(o *routerOptions) { o.automation = s } }
func optionalID(c *gin.Context, key string) (*uint64, error) {
	if c.Query(key) == "" {
		return nil, nil
	}
	id, e := parseID(c.Query(key))
	return &id, e
}
func registerAutomation(r *gin.Engine, s *automation.Service, identity *auth.Service) {
	root := r.Group("/api/v1/admin", middleware.Authenticate(identity))
	system := root.Group("/system")
	system.GET("/settings", handle(func(c *gin.Context) (any, error) { return s.PublicSettings(), nil }))
	system.PATCH("/settings", middleware.Action("system.settings.update", "system"), handle(func(c *gin.Context) (any, error) {
		var in automation.SettingsInput
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		return s.UpdateSettings(c.Request.Context(), in)
	}))
	system.POST("/smtp/test", middleware.Action("system.smtp.test", "system"), handle(func(c *gin.Context) (any, error) {
		var in struct {
			To string `json:"to"`
		}
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		return gin.H{}, s.TestMail(c.Request.Context(), in.To)
	}))
	system.GET("/backups", handle(func(c *gin.Context) (any, error) {
		rows, e := s.ListBackups()
		return gin.H{"items": rows, "total": len(rows)}, e
	}))
	system.POST("/backups", middleware.Action("system.backup.create", "backup"), handle(func(c *gin.Context) (any, error) {
		_ = http.NewResponseController(c.Writer).SetWriteDeadline(time.Now().Add(6 * time.Minute))
		row, e := s.Backup(c.Request.Context())
		if e == nil {
			middleware.ResourceID(c, row.Name)
		}
		return row, e
	}))
	system.GET("/backups/:name", middleware.Action("system.backup.download", "backup"), func(c *gin.Context) {
		file, e := s.OpenBackup(c.Param("name"))
		if e != nil {
			response.Fail(c, e)
			return
		}
		defer file.Close()
		info, e := file.Stat()
		if e != nil {
			response.Fail(c, apperror.NotFound())
			return
		}
		middleware.ResourceID(c, info.Name())
		c.Header("Content-Disposition", `attachment; filename="`+info.Name()+`"`)
		c.Header("Content-Type", "application/zip")
		c.Header("Content-Length", strconv.FormatInt(info.Size(), 10))
		serveBackup(c, file, info.Name(), info.ModTime(), 5*time.Minute)
	})
}
func runtimeProxy(s *automation.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("public_url", s.Current().PublicURL)
		request := c.Request.Clone(c.Request.Context())
		ip := s.ResolveIP(request.RemoteAddr, request.Header.Get("X-Forwarded-For"), request.Header.Get("X-Real-IP"))
		request.RemoteAddr = net.JoinHostPort(ip, "0")
		c.Request = request
		c.Next()
	}
}

func publicURL(c *gin.Context) string {
	v, _ := c.Get("public_url")
	text, _ := v.(string)
	return text
}

// A route-local absolute deadline bounds slow readers without the ordinary API's
// 30-second WriteTimeout truncating a healthy large download. Range is preserved.
func serveBackup(c *gin.Context, content io.ReadSeeker, name string, modified time.Time, budget time.Duration) {
	_ = http.NewResponseController(c.Writer).SetWriteDeadline(time.Now().Add(budget))
	http.ServeContent(c.Writer, c.Request, name, modified, content)
}
