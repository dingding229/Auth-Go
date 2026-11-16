package httpserver

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/automation"
	"authgo/internal/backupfile"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"io"
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
	system.GET("/settings", handle(func(c *gin.Context) (any, error) { return s.ReadSettings(c.Request.Context()) }))
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
		if e != nil {
			return nil, e
		}
		status, e := s.BackupStatus(c.Request.Context())
		return gin.H{"items": rows, "total": len(rows), "status": status}, e
	}))
	system.POST("/backups", middleware.Action("system.backup.create", "backup"), handle(func(c *gin.Context) (any, error) {
		_ = http.NewResponseController(c.Writer).SetWriteDeadline(time.Now().Add(6 * time.Minute))
		row, e := s.Backup(c.Request.Context())
		if e == nil {
			middleware.ResourceID(c, row.Name)
		}
		return row, e
	}))
	system.GET("/backups/:name", middleware.Action("system.backup.download", "backup"), func(c *gin.Context) { downloadBackup(c, s, "") })
	system.POST("/backups/:name/export", middleware.Action("system.backup.download", "backup"), func(c *gin.Context) {
		var input automation.BackupExportInput
		if err := response.BindJSON(c, &input); err != nil {
			response.Fail(c, err)
			return
		}
		downloadBackup(c, s, input.Password)
	})
}
func downloadBackup(c *gin.Context, s *automation.Service, password string) {
	encrypted := password != ""
	c.Set("audit_backup_encrypted", encrypted)
	if encrypted {
		if err := backupfile.ValidatePassword(password); err != nil {
			response.Fail(c, apperror.Invalid(err.Error()))
			return
		}
	}
	file, err := s.OpenBackup(c.Param("name"))
	if err != nil {
		response.Fail(c, err)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		response.Fail(c, apperror.NotFound())
		return
	}
	middleware.ResourceID(c, info.Name())
	name := info.Name()
	if encrypted {
		size, sizeErr := backupfile.EncryptedSize(info.Size())
		if sizeErr != nil {
			response.Fail(c, apperror.Invalid(sizeErr.Error()))
			return
		}
		name += ".enc"
		c.Header("Content-Length", strconv.FormatInt(size, 10))
		c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
		c.Header("Content-Type", "application/octet-stream")
		_ = http.NewResponseController(c.Writer).SetWriteDeadline(time.Now().Add(5 * time.Minute))
		if err = backupfile.Encrypt(c.Writer, file, password); err == nil && int64(c.Writer.Size()) == size && c.Request.Context().Err() == nil {
			s.RecordBackupDownload()
		} else {
			c.Set("response_code", "INTERNAL_ERROR")
			if !c.Writer.Written() {
				c.Writer.Header().Del("Content-Length")
				c.Writer.Header().Del("Content-Disposition")
				c.Writer.Header().Del("Content-Type")
				response.Fail(c, apperror.New(500, "INTERNAL_ERROR", "备份导出失败，请重试"))
			}
			c.Abort()
		}
		return
	}
	c.Header("Content-Disposition", `attachment; filename="`+name+`"`)
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Length", strconv.FormatInt(info.Size(), 10))
	serveBackup(c, file, name, info.ModTime(), 5*time.Minute)
	if c.Request.Method != "HEAD" && c.Writer.Status() == 200 && int64(c.Writer.Size()) == info.Size() && c.Request.Context().Err() == nil {
		s.RecordBackupDownload()
	}
}

func runtimeProxy(s *automation.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("public_url", s.Current().PublicURL)
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
