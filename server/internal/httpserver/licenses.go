package httpserver

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/licensing"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

func WithLicensing(service *licensing.Service) Option {
	return func(o *routerOptions) { o.licensing = service }
}
func licenseFilter(c *gin.Context) (licensing.Filter, error) {
	q, err := response.ParseList(c.Request.URL.Query(), "id", "key", "created_at", "updated_at", "expires_at", "type", "status", "app_id")
	if err != nil {
		return licensing.Filter{}, err
	}
	f := licensing.Filter{Query: q, Status: c.Query("status"), Type: c.Query("type"), BatchID: c.Query("batch_id"), Source: c.Query("source")}
	if c.Query("suspected_sharing") != "" {
		if c.Query("suspected_sharing") != "true" && c.Query("suspected_sharing") != "false" {
			return f, apperror.Invalid("疑似共享筛选必须为 true 或 false")
		}
		f.SuspectedSharing = c.Query("suspected_sharing") == "true"
	}
	for field, target := range map[string]**uint64{"app_id": &f.AppID, "user_id": &f.UserID} {
		if c.Request.URL.Query().Has(field) {
			id, err := parseID(c.Query(field))
			if err != nil {
				return f, err
			}
			*target = &id
		}
	}
	if f.Source != "" && f.Source != "self_trial" {
		return f, apperror.Invalid("授权来源无效")
	}
	if f.Status != "" {
		switch f.Status {
		case "unused", "active", "expired", "suspended", "revoked":
		default:
			return f, apperror.Invalid("状态筛选无效")
		}
	}
	if f.Type != "" {
		switch f.Type {
		case "trial", "standard", "subscription", "perpetual", "floating":
		default:
			return f, apperror.Invalid("类型筛选无效")
		}
	}
	if len(f.BatchID) > 128 {
		return f, apperror.Invalid("批次号过长")
	}
	for field, target := range map[string]**time.Time{"expires_from": &f.ExpiresFrom, "expires_to": &f.ExpiresTo} {
		if c.Request.URL.Query().Has(field) {
			at, err := time.Parse(time.RFC3339, c.Query(field))
			if err != nil {
				return f, apperror.Invalid("到期区间必须为 RFC3339")
			}
			at = at.UTC()
			*target = &at
		}
	}
	if f.ExpiresFrom != nil && f.ExpiresTo != nil && f.ExpiresFrom.After(*f.ExpiresTo) {
		return f, apperror.Invalid("到期区间开始不得晚于结束")
	}
	return f, nil
}
func readCSV(c *gin.Context) ([]byte, error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, licensing.MaxCSVBytes+(64<<10))
	content, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil && c.GetHeader("Content-Type") != "" {
		return nil, apperror.Invalid("Content-Type 无效")
	}
	read := func(r io.Reader) ([]byte, error) {
		raw, err := io.ReadAll(io.LimitReader(r, licensing.MaxCSVBytes+1))
		if err != nil {
			var max *http.MaxBytesError
			if errors.As(err, &max) {
				return nil, apperror.New(413, "CSV_TOO_LARGE", "CSV 文件过大")
			}
			return nil, apperror.Invalid("无法读取 CSV")
		}
		if len(raw) > licensing.MaxCSVBytes {
			return nil, apperror.New(413, "CSV_TOO_LARGE", "CSV 不得超过 16 MiB")
		}
		return raw, nil
	}
	if content == "multipart/form-data" {
		reader, err := c.Request.MultipartReader()
		if err != nil {
			return nil, apperror.Invalid("multipart 格式无效")
		}
		var data []byte
		found := false
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, apperror.Invalid("multipart 文件无效")
			}
			if part.FormName() != "file" || found {
				_ = part.Close()
				return nil, apperror.Invalid("仅允许一个名为 file 的 CSV 文件")
			}
			data, err = read(part)
			_ = part.Close()
			if err != nil {
				return nil, err
			}
			found = true
		}
		if !found {
			return nil, apperror.Invalid("缺少 CSV 文件")
		}
		return data, nil
	}
	if content != "" && content != "text/csv" && content != "application/csv" && content != "application/octet-stream" {
		return nil, apperror.New(415, "UNSUPPORTED_MEDIA_TYPE", "请提交 text/csv 或 multipart file")
	}
	return read(c.Request.Body)
}
func registerLicensing(r *gin.Engine, s *licensing.Service, identity *auth.Service) {
	root := r.Group("/api/v1/admin", middleware.Authenticate(identity))
	licenses := root.Group("/licenses")
	licenses.GET("", handle(func(c *gin.Context) (any, error) {
		f, err := licenseFilter(c)
		if err != nil {
			return nil, err
		}
		rows, total, err := s.List(c.Request.Context(), f)
		return f.Query.Data(rows, total), err
	}))
	licenses.POST("", middleware.Action("license.create", "license"), handle(func(c *gin.Context) (any, error) {
		var in licensing.CreateInput
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		l, err := s.Create(c.Request.Context(), in)
		if err == nil {
			markResource(c, l.ID)
		}
		return l, err
	}))
	licenses.PATCH("/:id", middleware.Action("license.assign", "license"), handle(func(c *gin.Context) (any, error) {
		id, err := parseID(c.Param("id"))
		if err != nil {
			return nil, err
		}
		var raw map[string]json.RawMessage
		if err := response.BindJSON(c, &raw); err != nil {
			return nil, err
		}
		value, ok := raw["user_id"]
		if !ok || len(raw) != 1 {
			return nil, apperror.Invalid("仅允许user_id字段，null表示未分配")
		}
		var in licensing.AssignmentInput
		if err := json.Unmarshal(value, &in.UserID); err != nil {
			return nil, apperror.Invalid("user_id格式无效")
		}

		return s.Assign(c.Request.Context(), id, in)
	}))

	licenses.POST("/batch", middleware.Action("license.batch", "license_batch"), handle(func(c *gin.Context) (any, error) {
		var in licensing.BatchInput
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		batch, err := s.Batch(c.Request.Context(), in)
		if err == nil {
			middleware.ResourceID(c, batch.BatchID)
		}
		return batch, err
	}))
	export := func(c *gin.Context) {
		f, err := licenseFilter(c)
		if err != nil {
			response.Fail(c, err)
			return
		}
		if batch := c.Param("batch_id"); batch != "" {
			if len(batch) != 30 || !strings.HasPrefix(batch, "batch_") {
				response.Fail(c, apperror.Invalid("批次号无效"))
				return
			}
			f.BatchID = batch
		}
		raw, err := s.Export(c.Request.Context(), f)
		if err != nil {
			response.Fail(c, err)
			return
		}
		c.Header("Content-Disposition", `attachment; filename="authgo-licenses.csv"`)
		c.Data(200, "text/csv; charset=utf-8", raw)
	}
	licenses.GET("/export", export)
	licenses.GET("/batches/:batch_id/export", export)
	licenses.POST("/import", middleware.Action("license.import", "license_batch"), handle(func(c *gin.Context) (any, error) {
		raw, err := readCSV(c)
		if err != nil {
			return nil, err
		}
		report, err := s.Import(c.Request.Context(), raw)
		if err == nil && report.BatchID != "" {
			middleware.ResourceID(c, report.BatchID)
		}
		return report, err
	}))
	licenses.GET("/:id", handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		return s.Get(c.Request.Context(), id)
	}))
	licenses.POST("/:id/renew", middleware.Action("license.renew", "license"), handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		var in licensing.RenewInput
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		return s.Renew(c.Request.Context(), id, in)
	}))
	for _, action := range []string{"suspend", "resume", "revoke"} {
		licenses.POST("/:id/"+action, middleware.Action("license."+action, "license"), handle(func(c *gin.Context) (any, error) {
			id, err := catalogID(c)
			if err != nil {
				return nil, err
			}
			return s.ChangeState(c.Request.Context(), id, action)
		}))
	}
	licenses.POST("/:id/portal-password", middleware.Action("license.portal_password", "license"), handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		var in struct {
			Password *string `json:"password"`
		}
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		if in.Password == nil {
			return nil, apperror.Invalid("必须提供 password，空字符串表示清除")
		}
		return gin.H{}, s.SetPortalPassword(c.Request.Context(), id, *in.Password)
	}))
	activationList := handle(func(c *gin.Context) (any, error) {
		q, err := response.ParseList(c.Request.URL.Query(), "id", "created_at", "last_seen_at", "hostname", "status")
		if err != nil {
			return nil, err
		}
		var id *uint64
		if value := c.Param("id"); value != "" {
			n, err := parseID(value)
			if err != nil {
				return nil, err
			}
			id = &n
		} else if c.Request.URL.Query().Has("license_id") {
			n, err := parseID(c.Query("license_id"))
			if err != nil {
				return nil, err
			}
			id = &n
		}
		userID, e := optionalID(c, "user_id")
		if e != nil {
			return nil, e
		}
		rows, total, err := s.ListActivations(c.Request.Context(), q, id, licensing.ActivationFilter{UserID: userID, Kind: c.Query("kind")})
		return q.Data(rows, total), err
	})
	licenses.GET("/:id/activations", activationList)
	root.GET("/activations", activationList)
	root.POST("/activations/:id/release-seat", middleware.Action("activation.release-seat", "activation"), handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		return s.ReleaseSeat(c.Request.Context(), id)
	}))
	for _, action := range []string{"unbind", "offline"} {
		root.POST("/activations/:id/"+action, middleware.Action("activation."+action, "activation"), handle(func(c *gin.Context) (any, error) {
			id, err := catalogID(c)
			if err != nil {
				return nil, err
			}
			return s.ManageActivation(c.Request.Context(), id, action == "unbind")
		}))
	}
}
