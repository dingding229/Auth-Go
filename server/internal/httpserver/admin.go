package httpserver

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/automation"
	"authgo/internal/bootstrap"
	"authgo/internal/catalog"
	"authgo/internal/client"
	"authgo/internal/ipinfo"
	"authgo/internal/licensing"
	"authgo/internal/middleware"
	"authgo/internal/model"
	"authgo/internal/portal"
	"authgo/internal/response"
	"authgo/internal/sharing"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strconv"
	"time"
)

type routerOptions struct {
	sharing    *sharing.Service
	ipinfo     *ipinfo.Service
	setup      *bootstrap.Setup
	portal     *portal.Service
	automation *automation.Service
	client     *client.Service
	auth       *auth.Service
	catalog    *catalog.Service
	licensing  *licensing.Service
	database   *gorm.DB
}
type Option func(*routerOptions)

func WithAdmin(service *auth.Service, database *gorm.DB) Option {
	return func(o *routerOptions) { o.auth = service; o.database = database }
}

type endpoint func(*gin.Context) (any, error)

func handle(fn endpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := fn(c)
		if err != nil {
			response.Fail(c, err)
			return
		}
		response.Success(c, data)
	}
}
func actor(c *gin.Context) auth.Principal { p, _ := middleware.Principal(c); return p }
func parseID(raw string) (uint64, error) {
	id, err := strconv.ParseUint(raw, 10, 63)
	if err != nil || id == 0 {
		return 0, apperror.Invalid("资源 ID 必须为正整数")
	}
	return id, nil
}

func registerAdmin(r *gin.Engine, service *auth.Service, database *gorm.DB, ips *ipinfo.Service) {
	root := r.Group("/api/v1/admin")
	security := root.Group("/auth")
	security.POST("/login", middleware.Action("auth.login", "auth"), handle(func(c *gin.Context) (any, error) {
		var in struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TOTPCode string `json:"totp_code"`
		}
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		if len(in.Username) <= 128 {
			c.Set("audit_operator", in.Username)
		}
		pair, err := service.Login(c.Request.Context(), in.Username, in.Password, in.TOTPCode, c.ClientIP())
		if err == nil {
			middleware.SetPrincipal(c, pair.Principal())
		}
		return pair, err
	}))
	security.POST("/refresh", middleware.Action("auth.refresh", "auth"), handle(func(c *gin.Context) (any, error) {
		var in struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		pair, err := service.Refresh(c.Request.Context(), in.RefreshToken)
		if err == nil {
			middleware.SetPrincipal(c, pair.Principal())
		}
		return pair, err
	}))
	self := security.Group("", middleware.Authenticate(service))
	self.GET("/me", handle(func(c *gin.Context) (any, error) { return service.Me(c.Request.Context(), actor(c)) }))
	self.POST("/logout", middleware.Action("auth.logout", "auth"), handle(func(c *gin.Context) (any, error) { return gin.H{}, service.Logout(c.Request.Context(), actor(c)) }))
	self.POST("/password", middleware.Action("auth.password", "admin"), handle(func(c *gin.Context) (any, error) {
		var in struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
		}
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		middleware.ResourceID(c, strconv.FormatUint(actor(c).AdminID, 10))
		return gin.H{}, service.ChangePassword(c.Request.Context(), actor(c), in.OldPassword, in.NewPassword)
	}))
	self.POST("/totp/setup", middleware.Action("auth.totp.setup", "admin"), handle(func(c *gin.Context) (any, error) {
		var in struct {
			Password string `json:"password"`
		}
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		middleware.ResourceID(c, strconv.FormatUint(actor(c).AdminID, 10))
		return service.SetupTOTP(c.Request.Context(), actor(c), in.Password)
	}))
	self.POST("/totp/enable", middleware.Action("auth.totp.enable", "admin"), handle(func(c *gin.Context) (any, error) {
		var in struct {
			TOTPCode string `json:"totp_code"`
		}
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		middleware.ResourceID(c, strconv.FormatUint(actor(c).AdminID, 10))
		return gin.H{}, service.EnableTOTP(c.Request.Context(), actor(c), in.TOTPCode)
	}))
	self.POST("/totp/disable", middleware.Action("auth.totp.disable", "admin"), handle(func(c *gin.Context) (any, error) {
		var in struct {
			Password string `json:"password"`
			TOTPCode string `json:"totp_code"`
		}
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		middleware.ResourceID(c, strconv.FormatUint(actor(c).AdminID, 10))
		return gin.H{}, service.DisableTOTP(c.Request.Context(), actor(c), in.Password, in.TOTPCode)
	}))
	protected := root.Group("", middleware.Authenticate(service))
	protected.GET("/audit-logs", handle(func(c *gin.Context) (any, error) { return listAudit(c, database, ips) }))
}

type auditInfo struct {
	IPInfo     *ipinfo.Info   `json:"ip_info,omitempty"`
	ID         uint64         `json:"id"`
	CreatedAt  time.Time      `json:"created_at"`
	AdminID    *uint64        `json:"admin_id"`
	Operator   string         `json:"operator"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	ResourceID string         `json:"resource_id"`
	IP         string         `json:"ip"`
	UserAgent  string         `json:"user_agent"`
	Summary    string         `json:"summary"`
	StatusCode int            `json:"status_code"`
	Details    map[string]any `json:"details"`
}

func listAudit(c *gin.Context, database *gorm.DB, ips *ipinfo.Service) (any, error) {
	page, err := response.ParsePage(c.Request.URL.Query())
	if err != nil {
		return nil, err
	}
	q := database.WithContext(c.Request.Context()).Model(&model.AuditLog{})
	for _, field := range []string{"action", "resource", "resource_id", "ip", "operator"} {
		if value := c.Query(field); value != "" {
			if len(value) > 128 {
				return nil, apperror.Invalid("筛选条件过长")
			}
			q = q.Where(field+" = ?", value)
		}
	}
	if raw := c.Query("admin_id"); raw != "" {
		id, err := parseID(raw)
		if err != nil {
			return nil, err
		}
		q = q.Where("admin_id = ?", id)
	}
	if raw := c.Query("status_code"); raw != "" {
		status, err := strconv.Atoi(raw)
		if err != nil || status < 0 || status > 599 {
			return nil, apperror.Invalid("HTTP 状态码无效")
		}
		q = q.Where("status_code = ?", status)
	}
	var from, to *time.Time
	for _, field := range []string{"from", "to"} {
		if raw := c.Query(field); raw != "" {
			value, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return nil, apperror.Invalid("时间筛选必须使用 RFC3339 格式")
			}
			if field == "from" {
				from = &value
				q = q.Where("created_at >= ?", value)
			} else {
				to = &value
				q = q.Where("created_at <= ?", value)
			}
		}
	}
	if from != nil && to != nil && from.After(*to) {
		return nil, apperror.Invalid("开始时间不得晚于结束时间")
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, err
	}
	var rows []model.AuditLog
	if err := q.Order("id DESC").Offset(page.Offset()).Limit(page.Size).Find(&rows).Error; err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(rows))
	for _, a := range rows {
		addresses = append(addresses, a.IP)
	}
	locations := ips.LookupBatch(addresses)
	items := make([]auditInfo, 0, len(rows))
	for _, a := range rows {
		items = append(items, auditInfo{locations[a.IP], a.ID, a.CreatedAt, a.AdminID, a.Operator, a.Action, a.Resource, a.ResourceID, a.IP, a.UserAgent, a.Summary, a.StatusCode, a.Details})
	}
	return page.Data(items, total), nil
}

func WithClient(service *client.Service) Option { return func(o *routerOptions) { o.client = service } }
