package middleware

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"log/slog"
	"strings"
	"time"
)

func Action(action, resource string) gin.HandlerFunc {
	return func(c *gin.Context) { c.Set("audit_action", action); c.Set("audit_resource", resource); c.Next() }
}
func ResourceID(c *gin.Context, id string) { c.Set("audit_resource_id", id) }
func clip(value string, n int) string {
	r := []rune(value)
	if len(r) > n {
		return string(r[:n])
	}
	return value
}

// Audit records intent BEFORE dispatch (fail closed on DB failure). Completion
// uses an independent timeout so client cancellation cannot erase the evidence.
// Passwords, request/response bodies and Authorization headers are never read.
func Audit(database *gorm.DB, log *slog.Logger, auditedReads ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if c.FullPath() == "" || (path != "/api/v1/admin" && !strings.HasPrefix(path, "/api/v1/admin/")) {
			c.Next()
			return
		}
		c.Header("Cache-Control", "no-store")
		principal, authenticated := Principal(c)
		if !authenticated || c.FullPath() == "" {
			c.Next()
			return
		}
		auditRead := false
		for _, route := range auditedReads {
			if route == c.Request.Method+" "+c.FullPath() {
				auditRead = true
				break
			}
		}
		if ReadOnlyMethod(c.Request.Method) && !auditRead {
			c.Next()
			return
		}
		route := c.FullPath()
		if route == "" {
			route = "未匹配路由"
		}
		adminID := principal.AdminID
		entry := model.AuditLog{AdminID: &adminID, Action: c.Request.Method + " " + route, Resource: "admin_api", IP: clip(c.ClientIP(), 128), UserAgent: clip(c.Request.UserAgent(), 512), Operator: principal.Username, Summary: "请求处理中"}
		if err := database.WithContext(c.Request.Context()).Create(&entry).Error; err != nil {
			log.Error("无法写入管理操作审计，已阻止执行", "error", err)
			response.Fail(c, apperror.New(503, "AUDIT_UNAVAILABLE", "审计服务暂不可用，请稍后重试"))
			return
		}
		defer func() {
			status := c.Writer.Status()
			code := c.GetString("response_code")
			if code == "" {
				code = "OK"
			}
			if action := c.GetString("audit_action"); action != "" {
				entry.Action = action
			}
			if resource := c.GetString("audit_resource"); resource != "" {
				entry.Resource = resource
			}
			entry.ResourceID = c.GetString("audit_resource_id")
			if entry.ResourceID == "" {
				entry.ResourceID = c.Param("id")
			}
			entry.ResourceID = clip(entry.ResourceID, 128)
			if p, ok := Principal(c); ok {
				id := p.AdminID
				entry.AdminID = &id
				entry.Operator = p.Username
				entry.Details = map[string]any{"code": code}
			} else {
				entry.Details = map[string]any{"code": code}
				if name := c.GetString("audit_operator"); name != "" {
					entry.Operator = clip(name, 128)
				}
			}
			entry.StatusCode = status
			entry.Summary = fmt.Sprintf("%s %s → %d (%s)", c.Request.Method, route, status, code)
			// A panic has not yet reached the outer recovery middleware. Keep the
			// persisted intent marked incomplete rather than claiming a 200 success.
			if value := recover(); value != nil {
				entry.StatusCode = 500
				entry.Summary = "管理请求发生异常"
				entry.Details = map[string]any{"code": "INTERNAL_ERROR"}
				finishAudit(database, log, &entry)
				panic(value)
			}
			finishAudit(database, log, &entry)
		}()
		c.Next()
	}
}
func finishAudit(database *gorm.DB, log *slog.Logger, entry *model.AuditLog) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := database.WithContext(ctx).Model(entry).Select("admin_id", "operator", "action", "resource", "resource_id", "summary", "status_code", "details").Updates(entry).Error; err != nil {
		log.Error("审计完成记录失败，已保留请求意图", "audit_id", entry.ID, "error", err)
	}
}
