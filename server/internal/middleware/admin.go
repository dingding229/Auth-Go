package middleware

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/netpolicy"
	"authgo/internal/ratelimit"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"strings"
	"time"
)

// AdminRequests resolves authentication before audit and bounds anonymous work.
// Missing routes never authenticate or write audit rows, even with a supplied bearer.
func AdminRequests(identity *auth.Service) gin.HandlerFunc {
	limiter := ratelimit.New(ratelimit.Options{Rate: 5, Burst: 30, Capacity: 10000, IdleTTL: time.Minute, SweepInterval: time.Minute})
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if c.FullPath() == "" || (path != "/api/v1/admin" && !strings.HasPrefix(path, "/api/v1/admin/")) {
			c.Next()
			return
		}
		c.Header("Cache-Control", "no-store")
		if c.FullPath() != "" {
			if raw, ok := Bearer(c); ok {
				principal, err := identity.Authenticate(c.Request.Context(), raw)
				if err == nil {
					SetPrincipal(c, principal)
					c.Next()
					return
				}
				// Preserve authentication errors for the route guard without a second DB lookup.
				c.Set("admin_auth_error", err)
			}
		}
		allowed := limiter.Allow(netpolicy.SourceKey(c.ClientIP()), time.Now())
		if !allowed {
			response.Fail(c, apperror.New(429, "RATE_LIMITED", "未认证管理请求过于频繁，请稍后再试"))
			return
		}
		c.Next()
	}
}
