package middleware

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/netpolicy"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"strings"
	"sync"
	"time"
)

type anonymousBudget struct {
	tokens float64
	at     time.Time
}

// AdminRequests resolves authentication before audit and bounds anonymous work.
// Missing routes never authenticate or write audit rows, even with a supplied bearer.
func AdminRequests(identity *auth.Service) gin.HandlerFunc {
	var mu sync.Mutex
	entries := map[string]anonymousBudget{}
	lastSweep := time.Time{}
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
		now := time.Now()
		key := netpolicy.SourceKey(c.ClientIP())
		mu.Lock()
		if now.Sub(lastSweep) >= time.Minute {
			for k, v := range entries {
				if now.Sub(v.at) > time.Minute {
					delete(entries, k)
				}
			}
			lastSweep = now
		}
		v, ok := entries[key]
		allowed := true
		if !ok {
			if len(entries) >= 10000 {
				allowed = false
			} else {
				v = anonymousBudget{tokens: 30, at: now}
			}
		}
		if allowed {
			v.tokens = min(30, v.tokens+now.Sub(v.at).Seconds()*5)
			v.at = now
			allowed = v.tokens >= 1
			if allowed {
				v.tokens--
			}
			entries[key] = v
		}
		mu.Unlock()
		if !allowed {
			response.Fail(c, apperror.New(429, "RATE_LIMITED", "未认证管理请求过于频繁，请稍后再试"))
			return
		}
		c.Next()
	}
}
