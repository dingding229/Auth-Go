package middleware

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

const principalKey = "admin_principal"

func SetPrincipal(c *gin.Context, p auth.Principal) { c.Set(principalKey, p) }
func Principal(c *gin.Context) (auth.Principal, bool) {
	v, ok := c.Get(principalKey)
	if !ok {
		return auth.Principal{}, false
	}
	p, ok := v.(auth.Principal)
	return p, ok
}
func Bearer(c *gin.Context) (string, bool) {
	header := c.GetHeader("Authorization")
	parts := strings.Fields(header)
	if len(header) > 8192 || len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}
func Authenticate(service *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := Principal(c); ok {
			c.Next()
			return
		}
		if prior, ok := c.Get("admin_auth_error"); ok {
			response.Fail(c, prior.(error))
			return
		}
		raw, ok := Bearer(c)
		if !ok {
			response.Fail(c, apperror.Unauthorized())
			return
		}
		p, err := service.Authenticate(c.Request.Context(), raw)
		if err != nil {
			response.Fail(c, err)
			return
		}
		SetPrincipal(c, p)
		c.Next()
	}
}

func ReadOnlyMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}
