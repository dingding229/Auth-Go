package middleware

import (
	"authgo/internal/apperror"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"net/http"
)

// BodyLimit replaces the former nginx ceiling, including chunked request bodies.
// Endpoint-specific parsers can impose stricter bounds.
func BodyLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := int64(32 << 20)
		if c.Request.Method == http.MethodPost && (c.Request.URL.Path == "/api/v1/admin/system/ip-info/city" || c.Request.URL.Path == "/api/v1/admin/system/ip-info/asn") {
			limit = 513 << 20
		}
		if c.Request.ContentLength > limit {
			response.Fail(c, apperror.New(http.StatusRequestEntityTooLarge, "INVALID_REQUEST", "请求体过大"))
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}
