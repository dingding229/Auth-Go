package httpserver

import (
	"authgo/internal/apidocs"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
)

func registerIntegration(r *gin.Engine, identity *auth.Service) {
	r.GET("/api/v1/admin/integration/protocol", middleware.Authenticate(identity), func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		response.Success(c, gin.H{"text": apidocs.Protocol})
	})
	r.GET("/api/v1/admin/integration/docker", middleware.Authenticate(identity), func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		response.Success(c, gin.H{"text": apidocs.Docker})
	})
}
