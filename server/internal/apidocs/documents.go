package apidocs

import (
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/response"

	"github.com/gin-gonic/gin"
)

// RegisterDocuments serves embedded documentation only to authenticated administrators.
func RegisterDocuments(r *gin.Engine, identity *auth.Service) {
	for _, document := range []struct {
		path string
		text string
	}{
		{"/api/v1/admin/integration/protocol", Protocol},
		{"/api/v1/admin/integration/docker", Docker},
		{"/api/v1/admin/integration/quickstart", Quickstart},
		{"/api/v1/admin/integration/customer", Customer},
		{"/api/v1/admin/integration/offline", Offline},
	} {
		r.GET(document.path, middleware.Authenticate(identity), func(c *gin.Context) {
			c.Header("Cache-Control", "no-store")
			response.Success(c, gin.H{"text": document.text})
		})
	}
}
