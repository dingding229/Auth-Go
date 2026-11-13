package adminpath

import (
	"authgo/internal/apidocs"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
)

// RegisterDocs exposes the management contract only through the existing bearer
// transport. There is no extra cookie, public bootstrap endpoint or URL token.
func (s *Service) RegisterDocs(r *gin.Engine, identity *auth.Service) {
	root := r.Group(CanonicalAPI+"/docs", middleware.Authenticate(identity))
	root.GET("/openapi.json", func(c *gin.Context) {
		doc, err := apidocs.Specification(true, "/api/v1"+Path(c.Request))
		if err != nil {
			response.Fail(c, err)
			return
		}
		response.Success(c, doc)
	})
	root.GET("/openapi.yaml", func(c *gin.Context) {
		raw, err := apidocs.SpecificationBytes(true, "/api/v1"+Path(c.Request), true)
		if err != nil {
			response.Fail(c, err)
			return
		}
		c.Header("Content-Type", "application/yaml; charset=utf-8")
		c.Data(200, "application/yaml; charset=utf-8", raw)
	})
}
