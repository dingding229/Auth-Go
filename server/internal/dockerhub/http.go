package dockerhub

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"strconv"
)

// Register mounts management operations using the same authentication/audit
// middleware as repository settings. No Hub host or credentials are inputs.
func (s *Service) Register(r *gin.Engine, identity *auth.Service) {
	root := r.Group("/api/v1/admin/applications/:id/dockerhub", middleware.Authenticate(identity))
	wrap := func(fn func(*gin.Context, uint64) (any, error)) gin.HandlerFunc {
		return func(c *gin.Context) {
			id, err := strconv.ParseUint(c.Param("id"), 10, 64)
			if err != nil || id == 0 {
				response.Fail(c, apperror.Invalid("软件编号无效"))
				return
			}
			value, err := fn(c, id)
			if err != nil {
				response.Fail(c, err)
				return
			}
			response.Success(c, value)
		}
	}
	root.GET("", wrap(func(c *gin.Context, id uint64) (any, error) { return s.Status(c.Request.Context(), id) }))
	root.POST("/test", middleware.Action("dockerhub.test", "application"), wrap(func(c *gin.Context, id uint64) (any, error) { return s.TestConnection(c.Request.Context(), id) }))
	root.POST("/sync", middleware.Action("dockerhub.sync", "application"), wrap(func(c *gin.Context, id uint64) (any, error) {
		return s.StartSync(c.Request.Context(), id)
	}))
}
