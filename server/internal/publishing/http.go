package publishing

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"strconv"
)

type DispatchInput struct {
	Version string `json:"version"`
}

func (s *Service) Register(r *gin.Engine, identity *auth.Service, publicURL func() string) {
	root := r.Group("/api/v1/admin", middleware.Authenticate(identity))
	handle := func(fn func(*gin.Context) (any, error)) gin.HandlerFunc {
		return func(c *gin.Context) {
			v, err := fn(c)
			if err != nil {
				response.Fail(c, err)
				return
			}
			response.Success(c, v)
		}
	}
	root.GET("/system/publishing", handle(func(c *gin.Context) (any, error) { return s.Credentials(c.Request.Context()) }))
	root.PATCH("/system/publishing", middleware.Action("publishing.credentials.update", "system"), handle(func(c *gin.Context) (any, error) {
		var in CredentialsInput
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		return s.SaveCredentials(c.Request.Context(), in)
	}))
	root.POST("/system/publishing/verify", middleware.Action("publishing.credentials.verify", "system"), handle(func(c *gin.Context) (any, error) {
		return s.VerifyCredentials(c.Request.Context())
	}))
	app := root.Group("/applications/:id/publishing")
	wrap := func(fn func(*gin.Context, uint64) (any, error)) gin.HandlerFunc {
		return handle(func(c *gin.Context) (any, error) {
			id, err := strconv.ParseUint(c.Param("id"), 10, 63)
			if err != nil || id == 0 {
				return nil, apperror.Invalid("软件编号无效")
			}
			v, err := s.Config(c.Request.Context(), id)
			if err != nil {
				return nil, err
			}
			// Repository identifiers are validated before persistence and contain no credentials.
			if v.Repository != "" {
				c.Set("audit_resource", "github:"+v.Repository)
			}
			return fn(c, id)
		})
	}
	app.GET("", wrap(func(c *gin.Context, id uint64) (any, error) { return s.Config(c.Request.Context(), id) }))
	app.PATCH("", middleware.Action("publishing.config.save", "application"), wrap(func(c *gin.Context, id uint64) (any, error) {
		var in Config
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		v, err := s.SaveConfig(c.Request.Context(), id, in)
		if err == nil {
			c.Set("audit_resource", "github:"+v.Repository)
		}
		return v, err
	}))
	app.GET("/workflow", wrap(func(c *gin.Context, id uint64) (any, error) {
		v, err := s.Preview(c.Request.Context(), id)
		return gin.H{"workflow": v}, err
	}))
	app.POST("/test", middleware.Action("publishing.connection.test", "application"), wrap(func(c *gin.Context, id uint64) (any, error) { return gin.H{}, s.Test(c.Request.Context(), id) }))
	app.POST("/sync", middleware.Action("publishing.repository.sync", "application"), wrap(func(c *gin.Context, id uint64) (any, error) {
		return gin.H{}, s.Sync(c.Request.Context(), id, publicURL())
	}))
	app.POST("/dispatch", middleware.Action("publishing.workflow.dispatch", "application"), wrap(func(c *gin.Context, id uint64) (any, error) {
		var in DispatchInput
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		return gin.H{}, s.Dispatch(c.Request.Context(), id, publicURL(), in.Version)
	}))
	app.GET("/runs", wrap(func(c *gin.Context, id uint64) (any, error) {
		runs, err := s.Runs(c.Request.Context(), id)
		return gin.H{"items": runs}, err
	}))
}
