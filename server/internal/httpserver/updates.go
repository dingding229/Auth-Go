package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"authgo/internal/updater"
	"github.com/gin-gonic/gin"
)

func registerUpdates(r *gin.Engine, s *updater.Service, identity *auth.Service) {
	root := r.Group("/api/v1/admin", middleware.Authenticate(identity))
	root.GET("/system/updates", handle(func(c *gin.Context) (any, error) { return s.CurrentSettings() }))
	root.PATCH("/system/updates", middleware.Action("system.updates.save", "system"), handle(func(c *gin.Context) (any, error) {
		var in updater.Settings
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		return gin.H{}, s.SaveSettings(c.Request.Context(), in)
	}))
}
