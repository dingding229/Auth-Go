package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/catalog"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
)

func registerReleases(r *gin.Engine, service *catalog.Service, identity *auth.Service) {
	root := r.Group("/api/v1/admin", middleware.Authenticate(identity))
	root.GET("/applications/:id/announcements", withID(func(c *gin.Context, id uint64) (any, error) {
		q, e := response.ParseList(c.Request.URL.Query(), "id", "title", "published_at", "created_at", "updated_at")
		if e != nil {
			return nil, e
		}
		v, n, e := service.ListAnnouncements(c.Request.Context(), id, q)
		return q.Data(v, n), e
	}))
	root.POST("/applications/:id/announcements", middleware.Action("announcement.create", "announcement"), withIDBody(func(c *gin.Context, id uint64, in catalog.AnnouncementInput) (any, error) {
		v, e := service.CreateAnnouncement(c.Request.Context(), id, in)
		created(c, v.ID, e)
		return v, e
	}))
	root.GET("/announcements/:id", withID(func(c *gin.Context, id uint64) (any, error) {
		return service.GetAnnouncement(c.Request.Context(), id)
	}))
	root.PATCH("/announcements/:id", middleware.Action("announcement.update", "announcement"), withIDBody(func(c *gin.Context, id uint64, in catalog.AnnouncementInput) (any, error) {
		return service.UpdateAnnouncement(c.Request.Context(), id, in)
	}))
	root.DELETE("/announcements/:id", middleware.Action("announcement.delete", "announcement"), withID(func(c *gin.Context, id uint64) (any, error) {
		return gin.H{}, service.DeleteAnnouncement(c.Request.Context(), id)
	}))
	root.GET("/applications/:id/versions", withID(func(c *gin.Context, id uint64) (any, error) {
		q, e := response.ParseList(c.Request.URL.Query(), "id", "version", "published_at", "created_at", "updated_at")
		if e != nil {
			return nil, e
		}
		v, n, e := service.ListVersions(c.Request.Context(), id, q)
		return q.Data(v, n), e
	}))
	root.POST("/applications/:id/versions", middleware.Action("version.create", "app_version"), withIDBody(func(c *gin.Context, id uint64, in catalog.VersionInput) (any, error) {
		v, e := service.CreateVersion(c.Request.Context(), id, in)
		created(c, v.ID, e)
		return v, e
	}))
	root.GET("/versions/:id", withID(func(c *gin.Context, id uint64) (any, error) {
		return service.GetVersion(c.Request.Context(), id)
	}))
	root.PATCH("/versions/:id", middleware.Action("version.update", "app_version"), withIDBody(func(c *gin.Context, id uint64, in catalog.VersionInput) (any, error) {
		return service.UpdateVersion(c.Request.Context(), id, in)
	}))
	root.DELETE("/versions/:id", middleware.Action("version.delete", "app_version"), withID(func(c *gin.Context, id uint64) (any, error) {
		return gin.H{}, service.DeleteVersion(c.Request.Context(), id)
	}))
}
