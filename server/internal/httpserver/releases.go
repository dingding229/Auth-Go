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
	root.GET("/applications/:id/announcements", handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		q, e := response.ParseList(c.Request.URL.Query(), "id", "title", "published_at", "created_at", "updated_at")
		if e != nil {
			return nil, e
		}
		v, n, e := service.ListAnnouncements(c.Request.Context(), id, q)
		return q.Data(v, n), e
	}))
	root.POST("/applications/:id/announcements", middleware.Action("announcement.create", "announcement"), handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		var in catalog.AnnouncementInput
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		v, e := service.CreateAnnouncement(c.Request.Context(), id, in)
		if e == nil {
			markResource(c, v.ID)
		}
		return v, e
	}))
	root.GET("/announcements/:id", handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		return service.GetAnnouncement(c.Request.Context(), id)
	}))
	root.PATCH("/announcements/:id", middleware.Action("announcement.update", "announcement"), handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		var in catalog.AnnouncementInput
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		return service.UpdateAnnouncement(c.Request.Context(), id, in)
	}))
	root.DELETE("/announcements/:id", middleware.Action("announcement.delete", "announcement"), handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		return gin.H{}, service.DeleteAnnouncement(c.Request.Context(), id)
	}))
	root.GET("/applications/:id/versions", handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		q, e := response.ParseList(c.Request.URL.Query(), "id", "version", "published_at", "created_at", "updated_at")
		if e != nil {
			return nil, e
		}
		v, n, e := service.ListVersions(c.Request.Context(), id, q)
		return q.Data(v, n), e
	}))
	root.POST("/applications/:id/versions", middleware.Action("version.create", "app_version"), handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		var in catalog.VersionInput
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		v, e := service.CreateVersion(c.Request.Context(), id, in)
		if e == nil {
			markResource(c, v.ID)
		}
		return v, e
	}))
	root.GET("/versions/:id", handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		return service.GetVersion(c.Request.Context(), id)
	}))
	root.PATCH("/versions/:id", middleware.Action("version.update", "app_version"), handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		var in catalog.VersionInput
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		return service.UpdateVersion(c.Request.Context(), id, in)
	}))
	root.DELETE("/versions/:id", middleware.Action("version.delete", "app_version"), handle(func(c *gin.Context) (any, error) {
		id, e := catalogID(c)
		if e != nil {
			return nil, e
		}
		return gin.H{}, service.DeleteVersion(c.Request.Context(), id)
	}))
}
