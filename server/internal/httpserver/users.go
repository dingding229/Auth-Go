package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/enduser"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerUsers(r *gin.Engine, db *gorm.DB, identity *auth.Service) {
	s := enduser.Service{DB: db}
	root := r.Group("/api/v1/admin/users", middleware.Authenticate(identity))
	root.GET("", handle(func(c *gin.Context) (any, error) {
		q, e := response.ParseList(c.Request.URL.Query(), "id", "name", "email", "created_at", "updated_at")
		if e != nil {
			return nil, e
		}
		items, n, e := s.List(c.Request.Context(), q, c.Query("status"))
		return q.Data(items, n), e
	}))
	root.POST("", middleware.Action("user.create", "user"), handle(func(c *gin.Context) (any, error) {
		var in enduser.Input
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		v, e := s.Create(c.Request.Context(), in)
		if e == nil {
			markResource(c, v.ID)
		}
		return v, e
	}))
	root.GET("/:id", handle(func(c *gin.Context) (any, error) {
		id, e := parseID(c.Param("id"))
		if e != nil {
			return nil, e
		}
		return s.Get(c.Request.Context(), id)
	}))
	root.PATCH("/:id", middleware.Action("user.update", "user"), handle(func(c *gin.Context) (any, error) {
		id, e := parseID(c.Param("id"))
		if e != nil {
			return nil, e
		}
		var in enduser.Input
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		return s.Update(c.Request.Context(), id, in)
	}))
	root.DELETE("/:id", middleware.Action("user.delete", "user"), handle(func(c *gin.Context) (any, error) {
		id, e := parseID(c.Param("id"))
		if e != nil {
			return nil, e
		}
		return gin.H{}, s.Delete(c.Request.Context(), id)
	}))
}
