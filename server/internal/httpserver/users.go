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
	root.POST("", middleware.Action("user.create", "user"), withBody(func(c *gin.Context, in enduser.Input) (any, error) {
		v, e := s.Create(c.Request.Context(), in)
		created(c, v.ID, e)
		return v, e
	}))
	root.GET("/:id", withID(func(c *gin.Context, id uint64) (any, error) {
		return s.Get(c.Request.Context(), id)
	}))
	root.PATCH("/:id", middleware.Action("user.update", "user"), withIDBody(func(c *gin.Context, id uint64, in enduser.Input) (any, error) {
		return s.Update(c.Request.Context(), id, in)
	}))
	root.DELETE("/:id", middleware.Action("user.delete", "user"), withID(func(c *gin.Context, id uint64) (any, error) {
		return gin.H{}, s.Delete(c.Request.Context(), id)
	}))
}
