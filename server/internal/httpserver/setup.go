package httpserver

import (
	"authgo/internal/adminpath"
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/bootstrap"
	"authgo/internal/middleware"
	"authgo/internal/model"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"net/http"
	"strconv"
)

func WithSetup(s *bootstrap.Setup) Option { return func(o *routerOptions) { o.setup = s } }
func registerSetup(r *gin.Engine, identity *auth.Service, database *gorm.DB, setup *bootstrap.Setup) {
	root := r.Group("/api/v1/admin/auth")
	status := handle(func(c *gin.Context) (any, error) {
		var n int64
		err := database.WithContext(c.Request.Context()).Model(&model.Admin{}).Count(&n).Error
		return gin.H{"initialized": n > 0, "setup_required": n == 0, "admin_path": adminpath.Path(c.Request)}, err
	})
	r.GET("/api/v1/admin/status", status)

	root.POST("/setup", middleware.Action("auth.setup", "admin"), handle(func(c *gin.Context) (any, error) {
		if setup == nil {
			return nil, apperror.New(http.StatusNotFound, "SETUP_UNAVAILABLE", "初始化入口已关闭")
		}
		if available, err := setup.Available(c.Request.Context()); err != nil {
			return nil, err
		} else if !available {
			return nil, apperror.New(404, "SETUP_UNAVAILABLE", "初始化入口已关闭")
		}
		var in struct {
			Token    string `json:"token"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		pair, err := identity.Setup(c.Request.Context(), setup, in.Token, in.Username, in.Password, c.ClientIP())
		if err == nil {
			middleware.SetPrincipal(c, pair.Principal())
			middleware.ResourceID(c, strconv.FormatUint(pair.Admin.ID, 10))
		}
		return pair, err
	}))
}
