package httpserver

import (
	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/catalog"
	"authgo/internal/integration"
	"authgo/internal/middleware"
	"authgo/internal/response"
	"fmt"
	"github.com/gin-gonic/gin"
	"strconv"
)

const applicationSecretRoute = "/api/v1/admin/applications/:id/secret"

func WithCatalog(service *catalog.Service) Option {
	return func(o *routerOptions) { o.catalog = service }
}
func catalogID(c *gin.Context) (uint64, error) { return parseID(c.Param("id")) }
func markResource(c *gin.Context, id uint64)   { middleware.ResourceID(c, strconv.FormatUint(id, 10)) }

func registerCatalog(r *gin.Engine, service *catalog.Service, identity *auth.Service) {
	root := r.Group("/api/v1/admin", middleware.Authenticate(identity))
	applications := root.Group("/applications")
	applications.GET("", handle(func(c *gin.Context) (any, error) {
		q, err := response.ParseList(c.Request.URL.Query(), "id", "name", "app_key", "status", "created_at", "updated_at")
		if err != nil {
			return nil, err
		}
		items, total, err := service.ListApplications(c.Request.Context(), q, c.Query("status"))
		return q.Data(items, total), err
	}))
	applications.POST("", middleware.Action("application.create", "application"), handle(func(c *gin.Context) (any, error) {
		var in catalog.ApplicationInput
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		app, err := service.CreateApplication(c.Request.Context(), in)
		if err == nil {
			markResource(c, app.ID)
		}
		return app, err
	}))
	applications.GET("/:id", handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		return service.GetApplication(c.Request.Context(), id)
	}))
	applications.PATCH("/:id", middleware.Action("application.update", "application"), handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		var in catalog.ApplicationInput
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		return service.UpdateApplication(c.Request.Context(), id, in)
	}))
	applications.DELETE("/:id", middleware.Action("application.delete", "application"), handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		return gin.H{}, service.DeleteApplication(c.Request.Context(), id)
	}))
	applications.GET("/:id/secret", middleware.Action("application.secret.view", "application"), handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		secret, err := service.RevealSecret(c.Request.Context(), id)
		return gin.H{"app_secret": secret}, err
	}))
	applications.POST("/:id/rotate-secret", middleware.Action("application.secret.rotate", "application"), handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		return service.RotateSecret(c.Request.Context(), id)
	}))
	applications.POST("/:id/rotate-key-pair", middleware.Action("application.key_pair.rotate", "application"), handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		return service.RotateKeyPair(c.Request.Context(), id)
	}))
	applications.GET("/gateway", handle(func(c *gin.Context) (any, error) { return service.GatewayInfo(c.Request.Context()) }))
	applications.POST("/gateway/rotate", middleware.Action("gateway.rotate", "system"), handle(func(c *gin.Context) (any, error) {
		var in struct {
			OverlapHours int `json:"overlap_hours"`
		}
		if e := response.BindJSON(c, &in); e != nil {
			return nil, e
		}
		return service.RotateGateway(c.Request.Context(), in.OverlapHours)
	}))
	applications.POST("/:id/connection", middleware.Action("application.secret.view", "application"), handle(func(c *gin.Context) (any, error) {
		id, err := catalogID(c)
		if err != nil {
			return nil, err
		}
		var in struct {
			URL string `json:"url"`
		}
		if err := response.BindJSON(c, &in); err != nil {
			return nil, err
		}
		if in.URL == "" && publicURL(c) != "" {
			in.URL = publicURL(c)
		}
		if in.URL == "" {
			return nil, apperror.Invalid("请填写程序可访问的服务地址")
		}
		normalized, err := integration.NormalizeURL(in.URL)
		if err != nil {
			return nil, apperror.Invalid("服务地址必须是完整 HTTP(S) 地址，不能含路径、凭据或参数")
		}
		in.URL = normalized
		config, err := service.ConnectionConfig(c.Request.Context(), id, in.URL)
		if err != nil {
			return nil, err
		}
		return gin.H{"config": config}, nil
	}))

	applications.GET("/:id/public-key", func(c *gin.Context) {
		id, err := catalogID(c)
		if err != nil {
			response.Fail(c, err)
			return
		}
		previous := false
		if c.Request.URL.Query().Has("previous") {
			previous, err = strconv.ParseBool(c.Query("previous"))
			if err != nil {
				response.Fail(c, apperror.Invalid("previous 必须为布尔值"))
				return
			}
		}
		pem, err := service.PublicKeyPEM(c.Request.Context(), id, previous)
		if err != nil {
			response.Fail(c, err)
			return
		}
		suffix := ""
		if previous {
			suffix = "-previous"
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="authgo-app-%d-public%s.pem"`, id, suffix))
		c.Data(200, "application/x-pem-file", pem)
	})
}
