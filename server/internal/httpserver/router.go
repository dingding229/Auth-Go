package httpserver

import (
	"authgo/internal/adminpath"
	"authgo/internal/apidocs"
	"authgo/internal/apperror"
	"authgo/internal/config"
	"authgo/internal/ipinfo"
	"authgo/internal/maintenance"
	"authgo/internal/middleware"
	"authgo/internal/portal"
	"authgo/internal/response"
	"authgo/internal/sharing"
	featuretemplate "authgo/internal/template"
	"authgo/internal/trial"
	"authgo/internal/webui"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// NewRouter assembles management APIs, middleware and the embedded UI.
func NewRouter(cfg config.Config, log *slog.Logger, ping func(context.Context) error, options ...Option) (*adminpath.Router, error) {
	opts := &routerOptions{}
	for _, option := range options {
		option(opts)
	}
	if (opts.auth == nil) != (opts.database == nil) {
		return nil, fmt.Errorf("管理员认证服务与数据库必须同时配置")
	}
	if (opts.catalog != nil || opts.licensing != nil || opts.automation != nil || opts.ipinfo != nil) && opts.auth == nil {
		return nil, fmt.Errorf("软件管理必须配置管理员认证")
	}
	if opts.client != nil && opts.automation != nil {
		opts.client.SetDockerHub(opts.automation.DockerHub())
	}
	if opts.database != nil && opts.sharing == nil {
		opts.sharing = sharing.New(opts.database, opts.ipinfo, nil)
	}
	if opts.licensing != nil {
		opts.licensing.SetSharing(opts.sharing)
		opts.licensing.SetIPInfo(opts.ipinfo)
	}
	if opts.portal != nil {
		opts.portal.SetIPInfo(opts.ipinfo)
		opts.portal.SetDeploymentGuide(apidocs.Docker)
	}
	if opts.portal != nil && opts.client != nil {
	}
	paths, err := adminpath.New(opts.database)
	if err != nil {
		return nil, err
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.RedirectTrailingSlash = false // Redirects bypass Gin middleware, including auditing.
	proxies := cfg.TrustedProxies
	if opts.automation != nil {
		proxies = nil
	}
	if err := r.SetTrustedProxies(proxies); err != nil {
		return nil, err
	}
	trust := middleware.TrustedPeer(cfg.TrustedProxies)
	if opts.automation != nil {
		trust = opts.automation.TrustsProxy
	}
	r.Use(middleware.ForwardedHeaders(trust))
	if opts.automation != nil {
		r.Use(runtimeProxy(opts.automation))
	}
	r.Use(middleware.BodyLimit())
	r.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		// Do not log query strings, request bodies, passwords or tokens.
		path := adminpath.OriginalPath(c.Request)
		if strings.HasPrefix(path, "/api/v1/client/download/") || strings.HasPrefix(path, "/api/v1/portal/download/") {
			path = "/api/v1/client/download/:token"
		}
		log.Info("HTTP 请求", "method", c.Request.Method, "path", path,
			"status", c.Writer.Status(), "duration", time.Since(start), "ip", c.ClientIP())
	}, func(c *gin.Context) {
		defer func() {
			if recover() != nil {
				log.Error("HTTP 处理异常")
				response.Fail(c, apperror.New(http.StatusInternalServerError, "INTERNAL_ERROR", "服务器内部错误"))
			}
		}()
		c.Next()
	})
	r.Use(adminpath.MissingGuard())
	if opts.auth != nil {
		r.Use(middleware.AdminRequests(opts.auth))
		r.Use(middleware.Audit(opts.database, log, http.MethodGet+" "+applicationSecretRoute, http.MethodGet+" "+backupDownloadRoute, http.MethodGet+" /api/v1/admin/applications/:id/payload-keys", http.MethodGet+" /api/v1/admin/applications/:id/watermark-tags"))
		registerAdmin(r, opts.auth, opts.database, opts.ipinfo)
		paths.Register(r, opts.auth)
		portal.RegisterSupport(r, opts.database, opts.auth)
		if opts.ipinfo != nil {
			opts.ipinfo.Register(r, opts.auth)
		}
		registerSetup(r, opts.auth, opts.database, opts.setup)
		registerIntegration(r, opts.auth)
		registerStats(r, opts.database, opts.auth, opts.ipinfo, opts.sharing)
		registerUsers(r, opts.database, opts.auth)
		if opts.automation != nil {
			registerAutomation(r, opts.automation, opts.auth)
			opts.automation.DockerHub().Register(r, opts.auth)
		}
		if opts.catalog != nil {
			registerCatalog(r, opts.catalog, opts.auth)
			registerReleases(r, opts.catalog, opts.auth)
			if opts.client != nil {
				registerUpdates(r, opts.client.Updates(), opts.auth)
			}
		}
		if opts.licensing != nil {
			opts.sharing.Register(r, opts.auth)
			registerLicensing(r, opts.licensing, opts.auth)
			maintenance.New(opts.database, nil).Register(r, opts.auth)
			trial.New(opts.database, nil).Register(r, opts.auth)
			featuretemplate.New(opts.database).Register(r, opts.auth)
		}
	}
	if opts.client != nil {
		opts.client.Register(r)
		if opts.auth != nil {
			opts.client.PayloadKeys().Register(r, opts.auth)
		}
	}
	if opts.portal != nil {
		opts.portal.Register(r)
	}
	registerSwagger(r, cfg.SwaggerEnabled)
	if opts.auth != nil {
		paths.RegisterDocs(r, opts.auth)
	}
	health := func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), time.Second)
		defer cancel()
		if err := ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "message": "数据库不可用"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
	r.GET("/healthz", health)
	r.HEAD("/healthz", health)
	for _, group := range []string{"admin", "client", "portal"} {
		if group == "admin" && opts.auth != nil || group == "client" && opts.client != nil || group == "portal" && opts.portal != nil {
			continue
		}
		api := r.Group("/api/v1/" + group)
		api.GET("", placeholder)
		api.GET("/", placeholder)
	}
	webui.Register(r, response.NotFound)
	return adminpath.Wrap(r, paths, webui.PublicPaths()), nil
}

func placeholder(c *gin.Context) {
	response.Fail(c, apperror.New(http.StatusNotImplemented, "NOT_IMPLEMENTED", "接口尚未实现"))
}

func WithPortal(s *portal.Service) Option { return func(o *routerOptions) { o.portal = s } }

func WithIPInfo(s *ipinfo.Service) Option { return func(o *routerOptions) { o.ipinfo = s } }

func WithSharing(s *sharing.Service) Option { return func(o *routerOptions) { o.sharing = s } }
