package httpserver

import (
	"authgo/internal/apidocs"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

const swaggerIndex = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Auth Go 接口文档</title><link rel="stylesheet" href="/swagger/swagger-ui.css"></head>
<body><div id="swagger-ui"></div><script src="/swagger/swagger-ui-bundle.js"></script><script src="/swagger/initializer.js"></script></body></html>`

// No CDN, remote validator or persistent credentials; the UI works offline.
const swaggerInitializer = `window.onload = function () { window.ui = SwaggerUIBundle({ url: "/swagger/openapi.json", dom_id: "#swagger-ui", deepLinking: true, validatorUrl: null, persistAuthorization: false, supportedSubmitMethods: [] }); };`

func registerSwagger(r *gin.Engine, enabled bool) {
	r.GET("/swagger", func(c *gin.Context) {
		if !enabled {
			response.NotFound(c)
			return
		}
		c.Redirect(http.StatusTemporaryRedirect, "/swagger/")
	})
	r.GET("/swagger/*file", func(c *gin.Context) {
		if !enabled {
			response.NotFound(c)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		name := strings.TrimPrefix(c.Param("file"), "/")
		var raw []byte
		var err error
		mime := "application/json; charset=utf-8"
		switch name {
		case "", "index.html":
			raw, mime = []byte(swaggerIndex), "text/html; charset=utf-8"
		case "initializer.js":
			raw, mime = []byte(swaggerInitializer), "text/javascript; charset=utf-8"
		case "openapi.json":
			raw, err = apidocs.SpecificationBytes(false, "", false)
		case "openapi.yaml":
			raw, err = apidocs.SpecificationBytes(false, "", true)
			mime = "application/yaml; charset=utf-8"
		case "swagger-ui.css", "swagger-ui-bundle.js":
			raw, err = apidocs.UIAsset(name)
			mime = "text/javascript; charset=utf-8"
			if strings.HasSuffix(name, ".css") {
				mime = "text/css; charset=utf-8"
			}
		case "LICENSE", "NOTICE", "swagger-ui-bundle.js.LICENSE.txt":
			raw, err = apidocs.UIAsset(name)
			mime = "text/plain; charset=utf-8"
		default:
			for name := range c.Writer.Header() {
				c.Writer.Header().Del(name)
			}
			response.NotFound(c)
			return
		}
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Data(http.StatusOK, mime, raw)
	})
}
