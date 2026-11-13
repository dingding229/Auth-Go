package portal

import (
	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Service) reply(c *gin.Context, id *identity, data any, err error) {
	status, code, message := 200, "OK", "操作成功"
	if err != nil {
		var safe *apperror.Error
		if !errors.As(err, &safe) {
			safe = apperror.New(500, "INTERNAL_ERROR", "服务器内部错误")
		}
		status, code, message = safe.Status, safe.Code, safe.Message
		data = nil
	}
	var signature any
	ts := s.now().Unix()
	if id != nil && len(id.Private) > 0 {
		raw, e := cryptoutil.CanonicalJSON(map[string]any{"code": code, "data": data, "ts": ts})
		if e == nil {
			var sig []byte
			sig, e = cryptoutil.Sign(id.Private, raw)
			if e == nil {
				signature = base64.StdEncoding.EncodeToString(sig)
			}
		}
		if e != nil {
			status, code, message, data, signature = 500, "INTERNAL_ERROR", "服务器内部错误", nil, nil
		}
	}
	c.Set("portal_response_code", code)
	c.JSON(status, gin.H{"code": code, "message": message, "data": data, "signature": signature, "ts": ts})
}
func (s *Service) Register(r *gin.Engine) {
	root := r.Group("/api/v1/portal", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		// Public login routes always use the original anonymous budget, even with
		// an Authorization header. Authenticated navigation has a separate IP budget.
		ip := s.sessionIP
		switch c.FullPath() {
		case "/api/v1/portal/login/options", "/api/v1/portal/login", "/api/v1/portal/login/code", "/api/v1/portal/user/login", "/api/v1/portal/user/login/code":
			ip = s.ip
		}
		if !ip.allow(c.ClientIP(), s.now()) {
			s.reply(c, nil, nil, rateError())
			c.Abort()
			return
		}
		c.Next()
	})
	root.GET("/login/options", func(c *gin.Context) { s.reply(c, nil, s.LoginOptions(), nil) })
	root.POST("/login/code", func(c *gin.Context) {
		var in struct {
			LicenseKey string `json:"license_key"`
			Email      string `json:"email"`
		}
		if e := response.BindJSON(c, &in); e != nil {
			s.reply(c, nil, nil, e)
			return
		}
		e := s.SendCode(c.Request.Context(), in.LicenseKey, in.Email, c.ClientIP())
		s.reply(c, nil, gin.H{"expires_in": 600}, e)
	})
	root.POST("/login", func(c *gin.Context) {
		var in LoginInput
		if e := response.BindJSON(c, &in); e != nil {
			s.reply(c, nil, nil, e)
			return
		}
		id, token, e := s.Login(c.Request.Context(), in, c.ClientIP())
		if e != nil {
			s.reply(c, nil, nil, e)
			return
		}
		s.reply(c, &id, gin.H{"portal_token": token, "token_type": "Bearer", "expires_in": 7200}, nil)
	})
	s.registerUserLogin(root)
	authed := root.Group("", s.authenticate(), s.audit())
	s.registerUserCenter(authed)
	s.registerUserOverview(authed)
	authed.GET("/session", func(c *gin.Context) {
		id := c.MustGet("portal_identity").(identity)
		scope := "license"
		if id.UserScope {
			scope = "user"
		}
		contact, e := supportContact(c.Request.Context(), s.db)
		if e != nil {
			s.reply(c, &id, nil, e)
			return
		}
		view := gin.H{"scope": scope, "selected_license_id": id.License.ID}
		if contact != "" {
			view["support_contact"] = contact
		}
		if s.ipinfo.UsesDBIP() {
			view["ip_info_dbip"] = true
		}
		s.reply(c, &id, view, nil)
	})
	type endpoint func(*gin.Context, identity) (any, error)
	handle := func(fn endpoint) gin.HandlerFunc {
		return func(c *gin.Context) {
			id := c.MustGet("portal_identity").(identity)
			data, e := fn(c, id)
			s.reply(c, &id, data, e)
		}
	}
	authed.GET("/update", handle(func(c *gin.Context, id identity) (any, error) {
		if id.App.DockerImage != "" && s.hub != nil {
			return s.hub.ForPortal(c.Request.Context(), id.License.ID, c.Query("current_version"))
		}
		return gin.H{"available": false}, nil
	}))
	authed.GET("/license", handle(func(c *gin.Context, id identity) (any, error) { return s.licenseView(c.Request.Context(), id) }))
	authed.GET("/activations", handle(func(c *gin.Context, id identity) (any, error) {
		rows, e := s.activations(c.Request.Context(), id.License.ID)
		return gin.H{"items": rows}, e
	}))
	authed.POST("/activations/:id/release-seat", handle(func(c *gin.Context, id identity) (any, error) {
		aid, e := strconv.ParseUint(c.Param("id"), 10, 63)
		if e != nil || aid == 0 {
			return nil, apperror.Invalid("绑定 ID 无效")
		}
		if id.UserScope {
			return gin.H{"released": true}, s.entitlements.ReleaseSelf(c.Request.Context(), id.License.ID, aid, id.User.ID)
		}
		return gin.H{"released": true}, s.entitlements.ReleaseSelf(c.Request.Context(), id.License.ID, aid)
	}))
	authed.GET("/logs", handle(func(c *gin.Context, id identity) (any, error) {
		rows, e := s.logs(c.Request.Context(), id.License.ID)
		if id.UserScope {
			for i := range rows {
				rows[i].Device = ""
			}
		}
		return gin.H{"items": rows}, e
	}))
	authed.GET("/announcements", handle(func(c *gin.Context, id identity) (any, error) {
		if id.UserScope {
			return s.userAnnouncements(c, id)
		}
		rows, e := s.announcements(c.Request.Context(), id.App.ID)
		return gin.H{"items": rows}, e
	}))
}
func (s *Service) authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		parts := strings.Fields(c.GetHeader("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			s.reply(c, nil, nil, unauthorized())
			c.Abort()
			return
		}
		claims, e := s.parse(parts[1])
		if e != nil {
			s.reply(c, nil, nil, e)
			c.Abort()
			return
		}
		if !s.session.allow(claims.KeyHash, s.now()) {
			s.reply(c, nil, nil, rateError())
			c.Abort()
			return
		}
		var id identity
		if claims.Scope == "user" {
			var u model.EndUser
			e = s.db.WithContext(c.Request.Context()).First(&u, claims.Subject).Error
			if e == nil && (u.Status != "active" || subtle.ConstantTimeCompare([]byte(claims.Credentials), []byte(s.userCredential(u))) != 1 || claims.KeyHash != cryptoutil.SHA256([]byte("user:"+claims.Subject))) {
				e = unauthorized()
			}
			if e == nil {
				id = identity{User: &u, UserScope: true, Email: u.Email}
				if claims.Selected != 0 {
					var selected identity
					selected, e = s.identity(c.Request.Context(), s.db.Where("id=? AND user_id=?", claims.Selected, u.ID))
					if e == nil {
						id = selected
						id.UserScope = true
					} else if accountEndpoint(c.FullPath()) {
						var safe *apperror.Error
						if errors.As(e, &safe) && safe.Status == 401 {
							e = nil
						}
					}
				}
			}
		} else {
			id, e = s.identity(c.Request.Context(), s.db.Where("id=?", claims.Subject))
			if e == nil && (subtle.ConstantTimeCompare([]byte(claims.Credentials), []byte(s.credential(id))) != 1 || claims.KeyHash != cryptoutil.SHA256([]byte(id.License.Key))) {
				e = unauthorized()
			}
		}
		if e != nil {
			e = unauthorized()
		}
		if e == nil && id.License.ID > 0 && !(id.UserScope && accountEndpoint(c.FullPath())) {
			e = s.signing(&id)
		}
		if e == nil && id.License.ID == 0 {
			if !accountEndpoint(c.FullPath()) {
				e = apperror.New(409, "LICENSE_NOT_SELECTED", "请先选择一个授权")
			}
		}
		if e != nil {
			s.reply(c, nil, nil, e)
			c.Abort()
			return
		}
		c.Set("portal_identity", id)
		c.Next()
	}
}
func clip(v string, n int) string {
	r := []rune(v)
	if len(r) > n {
		return string(r[:n])
	}
	return v
}
func (s *Service) audit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet {
			c.Next()
			return
		}
		id := c.MustGet("portal_identity").(identity)
		row := model.AuditLog{CreatedAt: s.now().UTC(), Action: "portal." + c.Request.Method + " " + c.FullPath(), Resource: "license", ResourceID: strconv.FormatUint(id.License.ID, 10), IP: clip(c.ClientIP(), 128), UserAgent: clip(c.Request.UserAgent(), 512), Operator: "portal:" + strconv.FormatUint(id.License.ID, 10), Summary: "用户中心请求处理中"}
		row.Details = map[string]any{"license_id": id.License.ID}
		if id.UserScope {
			row.Operator = "user:" + strconv.FormatUint(id.User.ID, 10)
			row.Details["user_id"] = id.User.ID
			if id.License.ID == 0 {
				row.Resource = "user"
				row.ResourceID = strconv.FormatUint(id.User.ID, 10)
			}
		}
		switch c.FullPath() {
		case "/api/v1/portal/activations/:id/release-seat", "/api/v1/portal/user/instances/:id/release-seat":
			row.Action = "portal.instance.release"
			row.Resource = "instance"
			row.ResourceID = clip(c.Param("id"), 32)
		case "/api/v1/portal/password":
			row.Action = "portal.user.password"
			row.Resource = "user"
			row.ResourceID = strconv.FormatUint(id.User.ID, 10)
		case "/api/v1/portal/switch":
			row.Action = "portal.license.switch"
			row.Resource = "user"
			row.ResourceID = strconv.FormatUint(id.User.ID, 10)
		}
		if e := s.db.WithContext(c.Request.Context()).Create(&row).Error; e != nil {
			s.reply(c, &id, nil, apperror.New(503, "AUDIT_UNAVAILABLE", "审计服务暂不可用"))
			c.Abort()
			return
		}
		defer func() {
			row.StatusCode = c.Writer.Status()
			row.Summary = "用户中心请求完成"
			result, _ := c.Get("portal_response_code")
			if result == nil {
				result = "OK"
			}
			row.Details["code"] = result
			if activationID, ok := c.Get("portal_activation_id"); ok {
				row.Details["activation_id"] = activationID
			}
			panicValue := recover()
			if panicValue != nil {
				row.StatusCode = 500
				row.Summary = "用户中心请求发生异常"
				row.Details["code"] = "INTERNAL_ERROR"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if e := s.db.WithContext(ctx).Model(&row).Select("status_code", "summary", "details").Updates(&row).Error; e != nil {
				slog.Error("用户中心审计完成记录失败，已保留请求意图", "audit_id", row.ID)
			}
			if panicValue != nil {
				panic(panicValue)
			}
		}()
		c.Next()
	}
}

func accountEndpoint(path string) bool {
	switch path {
	case "/api/v1/portal/user/attention", "/api/v1/portal/user/logs", "/api/v1/portal/user/updates", "/api/v1/portal/user/announcements", "/api/v1/portal/user/instances", "/api/v1/portal/licenses/:id", "/api/v1/portal/announcements":
		return true
	case "/api/v1/portal/session", "/api/v1/portal/user", "/api/v1/portal/user/instances/:id/release-seat", "/api/v1/portal/licenses", "/api/v1/portal/switch", "/api/v1/portal/password":
		return true
	}
	return false
}
