// Package adminpath owns the live management address, its settings API and local recovery.
package adminpath

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"authgo/internal/apperror"
	"authgo/internal/auth"
	"authgo/internal/middleware"
	"authgo/internal/model"
	"authgo/internal/response"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const Default = "/admin"
const SettingKey = "admin.path"
const CanonicalAPI = "/api/v1/admin"

var pathPattern = regexp.MustCompile(`^/[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)

// Actor identifies the existing authenticated administrator, or the local utility.
type Actor struct {
	AdminID  uint64
	Operator string
	IP       string
}
type Service struct {
	db     *gorm.DB
	routes func() gin.RoutesInfo
	pages  []string
}

func New(database *gorm.DB) (*Service, error) {
	s := &Service{db: database}
	if _, err := s.Current(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func Validate(path string) error {
	if !pathPattern.MatchString(path) {
		return apperror.Invalid("后台地址须为 / 加1至48个小写字母、数字或连字符，首尾须为字母或数字，且只能有一段")
	}
	return nil
}

// Current deliberately reads SQLite rather than a process-local cache: a separate
// admin-path reset process takes effect on the running service's next request.
func (s *Service) Current(ctx context.Context) (string, error) {
	if s == nil || s.db == nil {
		return Default, nil
	}
	var row model.Setting
	if err := s.db.WithContext(ctx).First(&row, "key = ?", SettingKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("后台地址配置缺失：数据库必须使用当前1.0.0初始结构")
		}
		return "", err
	}
	if err := Validate(row.Value); err != nil {
		return "", fmt.Errorf("后台地址配置损坏: %w", err)
	}
	return row.Value, nil
}

// Configure derives reservations from the actual registered server routes and
// the same public page definitions consumed by the Vue router, not a blacklist.
func (s *Service) Configure(routes func() gin.RoutesInfo, pages []string) {
	s.routes = routes
	s.pages = append([]string(nil), pages...)
}
func (s *Service) Reserved() []string {
	roots := map[string]bool{}
	add := func(path string) {
		first := strings.Split(strings.TrimPrefix(path, "/"), "/")[0]
		if first != "" && Validate("/"+first) == nil {
			roots[first] = true
		}
	}
	if s.routes != nil {
		for _, r := range s.routes() {
			add(r.Path)
			// The same segment is also used under /api/v1: client/portal/shared
			// namespaces must not be shadowed even when they have no page at /<segment>.
			if !prefix(r.Path, CanonicalAPI) && strings.HasPrefix(r.Path, "/api/v1/") {
				add("/" + strings.Split(strings.TrimPrefix(r.Path, "/api/v1/"), "/")[0])
			}
		}
	}
	for _, path := range s.pages {
		add(path)
	}
	out := make([]string, 0, len(roots))
	for root := range roots {
		out = append(out, root)
	}
	sort.Strings(out)
	return out
}
func (s *Service) Change(ctx context.Context, path string, actor Actor) (string, error) {
	return s.change(ctx, path, actor, "system.admin_path.update")
}
func (s *Service) Reset(ctx context.Context, actor Actor) (string, error) {
	return s.change(ctx, Default, actor, "system.admin_path.reset")
}
func (s *Service) change(ctx context.Context, path string, actor Actor, action string) (string, error) {
	if err := Validate(path); err != nil {
		return "", err
	}
	for _, root := range s.Reserved() {
		if path == "/"+root {
			return "", apperror.Invalid("后台地址与系统路由冲突")
		}
	}
	if s.db == nil {
		return "", fmt.Errorf("后台地址配置需要已初始化的数据库")
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		result := tx.Model(&model.Setting{}).Where("key = ?", SettingKey).Updates(map[string]any{"value": path, "updated_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("后台地址配置缺失")
		}
		// Access and refresh tokens both check this version and the session row.
		if err := tx.Model(&model.Admin{}).Where("1=1").Updates(map[string]any{"auth_version": gorm.Expr("auth_version + 1"), "pending_totp_secret": "", "pending_totp_expires_at": nil}).Error; err != nil {
			return err
		}
		revoked := tx.Model(&model.AdminSession{}).Where("revoked_at IS NULL").Update("revoked_at", now)
		if revoked.Error != nil {
			return revoked.Error
		}
		// HTTP uses the existing fail-closed audit intent/completion middleware. A
		// local command has no HTTP middleware, so its audit commits atomically here.
		if actor.AdminID == 0 {
			return tx.Create(&model.AuditLog{Action: action, Resource: "system", ResourceID: SettingKey, Operator: actor.Operator, IP: actor.IP, Summary: "后台地址已更新，管理员会话已撤销", StatusCode: 200, Details: map[string]any{"source": "local", "sessions_revoked": revoked.RowsAffected}}).Error
		}
		return nil
	})
	return path, err
}
func (s *Service) Register(r *gin.Engine, identity *auth.Service) {
	root := r.Group(CanonicalAPI+"/system/admin-path", middleware.Authenticate(identity))
	root.GET("", func(c *gin.Context) {
		path, err := s.Current(c.Request.Context())
		if err != nil {
			response.Fail(c, err)
			return
		}
		response.Success(c, gin.H{"path": path, "reserved": s.Reserved()})
	})
	root.PATCH("", middleware.Action("system.admin_path.update", "system"), func(c *gin.Context) {
		var input struct {
			Path string `json:"path"`
		}
		if err := response.BindJSON(c, &input); err != nil {
			response.Fail(c, err)
			return
		}
		actor, _ := middleware.Principal(c)
		path, err := s.Change(c.Request.Context(), input.Path, Actor{AdminID: actor.AdminID, Operator: actor.Username, IP: c.ClientIP()})
		if err != nil {
			response.Fail(c, err)
			return
		}
		middleware.ResourceID(c, SettingKey)
		response.Success(c, gin.H{"path": path, "login_url": path + "/login"})
	})
}
