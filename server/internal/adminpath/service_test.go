package adminpath

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"authgo/internal/bootstrap"
	"authgo/internal/db"
	"authgo/internal/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func fixture(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := database.DB()
	t.Cleanup(func() { pool.Close() })
	if err = db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.EnsureAdmin(database, "owner", "initial-password"); err != nil {
		t.Fatal(err)
	}
	s, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}
func TestPathShape(t *testing.T) {
	for _, path := range []string{"/admin", "/my-console", "/x", "/0", "/a--z", "/" + strings.Repeat("a", 48)} {
		if err := Validate(path); err != nil {
			t.Fatal(path, err)
		}
	}
	for _, path := range []string{"", "/", "admin", "//admin", "/admin/", "/UPPER", "/a/b", "/-admin", "/admin-", "/a?x=1", "/a#x", "/a%2fb", "/a_b", "/a.b", "/管理员", "/\x00", "/" + strings.Repeat("a", 49)} {
		if Validate(path) == nil {
			t.Fatal("accepted invalid", path)
		}
	}
}
func TestReservationsUseActualRegistrations(t *testing.T) {
	s, _ := fixture(t)
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	for _, path := range []string{"/healthz", "/swagger/*file", "/assets/*file", "/api/v1/client/gateway", "/new-public-route/:id"} {
		r.GET(path, func(c *gin.Context) { c.Status(204) })
	}
	s.Configure(r.Routes, []string{"/portal/login", "/forbidden", "/unavailable", "/not-found"})
	want := []string{"api", "assets", "client", "forbidden", "healthz", "new-public-route", "not-found", "portal", "swagger", "unavailable"}
	if !reflect.DeepEqual(s.Reserved(), want) {
		t.Fatal(s.Reserved())
	}
	for _, root := range want {
		if _, err := s.Change(context.Background(), "/"+root, Actor{Operator: "test"}); err == nil {
			t.Fatal("allowed reserved", root)
		}
	}
	if _, err := s.Change(context.Background(), "/console", Actor{Operator: "test"}); err != nil {
		t.Fatal(err)
	}
	r.GET("/later-route", func(c *gin.Context) { c.Status(204) })
	if _, err := s.Change(context.Background(), "/later-route", Actor{Operator: "test"}); err == nil {
		t.Fatal("ignored actual newly registered prefix")
	}
}
func TestLiveCommandAndAtomicAudit(t *testing.T) {
	s, dir := fixture(t)
	if path, err := Command(context.Background(), dir, false); err != nil || path != Default {
		t.Fatal(path, err)
	}
	if _, err := s.Change(context.Background(), "/private-console", Actor{Operator: "test"}); err != nil {
		t.Fatal(err)
	}
	// A second process/connection updates the existing live service without any timer.
	if path, err := Command(context.Background(), dir, true); err != nil || path != Default {
		t.Fatal(path, err)
	}
	if path, err := s.Current(context.Background()); err != nil || path != Default {
		t.Fatal(path, err)
	}
	var rows []model.AuditLog
	if err := s.db.Where("action=?", "system.admin_path.reset").Find(&rows).Error; err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if rows[0].Operator != "local-cli" || rows[0].StatusCode != 200 {
		t.Fatal(rows[0])
	}
	if _, err := Command(context.Background(), filepath.Join(dir, "missing"), false); err == nil {
		t.Fatal("created missing database")
	}
	s.db.Callback().Create().Before("gorm:create").Register("reject-admin-path-audit", func(tx *gorm.DB) {
		if tx.Statement.Table == "audit_logs" {
			tx.AddError(errors.New("audit unavailable"))
		}
	})
	if _, err := s.Change(context.Background(), "/must-not-commit", Actor{Operator: "local-test"}); err == nil {
		t.Fatal("audit failure accepted")
	}
	if path, _ := s.Current(context.Background()); path != Default {
		t.Fatal("non-atomic change", path)
	}
}
