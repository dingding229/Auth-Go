package middleware

import (
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"authgo/internal/auth"
	"authgo/internal/bootstrap"
	"authgo/internal/db"
	"authgo/internal/model"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func TestAuditPanicAndFailClosed(t *testing.T) {
	database, err := db.Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := database.DB()
	defer pool.Close()
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.EnsureAdmin(database, "owner", "initial-password"); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := gin.New()
	r.Use(gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) { c.AbortWithStatus(500) }), func(c *gin.Context) { SetPrincipal(c, auth.Principal{AdminID: 1, Username: "owner"}); c.Next() }, Audit(database, log))
	r.POST("/api/v1/admin/panic", Action("panic-test", "test"), func(c *gin.Context) { panic("secret-panic-value") })
	dispatched := false
	r.POST("/api/v1/admin/write", Action("write-test", "test"), func(c *gin.Context) { dispatched = true; c.Status(200) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/admin/panic", nil))
	if w.Code != 500 {
		t.Fatalf("panic status %d", w.Code)
	}
	var row model.AuditLog
	if err := database.First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.StatusCode != 500 || row.Details["code"] != "INTERNAL_ERROR" || row.Action != "panic-test" {
		t.Fatal("panic not audited accurately")
	}
	_ = pool.Close()
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/admin/write", nil))
	if dispatched || w.Code != 503 {
		t.Fatal("unauditable write was dispatched")
	}
}

func TestAuditIncompleteIntentRetainsAuthenticatedActor(t *testing.T) {
	database, err := db.Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := database.DB()
	defer pool.Close()
	if err = db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.EnsureAdmin(database, "owner", "initial-password"); err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(func(c *gin.Context) { SetPrincipal(c, auth.Principal{AdminID: 1, Username: "owner"}); c.Next() }, Audit(database, slog.New(slog.NewTextHandler(io.Discard, nil))))
	r.POST("/api/v1/admin/intent", Action("finished-action", "test"), func(c *gin.Context) { c.Status(204) })
	// Completion can fail independently of the already persisted intent.
	database.Callback().Update().Before("gorm:update").Register("contract_fail_completion", func(tx *gorm.DB) {
		if tx.Statement.Table == "audit_logs" {
			tx.AddError(errors.New("completion unavailable"))
		}
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/admin/intent", nil))
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
	var row model.AuditLog
	if e := database.First(&row).Error; e != nil {
		t.Fatal(e)
	}
	if row.Operator != "owner" || row.AdminID == nil || *row.AdminID != 1 || row.Summary != "请求处理中" || row.Action != "POST /api/v1/admin/intent" {
		t.Fatal("incomplete intent lost authenticated actor", row)
	}
}
