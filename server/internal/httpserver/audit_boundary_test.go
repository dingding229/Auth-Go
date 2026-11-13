package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/model"
	"bytes"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnonymousAndUnmatchedAdminNeverAuditOrAuthenticate(t *testing.T) {
	f := newAdminFixture(t)
	pair := f.login(t, "owner", "initial-password", "")
	token := pair["access_token"].(string)
	for _, method := range []string{"GET", "POST"} {
		for _, path := range []string{"/api/v1/admin/unknown", "/api/v1/admin/applications"} {
			tokens := []string{"", "invalid"}
			if strings.HasSuffix(path, "unknown") {
				tokens = append(tokens, token)
			}
			for _, bearer := range tokens {
				q := httptest.NewRequest(method, path, bytes.NewBufferString(`{}`))
				q.RemoteAddr = "192.0.2.3:8000"
				q.Header.Set("Content-Type", "application/json")
				if bearer != "" {
					q.Header.Set("Authorization", "Bearer "+bearer)
				}
				w := httptest.NewRecorder()
				f.r.ServeHTTP(w, q)
				if w.Code >= 500 {
					t.Fatal(path, w.Code, w.Body.String())
				}
			}
		}
	}
	var count int64
	f.db.Model(&model.AuditLog{}).Count(&count)
	if count != 0 {
		t.Fatal("anonymous/missing route persisted audit", count)
	}
	queries, routingReads := 0, 0
	f.db.Callback().Query().Before("gorm:query").Register("contract_count_auth", func(tx *gorm.DB) {
		if tx.Statement.Table == "settings" {
			routingReads++
			return
		}
		queries++
	})
	for i := 0; i < 3; i++ {
		q := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/admin/unknown-%d", i), nil)
		q.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.r.ServeHTTP(w, q)
		if w.Code != 404 {
			t.Fatal(w.Code)
		}
	}
	f.db.Callback().Query().Remove("contract_count_auth")
	if queries != 0 {
		t.Fatal("missing route queried authentication database", queries)
	}
	if routingReads != 3 {
		t.Fatal("missing route did not resolve live address exactly once", routingReads)
	}
}
func TestAuthenticatedAuditFailClosedAndAnonymousBudgetIsolation(t *testing.T) {
	f := newAdminFixture(t)
	pair := f.login(t, "owner", "initial-password", "")
	token := pair["access_token"].(string)
	for i := 0; i < 35; i++ {
		q := httptest.NewRequest("GET", "/api/v1/admin/auth/me", nil)
		w := httptest.NewRecorder()
		f.r.ServeHTTP(w, q)
		if i == 34 && w.Code != 429 {
			t.Fatal("anonymous not throttled", w.Code)
		}
	}
	// A valid authenticated operation is not starved by the anonymous budget.
	f.request(t, "POST", "/auth/password", token, gin.H{"old_password": "bad-password", "new_password": "new-password"}, 401)
	var rows []model.AuditLog
	f.db.Find(&rows)
	if len(rows) != 1 || rows[0].Operator != "owner" || rows[0].StatusCode != 401 {
		t.Fatal("authenticated denied mutation not audited", rows)
	}
	if e := f.db.Migrator().DropTable(&model.AuditLog{}); e != nil {
		t.Fatal(e)
	}
	result := f.request(t, "POST", "/auth/password", token, gin.H{"old_password": "initial-password", "new_password": "new-password"}, 503)
	if result["code"] != "AUDIT_UNAVAILABLE" {
		t.Fatal("not fail-closed", result)
	}
	// Keep DB/session healthy: only audit storage is unavailable, password must not change.
	var admin model.Admin
	if e := f.db.First(&admin).Error; e != nil {
		t.Fatal(e)
	}
	if admin.PasswordHash == "" {
		t.Fatal("missing password")
	}
	// Inspect through a separately constructed auth service to avoid exhausted anonymous budget.
	identity, e := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = identity.Login(context.Background(), "owner", "initial-password", "", "198.51.100.1"); e != nil {
		t.Fatal("unauditable mutation changed password", e)
	}
}
