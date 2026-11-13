package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"authgo/internal/adminpath"
	"authgo/internal/config"
	"authgo/internal/model"
	"gorm.io/gorm"
)

func pathRequest(r http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.RemoteAddr = "192.0.2.55:1234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
func assertPathStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
}
func pathBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestAdminPathSwitchAndOpaque404(t *testing.T) {
	f := newAdminFixture(t)
	pair := f.login(t, "owner", "initial-password", "")
	token := pair["access_token"].(string)
	assertPathStatus(t, pathRequest(f.r, "PATCH", "/api/v1/admin/system/admin-path", "", map[string]any{"path": "/private-console"}), 401)
	for _, bad := range []string{"/api", "/client", "/assets", "/swagger", "/healthz", "/portal", "/unavailable", "/forbidden", "/not-found", "/bad/path", "/UPPER", "/-console", "/console-"} {
		assertPathStatus(t, pathRequest(f.r, "PATCH", "/api/v1/admin/system/admin-path", token, map[string]any{"path": bad}), 400)
	}
	change := pathRequest(f.r, "PATCH", "/api/v1/admin/system/admin-path", token, map[string]any{"path": "/private-console"})
	assertPathStatus(t, change, 200)
	if pathBody(t, change)["data"].(map[string]any)["login_url"] != "/private-console/login" {
		t.Fatal(change.Body.String())
	}
	for _, method := range []string{"GET", "HEAD", "POST", "PATCH", "DELETE"} {
		for _, path := range []string{"/admin", "/admin/", "/admin/login", "/admin/setup", "/admin/not-a-page", "/api/v1/admin/status", "/api/v1/admin/auth/login", "/api/v1/admin/system/settings", "/api/v1/private-console/not-a-route", "/assets/not-an-asset.js", "/portal/not-a-page", "/swagger/not-a-file"} {
			old := pathRequest(f.r, method, path, token, nil)
			random := pathRequest(f.r, method, "/random-path-never-here", token, nil)
			if old.Code != 404 || old.Code != random.Code || !bytes.Equal(old.Body.Bytes(), random.Body.Bytes()) || !reflect.DeepEqual(old.Header(), random.Header()) {
				t.Fatalf("%s %s differs from unknown: status=%d/%d headers=%v/%v body=%q/%q", method, path, old.Code, random.Code, old.Header(), random.Header(), old.Body.String(), random.Body.String())
			}
		}
	}
	assertPathStatus(t, pathRequest(f.r, "GET", "/api/v1/private-console/status", "", nil), 200)
	assertPathStatus(t, pathRequest(f.r, "GET", "/api/v1/private-console/auth/me", token, nil), 401)
	assertPathStatus(t, pathRequest(f.r, "POST", "/api/v1/private-console/auth/refresh", "", map[string]any{"refresh_token": pair["refresh_token"]}), 401)
	login := pathRequest(f.r, "POST", "/api/v1/private-console/auth/login", "", map[string]any{"username": "owner", "password": "initial-password"})
	assertPathStatus(t, login, 200)
	fresh := pathBody(t, login)["data"].(map[string]any)["access_token"].(string)
	assertPathStatus(t, pathRequest(f.r, "GET", "/api/v1/private-console/auth/me", fresh, nil), 200)
	// Cookie-only cross-site requests have no authority, even with a token value.
	q := httptest.NewRequest("GET", "/api/v1/private-console/auth/me", nil)
	q.Header.Set("Cookie", "access_token="+fresh)
	q.Header.Set("Origin", "https://foreign.example")
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, q)
	assertPathStatus(t, w, 401)
	var events []model.AuditLog
	if err := f.db.Where("action=?", "system.admin_path.update").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.StatusCode == 200 && event.Operator == "owner" {
			found = true
		}
	}
	if !found {
		t.Fatal("successful change was not audited")
	}
	// The reserved namespace must still work, and login failures retain their rate limit.
	assertPathStatus(t, pathRequest(f.r, "GET", "/healthz", "", nil), 200)
	limited := false
	for i := 0; i < 8; i++ {
		w := pathRequest(f.r, "POST", "/api/v1/private-console/auth/login", "", map[string]any{"username": "unknown-name", "password": "incorrect-password"})
		if w.Code == 429 {
			limited = true
		}
		if w.Code != 401 && w.Code != 429 {
			t.Fatal(w.Code)
		}
	}
	if !limited {
		t.Fatal("new management path bypassed login rate limit")
	}
}

func TestAdminPathLiveCLIReset(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.r.AdminPaths.Change(context.Background(), "/hidden-console", adminpath.Actor{Operator: "test"}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(f.r)
	defer server.Close()
	login := pathRequest(f.r, "POST", "/api/v1/hidden-console/auth/login", "", map[string]any{"username": "owner", "password": "initial-password"})
	assertPathStatus(t, login, 200)
	old := pathBody(t, login)["data"].(map[string]any)["access_token"].(string)
	var file struct {
		Name string
		File string
	}
	if err := f.db.Raw("PRAGMA database_list").Scan(&file).Error; err != nil {
		t.Fatal(err)
	}
	if current, err := adminpath.Command(context.Background(), filepath.Dir(file.File), false); err != nil || current != "/hidden-console" {
		t.Fatal(current, err)
	}
	if current, err := adminpath.Command(context.Background(), filepath.Dir(file.File), true); err != nil || current != "/admin" {
		t.Fatal(current, err)
	}
	response, err := http.Get(server.URL + "/api/v1/admin/status")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	assertPathStatus(t, pathRequest(f.r, "GET", "/api/v1/hidden-console/status", "", nil), 404)
	assertPathStatus(t, pathRequest(f.r, "GET", "/api/v1/admin/auth/me", old, nil), 401)
	assertPathStatus(t, pathRequest(f.r, "POST", "/api/v1/admin/auth/login", "", map[string]any{"username": "owner", "password": "initial-password"}), 200)
}

func TestAdminDocsPrivateAndProjected(t *testing.T) {
	f := newAdminFixture(t)
	pool, _ := f.db.DB()
	r, err := NewRouter(config.Config{SwaggerEnabled: true}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext)
	if err != nil {
		t.Fatal(err)
	}
	public := pathRequest(r, "GET", "/swagger/openapi.json", "", nil)
	assertPathStatus(t, public, 200)
	if strings.Contains(public.Body.String(), "/api/v1/admin") || strings.Contains(public.Body.String(), "AdminBearer") {
		t.Fatal("public document exposes management contract")
	}
	if _, err := f.r.AdminPaths.Change(context.Background(), "/doc-console", adminpath.Actor{Operator: "test"}); err != nil {
		t.Fatal(err)
	}
	assertPathStatus(t, pathRequest(f.r, "GET", "/api/v1/doc-console/docs/openapi.json", "", nil), 401)
	login := pathRequest(f.r, "POST", "/api/v1/doc-console/auth/login", "", map[string]any{"username": "owner", "password": "initial-password"})
	assertPathStatus(t, login, 200)
	token := pathBody(t, login)["data"].(map[string]any)["access_token"].(string)
	private := pathRequest(f.r, "GET", "/api/v1/doc-console/docs/openapi.json", token, nil)
	assertPathStatus(t, private, 200)
	body := private.Body.String()
	if !strings.Contains(body, "/api/v1/doc-console/auth/login") || strings.Contains(body, "/api/v1/admin/") {
		t.Fatal("private contract not projected")
	}
}

func TestAdminPathAuditFailureDoesNotChangeOrRevoke(t *testing.T) {
	f := newAdminFixture(t)
	pair := f.login(t, "owner", "initial-password", "")
	token := pair["access_token"].(string)
	if err := f.db.Callback().Create().Before("gorm:create").Register("fail-path-audit", func(tx *gorm.DB) {
		if tx.Statement.Table == "audit_logs" {
			tx.AddError(errors.New("unavailable audit"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	rejected := pathRequest(f.r, "PATCH", "/api/v1/admin/system/admin-path", token, map[string]any{"path": "/must-not-apply"})
	assertPathStatus(t, rejected, 503)
	if current, err := f.r.AdminPaths.Current(context.Background()); err != nil || current != "/admin" {
		t.Fatal("audit failure changed address", current, err)
	}
	assertPathStatus(t, pathRequest(f.r, "GET", "/api/v1/admin/auth/me", token, nil), 200)
	assertPathStatus(t, pathRequest(f.r, "GET", "/api/v1/must-not-apply/status", "", nil), 404)
}
