package httpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"authgo/internal/auth"
	"authgo/internal/catalog"
	"authgo/internal/config"
	"authgo/internal/model"

	"github.com/gin-gonic/gin"
)

func newCatalogFixture(t *testing.T) *adminFixture {
	t.Helper()
	f := newAdminFixture(t)
	pool, _ := f.db.DB()
	identity, err := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := catalog.NewService(f.db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.r, err = NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext, WithAdmin(identity, f.db), WithCatalog(service))
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func noCredentialFields(t *testing.T, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"app_secret", "private_key", "encrypted"} {
		if bytes.Contains(encoded, []byte(bad)) {
			t.Fatalf("credential field in ordinary response: %s", encoded)
		}
	}
}
func pemRequest(t *testing.T, f *adminFixture, path, token string) []byte {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/admin"+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-pem-file" || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatalf("PEM %d %s %s", w.Code, w.Header(), w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("PEM missing management cache policy")
	}
	return w.Body.Bytes()
}

func TestCatalogListInputsAndLiteralSearch(t *testing.T) {
	f := newCatalogFixture(t)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	for _, name := range []string{"100% 产品", "普通产品"} {
		f.request(t, "POST", "/applications", owner, gin.H{"name": name}, 200)
	}
	page := data(f.request(t, "GET", "/applications?q=%25", owner, nil, 200))
	if page["total"] != float64(1) {
		t.Fatal("LIKE wildcard not escaped")
	}
	for _, resource := range []string{"/applications"} {
		for _, query := range []string{"page=0", "page_size=101", "sort_by=name%3BDROP%20TABLE%20admins", "sort_by=app_secret_encrypted", "sort_order=sideways"} {
			f.request(t, "GET", resource+"?"+query, owner, nil, 400)
		}
	}
	f.request(t, "GET", "/applications?status=invalid", owner, nil, 400)
	f.request(t, "GET", "/applications/bad", owner, nil, 400)
	f.request(t, "GET", "/applications?q="+strings.Repeat("a", 129), owner, nil, 400)
}

func TestCatalogCannotBeMountedWithoutAuthentication(t *testing.T) {
	f := newAdminFixture(t)
	pool, _ := f.db.DB()
	service, err := catalog.NewService(f.db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext, WithCatalog(service))
	if err == nil {
		t.Fatal("catalog mounted without authentication")
	}
}

func TestApplicationCredentialRoutesAndAudit(t *testing.T) {
	f := newCatalogFixture(t)
	token := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	app := data(f.request(t, "POST", "/applications", token, gin.H{"name": "密钥应用"}, 200))
	noCredentialFields(t, app)
	path := "/applications/" + fmt.Sprint(app["id"])
	secret := data(f.request(t, "GET", path+"/secret", token, nil, 200))["app_secret"]
	if secret == "" {
		t.Fatal("empty secret")
	}
	f.request(t, "POST", path+"/rotate-secret", token, nil, 200)
	next := data(f.request(t, "GET", path+"/secret", token, nil, 200))["app_secret"]
	if next == secret {
		t.Fatal("rotation unchanged")
	}
	f.request(t, "POST", path+"/rotate-key-pair", token, nil, 200)
	pemRequest(t, f, path+"/public-key", token)
	f.request(t, "PATCH", path, token, gin.H{"name": "更新应用", "status": "disabled"}, 200)
	var logs []model.AuditLog
	f.db.Where("action=?", "application.secret.view").Find(&logs)
	if len(logs) != 2 {
		t.Fatal(logs)
	}
	f.request(t, "DELETE", path, token, nil, 200)
	f.request(t, "GET", path, token, nil, 404)
}

func TestConnectionConfigAudited(t *testing.T) {
	f := newCatalogFixture(t)
	token := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	app := data(f.request(t, "POST", "/applications", token, gin.H{"name": "接入测试"}, 200))
	id := fmt.Sprint(app["id"])
	f.request(t, "POST", "/applications/"+id+"/connection", "", gin.H{"url": "https://example.com"}, 401)
	f.request(t, "POST", "/applications/"+id+"/connection", token, gin.H{"url": "https://secret@example.com"}, 400)
	v := data(f.request(t, "POST", "/applications/"+id+"/connection", token, gin.H{"url": "https://example.com"}, 200))
	if !strings.HasPrefix(v["config"].(string), "authgo2.") {
		t.Fatal("invalid config")
	}
	var audit model.AuditLog
	if e := f.db.Where("action=? AND resource_id=? AND status_code=?", "application.secret.view", id, 200).Last(&audit).Error; e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(audit)
	if strings.Contains(string(b), "authgo2.") {
		t.Fatal("config leaked to audit")
	}
}
