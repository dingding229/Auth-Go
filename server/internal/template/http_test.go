package template_test

import (
	"authgo/internal/auth"
	"authgo/internal/bootstrap"
	"authgo/internal/db"
	"authgo/internal/middleware"
	"authgo/internal/model"
	featuretemplate "authgo/internal/template"
	"authgo/internal/trial"
	"bytes"
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io"
	"log/slog"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestManagementRoutesPermissionsAuditAndTrialSelection(t *testing.T) {
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if _, e = bootstrap.EnsureAdmin(d, "owner", "initial-password"); e != nil {
		t.Fatal(e)
	}
	identity, e := auth.NewService(d, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	token, e := identity.Login(context.Background(), "owner", "initial-password", "", "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	a := model.Application{Name: "one", AppKey: "one"}
	b := model.Application{Name: "two", AppKey: "two"}
	d.Create(&a)
	d.Create(&b)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AdminRequests(identity), middleware.Audit(d, slog.New(slog.NewTextHandler(io.Discard, nil))))
	featuretemplate.New(d).Register(r, identity)
	trial.New(d, nil).Register(r, identity)
	base := "/api/v1/admin/applications/" + strconv.FormatUint(a.ID, 10)
	other := "/api/v1/admin/applications/" + strconv.FormatUint(b.ID, 10)
	call := func(method, path, body string, authenticated bool, want int) map[string]any {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s %s %d want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		var out map[string]any
		if e = json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	call("GET", base+"/templates", "", false, 401)
	call("POST", base+"/templates", `{"name":"basic","features":{"export":true}}`, true, 200)
	call("GET", base+"/templates?page=1&page_size=1", "", true, 200)
	call("PATCH", other+"/templates/1", `{"name":"bad"}`, true, 404)
	call("DELETE", other+"/templates/1", "", true, 404)
	call("PATCH", other+"/trial", `{"trial_template_id":1}`, true, 404)
	selected := call("PATCH", base+"/trial", `{"trial_enabled":true,"trial_days":5,"trial_template_id":1}`, true, 200)
	if selected["data"].(map[string]any)["trial_template_id"] != float64(1) {
		t.Fatal(selected)
	}
	current := call("GET", base+"/trial", "", true, 200)
	if current["data"].(map[string]any)["trial_template_id"] != float64(1) {
		t.Fatal(current)
	}
	call("DELETE", base+"/templates/1", "", true, 409)
	call("PATCH", base+"/templates/1", `{"features":{"export":false}}`, true, 200)
	call("PATCH", base+"/trial", `{"trial_template_id":null}`, true, 200)
	call("DELETE", base+"/templates/1", "", true, 200)
	var n int64
	d.Model(&model.AuditLog{}).Where("action IN ? AND status_code=200", []string{"template.create", "template.update", "template.delete", "trial.settings"}).Count(&n)
	if n != 5 {
		t.Fatalf("missing successful audits: %d", n)
	}
}
