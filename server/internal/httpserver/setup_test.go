package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/bootstrap"
	"authgo/internal/config"
	"authgo/internal/db"
	"authgo/internal/model"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetupHTTP(t *testing.T) {
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	identity, e := auth.NewService(d, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	setup, token, e := bootstrap.NewSetup(d)
	if e != nil {
		t.Fatal(e)
	}
	r, e := NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext, WithAdmin(identity, d), WithSetup(setup))
	if e != nil {
		t.Fatal(e)
	}
	request := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		b, _ := json.Marshal(body)
		q := httptest.NewRequest(method, path, bytes.NewReader(b))
		q.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		if w.Code != want {
			t.Fatalf("%s %d %s", path, w.Code, w.Body.String())
		}
		v := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		return v
	}
	for _, v := range []string{"", "wrong"} {
		request("POST", "/api/v1/admin/auth/setup", map[string]string{"token": v, "username": "owner", "password": "password123"}, 401)
	}
	result := request("POST", "/api/v1/admin/auth/setup", map[string]string{"token": token, "username": "owner", "password": "password123"}, 200)
	data := result["data"].(map[string]any)
	if data["access_token"] == "" || data["refresh_token"] == "" {
		t.Fatal("no login session")
	}
	request("POST", "/api/v1/admin/auth/setup", map[string]string{"token": token, "username": "other", "password": "password123"}, 404)
	// The one-time initialization token must never be an administrator credential.
	for _, path := range []string{"/api/v1/admin/auth/me", "/api/v1/admin/integration/protocol"} {
		q := httptest.NewRequest("GET", path, nil)
		q.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		if w.Code != 401 {
			t.Fatalf("setup token accepted by %s: %d", path, w.Code)
		}
	}
	var sessions int64
	d.Model(&model.AdminSession{}).Count(&sessions)
	if sessions != 1 {
		t.Fatal(sessions)
	}
	var audits int64
	d.Model(&model.AuditLog{}).Count(&audits)
	if audits != 0 {
		t.Fatal("unauthenticated initialization must not write synchronous audit", audits)
	}
}
