package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/automation"
	"authgo/internal/config"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log/slog"
	"testing"
)

func TestVersionMetadataHTTP(t *testing.T) {
	f := newCatalogFixture(t)
	token := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	app := data(f.request(t, "POST", "/applications", token, gin.H{"name": "payload metadata"}, 200))
	path := "/applications/" + fmt.Sprint(app["id"]) + "/versions"
	f.request(t, "POST", path, token, gin.H{"version": "1.0.0", "encrypted": true}, 400)
	v := data(f.request(t, "POST", path, token, gin.H{"version": "1.0.0", "encrypted": true, "built_at": "2026-11-08T00:00:00Z"}, 200))
	if v["encrypted"] != true || v["built_at"] == nil {
		t.Fatal(v)
	}
	id := "/versions/" + fmt.Sprint(v["id"])
	v = data(f.request(t, "PATCH", id, token, gin.H{"changelog": "preserve"}, 200))
	if v["encrypted"] != true {
		t.Fatal("patch dropped metadata")
	}
	v = data(f.request(t, "GET", id, token, nil, 200))
	if v["built_at"] != "2026-11-08T00:00:00Z" {
		t.Fatal(v)
	}
	v = data(f.request(t, "PATCH", id, token, gin.H{"encrypted": false}, 200))
	if v["built_at"] != nil {
		t.Fatal("stale built_at", v)
	}
}
func TestToolSettingsHTTP(t *testing.T) {
	f := newAdminFixture(t)
	identity, e := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	settings, e := automation.New(f.db, make([]byte, 32), log, automation.Options{Now: f.clock.now, DataDir: t.TempDir()})
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := f.db.DB()
	f.r, e = NewRouter(config.Config{}, log, pool.PingContext, WithAdmin(identity, f.db), WithAutomation(settings))
	if e != nil {
		t.Fatal(e)
	}
	token := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	f.request(t, "PATCH", "/system/settings", token, gin.H{"tools_image": "https://invalid", "tools_version": "v1"}, 400)
	v := data(f.request(t, "PATCH", "/system/settings", token, gin.H{"tools_image": "registry.example.com/team/tools", "tools_version": "v1"}, 200))
	if v["tools_version"] != "v1" {
		t.Fatal(v)
	}
	v = data(f.request(t, "GET", "/system/settings", token, nil, 200))
	if v["tools_image"] != "registry.example.com/team/tools" {
		t.Fatal(v)
	}
}
