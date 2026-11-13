package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/catalog"
	"authgo/internal/client"
	"authgo/internal/config"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/internal/payloadkey"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestWatermarkAdminRoutesScopePrivacyAndAudit(t *testing.T) {
	f := newAdminFixture(t)
	identity, e := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	cat, e := catalog.NewService(f.db, make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gateway, e := client.NewService(f.db, make([]byte, 32), log, client.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer gateway.Close(context.Background())
	pool, _ := f.db.DB()
	f.r, e = NewRouter(config.Config{}, log, pool.PingContext, WithAdmin(identity, f.db), WithCatalog(cat), WithClient(gateway))
	if e != nil {
		t.Fatal(e)
	}
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	a := data(f.request(t, "POST", "/applications", owner, gin.H{"name": "watermark-http"}, 200))
	id := uint64(a["id"].(float64))
	base := fmt.Sprintf("/applications/%d", id)
	f.request(t, "GET", base+"/watermark-tags", "", nil, 401)
	f.request(t, "POST", base+"/watermark-trace", "", gin.H{"watermark": strings.Repeat("1", 64)}, 401)
	f.request(t, "GET", base+"/watermark-tags", "not-an-admin-token", nil, 401)
	key := data(f.request(t, "POST", base+"/payload-keys", owner, gin.H{}, 200))
	var app model.Application
	if e = f.db.First(&app, id).Error; e != nil {
		t.Fatal(e)
	}
	license := model.License{AppID: id, Key: "DO_NOT_RETURN_AUTHORIZATION_KEY"}
	if e = f.db.Omit("Application", "User").Create(&license).Error; e != nil {
		t.Fatal(e)
	}
	box, _ := cryptoutil.NewCipher(make([]byte, 32))
	service := payloadkey.New(f.db, box)
	value, e := service.WatermarkForLicense(f.db, app, key["key_id"].(string), license.ID)
	if e != nil {
		t.Fatal(e)
	}
	f.request(t, "POST", base+"/payload-keys", owner, gin.H{}, 200)
	tags := data(f.request(t, "GET", base+"/watermark-tags", owner, nil, 200))
	if len(tags["items"].([]any)) != 2 {
		t.Fatal("old/new tags missing")
	}
	found := data(f.request(t, "POST", base+"/watermark-trace", owner, gin.H{"watermark": value}, 200))
	if found["found"] != true || uint64(found["license_id"].(float64)) != license.ID {
		t.Fatal("trace did not resolve original key after rotation")
	}
	for _, bad := range []gin.H{{"watermark": strings.Repeat("0", 64)}, {"watermark": strings.Repeat("A", 64)}, {"watermark": value, "file": "must never upload"}, {"watermark": value, "filename": "secret.jar"}, {"watermark": value, "fragment": strings.Repeat("x", 300)}} {
		f.request(t, "POST", base+"/watermark-trace", owner, bad, 400)
	}
	other := data(f.request(t, "POST", "/applications", owner, gin.H{"name": "other-software"}, 200))
	otherBase := fmt.Sprintf("/applications/%.0f", other["id"].(float64))
	miss := data(f.request(t, "POST", otherBase+"/watermark-trace", owner, gin.H{"watermark": value}, 200))
	if miss["found"] != false {
		t.Fatal("cross application leak")
	}
	f.request(t, "GET", "/applications/999999/watermark-tags", owner, nil, 404)
	f.request(t, "POST", "/applications/999999/watermark-trace", owner, gin.H{"watermark": value}, 404)
	f.request(t, "GET", "/applications/invalid/watermark-tags", owner, nil, 400)
	var audits []model.AuditLog
	if e = f.db.Where("action IN ?", []string{"watermark.tags", "watermark.trace"}).Find(&audits).Error; e != nil {
		t.Fatal(e)
	}
	var reads, writes int
	for _, a := range audits {
		if a.StatusCode == 200 {
			if a.Action == "watermark.tags" {
				reads++
			}
			if a.Action == "watermark.trace" {
				writes++
			}
		}
	}
	if reads != 1 || writes != 2 {
		t.Fatal("missing audited reads/traces", reads, writes)
	}
	for _, v := range []any{found, tags, audits} {
		encoded, _ := json.Marshal(v)
		text := string(encoded)
		for _, bad := range []string{license.Key, value, "private_key_encrypted", "secret.jar", "must never upload"} {
			if strings.Contains(text, bad) {
				t.Fatal("private/file data escaped into response or audit")
			}
		}
	}
}
