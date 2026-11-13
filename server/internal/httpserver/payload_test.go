package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/catalog"
	"authgo/internal/client"
	"authgo/internal/config"
	"authgo/internal/model"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestPayloadKeyManagementAuthenticatedAuditedAndPrivate(t *testing.T) {
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
	a := data(f.request(t, "POST", "/applications", owner, gin.H{"name": "pack"}, 200))
	path := fmt.Sprintf("/applications/%.0f/payload-keys", a["id"].(float64))
	f.request(t, "GET", path, "", nil, 401)
	f.request(t, "POST", path, "", gin.H{}, 401)
	empty := data(f.request(t, "GET", path, owner, nil, 200))
	if len(empty["items"].([]any)) != 0 {
		t.Fatal("not empty")
	}
	first := data(f.request(t, "POST", path, owner, gin.H{}, 200))
	second := data(f.request(t, "POST", path, owner, gin.H{}, 200))
	if first["key_id"] == second["key_id"] {
		t.Fatal("rotation did not generate a key")
	}
	list := data(f.request(t, "GET", path, owner, nil, 200))
	items := list["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["is_current"] != true || items[1].(map[string]any)["is_current"] != false {
		t.Fatal("history")
	}
	noCredentialFields(t, list)
	noCredentialFields(t, first)
	f.request(t, "GET", "/applications/999999/payload-keys", owner, nil, 404)
	f.request(t, "POST", "/applications/999999/payload-keys", owner, gin.H{}, 404)
	var audit []model.AuditLog
	if e = f.db.Where("action IN ?", []string{"payload_key.list", "payload_key.rotate"}).Find(&audit).Error; e != nil {
		t.Fatal(e)
	}
	var reads, writes int
	for _, entry := range audit {
		if entry.Action == "payload_key.list" && entry.StatusCode == 200 {
			reads++
		}
		if entry.Action == "payload_key.rotate" && entry.StatusCode == 200 {
			writes++
		}
	}
	if reads != 2 || writes != 2 {
		t.Fatal("not audited", reads, writes)
	}
	raw, _ := json.Marshal(audit)
	for _, bad := range []string{"private_key_encrypted", "payload.json", "envelope"} {
		if strings.Contains(string(raw), bad) {
			t.Fatal("sensitive audit")
		}
	}
}
