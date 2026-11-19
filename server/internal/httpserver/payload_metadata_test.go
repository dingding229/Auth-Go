package httpserver

import (
	"authgo/internal/model"
	"fmt"
	"github.com/gin-gonic/gin"
	"reflect"
	"testing"
)

func TestVersionMetadataHTTP(t *testing.T) {
	f := newCatalogFixture(t)
	token := f.login(t, "owner", "initial-password")["access_token"].(string)
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

func TestConfirmedVersionMetadataHTTP(t *testing.T) {
	f := newCatalogFixture(t)
	token := f.login(t, "owner", "initial-password")["access_token"].(string)
	app := data(f.request(t, "POST", "/applications", token, gin.H{"name": "confirmed metadata"}, 200))
	path := "/applications/" + fmt.Sprint(app["id"]) + "/versions"
	v := data(f.request(t, "POST", path, token, gin.H{"version": "1.0.0", "encrypted": true, "built_at": "2026-11-08T00:00:00Z"}, 200))
	if v["build_verified"] != false {
		t.Fatal("manual creation was marked verified", v)
	}
	if err := f.db.Model(&model.AppVersion{}).Where("id=?", v["id"]).Update("build_verified", true).Error; err != nil {
		t.Fatal(err)
	}
	id := "/versions/" + fmt.Sprint(v["id"])
	v = data(f.request(t, "PATCH", id, token, gin.H{"encrypted": false, "built_at": nil, "changelog": "edited", "disabled": true}, 200))
	if v["build_verified"] != true || v["encrypted"] != true || v["built_at"] != "2026-11-08T00:00:00Z" || v["changelog"] != "edited" || v["disabled"] != true {
		t.Fatal("PATCH changed confirmed fields or rejected other fields", v)
	}
	v = data(f.request(t, "GET", id, token, nil, 200))
	if v["build_verified"] != true {
		t.Fatal("GET omitted confirmation", v)
	}
}

func TestVersionArchitecturesAreReadOnly(t *testing.T) {
	f := newCatalogFixture(t)
	token := f.login(t, "owner", "initial-password")["access_token"].(string)
	app := data(f.request(t, "POST", "/applications", token, gin.H{"name": "软件架构"}, 200))
	path := idPath("/applications", app["id"]) + "/versions"
	manual := data(f.request(t, "POST", path, token, gin.H{"version": "1.0.0"}, 200))
	f.request(t, "POST", path, token, gin.H{"version": "3.0.0", "architectures": []string{"s390x"}}, 400)
	version := data(f.request(t, "POST", path, token, gin.H{"version": "2.0.0"}, 200))
	if err := f.db.Model(&model.AppVersion{}).Where("id=?", version["id"]).Update("architectures", "amd64,arm/v7").Error; err != nil {
		t.Fatal(err)
	}
	items := data(f.request(t, "GET", path+"?sort_by=id&sort_order=asc", token, nil, 200))["items"].([]any)
	if len(items) != 2 {
		t.Fatal(items)
	}
	first, second := items[0].(map[string]any), items[1].(map[string]any)
	if first["id"] != manual["id"] || !reflect.DeepEqual(first["architectures"], []any{}) || !reflect.DeepEqual(second["architectures"], []any{"amd64", "arm/v7"}) {
		t.Fatal(items)
	}
	id := idPath("/versions", version["id"])
	updated := data(f.request(t, "PATCH", id, token, gin.H{"architectures": []string{"s390x"}, "changelog": "变更说明"}, 200))
	if updated["changelog"] != "变更说明" || !reflect.DeepEqual(updated["architectures"], second["architectures"]) {
		t.Fatal(updated)
	}
	stored := data(f.request(t, "GET", id, token, nil, 200))
	unchanged := data(f.request(t, "PATCH", id, token, gin.H{"architectures": nil}, 200))
	if !reflect.DeepEqual(unchanged, stored) {
		t.Fatal("read-only PATCH changed the version", unchanged, stored)
	}
	f.request(t, "PATCH", id, token, gin.H{"architectures": []string{}, "unknown_field": true}, 400)
	f.request(t, "PATCH", id, token, gin.H{}, 400)
}
