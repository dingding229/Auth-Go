package httpserver

import (
	"fmt"
	"github.com/gin-gonic/gin"
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
