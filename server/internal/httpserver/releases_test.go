package httpserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"authgo/internal/catalog"
	"authgo/internal/client"
	"authgo/internal/code"
	"authgo/internal/model"

	"github.com/gin-gonic/gin"
)

func TestReleaseCRUDPublicationAndAudit(t *testing.T) {
	f := newClientFixture(t, client.Options{}, nil)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)

	base := fmt.Sprintf("/applications/%d", f.app.ID)
	announcement := data(f.request(t, "POST", base+"/announcements", owner, gin.H{"title": "中文公告", "content": "欢迎使用"}, 200))
	path := idPath("/announcements", announcement["id"])
	if len(data(f.call(t, "announcement", nil, code.OK))["items"].([]any)) != 0 {
		t.Fatal("draft visible")
	}
	f.request(t, "GET", path, owner, nil, 200)
	f.request(t, "PATCH", path, owner, gin.H{"published_at": f.clock.now(), "expires_at": f.clock.now().Add(time.Hour)}, 200)
	f.request(t, "POST", base+"/announcements", owner, gin.H{"title": "未来公告", "published_at": f.clock.now().Add(time.Minute)}, 200)
	f.request(t, "POST", base+"/announcements", owner, gin.H{"title": "刚刚失效", "published_at": f.clock.now().Add(-time.Hour), "expires_at": f.clock.now()}, 200)
	if items := data(f.call(t, "announcement", nil, code.OK))["items"].([]any); len(items) != 1 || items[0].(map[string]any)["title"] != "中文公告" {
		t.Fatal(items)
	}
	f.request(t, "PATCH", path, owner, gin.H{"expires_at": nil, "content": "已更新"}, 200)
	f.request(t, "PATCH", path, owner, gin.H{"published_at": nil}, 200)
	if len(data(f.call(t, "announcement", nil, code.OK))["items"].([]any)) != 0 {
		t.Fatal("unpublished still visible")
	}
	f.request(t, "GET", base+"/announcements?q=中文&sort_by=title&sort_order=asc&page_size=1", owner, nil, 200)
	f.request(t, "PATCH", path, owner, gin.H{"published_at": "invalid"}, 400)
	f.request(t, "DELETE", path, owner, nil, 200)
	f.request(t, "GET", path, owner, nil, 404)
	f.call(t, "version", nil, code.VersionNotFound)
	v := data(f.request(t, "POST", base+"/versions", owner, gin.H{"version": "1.10.0", "changelog": "更新", "mandatory": true}, 200))
	vp := idPath("/versions", v["id"])
	f.call(t, "version", nil, code.VersionNotFound)
	f.request(t, "PATCH", vp, owner, gin.H{"published_at": f.clock.now()}, 200)
	f.request(t, "POST", base+"/versions", owner, gin.H{"version": "1.9.0", "published_at": f.clock.now()}, 200)
	f.request(t, "POST", base+"/versions", owner, gin.H{"version": "9.0.0", "published_at": f.clock.now().Add(time.Hour)}, 200)
	got := data(f.call(t, "version", nil, code.OK))["version"].(map[string]any)
	if got["version"] != "1.10.0" || got["mandatory"] != true {
		t.Fatal(got)
	}
	f.request(t, "POST", base+"/versions", owner, gin.H{"version": "1.10.0"}, 409)
	f.request(t, "POST", base+"/versions", owner, gin.H{"version": "1.2"}, 400)
	f.request(t, "GET", vp, owner, nil, 200)
	f.request(t, "GET", base+"/versions?q=1.&sort_by=version", owner, nil, 200)
	f.request(t, "DELETE", vp, owner, nil, 200)
	got = data(f.call(t, "version", nil, code.OK))["version"].(map[string]any)
	if got["version"] != "1.9.0" {
		t.Fatal(got)
	}
	var audits []model.AuditLog
	if e := f.db.Where("action IN ?", []string{"announcement.create", "announcement.update", "announcement.delete", "version.create", "version.update", "version.delete"}).Find(&audits).Error; e != nil {
		t.Fatal(e)
	}
	found := map[string]bool{}
	for _, a := range audits {
		if a.StatusCode == 200 {
			found[a.Action] = true
			if a.Operator == "" || a.ResourceID == "" {
				t.Fatalf("incomplete audit %+v", a)
			}
		}
	}
	for _, a := range []string{"announcement.create", "announcement.update", "announcement.delete", "version.create", "version.update", "version.delete"} {
		if !found[a] {
			t.Fatal("missing audit", a)
		}
	}
	f.request(t, "PATCH", base, owner, gin.H{"heartbeat_interval": 4}, 400)
	updated := data(f.request(t, "PATCH", base, owner, gin.H{"heartbeat_interval": 30}, 200))
	if updated["heartbeat_interval"] != float64(30) {
		t.Fatal(updated)
	}
	if _, e := f.catalog.UpdateApplication(context.Background(), f.app.ID, catalog.ApplicationInput{HeartbeatInterval: ptr(30)}); e != nil {
		t.Fatal(e)
	}
}

func TestVersionDisabledAdminPatchAndDTO(t *testing.T) {
	f := newClientFixture(t, client.Options{}, nil)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	v := data(f.request(t, "POST", fmt.Sprintf("/applications/%d/versions", f.app.ID), owner, gin.H{"version": "1.0.0"}, 200))
	path := idPath("/versions", v["id"])
	v = data(f.request(t, "PATCH", path, owner, gin.H{"disabled": true}, 200))
	if v["disabled"] != true || v["withdrawn"] != false {
		t.Fatal(v)
	}
	v = data(f.request(t, "PATCH", path, owner, gin.H{"disabled": false}, 200))
	if v["disabled"] != false {
		t.Fatal(v)
	}
}
