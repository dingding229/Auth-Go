package httpserver

import (
	"authgo/internal/model"
	"fmt"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLicenseTemplateRoutesAndAudit(t *testing.T) {
	f := newLicensingFixture(t)
	owner := f.login(t, "owner", "initial-password")["access_token"].(string)
	app := data(f.request(t, "POST", "/applications", owner, gin.H{"name": "同步软件"}, 200))
	user := data(f.request(t, "POST", "/users", owner, gin.H{"name": "用户"}, 200))
	base := idPath("/applications", app["id"]) + "/templates"
	source := data(f.request(t, "POST", base, owner, gin.H{"name": "专业版", "features": gin.H{"export": true}}, 200))
	l := data(f.request(t, "POST", "/licenses", owner, gin.H{"app_id": app["id"], "user_id": user["id"], "template_id": source["id"], "features": gin.H{"manual": true}}, 200))
	if l["template_id"] != source["id"] || l["template_name"] != "专业版" || l["features"].(map[string]any)["manual"] != true {
		t.Fatal(l)
	}
	licensePath, sourcePath := idPath("/licenses", l["id"]), idPath(base, source["id"])
	f.request(t, "GET", sourcePath+"/counts", "", nil, 401)
	f.request(t, "POST", sourcePath+"/sync", "", gin.H{"scope": "all"}, 401)
	f.request(t, "POST", licensePath+"/template", "", gin.H{"template_id": source["id"]}, 401)
	counts := data(f.request(t, "GET", sourcePath+"/counts", owner, nil, 200))
	if counts["linked"] != float64(1) || counts["all"] != float64(1) {
		t.Fatal(counts)
	}
	f.request(t, "POST", sourcePath+"/sync", owner, gin.H{"scope": "invalid"}, 400)
	f.request(t, "POST", sourcePath+"/sync", owner, gin.H{"scope": "all", "extra": 1}, 400)
	out := data(f.request(t, "POST", sourcePath+"/sync", owner, gin.H{"scope": "linked"}, 200))
	if out["count"] != float64(1) {
		t.Fatal(out)
	}
	var audit model.AuditLog
	if err := f.db.Where("action=? AND status_code=200", "template.sync").First(&audit).Error; err != nil {
		t.Fatal(err)
	}
	if audit.ResourceID != fmt.Sprint(source["id"]) || audit.Details["scope"] != "linked" || fmt.Sprint(audit.Details["count"]) != "1" {
		t.Fatal(audit)
	}
	f.request(t, "POST", licensePath+"/template", owner, gin.H{"template_id": source["id"]}, 200)
	audit = model.AuditLog{}
	if err := f.db.Where("action=? AND status_code=200", "license.template").First(&audit).Error; err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(audit.Details["template_id"]) != fmt.Sprint(source["id"]) {
		t.Fatal(audit)
	}
	f.request(t, "DELETE", sourcePath, owner, nil, 200)
	l = data(f.request(t, "GET", licensePath, owner, nil, 200))
	if l["template_id"] != nil || l["template_name"] != "" || l["features"].(map[string]any)["export"] != true {
		t.Fatal(l)
	}
}
