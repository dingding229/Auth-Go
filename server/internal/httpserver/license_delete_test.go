package httpserver

import (
	"authgo/internal/model"
	"authgo/internal/portal"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLicenseDeletionHTTPAuditAndLogs(t *testing.T) {
	f := newLicensingFixture(t)
	token := f.login(t, "owner", "initial-password")["access_token"].(string)
	app := data(f.request(t, "POST", "/applications", token, gin.H{"name": "deletion"}, 200))
	user := data(f.request(t, "POST", "/users", token, gin.H{"name": "customer"}, 200))
	license := data(f.request(t, "POST", "/licenses", token, gin.H{"app_id": app["id"], "user_id": user["id"]}, 200))
	path := idPath("/licenses", license["id"])
	f.request(t, "DELETE", path, "", nil, 401)
	f.request(t, "DELETE", path, token, nil, 400)
	var l model.License
	if err := f.db.First(&l).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&model.VerifyLog{LicenseID: &l.ID, AppID: &l.AppID, Code: "OK", Reason: "verified"}).Error; err != nil {
		t.Fatal(err)
	}
	f.request(t, "POST", path+"/revoke", token, gin.H{}, 200)
	out := data(f.request(t, "DELETE", path, token, nil, 200))
	if out["key_suffix"] != l.Key[len(l.Key)-4:] {
		t.Fatal(out)
	}
	f.request(t, "GET", path, token, nil, 404)
	logs := data(f.request(t, "GET", "/verify-logs", token, nil, 200))["items"].([]any)
	if len(logs) != 1 || logs[0].(map[string]any)["license_deleted"] != true || logs[0].(map[string]any)["license_id"] != nil {
		t.Fatal(logs)
	}
	var audit model.AuditLog
	if err := f.db.Where("action='license.delete' AND status_code=200").First(&audit).Error; err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(audit)
	if err != nil || strings.Contains(string(raw), l.Key) || audit.Details["key_suffix"] != l.Key[len(l.Key)-4:] || audit.ResourceID != fmt.Sprint(l.ID) {
		t.Fatal(string(raw), err)
	}
}

func TestPurgeRevokedHTTP(t *testing.T) {
	f := newLicensingFixture(t)
	token := f.login(t, "owner", "initial-password")["access_token"].(string)
	app := data(f.request(t, "POST", "/applications", token, gin.H{"name": "purge"}, 200))
	user := data(f.request(t, "POST", "/users", token, gin.H{"name": "user"}, 200))
	license := data(f.request(t, "POST", "/licenses", token, gin.H{"app_id": app["id"], "user_id": user["id"]}, 200))
	f.request(t, "POST", idPath("/licenses", license["id"])+"/revoke", token, gin.H{}, 200)
	f.request(t, "POST", "/licenses/purge-revoked", "", gin.H{}, 401)
	f.request(t, "POST", "/licenses/purge-revoked", token, gin.H{"app_id": 0}, 400)
	f.request(t, "GET", "/licenses?exclude_trial=bad", token, nil, 400)
	list := data(f.request(t, "GET", "/licenses?status=revoked&exclude_trial=true&page_size=1", token, nil, 200))
	if list["total"] != float64(1) {
		t.Fatal(list)
	}
	out := data(f.request(t, "POST", "/licenses/purge-revoked", token, gin.H{"app_id": app["id"]}, 200))
	if out["count"] != float64(1) {
		t.Fatal(out)
	}
	var audits []model.AuditLog
	if err := f.db.Where("action IN ? AND status_code=200", []string{"license.delete", "license.purge_revoked"}).Find(&audits).Error; err != nil || len(audits) != 2 {
		t.Fatal(audits, err)
	}
	for _, audit := range audits {
		raw, _ := json.Marshal(audit)
		if strings.Contains(string(raw), license["key"].(string)) {
			t.Fatal("audit leaked full license key")
		}
	}
}

func TestDeletedLicenseDisappearsFromUserCenter(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	token := userPassword(t, f)
	if _, err := f.licensing.ChangeState(context.Background(), f.license.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.licensing.Delete(context.Background(), f.license.ID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/licenses", "/user/instances", "/user/logs", "/user/updates"} {
		out := data(f.p(t, "GET", path, token, nil, "OK"))
		if fmt.Sprint(out["total"]) != "0" {
			t.Fatal(path, out)
		}
	}
	f.p(t, "GET", fmt.Sprintf("/licenses/%d", f.license.ID), token, nil, "NOT_FOUND")
}
