package httpserver

import (
	"authgo/internal/apidocs"
	"authgo/internal/model"
	"strconv"
	"testing"
	"time"
)

func TestAdminManagementAndDockerDocs(t *testing.T) {
	f := newLicensingFixture(t)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	a := data(f.request(t, "POST", "/applications", owner, map[string]any{"name": "容器软件", "docker_image": "your-org/your-app", "grace_hours": 0}, 200))
	if a["docker_image"] != "your-org/your-app" || a["grace_hours"] != float64(0) {
		t.Fatal(a)
	}
	f.request(t, "GET", "/integration/docker", "", nil, 401)
	doc := data(f.request(t, "GET", "/integration/docker", owner, nil, 200))
	if doc["text"] != apidocs.Docker {
		t.Fatal("wrong document")
	}
	app := model.Application{Name: "实例统计", AppKey: "instance-stats", AppSecretEncrypted: "cipher", PrivateKeyEncrypted: "cipher", PublicKey: "pub"}
	if err := f.db.Create(&app).Error; err != nil {
		t.Fatal(err)
	}
	l := model.License{AppID: app.ID, Key: "AUTH-TEST-INSTANCE", Status: "active"}
	if err := f.db.Create(&l).Error; err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	activation := model.Activation{LicenseID: l.ID, Kind: "floating", Value: "instance-floating", Token: "test-only", Status: "active", LeaseExpiresAt: &future}
	if err := f.db.Create(&activation).Error; err != nil {
		t.Fatal(err)
	}
	before := data(f.request(t, "GET", "/stats/overview", owner, nil, 200))
	if before["counts"].(map[string]any)["online_instances"] != float64(1) {
		t.Fatal(before)
	}
	path := "/activations/" + strconv.FormatUint(activation.ID, 10) + "/release-seat"
	f.request(t, "POST", path, "", map[string]any{}, 401)
	f.request(t, "POST", path, owner, map[string]any{}, 200)
	after := data(f.request(t, "GET", "/stats/overview", owner, nil, 200))
	if after["counts"].(map[string]any)["online_instances"] != float64(0) {
		t.Fatal(after)
	}
	var audits int64
	f.db.Model(&model.AuditLog{}).Where("action=?", "activation.release-seat").Count(&audits)
	if audits != 1 {
		t.Fatal("release not audited", audits)
	}
}
