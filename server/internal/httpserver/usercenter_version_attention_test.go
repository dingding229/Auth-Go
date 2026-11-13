package httpserver

import (
	"authgo/internal/licensing"
	"authgo/internal/model"
	"authgo/internal/portal"
	"fmt"
	"testing"
	"time"
)

func TestUpdatesRequireAnOlderOnlineInstanceButKeepPublishedVersion(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, func(in *licensing.CreateInput) { in.VerifyMethods = ptr([]string{"KEY", "FLOATING"}) })
	token := userPassword(t, f)
	now := f.clock.now()
	future := now.Add(time.Hour)
	if err := f.db.Model(&model.Application{}).Where("id=?", f.app.ID).Update("docker_image", "example-org/public-app").Error; err != nil {
		t.Fatal(err)
	}
	usercenterVersion(t, f, f.app.ID, "2.0.0", now.Add(-time.Hour), false, "docker")
	usercenterDockerTags(t, f, `{"2.0.0":"2.0.0"}`)
	for _, tc := range []struct {
		name string
		rows []model.Activation
		want bool
	}{
		{"never run", nil, false},
		{"expired lease", []model.Activation{{Kind: "floating", Status: "active", ClientVersion: "1.0.0", LeaseExpiresAt: &now}}, false},
		{"released", []model.Activation{{Kind: "floating", Status: "released", ClientVersion: "1.0.0", LeaseExpiresAt: &future}}, false},
		{"offline", []model.Activation{{Kind: "floating", Status: "active", ClientVersion: "1.0.0", LeaseExpiresAt: &future, OfflineAt: &now}}, false},
		{"unknown version", []model.Activation{{Kind: "floating", Status: "active", ClientVersion: "unknown", LeaseExpiresAt: &future}}, false},
		{"empty version", []model.Activation{{Kind: "floating", Status: "active", LeaseExpiresAt: &future}}, false},
		{"current", []model.Activation{{Kind: "floating", Status: "active", ClientVersion: "2.0.0", LeaseExpiresAt: &future}}, false},
		{"newer", []model.Activation{{Kind: "floating", Status: "active", ClientVersion: "3.0.0", LeaseExpiresAt: &future}}, false},
		{"older", []model.Activation{{Kind: "floating", Status: "active", ClientVersion: "v1.0.0", LeaseExpiresAt: &future}}, true},
		{"one older among online", []model.Activation{{Kind: "floating", Status: "active", ClientVersion: "2.0.0", LeaseExpiresAt: &future}, {Kind: "floating", Status: "active", ClientVersion: "1.0.0", LeaseExpiresAt: &future}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.db.Where("license_id=?", f.license.ID).Delete(&model.Activation{}).Error; err != nil {
				t.Fatal(err)
			}
			for i, row := range tc.rows {
				row.LicenseID = f.license.ID
				row.Value = fmt.Sprintf("version-case-%d", i)
				row.Token = fmt.Sprintf("synthetic-version-case-%d", i)
				usercenterCreate(t, f, &row)
			}
			attention := data(f.p(t, "GET", "/user/attention", token, nil, "OK"))
			updateAttention := false
			for _, item := range attention["items"].([]any) {
				if item.(map[string]any)["type"] == "update_available" {
					updateAttention = true
				}
			}
			if updateAttention != tc.want {
				t.Fatalf("update attention=%v want=%v", updateAttention, tc.want)
			}
			updates := data(f.p(t, "GET", "/user/updates", token, nil, "OK"))["items"].([]any)
			if len(updates) != 1 {
				t.Fatal("published software missing")
			}
			row := updates[0].(map[string]any)
			if row["has_update"] != tc.want || row["version"] != "2.0.0" || row["latest_entitled_version"] != "2.0.0" || row["docker_pull"] != "docker pull example-org/public-app:2.0.0" || row["available"] != true {
				t.Fatalf("version projection missing or wrong: %+v", row)
			}
		})
	}
}

func TestUserUpdateAggregatesOnlineNeedsWithoutFlaggingUnrunLicense(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, func(in *licensing.CreateInput) { in.VerifyMethods = ptr([]string{"KEY", "FLOATING"}) })
	token := userPassword(t, f)
	now := f.clock.now()
	maintenanceAt := now.Add(-30 * time.Minute)
	lease := now.Add(time.Hour)
	if err := f.db.Model(&model.Application{}).Where("id=?", f.app.ID).Update("docker_image", "example-org/public-app").Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Model(&model.License{}).Where("id=?", f.license.ID).Update("maintenance_until", maintenanceAt).Error; err != nil {
		t.Fatal(err)
	}
	usercenterVersion(t, f, f.app.ID, "2.0.0", now.Add(-time.Hour), false, "docker")
	usercenterVersion(t, f, f.app.ID, "3.0.0", now, false, "docker")
	usercenterDockerTags(t, f, `{"2.0.0":"2.0.0","3.0.0":"3.0.0"}`)
	_ = usercenterLicense(t, f, f.app.ID, *f.license.UserID) // Higher entitlement, never run.
	usercenterCreate(t, f, &model.Activation{LicenseID: f.license.ID, Kind: "floating", Value: "running-old", Token: "synthetic-running-old", Status: "active", ClientVersion: "1.0.0", LeaseExpiresAt: &lease})
	rows := data(f.p(t, "GET", "/user/updates", token, nil, "OK"))["items"].([]any)
	if len(rows) != 1 {
		t.Fatal("software not grouped")
	}
	row := rows[0].(map[string]any)
	if row["has_update"] != true || row["latest_entitled_version"] != "3.0.0" || row["docker_pull"] != "docker pull example-org/public-app:3.0.0" {
		t.Fatal("online update need lost when selecting deployment license", row)
	}
	count := 0
	for _, raw := range data(f.p(t, "GET", "/user/attention", token, nil, "OK"))["items"].([]any) {
		item := raw.(map[string]any)
		if item["type"] == "update_available" {
			count++
			if fmt.Sprint(item["license_id"]) != fmt.Sprint(f.license.ID) {
				t.Fatal("unrun license has update attention")
			}
		}
	}
	if count != 1 {
		t.Fatalf("update attention count=%d", count)
	}
}
