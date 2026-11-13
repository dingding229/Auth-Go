package httpserver

import (
	"authgo/internal/model"
	"strings"
	"testing"
	"time"
)

func TestStatsReadModelsAndFilters(t *testing.T) {
	f := newAdminFixture(t)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)

	app := model.Application{Name: "统计应用", AppKey: "stats-app", AppSecretEncrypted: "secret-cipher", PrivateKeyEncrypted: "private-cipher", PublicKey: "pub"}
	f.db.Create(&app)
	now := time.Now().UTC()
	expiry := now.Add(24 * time.Hour)
	l := model.License{AppID: app.ID, Key: "AUTH-STATS-KEY", Status: "active", ExpiresAt: &expiry}
	f.db.Create(&l)
	for _, v := range []model.VerifyLog{{CreatedAt: now.Add(-time.Second), AppID: &app.ID, LicenseID: &l.ID, Success: true, Code: "OK", IP: "203.0.113.1"}, {CreatedAt: now.Add(-2 * time.Second), AppID: &app.ID, LicenseID: &l.ID, Success: false, Code: "FLOATING_LIMIT_REACHED", Device: "stats-instance"}, {CreatedAt: now.AddDate(0, 0, -31), AppID: &app.ID, LicenseID: &l.ID, Success: false, Code: "OLD"}} {
		if e := f.db.Create(&v).Error; e != nil {
			t.Fatal(e)
		}
	}
	overview := data(f.request(t, "GET", "/stats/overview", owner, nil, 200))
	counts := overview["counts"].(map[string]any)
	expiring := overview["expiring"].([]any)
	if len(expiring) != 1 || expiring[0].(map[string]any)["app_name"] != app.Name {
		t.Fatal("missing software name", expiring)
	}
	asOf, err := time.Parse(time.RFC3339Nano, overview["as_of"].(string))
	if err != nil {
		t.Fatal(err)
	}
	expectedTotal, expectedFailed := float64(0), float64(0)
	if !now.Add(-time.Second).Before(asOf.Truncate(24 * time.Hour)) {
		expectedTotal++
	}
	if !now.Add(-2 * time.Second).Before(asOf.Truncate(24 * time.Hour)) {
		expectedTotal++
		expectedFailed++
	}
	expectedRate := float64(0)
	if expectedTotal > 0 {
		expectedRate = expectedFailed / expectedTotal
	}
	if counts["licenses_total"] != float64(1) || counts["today_verifications"] != expectedTotal || overview["today_failure_rate"] != expectedRate {
		t.Fatal(overview)
	}
	trend := data(f.request(t, "GET", "/stats/trend", owner, nil, 200))["items"].([]any)
	sum := float64(0)
	for _, v := range trend {
		sum += v.(map[string]any)["total"].(float64)
	}
	if len(trend) != 30 || sum != 2 {
		t.Fatal(trend)
	}
	failures := data(f.request(t, "GET", "/stats/failures", owner, nil, 200))["items"].([]any)
	if len(failures) != 1 || failures[0].(map[string]any)["code"] != "FLOATING_LIMIT_REACHED" {
		t.Fatal(failures)
	}
	logs := data(f.request(t, "GET", "/verify-logs?success=false&q=stats-instance", owner, nil, 200))
	if logs["total"] != float64(1) {
		t.Fatal(logs)
	}
	for _, path := range []string{"/verify-logs?app_id=bad", "/verify-logs?success=unknown", "/verify-logs?sort_by=token", "/verify-logs?from=bad", "/verify-logs?from=2026-11-04T00:00:00Z&to=2026-11-03T00:00:00Z"} {
		f.request(t, "GET", path, owner, nil, 400)
	}
	f.request(t, "GET", "/stats/overview", "", nil, 401)
	// None of the response projections expose application credentials.
	for _, row := range logs["items"].([]any) {
		for key := range row.(map[string]any) {
			if strings.Contains(key, "token") || strings.Contains(key, "secret") {
				t.Fatal(key)
			}
		}
	}
}
