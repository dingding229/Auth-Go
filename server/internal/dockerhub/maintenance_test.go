package dockerhub

import (
	"authgo/internal/model"
	"context"
	"net/http"
	"testing"
	"time"
)

func TestPortalMaintenancePullsOnlyEntitledVersions(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		responsePage(w, []map[string]any{good("1.0.0"), {"name": "2.0.0", "tag_last_pushed": "2025-01-03T03:04:05Z"}}, nil)
	})
	ctx := context.Background()
	if err := f.dbService.Sync(ctx, f.app.ID); err != nil {
		t.Fatal(err)
	}
	bound := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	l := model.License{AppID: f.app.ID, Key: "maintenance-key", Status: "active", MaintenanceUntil: &bound, ValidityRule: "perpetual", VerifyMethods: []string{"KEY"}, MatchMode: "all", MaxActivations: 1}
	if err := f.dbService.db.Create(&l).Error; err != nil {
		t.Fatal(err)
	}
	out, err := f.dbService.ForPortal(ctx, l.ID, "")
	if err != nil || !out.Available || out.Version != "1.0.0" || !out.RenewalRequired || out.LatestEntitledVersion != "1.0.0" || out.DockerPull != "docker pull example-org/example-app:1.0.0" {
		t.Fatal(out, err)
	}
	f.dbService.db.Model(&model.AppVersion{}).Where("app_id=? AND version=?", f.app.ID, "1.0.0").Update("disabled", true)
	out, err = f.dbService.ForPortal(ctx, l.ID, "")
	if err != nil || out.Available || out.DockerPull != "" || out.LatestEntitledVersion != "" || !out.RenewalRequired {
		t.Fatal(out, err)
	}
}
