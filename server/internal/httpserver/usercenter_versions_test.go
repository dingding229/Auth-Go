package httpserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"authgo/internal/licensing"
	"authgo/internal/model"
	"authgo/internal/portal"
	"github.com/gin-gonic/gin"
)

func TestKeyOnlyQuotaStatusesDaysAndStableAttentionOrder(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	token := userPassword(t, f)
	now := f.clock.now()
	keyOnly, e := f.licensing.Create(context.Background(), licensing.CreateInput{AppID: f.app.ID, UserID: f.license.UserID, VerifyMethods: ptr([]string{"KEY"})})
	if e != nil {
		t.Fatal(e)
	}
	first := now.Add(24 * time.Hour)
	second := now.Add(2 * 24 * time.Hour)
	if e = f.db.Model(&model.License{}).Where("id=?", f.license.ID).Update("expires_at", second).Error; e != nil {
		t.Fatal(e)
	}
	if e = f.db.Model(&model.License{}).Where("id=?", keyOnly.ID).Update("expires_at", first).Error; e != nil {
		t.Fatal(e)
	}
	view := data(f.p(t, "GET", "/licenses", token, nil, "OK"))
	for _, raw := range view["items"].([]any) {
		row := raw.(map[string]any)
		if fmt.Sprint(row["id"]) == fmt.Sprint(keyOnly.ID) {
			if row["unlimited_instances"] != true || fmt.Sprint(row["remaining_days"]) != "1" {
				t.Fatal(row)
			}
		}
	}
	attention := data(f.p(t, "GET", "/user/attention", token, nil, "OK"))["items"].([]any)
	if len(attention) != 2 || fmt.Sprint(attention[0].(map[string]any)["license_id"]) != fmt.Sprint(keyOnly.ID) {
		t.Fatal("same-priority items must be deadline-ordered", attention)
	}
	// Expired status is derived at the boundary; the stored active/unused status is untouched.
	if e = f.db.Model(&model.License{}).Where("id=?", keyOnly.ID).Updates(map[string]any{"type": "trial", "expires_at": now}).Error; e != nil {
		t.Fatal(e)
	}
	detail := data(f.p(t, "GET", fmt.Sprintf("/licenses/%d", keyOnly.ID), token, nil, "OK"))
	if detail["status"] != "expired" || detail["renewal_required"] != true || fmt.Sprint(detail["remaining_days"]) != "0" || fmt.Sprint(detail["trial_remaining_days"]) != "0" || detail["deployment"].(map[string]any)["compose"] != "" {
		t.Fatal(detail)
	}
	expired := data(f.p(t, "GET", "/licenses?status=expired", token, nil, "OK"))
	if fmt.Sprint(expired["total"]) != "1" {
		t.Fatal(expired)
	}
	active := data(f.p(t, "GET", "/licenses?status=unused", token, nil, "OK"))
	if fmt.Sprint(active["total"]) != "1" {
		t.Fatal(active)
	}
	// No selected license is needed for global data, including when a prior selection expires.
	selected := data(f.p(t, "POST", "/switch", token, gin.H{"license_id": keyOnly.ID}, "OK"))["portal_token"].(string)
	f.p(t, "GET", "/user/updates", selected, nil, "OK")
	// Missing deadlines sort after dated deadlines, preserving a strict total order.
	if e = f.db.Model(&model.License{}).Where("id=?", f.license.ID).Update("expires_at", now).Error; e != nil {
		t.Fatal(e)
	}
	if e = f.db.Model(&model.License{}).Where("id=?", keyOnly.ID).Updates(map[string]any{"status": "expired", "expires_at": nil}).Error; e != nil {
		t.Fatal(e)
	}
	older := usercenterLicense(t, f, f.app.ID, *f.license.UserID)
	if e = f.db.Model(&model.License{}).Where("id=?", older.ID).Update("expires_at", now.Add(-24*time.Hour)).Error; e != nil {
		t.Fatal(e)
	}
	ordered := data(f.p(t, "GET", "/user/attention", token, nil, "OK"))["items"].([]any)
	expected := []uint64{older.ID, f.license.ID, keyOnly.ID}
	if len(ordered) != len(expected) {
		t.Fatal(ordered)
	}
	for i, row := range ordered {
		if fmt.Sprint(row.(map[string]any)["license_id"]) != fmt.Sprint(expected[i]) {
			t.Fatal("deadline order is unstable", ordered)
		}
	}
}

func TestGithubRepositoryAndAssetsNotPublic(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	pair := f.login(t, "owner", "initial-password", "")
	token := pair["access_token"].(string)
	for _, path := range []string{"/applications/1/repository", "/applications/1/update-versions", "/version-assets/1"} {
		f.request(t, "GET", path, token, nil, 404)
	}
}
