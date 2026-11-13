package httpserver

import (
	"authgo/internal/code"
	"authgo/internal/model"
	"authgo/internal/portal"
	"fmt"
	"github.com/gin-gonic/gin"
	"strconv"
	"testing"
)

func TestAllReleaseEntrypointsDeleteInstanceAndAudit(t *testing.T) {
	for _, source := range []string{"admin", "portal", "sdk"} {
		t.Run(source, func(t *testing.T) {
			f := newPortalFixture(t, portal.Options{}, nil)
			admin := f.login(t, "owner", "initial-password", "")["access_token"].(string)
			user := userPassword(t, f)
			token := data(f.call(t, "activate", f.input(""), code.OK))["activation_token"].(string)
			var instance model.Activation
			if err := f.db.Where("license_id=? AND kind='floating'", f.license.ID).First(&instance).Error; err != nil {
				t.Fatal(err)
			}
			id := strconv.FormatUint(instance.ID, 10)
			// Natural lease timeout must leave an offline row visible, unlike release.
			past := f.clock.now().Add(-1)
			if err := f.db.Model(&instance).Update("lease_expires_at", past).Error; err != nil {
				t.Fatal(err)
			}
			before := data(f.request(t, "GET", "/activations?kind=floating", admin, nil, 200))
			if before["total"] != float64(1) {
				t.Fatal("expired instance was hidden", before["total"])
			}
			switch source {
			case "admin":
				f.request(t, "POST", "/activations/"+id+"/release-seat", admin, gin.H{}, 200)
			case "portal":
				f.p(t, "POST", "/user/instances/"+id+"/release-seat", user, gin.H{}, "OK")
			case "sdk":
				f.call(t, "release-seat", f.input(token), code.OK)
			}
			for _, path := range []string{"/activations?kind=floating", fmt.Sprintf("/licenses/%d/activations?kind=floating", f.license.ID)} {
				result := data(f.request(t, "GET", path, admin, nil, 200))
				if result["total"] != float64(0) || len(result["items"].([]any)) != 0 {
					t.Fatal("released instance remains", path, result["total"])
				}
			}
			detail := data(f.request(t, "GET", fmt.Sprintf("/licenses/%d", f.license.ID), admin, nil, 200))
			if detail["online_instances"] != float64(0) {
				t.Fatal("unexpected online instance count", detail["online_instances"])
			}
			for _, item := range detail["activations"].([]any) {
				if item.(map[string]any)["id"] == float64(instance.ID) {
					t.Fatal("detail retained deleted instance")
				}
			}
			var count int64
			if err := f.db.Model(&model.AuditLog{}).Where("action='instance.release' AND resource_id=? AND operator=?", id, source).Count(&count).Error; err != nil || count != 1 {
				t.Fatal("missing transactional audit", count, err)
			}
			auditView := data(f.request(t, "GET", "/audit-logs?action=instance.release", admin, nil, 200))
			found := false
			for _, entry := range auditView["items"].([]any) {
				row := entry.(map[string]any)
				if row["resource_id"] == id && row["operator"] == source {
					found = true
				}
			}
			if !found {
				t.Fatal("release not exposed by audit API", auditView)
			}
			// Session proof and original cache remain valid: recompetition is authorized,
			// and the newly created instance must get a fresh binding reference.
			f.call(t, "heartbeat", f.input(token), code.OK)
			var fresh model.Activation
			if err := f.db.Where("kind='floating' AND license_id=?", f.license.ID).First(&fresh).Error; err != nil || fresh.ID == instance.ID {
				t.Fatal("not recreated", fresh, err)
			}
			var refs int64
			if err := f.db.Model(&model.ClientSessionBinding{}).Where("activation_id=?", fresh.ID).Count(&refs).Error; err != nil || refs != 1 {
				t.Fatal("new instance lacks proof binding", refs, err)
			}
			view := data(f.request(t, "GET", "/activations", admin, nil, 200))["items"].([]any)
			foundInstance := false
			for _, raw := range view {
				row := raw.(map[string]any)
				if row["id"] == float64(fresh.ID) {
					foundInstance = true
					if row["instance_id"] != f.input(token)["device_fingerprint"] {
						t.Fatal("instance identity mismatch")
					}
				}
			}
			if !foundInstance {
				t.Fatal("recreated instance missing from list")
			}

			f.drain(t)
			var releaseLogs int64
			if err := f.db.Model(&model.VerifyLog{}).Where("action='release-seat' AND success=1").Count(&releaseLogs).Error; err != nil || releaseLogs != 0 {
				t.Fatal("successful release must only be in audit log", releaseLogs, err)
			}
		})
	}
}
