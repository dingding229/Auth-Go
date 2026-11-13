package verify

import (
	"authgo/internal/code"
	"authgo/internal/model"
	"testing"
	"time"
)

func TestMaintenanceBoundariesAllAuthorizationActions(t *testing.T) {
	for _, op := range []string{Activate, Verify, Heartbeat} {
		for _, tc := range []struct {
			name   string
			offset time.Duration
			want   bool
		}{{"before", -time.Second, true}, {"equal", 0, true}, {"after", time.Second, false}} {
			t.Run(op+"/"+tc.name, func(t *testing.T) {
				in := fixture()
				in.Request.Operation = op
				in.License.Status = "active"
				bound := now.Add(-time.Hour)
				published := bound.Add(tc.offset)
				in.License.MaintenanceUntil = &bound
				in.Versions = []model.AppVersion{{Version: in.Request.Version, PublishedAt: &published, Withdrawn: true}, {Version: "2.0.0", PublishedAt: &bound}}
				r := Evaluate(in)
				if r.Pass != tc.want {
					t.Fatalf("%+v", r)
				}
				if !tc.want && (len(r.Errors) != 1 || r.Errors[0] != code.MaintenanceExpired || r.LatestEntitledVersion != "2.0.0") {
					t.Fatal(r)
				}
				if tc.want && r.LatestEntitledVersion != "2.0.0" {
					t.Fatal(r)
				}
			})
		}
	}
}
func TestMaintenanceUnknownAndDecisionPriority(t *testing.T) {
	in := fixture()
	bound := now.Add(-time.Hour)
	in.License.MaintenanceUntil = &bound
	for _, versions := range [][]model.AppVersion{nil, {{Version: in.Request.Version}}} {
		in.Versions = versions
		r := Evaluate(in)
		if !r.Pass || !r.MaintenanceUnknown {
			t.Fatal(r)
		}
	}
	in.Request.Version = ""
	if r := Evaluate(in); !r.Pass || r.MaintenanceUnknown {
		t.Fatal(r)
	}
	in.Request.Version = "1.2.3"
	in.Versions = []model.AppVersion{{Version: "1.2.3", PublishedAt: &now, Disabled: true}}
	if r := Evaluate(in); r.Errors[0] != code.VersionDisabled {
		t.Fatal(r)
	}
	in.License.Status = "revoked"
	if r := Evaluate(in); r.Errors[0] != code.LicenseRevoked {
		t.Fatal(r)
	}
	in.License.Status = "active"
	in.Versions[0].Disabled = false
	in.License.MaintenanceUntil = nil
	if r := Evaluate(in); !r.Pass || r.LatestEntitledVersion != "" {
		t.Fatal(r)
	}
	in.License.MaintenanceUntil = &bound
	in.Request.SkipVersionCheck = true
	if r := Evaluate(in); !r.Pass {
		t.Fatal(r)
	}
}
func TestLatestEntitledFilters(t *testing.T) {
	in := fixture()
	bound := now.Add(-time.Hour)
	in.License.MaintenanceUntil = &bound
	in.Versions = []model.AppVersion{{Version: "1.2.3", PublishedAt: &now}, {Version: "1.0.0", PublishedAt: &bound}, {Version: "2.0.0", PublishedAt: &bound}, {Version: "3.0.0", PublishedAt: &bound, Disabled: true}, {Version: "4.0.0", PublishedAt: &bound, Withdrawn: true}, {Version: "5.0.0", PublishedAt: &bound}, {Version: "9.0.0"}, {Version: "not-semver", PublishedAt: &bound}}
	r := Evaluate(in)
	if r.Errors[0] != code.MaintenanceExpired || r.LatestEntitledVersion != "5.0.0" {
		t.Fatal(r)
	}
	in.Versions[2].Disabled = true
	in.Versions[5].Disabled = true
	in.Versions[1].Disabled = true
	r = Evaluate(in)
	if r.Errors[0] != code.MaintenanceExpired || r.LatestEntitledVersion != "" {
		t.Fatal(r)
	}
}
