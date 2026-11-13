package verify

import (
	"authgo/internal/code"
	"authgo/internal/model"
	"testing"
	"time"
)

func TestDisabledVersionIsIndependentOfWithdrawal(t *testing.T) {
	now := time.Now().UTC()
	in := Input{Application: model.Application{Base: model.Base{ID: 1}, Status: "active", HeartbeatInterval: 60}, License: model.License{Base: model.Base{ID: 1}, AppID: 1, Key: "key", Status: "active", VerifyMethods: []string{"KEY"}, MatchMode: "all", MaxActivations: 1, ValidityRule: "perpetual"}, Request: Request{Operation: Activate, IP: "203.0.113.7", Key: "key", Version: "1.0.0", SessionID: "s", Now: now}, Versions: []model.AppVersion{{Version: "1.0.0", Disabled: true, PublishedAt: &now}, {Version: "2.0.0", PublishedAt: &now}, {Version: "3.0.0", Withdrawn: true, PublishedAt: &now}, {Version: "4.0.0", Disabled: true, PublishedAt: &now}}}
	r := Evaluate(in)
	if r.Pass || r.Errors[0] != code.VersionDisabled || r.LatestVersion != "2.0.0" {
		t.Fatal(r)
	}
	in.Versions[0].Disabled = false
	in.Versions[0].Withdrawn = true
	if r = Evaluate(in); !r.Pass {
		t.Fatal("withdrawal disabled running version", r)
	}
	in.Versions[0].Disabled = true
	in.Request.Version = ""
	if r = Evaluate(in); !r.Pass {
		t.Fatal("empty version refused", r)
	}
	in.Request.Version = "1.0.0"
	in.Request.SkipVersionCheck = true
	if r = Evaluate(in); !r.Pass {
		t.Fatal("update authorization blocked by disabled running version", r)
	}
	in.Request.SkipVersionCheck = false
	in.License.Status = "revoked"
	if r = Evaluate(in); r.Errors[0] != code.LicenseRevoked {
		t.Fatal("explicit license refusal did not win", r)
	}
}
