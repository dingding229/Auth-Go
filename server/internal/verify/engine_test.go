package verify

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"authgo/internal/code"
	"authgo/internal/model"
)

var now = time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
var fingerprint = strings.Repeat("a", 64)

func instant(d time.Duration) *time.Time { v := now.Add(d); return &v }
func fixture() Input {
	return Input{
		Application: model.Application{Base: model.Base{ID: 1}, Status: "active", HeartbeatInterval: 60},
		License:     model.License{Base: model.Base{ID: 2}, AppID: 1, Key: "key", Status: "unused", VerifyMethods: []string{"KEY"}, MatchMode: "all", MaxActivations: 1, ValidityRule: "perpetual"},
		Request:     Request{Operation: Activate, Key: "key", IP: "203.0.113.1", Device: fingerprint, Version: "1.2.3", SessionID: "session", Now: now},
	}
}
func TestEnginePolicies(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Input)
		want   string
		writes int
	}{
		{"key", func(i *Input) {}, "", 0}, {"key always required with any", func(i *Input) {
			i.License.MatchMode = "any"
			i.License.VerifyMethods = []string{"KEY", "FLOATING"}
			i.Request.Key = "wrong"
		}, code.LicenseNotFound, 0},
		{"missing KEY policy", func(i *Input) { i.License.VerifyMethods = []string{"FLOATING"} }, code.InvalidPolicy, 0},
		{"disabled user before any", func(i *Input) {
			id := uint64(7)
			i.License.UserID = &id
			i.License.User = &model.EndUser{Status: "disabled"}
			i.License.MatchMode = "any"
		}, code.UserDisabled, 0},
		{"missing user snapshot", func(i *Input) { id := uint64(7); i.License.UserID = &id }, code.UserDisabled, 0},
		{"active user", func(i *Input) {
			id := uint64(7)
			i.License.UserID = &id
			i.License.User = &model.EndUser{Status: "active"}
		}, "", 0},
		{"disabled app", func(i *Input) { i.Application.Status = "disabled" }, code.AppDisabled, 0},
		{"revoked before instance checks", func(i *Input) {
			i.License.Status = "revoked"
			i.License.VerifyMethods = []string{"KEY", "FLOATING"}
			i.Request.Device = ""
		}, code.LicenseRevoked, 0},
		{"suspended", func(i *Input) { i.License.Status = "suspended" }, code.LicenseSuspended, 0},
		{"expired state", func(i *Input) { i.License.Status = "expired" }, code.LicenseExpired, 0},
		{"unused verify", func(i *Input) { i.Request.Operation = Verify }, code.LicenseNotActivated, 0},
		{"future start", func(i *Input) { i.License.StartsAt = instant(time.Second) }, code.LicenseNotStarted, 0},
		{"expires exact second", func(i *Input) { i.License.ExpiresAt = instant(0) }, code.LicenseExpired, 0},
		{"before expiration", func(i *Input) { i.License.ExpiresAt = instant(time.Nanosecond) }, "", 0},
		{"invalid method", func(i *Input) { i.License.VerifyMethods = []string{"KEY", "USER"} }, code.InvalidPolicy, 0},
		{"duplicate method", func(i *Input) { i.License.VerifyMethods = []string{"KEY", "KEY"} }, code.InvalidPolicy, 0},
		{"strict semver", func(i *Input) { i.Request.Version = "1.2" }, code.VersionNotAllowed, 0},
		{"device invalid", func(i *Input) { i.Request.Device = "not-hash" }, code.DeviceInvalid, 0},
		{"floating no device needed", func(i *Input) { i.License.VerifyMethods = []string{"KEY", "FLOATING"}; i.Request.Device = "" }, "", 1},
		{"floating full", func(i *Input) {
			i.License.VerifyMethods = []string{"KEY", "FLOATING"}
			i.Activations = []model.Activation{{Kind: "floating", Value: "other", Status: "active", LeaseExpiresAt: instant(time.Second)}}
		}, code.FloatingLimitReached, 0},
		{"floating lease expires exact", func(i *Input) {
			i.License.VerifyMethods = []string{"KEY", "FLOATING"}
			i.Activations = []model.Activation{{Kind: "floating", Value: "other", Status: "active", LeaseExpiresAt: instant(0)}}
		}, "", 1},
		{"verify expired own lease", func(i *Input) {
			i.License.Status = "active"
			i.License.VerifyMethods = []string{"KEY", "FLOATING"}
			i.Request.Operation = Verify
			i.Activations = []model.Activation{{Kind: "floating", Value: "session", Status: "active", LeaseExpiresAt: instant(0)}}
		}, code.LeaseExpired, 0},
		{"heartbeat reacquires", func(i *Input) {
			i.License.Status = "active"
			i.License.VerifyMethods = []string{"KEY", "FLOATING"}
			i.Request.Operation = Heartbeat
			i.Activations = []model.Activation{{Kind: "floating", Value: "session", Status: "active", LeaseExpiresAt: instant(0)}}
		}, "", 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			in := fixture()
			tt.change(&in)
			before, _ := json.Marshal(in)
			got := Evaluate(in)
			after, _ := json.Marshal(in)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("engine mutated inputs")
			}
			if got.Pass != (tt.want == "") {
				t.Fatalf("result=%+v want=%s", got, tt.want)
			}
			if tt.want != "" && (len(got.Errors) == 0 || got.Errors[0] != tt.want) {
				t.Fatalf("result=%+v want=%s", got, tt.want)
			}
			if len(got.Writes) != tt.writes {
				t.Fatalf("writes=%+v want=%d", got.Writes, tt.writes)
			}
		})
	}
}
func TestActivationClockAndLease(t *testing.T) {
	in := fixture()
	in.License.ValidityRule = "after_activation"
	in.License.DurationDays = 2
	in.License.VerifyMethods = []string{"KEY", "FLOATING"}
	got := Evaluate(in)
	if !got.Pass || !got.StartsAt.Equal(now) || !got.ExpiresAt.Equal(now.AddDate(0, 0, 2)) || !got.Writes[0].LeaseExpiresAt.Equal(now.Add(120*time.Second)) {
		t.Fatalf("%+v", got)
	}
	in.License.ValidityRule = "fixed_expiry"
	in.License.ExpiresAt = instant(10 * time.Second)
	got = Evaluate(in)
	if !got.Writes[0].LeaseExpiresAt.Equal(*in.License.ExpiresAt) {
		t.Fatal("lease exceeded expiry")
	}

}

func TestWithdrawnDockerVersionStillRunsAndParticipatesInDisabledHint(t *testing.T) {
	in := fixture()
	at := now.Add(-time.Hour)
	in.Versions = []model.AppVersion{{Version: in.Request.Version, Source: "docker", Withdrawn: true, PublishedAt: &at}}
	if out := Evaluate(in); !out.Pass {
		t.Fatal("withdrawal must not revoke runtime authorization", out)
	}
	in.Versions[0].Disabled = true
	in.Versions = append(in.Versions, model.AppVersion{Version: "2.0.0", Source: "docker", PublishedAt: &at})
	out := Evaluate(in)
	if out.Pass || len(out.Errors) == 0 || out.Errors[0] != code.VersionDisabled || out.LatestVersion != "2.0.0" {
		t.Fatal(out)
	}
}

func TestReleasedInstanceRestartUsesKeyAnchorWithoutBypassingCapacity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Input)
		want   string
	}{
		{"new process", func(*Input) {}, ""},
		{"same process still needs heartbeat", func(i *Input) { i.Request.InstanceSession = "old" }, code.LeaseExpired},
		{"missing anchor", func(i *Input) { i.Activations = nil }, code.LeaseExpired},
		{"inactive anchor", func(i *Input) { i.Activations[0].Status = "unbound" }, code.LeaseExpired},
		{"offline anchor", func(i *Input) { i.Activations[0].OfflineAt = instant(-time.Second) }, code.LeaseExpired},
		{"internal update or unlock cannot acquire", func(i *Input) { i.Request.SkipVersionCheck = true }, code.LeaseExpired},
		{"full remains full", func(i *Input) {
			i.Activations = append(i.Activations, model.Activation{Kind: "floating", Value: "other", Status: "active", LeaseExpiresAt: instant(time.Minute)})
		}, code.FloatingLimitReached},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := fixture()
			in.License.Status = "active"
			in.License.VerifyMethods = []string{"KEY", "FLOATING"}
			in.Request.Operation = Verify
			in.Request.InstanceSession = "new"
			in.Activations = []model.Activation{{Kind: "key", Value: in.Request.SessionID, Status: "active", InstanceSession: "old"}}
			tc.change(&in)
			result := Evaluate(in)
			if tc.want != "" {
				if result.Pass || len(result.Errors) == 0 || result.Errors[0] != tc.want || len(result.Writes) != 0 {
					t.Fatal("unexpected refusal or writes", result.Errors, len(result.Writes))
				}
				return
			}
			if !result.Pass || len(result.Writes) != 1 || result.Writes[0].Kind != "floating" || result.Writes[0].Value != fingerprint {
				t.Fatal("new process did not reacquire")
			}
		})
	}
}
