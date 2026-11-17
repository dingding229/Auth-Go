package client

import (
	"authgo/internal/code"
	"authgo/internal/model"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestPayloadConfirmsExistingBuild(t *testing.T) {
	for _, trial := range []bool{false, true} {
		t.Run(map[bool]string{false: "standard", true: "trial"}[trial], func(t *testing.T) {
			f := newUnlockFixture(t)
			if trial {
				if err := f.db.Model(&f.l).Update("type", model.LicenseTrial).Error; err != nil {
					t.Fatal(err)
				}
			}
			// An unconfirmed manual time is not evidence, even if it is earlier.
			manual := f.clock.now().Add(-24 * time.Hour)
			row := model.AppVersion{AppID: f.app.ID, Version: f.p.Version, BuiltAt: &manual}
			if err := f.db.Create(&row).Error; err != nil {
				t.Fatal(err)
			}
			if err := f.db.Exec("CREATE TABLE build_updates (id integer); CREATE TRIGGER count_build_updates AFTER UPDATE ON app_versions BEGIN INSERT INTO build_updates VALUES (1); END").Error; err != nil {
				t.Fatal(err)
			}
			if out := f.call(f.in); out.Code != code.OK {
				t.Fatal(out.Code)
			}
			if err := f.db.First(&row, row.ID).Error; err != nil {
				t.Fatal(err)
			}
			built, _ := time.Parse(time.RFC3339, f.p.BuiltAt)
			if !row.Encrypted || !row.BuildVerified || row.BuiltAt == nil || !row.BuiltAt.Equal(built) {
				t.Fatalf("build not confirmed: %+v", row)
			}
			if out := f.call(f.in); out.Code != code.OK {
				t.Fatal(out.Code)
			}
			var writes int64
			if err := f.db.Table("build_updates").Count(&writes).Error; err != nil || writes != 1 {
				t.Fatal("repeat unlock wrote build metadata", writes, err)
			}
		})
	}
}

func TestPayloadBuildKeepsEarliestAuthenticatedTime(t *testing.T) {
	f := newUnlockFixture(t)
	row := model.AppVersion{AppID: f.app.ID, Version: f.p.Version}
	if err := f.db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	keys, err := f.service.PayloadKeys().List(context.Background(), f.app.ID)
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	base, _ := time.Parse(time.RFC3339, f.p.BuiltAt)
	// Cover later then earlier, and earlier then later, for the same release.
	for _, hours := range []int{0, 1, -1, 2} {
		p := f.p
		p.BuiltAt = base.Add(time.Duration(hours) * time.Hour).Format(time.RFC3339)
		p = sealPayload(t, p, keys[0].PublicKey)
		in := f.in
		in.Payload, err = json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if out := f.call(in); out.Code != code.OK {
			t.Fatal(out.Code)
		}
		if err := f.db.First(&row, row.ID).Error; err != nil {
			t.Fatal(err)
		}
		want := base
		if hours == -1 || hours == 2 {
			want = base.Add(-time.Hour)
		}
		if row.BuiltAt == nil || !row.BuiltAt.Equal(want) {
			t.Fatal("did not keep earliest authenticated time", row.BuiltAt, want)
		}
	}
}

func TestDeniedPayloadDoesNotConfirmBuild(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(*testing.T, *unlockFixture, *Input)
	}{
		{"session", code.ActivationInvalid, func(_ *testing.T, _ *unlockFixture, in *Input) { in.ActivationToken = "bad" }},
		{"envelope", code.PayloadInvalid, func(_ *testing.T, f *unlockFixture, in *Input) {
			p := f.p
			p.BuiltAt = f.clock.now().Add(-time.Hour).Format(time.RFC3339)
			in.Payload, _ = json.Marshal(p) // The modified timestamp is not authenticated.
		}},
		{"disabled", code.VersionDisabled, func(t *testing.T, f *unlockFixture, _ *Input) {
			if err := f.db.Model(&model.AppVersion{}).Where("app_id=?", f.app.ID).Update("disabled", true).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{"maintenance", code.MaintenanceExpired, func(t *testing.T, f *unlockFixture, _ *Input) {
			if err := f.db.Model(&f.l).Update("maintenance_until", f.clock.now().Add(-time.Hour)).Error; err != nil {
				t.Fatal(err)
			}
		}},
		{"rewrap", code.PayloadInvalid, func(_ *testing.T, _ *unlockFixture, in *Input) { in.EphemeralPublicKey = "invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newUnlockFixture(t)
			row := model.AppVersion{AppID: f.app.ID, Version: f.p.Version}
			if err := f.db.Create(&row).Error; err != nil {
				t.Fatal(err)
			}
			in := f.in
			tc.mutate(t, f, &in)
			if out := f.call(in); out.Code != tc.want {
				t.Fatal(out.Code, tc.want)
			}
			if err := f.db.First(&row, row.ID).Error; err != nil {
				t.Fatal(err)
			}
			if row.Encrypted || row.BuildVerified || row.BuiltAt != nil {
				t.Fatalf("denied unlock registered metadata: %+v", row)
			}
		})
	}
}

func TestPayloadBuildRegistrationFailureDoesNotFailUnlock(t *testing.T) {
	f := newUnlockFixture(t)
	row := model.AppVersion{AppID: f.app.ID, Version: f.p.Version}
	if err := f.db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	// FAIL retains preceding trigger changes unless the savepoint rolls them back.
	if err := f.db.Exec("CREATE TABLE build_updates (id integer); CREATE TRIGGER fail_build_update BEFORE UPDATE ON app_versions BEGIN INSERT INTO build_updates VALUES (1); SELECT RAISE(FAIL, 'metadata unavailable'); END").Error; err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	f.service.log = slog.New(slog.NewTextHandler(&logs, nil))
	out := f.call(f.in)
	if out.Code != code.OK {
		t.Fatal("metadata failure rejected unlock", out.Code)
	}
	f.unwrap(t, out)
	if !strings.Contains(logs.String(), "登记加密构建元数据失败") {
		t.Fatal("missing metadata warning")
	}
	for _, secret := range []string{"metadata unavailable", f.in.LicenseKey, f.p.Config, string(f.in.Payload)} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("warning leaked request or database details")
		}
	}
	if err := f.db.First(&row, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if row.Encrypted || row.BuildVerified || row.BuiltAt != nil {
		t.Fatal("failed registration changed metadata", row)
	}
	var writes int64
	if err := f.db.Table("build_updates").Count(&writes).Error; err != nil || writes != 0 {
		t.Fatal("failed metadata side effects escaped savepoint", writes, err)
	}
}

func TestPayloadWithoutReleaseDoesNotCreateOne(t *testing.T) {
	f := newUnlockFixture(t)
	if out := f.call(f.in); out.Code != code.OK {
		t.Fatal(out.Code)
	}
	var count int64
	if err := f.db.Model(&model.AppVersion{}).Where("app_id=?", f.app.ID).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("unlock created an unpublished release", count, err)
	}
}

func TestPayloadBuildConfirmationRollsBackWithUnlock(t *testing.T) {
	f := newUnlockFixture(t)
	row := model.AppVersion{AppID: f.app.ID, Version: f.p.Version}
	if err := f.db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	// A later failure in the enclosing transaction must undo confirmation too.
	if err := f.db.Exec("CREATE TRIGGER fail_session_activity BEFORE UPDATE ON client_sessions BEGIN SELECT RAISE(ABORT, 'activity unavailable'); END").Error; err != nil {
		t.Fatal(err)
	}
	if out := f.call(f.in); out.Code != code.InternalError {
		t.Fatal("expected enclosing transaction failure", out.Code)
	}
	if err := f.db.First(&row, row.ID).Error; err != nil {
		t.Fatal(err)
	}
	if row.Encrypted || row.BuildVerified || row.BuiltAt != nil {
		t.Fatal("failed unlock committed confirmation", row)
	}
}
