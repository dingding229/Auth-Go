package client

import (
	"authgo/internal/code"
	"authgo/internal/model"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestInstanceTakeoverAndRelease(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	var l model.License
	f.db.First(&l, "key=?", f.key)
	l.VerifyMethods = []string{"KEY", "FLOATING"}
	if e := f.db.Save(&l).Error; e != nil {
		t.Fatal(e)
	}
	app, e := f.service.channel.EnsureApplication(context.Background(), f.app.ID)
	if e != nil {
		t.Fatal(e)
	}
	proc := func(b byte) string {
		return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(b), 16)))
	}
	reportedVersion := ""
	call := func(op, token, session, device string) outcome {
		return f.service.process(context.Background(), app, op, "203.0.113.7", Input{LicenseKey: f.key, Device: strings.Repeat(device, 64), Version: reportedVersion, ActivationToken: token, InstanceSession: session, Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, f.clock.now())
	}
	a := call("activate", "", proc('a'), "a")
	if a.Code != code.OK {
		t.Fatal(a)
	}
	token := a.Data["activation_token"].(string)
	if r := call("verify", token, proc('b'), "a"); r.Code != code.OK {
		t.Fatal("new process did not take over", r)
	}
	for i := 0; i < 2; i++ {
		if r := call("heartbeat", token, proc('a'), "a"); r.Code != code.InstanceReplaced {
			t.Fatal("old process reclaimed", r)
		}
	}
	if r := call("verify", token, proc('b'), "a"); r.Code != code.OK {
		t.Fatal(r)
	}
	if e := f.db.Create(&model.AppVersion{AppID: app.ID, Version: "1.0.0", Disabled: true}).Error; e != nil {
		t.Fatal(e)
	}
	reportedVersion = "1.0.0"
	if r := call("verify", token, proc('a'), "a"); r.Code != code.InstanceReplaced {
		t.Fatal("old version clobbered replacement proof", r.Code)
	}
	if r := call("verify", token, proc('b'), "a"); r.Code != code.VersionDisabled {
		t.Fatal("current disabled version was allowed", r.Code)
	}
	reportedVersion = ""
	other, e := NewService(f.db, make([]byte, 32), nil, Options{Now: f.clock.now})
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close(context.Background())
	if r := other.process(context.Background(), app, "verify", "203.0.113.7", Input{LicenseKey: f.key, Device: strings.Repeat("a", 64), ActivationToken: token, InstanceSession: proc('a')}, f.clock.now()); r.Code != code.InstanceReplaced {
		t.Fatal("restart lost replaced IDs", r)
	}
	if r := call("release-seat", token, proc('b'), "a"); r.Code != code.OK || r.Data["released"] != true {
		t.Fatal(r)
	}
	b := call("activate", "", proc('c'), "b")
	if b.Code != code.OK {
		t.Fatal("release did not free capacity", b)
	}
	if r := call("heartbeat", token, proc('b'), "a"); r.Code != code.FloatingLimitReached {
		t.Fatal("full seat not refused", r)
	}

}
func TestFloatingGraceSignedWithoutLeaseClampAndDisabledVersion(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	var l model.License
	f.db.First(&l, "key=?", f.key)
	l.VerifyMethods = []string{"KEY", "FLOATING"}
	end := f.clock.now().Add(time.Hour)
	l.ExpiresAt = &end
	l.ValidityRule = "fixed_expiry"
	if e := f.db.Save(&l).Error; e != nil {
		t.Fatal(e)
	}
	app, e := f.service.channel.EnsureApplication(context.Background(), f.app.ID)
	if e != nil {
		t.Fatal(e)
	}
	in := Input{LicenseKey: f.key, Device: strings.Repeat("a", 64), Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), InstanceSession: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
	v := f.service.process(context.Background(), app, "activate", "203.0.113.7", in, f.clock.now())
	if v.Code != code.OK {
		t.Fatal(v)
	}
	if !v.Data["grace_until"].(time.Time).Equal(end) || !v.Data["lease_expires_at"].(*time.Time).Before(end) {
		t.Fatal("grace horizon did not match signed license expiry")
	}
	now := f.clock.now()
	if e := f.db.Create(&model.AppVersion{AppID: app.ID, Version: "1.0.0", Disabled: true, PublishedAt: &now}).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.db.Create(&model.AppVersion{AppID: app.ID, Version: "2.1.0", PublishedAt: &now}).Error; e != nil {
		t.Fatal(e)
	}
	in.ActivationToken = v.Data["activation_token"].(string)
	in.Version = "1.0.0"
	v = f.service.process(context.Background(), app, "verify", "203.0.113.7", in, now)
	if v.Code != code.VersionDisabled || v.Data["latest_version"] != "2.1.0" {
		t.Fatal(v)
	}
	in.Version = ""
	if v = f.service.process(context.Background(), app, "verify", "203.0.113.7", in, now); v.Code != code.OK {
		t.Fatal("unreported version refused", v)
	}
}
func TestReleaseSeatKeyOnlyNoopKeepsSessionProof(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	var l model.License
	f.db.First(&l, "key=?", f.key)
	l.VerifyMethods = []string{"KEY"}
	f.db.Save(&l)
	app, e := f.service.channel.EnsureApplication(context.Background(), f.app.ID)
	if e != nil {
		t.Fatal(e)
	}
	in := Input{LicenseKey: f.key, Device: strings.Repeat("a", 64), Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	r := f.service.process(context.Background(), app, "activate", "203.0.113.7", in, f.clock.now())
	if r.Code != code.OK {
		t.Fatal(r)
	}
	in.ActivationToken = r.Data["activation_token"].(string)
	var before model.Activation
	f.db.Where("license_id=? AND kind='key'", l.ID).First(&before)
	r = f.service.process(context.Background(), app, "release-seat", "203.0.113.7", in, f.clock.now())
	if r.Code != code.OK || r.Data["released"] != false {
		t.Fatal(r)
	}
	var after model.Activation
	f.db.First(&after, before.ID)
	f.db.First(&l, l.ID)
	if after.Token != before.Token || after.Status != before.Status || after.OfflineAt != nil {
		t.Fatal("device release mutated binding or quota")
	}
	if r = f.service.process(context.Background(), app, "verify", "203.0.113.7", in, f.clock.now()); r.Code != code.OK {
		t.Fatal("device token invalidated", r)
	}
}

func TestInstanceHistoryRetainsLatest32(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	var l model.License
	if e := f.db.First(&l, "key=?", f.key).Error; e != nil {
		t.Fatal(e)
	}
	a := model.Activation{LicenseID: l.ID, Kind: "key", Value: "test-session", Status: "active"}
	if e := f.db.Create(&a).Error; e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 40; i++ {
		if e := rememberInstance(f.db, a.ID, fmt.Sprintf("session-%02d", i)); e != nil {
			t.Fatal(e)
		}
	}
	var count int64
	if e := f.db.Table("activation_instance_sessions").Where("activation_id=?", a.ID).Count(&count).Error; e != nil || count != 32 {
		t.Fatal(count, e)
	}
	for _, item := range []struct {
		session string
		want    string
	}{{"session-39", code.InstanceReplaced}, {"session-08", code.InstanceReplaced}, {"session-07", ""}} {
		got, e := instanceCheck(f.db, []model.Activation{a}, a.Value, "", item.session, true)
		if e != nil || got != item.want {
			t.Fatal(item, got, e)
		}
	}
}

func TestReleaseThenRestartVerifyRecreatesSeatAndKeepsOldProcessRefused(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	var license model.License
	if err := f.db.Where("key=?", f.key).First(&license).Error; err != nil {
		t.Fatal(err)
	}
	license.VerifyMethods = []string{"KEY", "FLOATING"}
	if err := f.db.Save(&license).Error; err != nil {
		t.Fatal(err)
	}
	app, err := f.service.channel.EnsureApplication(context.Background(), f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	proc := func(b byte) string {
		return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(b), 16)))
	}
	call := func(op, token, session, device string) outcome {
		return f.service.process(context.Background(), app, op, "203.0.113.7", Input{LicenseKey: f.key, Device: strings.Repeat(device, 64), ActivationToken: token, InstanceSession: session, Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, f.clock.now())
	}
	activated := call("activate", "", proc('a'), "a")
	if activated.Code != code.OK {
		t.Fatal(activated.Code)
	}
	token := activated.Data["activation_token"].(string)
	if result := call("release-seat", token, proc('a'), "a"); result.Code != code.OK {
		t.Fatal(result.Code)
	}
	// A payload request may not implicitly create a seat from the retained anchor.
	for _, test := range []struct{ session, want string }{{proc('a'), code.LeaseExpired}, {proc('b'), code.InstanceReplaced}} {
		blocked := f.service.processPolicyPayload(context.Background(), app, "verify", "203.0.113.7", Input{LicenseKey: f.key, Device: strings.Repeat("a", 64), ActivationToken: token, InstanceSession: test.session}, f.clock.now(), true, true)
		if blocked.Code != test.want {
			t.Fatal("unlock bypassed lease or attempted takeover", blocked.Code)
		}
	}
	var n int64
	f.db.Model(&model.Activation{}).Where("kind='floating' AND status='active'").Count(&n)
	if n != 0 {
		t.Fatal("unlock acquired seat")
	}
	if result := call("verify", token, proc('b'), "a"); result.Code != code.OK {
		t.Fatal("normal restarted Check failed", result.Code)
	}
	if result := call("heartbeat", token, proc('a'), "a"); result.Code != code.InstanceReplaced {
		t.Fatal("old process was revived", result.Code)
	}
	var instance model.Activation
	if err = f.db.Where("kind='floating'").First(&instance).Error; err != nil {
		t.Fatal(err)
	}
	var refs int64
	if err = f.db.Model(&model.ClientSessionBinding{}).Where("activation_id=?", instance.ID).Count(&refs).Error; err != nil || refs != 1 {
		t.Fatal("missing restarted proof", refs, err)
	}
	if result := call("release-seat", token, proc('b'), "a"); result.Code != code.OK {
		t.Fatal(result.Code)
	}
	if result := call("activate", "", proc('c'), "b"); result.Code != code.OK {
		t.Fatal(result.Code)
	}
	if result := call("verify", token, proc('d'), "a"); result.Code != code.FloatingLimitReached {
		t.Fatal("new process bypassed capacity", result.Code)
	}
}
