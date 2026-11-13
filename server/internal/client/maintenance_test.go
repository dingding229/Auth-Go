package client

import (
	"authgo/internal/code"
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"authgo/sdk/wire"
	"context"
	"encoding/base64"
	"testing"
	"time"
)

func TestMaintenanceOnlineRenewalRetainsActivationAndSignsFields(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	ctx := context.Background()
	var l model.License
	f.db.First(&l, "key=?", f.key)
	bound := f.clock.now().Add(-time.Hour)
	published := bound.Add(time.Second)
	f.db.Model(&l).Update("maintenance_until", published)
	v := model.AppVersion{AppID: f.app.ID, Version: "1.0.0", Source: "manual", PublishedAt: &published, Withdrawn: true}
	if err := f.db.Create(&v).Error; err != nil {
		t.Fatal(err)
	}
	app, err := f.service.channel.EnsureApplication(ctx, f.app.ID)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{LicenseKey: f.key, Version: "1.0.0", Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	call := func(op string) outcome { return f.service.process(ctx, app, op, "203.0.113.7", in, f.clock.now()) }
	first := call("activate")
	if first.Code != code.OK {
		t.Fatal(first)
	}
	in.ActivationToken = first.Data["activation_token"].(string)
	public, _ := base64.StdEncoding.DecodeString(app.PublicKey)
	grant, err := wire.DecodeTicket(first.Data["ticket"].(string), public)
	if err != nil || grant.MaintenanceUntil == nil || !grant.MaintenanceUntil.Equal(published) {
		t.Fatal(grant, err)
	}
	for _, op := range []string{"verify", "heartbeat"} {
		if err := f.db.Model(&l).Update("maintenance_until", bound).Error; err != nil {
			t.Fatal(err)
		}
		denied := call(op)
		if denied.Code != code.MaintenanceExpired || denied.Data["latest_entitled_version"] != "" {
			t.Fatal(denied)
		}
		if err := f.db.Model(&l).Update("maintenance_until", published).Error; err != nil {
			t.Fatal(err)
		}
		if recovered := call(op); recovered.Code != code.OK {
			t.Fatal(recovered)
		}
	}
	var count int64
	f.db.Model(&model.ClientSession{}).Where("license_id=?", l.ID).Count(&count)
	if count != 1 {
		t.Fatal("renewal reactivated client", count)
	}
}

func TestMaintenanceDownloadErrorDetails(t *testing.T) {
	at := time.Now().UTC()
	out := updateFailure(&maintenance.Refusal{LatestEntitledVersion: "1.0.0", MaintenanceUntil: &at})
	if out.Code != code.MaintenanceExpired || out.Data["latest_entitled_version"] != "1.0.0" {
		t.Fatal(out)
	}
}

func TestUnknownMaintenanceLogsAreSampledByLicenseAndVersion(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	var l model.License
	f.db.First(&l, "key=?", f.key)
	for _, version := range []string{"1.0.0", "2.0.0"} {
		for i := 0; i < 10; i++ {
			f.service.recordVerifyLog(model.VerifyLog{LicenseID: &l.ID, IP: "203.0.113.7", ClientVersion: version, Code: code.OK, Success: true, Reason: "版本未收录或缺少发布时间，维护期检查已放行", CreatedAt: f.clock.now()}, true)
		}
	}
	f.drain(t)
	var n int64
	f.db.Model(&model.VerifyLog{}).Where("license_id=?", l.ID).Count(&n)
	if n != 2 {
		t.Fatal("unknown version logs were not rate limited per license/version", n)
	}
}
