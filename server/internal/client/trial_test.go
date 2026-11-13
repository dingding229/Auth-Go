package client

import (
	"authgo/internal/code"
	"authgo/internal/model"
	"authgo/internal/trial"
	"authgo/sdk/wire"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestTrialResultTicketExpiryAndConversion(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	ctx := context.Background()
	if e := f.db.Model(&f.app).Updates(map[string]any{"trial_enabled": true, "trial_days": 1}).Error; e != nil {
		t.Fatal(e)
	}
	app, e := f.service.channel.EnsureApplication(ctx, f.app.ID)
	if e != nil {
		t.Fatal(e)
	}
	l, e := f.service.trials.Acquire(ctx, app.ID, "203.0.113.7", strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	in := Input{LicenseKey: l.Key, Device: strings.Repeat("a", 64), Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	call := func(op string) outcome { return f.service.process(ctx, app, op, "203.0.113.7", in, f.clock.now()) }
	out := call("activate")
	if out.Code != code.OK || out.Data["is_trial"] != true {
		t.Fatal(out)
	}
	public, _ := base64.StdEncoding.DecodeString(app.PublicKey)
	g, e := wire.DecodeTicket(out.Data["ticket"].(string), public)
	if e != nil || !g.IsTrial || !g.GraceUntil.Equal(g.IssuedAt.Add(time.Duration(g.NextCheckIn)*time.Second+trialRefreshOverlap)) {
		t.Fatal(g, e)
	}
	in.ActivationToken = out.Data["activation_token"].(string)
	f.clock.add(25 * time.Hour)
	if x := call("heartbeat"); x.Code != code.LicenseExpired {
		t.Fatal(x)
	}
	user := model.EndUser{Name: "customer", Status: "active"}
	f.db.Create(&user)
	days := 30
	if _, e := trial.New(f.db, f.clock.now).Convert(ctx, l.ID, trial.ConvertInput{UserID: user.ID, Days: &days}); e != nil {
		t.Fatal(e)
	}
	out = call("heartbeat")
	if out.Code != code.OK || out.Data["is_trial"] != false || !out.Data["grace_until"].(time.Time).After(f.clock.now()) {
		t.Fatal(out)
	}
}

func TestTrialRefreshOverlapAndFormalGrace(t *testing.T) {
	for _, tc := range []struct {
		name, kind               string
		expiresAfter, wantWindow time.Duration
		graceHours               int
	}{
		{"trial overlap", "trial", 2 * time.Hour, 33 * time.Second, 72},
		{"trial expiry cap", "trial", 10 * time.Second, 10 * time.Second, 72},
		{"formal grace unchanged", "standard", 0, 2 * time.Hour, 2},
		{"formal expiry cap unchanged", "standard", 10 * time.Second, 10 * time.Second, 2},
		{"formal zero grace unchanged", "standard", 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoggingFixture(t, Options{})
			if e := f.db.Model(&f.app).Updates(map[string]any{"next_check_in": 3, "grace_hours": tc.graceHours}).Error; e != nil {
				t.Fatal(e)
			}
			var l model.License
			if e := f.db.Where("key=?", f.key).First(&l).Error; e != nil {
				t.Fatal(e)
			}
			l.Type = tc.kind
			l.VerifyMethods = []string{"KEY", "FLOATING"}
			l.Features = model.JSONMap{"probe": true}
			if tc.expiresAfter > 0 {
				v := f.clock.now().Add(tc.expiresAfter)
				l.ExpiresAt = &v
				l.ValidityRule = "fixed_expiry"
			}
			if e := f.db.Save(&l).Error; e != nil {
				t.Fatal(e)
			}
			app, e := f.service.channel.EnsureApplication(context.Background(), f.app.ID)
			if e != nil {
				t.Fatal(e)
			}
			public, _ := base64.StdEncoding.DecodeString(app.PublicKey)
			in := Input{LicenseKey: f.key, Device: strings.Repeat("b", 64), Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
			for _, op := range []string{"activate", "verify", "heartbeat"} {
				out := f.service.process(context.Background(), app, op, "203.0.113.8", in, f.clock.now())
				if out.Code != code.OK {
					t.Fatal(op, out)
				}
				if op == "activate" {
					in.ActivationToken = out.Data["activation_token"].(string)
				}
				g, e := wire.DecodeTicket(out.Data["ticket"].(string), public)
				if e != nil {
					t.Fatal(e)
				}
				want := g.IssuedAt.Add(tc.wantWindow)
				if l.ExpiresAt != nil && want.After(*l.ExpiresAt) {
					want = *l.ExpiresAt
				}
				if !g.GraceUntil.Equal(want) || !out.Data["grace_until"].(time.Time).Equal(want) {
					t.Fatalf("%s grace=%s want=%s", op, g.GraceUntil, want)
				}
				if g.IsTrial != (tc.kind == "trial") {
					t.Fatal("trial marker changed", op)
				}
				f.clock.add(time.Second)
			}
		})
	}
}
