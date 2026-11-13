package trial

import (
	"authgo/internal/apperror"
	"authgo/internal/code"
	"authgo/internal/db"
	"authgo/internal/model"
	"context"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	s   *Service
	db  *gorm.DB
	a   model.Application
	now time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	t.Cleanup(func() { pool.Close() })
	f := &fixture{db: d, now: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), a: model.Application{Name: "trial", AppKey: "trial", Status: "active", TrialEnabled: true, TrialDays: 14}}
	if e := d.Create(&f.a).Error; e != nil {
		t.Fatal(e)
	}
	f.s = New(d, func() time.Time { return f.now })
	return f
}
func requireCode(t *testing.T, e error, want string) {
	t.Helper()
	var a *apperror.Error
	if !errors.As(e, &a) || a.Code != want {
		t.Fatalf("%v, want %s", e, want)
	}
}
func (f *fixture) claim(t *testing.T, ip, id string) model.License {
	t.Helper()
	l, e := f.s.Acquire(context.Background(), f.a.ID, ip, strings.Repeat(id, 64))
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func TestClaimOrderReuseAndDisabled(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	l := f.claim(t, "203.0.113.1", "a")
	if l.Type != "trial" || l.Source != "self_trial" || l.UserID != nil || l.MaxActivations != 1 || !l.ExpiresAt.Equal(f.now.AddDate(0, 0, 14)) || len(l.VerifyMethods) != 2 || l.VerifyMethods[1] != "FLOATING" {
		t.Fatal(l)
	}
	// NAT/rebuild aliases do not create another license or extend the date.
	same := f.claim(t, "203.0.113.1", "b")
	if same.ID != l.ID {
		t.Fatal("NAT created a second trial")
	}
	f.db.Model(&f.a).Update("trial_enabled", false)
	if x := f.claim(t, "198.51.100.1", "a"); x.ID != l.ID {
		t.Fatal(x)
	}
	if x := f.claim(t, "198.51.100.1", "b"); x.ID != l.ID {
		t.Fatal("alias not remembered")
	}
	_, e := f.s.Acquire(ctx, f.a.ID, "203.0.113.2", strings.Repeat("c", 64))
	requireCode(t, e, code.TrialDisabled)
	f.db.Model(&f.a).Update("status", "disabled")
	if x := f.claim(t, "203.0.113.3", "a"); x.ID != l.ID {
		t.Fatal(x)
	}
	f.now = f.now.AddDate(0, 0, 20)
	if x := f.claim(t, "203.0.113.3", "a"); x.ID != l.ID || x.ExpiresAt.After(f.now) {
		t.Fatal("expired trial renewed", x)
	}
}
func TestIPv6AndIPv4IPKeys(t *testing.T) {
	for _, tc := range []struct{ in, want string }{{"203.0.113.1", "203.0.113.1"}, {"::ffff:203.0.113.1", "203.0.113.1"}, {"2001:db8:1:2::1", "2001:db8:1:2::/64"}, {"2001:db8:1:2:ffff::abcd", "2001:db8:1:2::/64"}} {
		v, e := IPKey(tc.in)
		if e != nil || v != tc.want {
			t.Fatal(tc, v, e)
		}
	}
	f := setup(t)
	a := f.claim(t, "2001:db8::1", "a")
	b := f.claim(t, "2001:db8::ffff", "b")
	if a.ID != b.ID {
		t.Fatal("IPv6 host bits bypassed NAT reuse")
	}
	for _, bad := range []string{"bad", "fe80::1%eth0"} {
		if _, e := IPKey(bad); e == nil {
			t.Fatal(bad)
		}
	}
}
func TestIPLimitPrecedesGlobalAndOnlyNewIssuesCount(t *testing.T) {
	f := setup(t)
	l := f.claim(t, "203.0.113.1", "a")
	for i := 0; i < 99; i++ {
		x := model.License{AppID: f.a.ID, Key: fmt.Sprintf("quota-%d", i), Source: "self_trial", Type: "trial"}
		x.CreatedAt = f.now
		if e := f.db.Create(&x).Error; e != nil {
			t.Fatal(e)
		}
	}
	if same := f.claim(t, "203.0.113.1", "b"); same.ID != l.ID {
		t.Fatal(same)
	}
	_, e := f.s.Acquire(context.Background(), f.a.ID, "198.51.100.1", strings.Repeat("c", 64))
	requireCode(t, e, code.TrialQuotaExceeded)
	for _, values := range []map[string]any{{"converted_at": f.now}, {"converted_at": nil, "status": "revoked"}, {"status": "active", "type": "standard"}} {
		f.db.Model(&l).Updates(values)
		_, e = f.s.Acquire(context.Background(), f.a.ID, "203.0.113.1", strings.Repeat("d", 64))
		requireCode(t, e, code.TrialIPLimit)
		// An existing instance returns the original even when converted/revoked.
		if same := f.claim(t, "198.51.100.2", "a"); same.ID != l.ID {
			t.Fatal(same)
		}
	}
	f.now = f.now.AddDate(0, 0, 31)
	if x := f.claim(t, "203.0.113.1", "e"); x.ID == l.ID {
		t.Fatal("IP cooldown did not end")
	}
}
func TestConcurrentClaimsAndRateLimitBeforeWrites(t *testing.T) {
	f := setup(t)
	var wg sync.WaitGroup
	ids := make(chan uint64, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, e := f.s.Acquire(context.Background(), f.a.ID, "203.0.113.1", strings.Repeat("a", 64))
			if e != nil {
				t.Error(e)
				return
			}
			ids <- l.ID
		}()
	}
	wg.Wait()
	close(ids)
	var first uint64
	for id := range ids {
		if first == 0 {
			first = id
		}
		if id != first {
			t.Fatal("duplicate license")
		}
	}
	for i := 0; i < 2; i++ {
		f.claim(t, "203.0.113.1", "a")
	}
	_, e := f.s.Acquire(context.Background(), f.a.ID, "203.0.113.1", strings.Repeat("b", 64))
	requireCode(t, e, code.RateLimited)
	var n int64
	f.db.Model(&Claim{}).Count(&n)
	if n != 1 {
		t.Fatal("rate-limited request wrote claim", n)
	}
	f.db.Model(&model.License{}).Count(&n)
	if n != 1 {
		t.Fatal(n)
	}
}
func TestAdminConversionAndFormalActivationRetiresTrial(t *testing.T) {
	f := setup(t)
	l := f.claim(t, "203.0.113.1", "a")
	u := model.EndUser{Name: "customer", Status: "active"}
	f.db.Create(&u)
	days := 30
	limit := 3
	out, e := f.s.Convert(context.Background(), l.ID, ConvertInput{UserID: u.ID, Days: &days, MaxActivations: &limit})
	if e != nil || out.Type != "standard" || out.ConvertedAt == nil || out.UserID == nil || out.MaxActivations != 3 {
		t.Fatal(out, e)
	}
	if same := f.claim(t, "203.0.113.2", "a"); same.ID != l.ID || same.Type != "standard" {
		t.Fatal(same)
	}
	_, e = f.s.Acquire(context.Background(), f.a.ID, "203.0.113.1", strings.Repeat("b", 64))
	requireCode(t, e, code.TrialIPLimit)
	second := f.claim(t, "203.0.113.3", "c")
	lease := f.now.Add(time.Hour)
	activation := model.Activation{LicenseID: second.ID, Kind: "floating", Value: strings.Repeat("c", 64), Status: "active", Token: "old", LeaseExpiresAt: &lease}
	f.db.Create(&activation)
	if e := f.db.Transaction(func(tx *gorm.DB) error { return ConvertOnActivation(tx, out, strings.Repeat("c", 64), f.now) }); e != nil {
		t.Fatal(e)
	}
	f.db.First(&second, second.ID)
	f.db.First(&activation, activation.ID)
	if second.ConvertedAt == nil || second.Status != "revoked" || activation.Status == "active" || activation.LeaseExpiresAt.After(f.now) {
		t.Fatal(second, activation)
	}
}

func TestTrialCopiesTemplateFeaturesOnlyAtCreation(t *testing.T) {
	f := setup(t)
	if e := f.db.Exec(`INSERT INTO feature_templates(app_id,name,features,default_days,default_max_activations,default_maintenance_days) VALUES(?,'trial','{"export":true,"quota":12345678901234567890}',90,20,90)`, f.a.ID).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.db.Model(&f.a).Update("trial_template_id", 1).Error; e != nil {
		t.Fatal(e)
	}
	first := f.claim(t, "203.0.113.10", "1")
	if first.Features["export"] != true || fmt.Sprint(first.Features["quota"]) != "12345678901234567890" || first.MaxActivations != 1 || first.MaintenanceUntil != nil || !first.ExpiresAt.Equal(f.now.AddDate(0, 0, 14)) {
		t.Fatal(first)
	}
	if e := f.db.Exec(`UPDATE feature_templates SET features='{"export":false}' WHERE id=1`).Error; e != nil {
		t.Fatal(e)
	}
	old := f.claim(t, "203.0.113.11", "1")
	if old.ID != first.ID || old.Features["export"] != true {
		t.Fatal("trial snapshot changed", old)
	}
	next := f.claim(t, "203.0.113.12", "2")
	if next.Features["export"] != false {
		t.Fatal(next)
	}
	if e := f.db.Model(&f.a).Update("trial_template_id", nil).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.db.Exec("DELETE FROM feature_templates WHERE id=1").Error; e != nil {
		t.Fatal(e)
	}
	var saved model.License
	if e := f.db.First(&saved, first.ID).Error; e != nil || saved.Features["export"] != true {
		t.Fatal("deleted template changed issued trial", saved.Features, e)
	}

}
