package sharing

import (
	"authgo/internal/db"
	"authgo/internal/ipinfo"
	"authgo/internal/model"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type localFixture struct {
	enabled bool
	data    map[string]*ipinfo.Info
	batches int
	largest int
}

func (f *localFixture) Status() ipinfo.Status {
	return ipinfo.Status{Enabled: f.enabled, City: &ipinfo.DatabaseStatus{}, ASN: &ipinfo.DatabaseStatus{}}
}
func (f *localFixture) LookupBatch(ips []string) map[string]*ipinfo.Info {
	f.batches++
	if len(ips) > f.largest {
		f.largest = len(ips)
	}
	out := map[string]*ipinfo.Info{}
	for _, ip := range ips {
		out[ip] = f.data[ip]
	}
	return out
}
func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	p, _ := d.DB()
	t.Cleanup(func() { _ = p.Close() })
	return d
}
func create[T any](t *testing.T, d *gorm.DB, v *T) {
	t.Helper()
	if e := d.Create(v).Error; e != nil {
		t.Fatal(e)
	}
}
func seedLicense(t *testing.T, d *gorm.DB, kind string) model.License {
	t.Helper()
	a := model.Application{Name: "synthetic", AppKey: fmt.Sprint(time.Now().UnixNano()), Status: "active"}
	create(t, d, &a)
	l := model.License{AppID: a.ID, Key: fmt.Sprint("synthetic-", a.ID), Type: kind, Status: "active"}
	create(t, d, &l)
	return l
}
func logIP(t *testing.T, d *gorm.DB, l model.License, ip, action string, success bool, at time.Time) {
	t.Helper()
	create(t, d, &model.VerifyLog{LicenseID: &l.ID, AppID: &l.AppID, IP: ip, Action: action, Success: success, CreatedAt: at})
}
func mustTick(t *testing.T, s *Service) {
	t.Helper()
	if e := s.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func mustView(t *testing.T, s *Service, id uint64) View {
	t.Helper()
	v, e := s.Get(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestThresholdBoundariesDedupTrialAndNoIPs(t *testing.T) {
	for _, tc := range []struct {
		name            string
		countries, asns int
		flagged         bool
	}{{"3 countries", 3, 1, false}, {"4 countries", 4, 1, true}, {"5 ASN", 1, 5, false}, {"6 ASN", 1, 6, true}} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDB(t)
			l := seedLicense(t, d, "trial")
			now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
			f := &localFixture{enabled: true, data: map[string]*ipinfo.Info{}}
			s := New(d, f, func() time.Time { return now })
			n := max(tc.countries, tc.asns)
			for i := 0; i < n; i++ {
				ip := fmt.Sprintf("8.8.%d.1", i)
				f.data[ip] = &ipinfo.Info{Scope: "public", CountryCode: fmt.Sprintf("C%d", i%tc.countries), ASN: uint(100 + i%tc.asns), ASOrg: "Synthetic Network"}
				for _, action := range []string{"activate", "verify", "heartbeat"} {
					logIP(t, d, l, ip, action, true, now.Add(-time.Hour))
				}
			}
			// Neither failures, non-verification actions, old nor future records count.
			for _, v := range []struct {
				ip, action string
				ok         bool
				at         time.Time
			}{{"9.9.1.1", "verify", false, now}, {"9.9.1.2", "release", true, now}, {"9.9.1.3", "verify", true, now.Add(-24*time.Hour - time.Second)}, {"9.9.1.4", "verify", true, now.Add(time.Second)}} {
				f.data[v.ip] = &ipinfo.Info{Scope: "public", CountryCode: "OTHER", ASN: 999}
				logIP(t, d, l, v.ip, v.action, v.ok, v.at)
			}
			mustTick(t, s)
			v := mustView(t, s, l.ID)
			if v.Flagged != tc.flagged || len(v.Countries) != tc.countries || len(v.ASNs) != tc.asns || v.InstanceCount != int64(n) {
				t.Fatalf("unexpected distribution: %+v", v)
			}
			raw, _ := json.Marshal(v)
			if bytes.Contains(raw, []byte("8.8.")) || bytes.Contains(raw, []byte("9.9.")) {
				t.Fatal("IP in API distribution")
			}
			var stored Summary
			if e := d.First(&stored, "license_id=?", l.ID).Error; e != nil {
				t.Fatal(e)
			}
			raw, _ = json.Marshal(stored)
			if bytes.Contains(raw, []byte("8.8.")) {
				t.Fatal("IP persisted")
			}
		})
	}
}
func TestScopesMissingDimensionsCanonicalIPsAndWindowBoundary(t *testing.T) {
	d := newDB(t)
	l := seedLicense(t, d, "standard")
	now := time.Now().UTC().Truncate(time.Second)
	f := &localFixture{enabled: true, data: map[string]*ipinfo.Info{
		"8.8.8.8": {Scope: "public", CountryCode: "CN", ASN: 4134}, "::ffff:8.8.8.8": {Scope: "public", CountryCode: "CN", ASN: 4134},
		"9.9.9.9": {Scope: "public"}, "1.1.1.1": {Scope: "public", CountryCode: "US"}, "2.2.2.2": {Scope: "public", ASN: 100},
		"10.0.0.1": {Scope: "private", CountryCode: "PRIVATE", ASN: 999}, "127.0.0.1": {Scope: "loopback", CountryCode: "LOOP", ASN: 998}, "203.0.113.1": {Scope: "unknown", CountryCode: "BAD", ASN: 997},
	}}
	s := New(d, f, func() time.Time { return now })
	for ip := range f.data {
		logIP(t, d, l, ip, "verify", true, now.Add(-24*time.Hour))
	}
	mustTick(t, s)
	v := mustView(t, s, l.ID)
	if v.InstanceCount != 4 || len(v.Countries) != 2 || len(v.ASNs) != 2 || v.Flagged {
		t.Fatal(v)
	}
	if v.Countries[0].Count != 1 || v.ASNs[1].Count != 1 {
		t.Fatal("aliases not deduplicated", v)
	}
}
func TestIgnoreExpiryDisabledRetentionRecoveryAndCascade(t *testing.T) {
	d := newDB(t)
	l := seedLicense(t, d, "standard")
	now := time.Now().UTC().Truncate(time.Second)
	f := &localFixture{enabled: true, data: map[string]*ipinfo.Info{}}
	s := New(d, f, func() time.Time { return now })
	seed := func() {
		for i := 0; i < 4; i++ {
			ip := fmt.Sprintf("8.8.0.%d", i+1)
			f.data[ip] = &ipinfo.Info{Scope: "public", CountryCode: fmt.Sprint("C", i)}
			logIP(t, d, l, ip, "verify", true, now)
		}
	}
	seed()
	mustTick(t, s)
	initial := mustView(t, s, l.ID)
	if !initial.Flagged {
		t.Fatal(initial)
	}
	v, e := s.Ignore(context.Background(), l.ID)
	if e != nil || v.Flagged || !v.Ignored || !v.IgnoredUntil.Equal(now.Add(30*24*time.Hour)) {
		t.Fatal(v, e)
	}
	now = now.Add(30 * 24 * time.Hour)
	v = mustView(t, s, l.ID)
	if v.Flagged {
		t.Fatal("old summary reappeared without a fresh scan")
	}
	seed()
	mustTick(t, s)
	v = mustView(t, s, l.ID)
	if !v.Flagged || v.Ignored {
		t.Fatal("expired ignore not reevaluated", v)
	}
	f.enabled = false
	if e = d.Where("license_id=?", l.ID).Delete(&model.VerifyLog{}).Error; e != nil {
		t.Fatal(e)
	}
	mustTick(t, s)
	v = mustView(t, s, l.ID)
	if v.Available || v.Flagged || v.FlaggedAt == nil {
		t.Fatal("disabled scan changed flags", v)
	}
	n, e := s.Count(context.Background())
	if e != nil || n != 0 {
		t.Fatal(n, e)
	}
	f.enabled = true
	mustTick(t, s)
	v = mustView(t, s, l.ID)
	if v.Flagged || v.FlaggedAt != nil || v.InstanceCount != 0 || len(v.Countries) != 0 {
		t.Fatal("retention/recovery did not clear", v)
	}
	if e = d.Delete(&model.License{}, l.ID).Error; e != nil {
		t.Fatal(e)
	}
	var nRows int64
	d.Model(&Summary{}).Where("license_id=?", l.ID).Count(&nRows)
	if nRows != 0 {
		t.Fatal("missing delete cascade")
	}
}
func TestRealSmallMMDBCityOnlyASNOnlyAndDisabled(t *testing.T) {
	for _, kind := range []string{"city", "asn"} {
		t.Run(kind, func(t *testing.T) {
			d := newDB(t)
			l := seedLicense(t, d, "trial")
			ips, e := ipinfo.New(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer ips.Close()
			raw, e := os.ReadFile(filepath.Join("..", "ipinfo", "testdata", kind+".mmdb"))
			if e != nil {
				t.Fatal(e)
			}
			if e = ips.Upload(context.Background(), kind, bytes.NewReader(raw)); e != nil {
				t.Fatal(e)
			}
			now := time.Now().UTC().Truncate(time.Second)
			s := New(d, ips, func() time.Time { return now })
			for _, ip := range []string{"8.8.8.8", "10.0.0.1", "127.0.0.1", "9.9.9.9"} {
				logIP(t, d, l, ip, "heartbeat", true, now)
			}
			mustTick(t, s)
			v := mustView(t, s, l.ID)
			if !v.Available || v.InstanceCount != 2 || v.Flagged {
				t.Fatal(v)
			}
			if kind == "city" && (len(v.Countries) != 1 || len(v.ASNs) != 0) {
				t.Fatal(v)
			}
			if kind == "asn" && (len(v.ASNs) != 1 || len(v.Countries) != 0) {
				t.Fatal(v)
			}
			if e = ips.Delete(context.Background()); e != nil {
				t.Fatal(e)
			}
			mustTick(t, s)
			if mustView(t, s, l.ID).Available {
				t.Fatal("disabled still available")
			}
		})
	}
}
func TestCursorBatchingAndCancellationKeepPreviousResult(t *testing.T) {
	d := newDB(t)
	l := seedLicense(t, d, "standard")
	now := time.Now().UTC().Truncate(time.Second)
	f := &localFixture{enabled: true, data: map[string]*ipinfo.Info{}}
	s := New(d, f, func() time.Time { return now })
	logs := []model.VerifyLog{}
	for i := 0; i < batchSize+30; i++ {
		ip := fmt.Sprintf("8.9.%d.%d", i/250, i%250)
		f.data[ip] = &ipinfo.Info{Scope: "public", CountryCode: "CN"}
		logs = append(logs, model.VerifyLog{LicenseID: &l.ID, IP: ip, Action: "verify", Success: true, CreatedAt: now})
	}
	if e := d.CreateInBatches(logs, 100).Error; e != nil {
		t.Fatal(e)
	}
	mustTick(t, s)
	if f.batches < 2 || f.largest > batchSize || mustView(t, s, l.ID).InstanceCount != batchSize+30 {
		t.Fatal("unbounded/incorrect cursor scan", f)
	}
	before := mustView(t, s, l.ID)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := s.Tick(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	after := mustView(t, s, l.ID)
	if before.InstanceCount != after.InstanceCount {
		t.Fatal("cancellation erased results")
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if e := s.Tick(expired); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	mustTick(t, s)
}

func TestGroupedCursorUsesPartialCoveringIndex(t *testing.T) {
	d := newDB(t)
	now := time.Now().UTC()
	var plan []struct{ Detail string }
	statement := groupedPage(d.Session(&gorm.Session{DryRun: true}), now.Add(-24*time.Hour), now, 1, "8.8.8.8").Find(&[]sample{}).Statement
	e := d.Raw("EXPLAIN QUERY PLAN "+statement.SQL.String(), statement.Vars...).Scan(&plan).Error
	if e != nil {
		t.Fatal(e)
	}
	details := ""
	for _, v := range plan {
		details += v.Detail
	}
	if !strings.Contains(details, "idx_verify_logs_sharing") || strings.Contains(details, "TEMP B-TREE") {
		t.Fatal("sharing scan lost its bounded cursor index", details)
	}
}
func TestFallingBelowThresholdClearsFlagButKeepsIgnore(t *testing.T) {
	d := newDB(t)
	l := seedLicense(t, d, "trial")
	now := time.Now().UTC().Truncate(time.Second)
	f := &localFixture{enabled: true, data: map[string]*ipinfo.Info{}}
	s := New(d, f, func() time.Time { return now })
	for i, code := range []string{"CN", "US", "JP", "FR"} {
		ip := fmt.Sprintf("8.8.0.%d", i+1)
		f.data[ip] = &ipinfo.Info{Scope: "public", CountryCode: code}
		logIP(t, d, l, ip, "verify", true, now)
	}
	mustTick(t, s)
	if !mustView(t, s, l.ID).Flagged {
		t.Fatal("missing initial flag")
	}
	v, e := s.Ignore(context.Background(), l.ID)
	if e != nil {
		t.Fatal(e)
	}
	until := *v.IgnoredUntil
	if e = d.Where("license_id=? AND ip=?", l.ID, "8.8.0.4").Delete(&model.VerifyLog{}).Error; e != nil {
		t.Fatal(e)
	}
	mustTick(t, s)
	v = mustView(t, s, l.ID)
	if v.FlaggedAt != nil || len(v.Countries) != 3 || !v.IgnoredUntil.Equal(until) {
		t.Fatal(v)
	}
	logIP(t, d, l, "8.8.0.4", "heartbeat", true, now)
	mustTick(t, s)
	v = mustView(t, s, l.ID)
	if v.Flagged || v.FlaggedAt == nil || !v.Ignored {
		t.Fatal("recovery reset the ignore period", v)
	}
}
