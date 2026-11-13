package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/config"
	"authgo/internal/ipinfo"
	"authgo/internal/licensing"
	"authgo/internal/model"
	"authgo/internal/portal"
	"authgo/internal/response"
	"authgo/internal/sharing"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm/logger"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"
)

type sharingLookup struct{ enabled bool }

func (s *sharingLookup) Status() ipinfo.Status {
	return ipinfo.Status{Enabled: s.enabled, City: &ipinfo.DatabaseStatus{}}
}
func (s *sharingLookup) LookupBatch(ips []string) map[string]*ipinfo.Info {
	out := map[string]*ipinfo.Info{}
	for _, ip := range ips {
		for i, c := range []string{"CN", "US", "JP", "FR"} {
			if ip == fmt.Sprintf("8.8.0.%d", i+1) {
				out[ip] = &ipinfo.Info{Scope: "public", CountryCode: c, ASN: 4134, ASOrg: "Synthetic Network"}
			}
		}
	}
	return out
}
func sharingFixture(t *testing.T) (*portalFixture, *sharing.Service, *sharingLookup) {
	f := newPortalFixture(t, portal.Options{}, nil)
	lookup := &sharingLookup{true}
	shares := sharing.New(f.db, lookup, f.clock.now)
	identity, e := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := f.db.DB()
	f.r, e = NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext, WithAdmin(identity, f.db), WithCatalog(f.catalog), WithLicensing(f.licensing), WithClient(f.service), WithPortal(f.portalService), WithSharing(shares))
	if e != nil {
		t.Fatal(e)
	}
	return f, shares, lookup
}
func TestSharingEndpointsListsStatsIgnoreAuditAndClientIsolation(t *testing.T) {
	f, s, lookup := sharingFixture(t)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	activated := data(f.call(t, "activate", f.input(""), "OK"))
	activation := activated["activation_token"].(string)
	seed := func() {
		for i := 0; i < 4; i++ {
			usercenterCreate(t, f, &model.VerifyLog{LicenseID: &f.license.ID, Action: "verify", Success: true, IP: fmt.Sprintf("8.8.0.%d", i+1), CreatedAt: f.clock.now()})
		}
	}
	seed()
	if e := s.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	path := fmt.Sprintf("/licenses/%d/sharing", f.license.ID)
	f.request(t, "GET", path, "", nil, 401)
	view := data(f.request(t, "GET", path, owner, nil, 200))
	if view["flagged"] != true || view["available"] != true {
		t.Fatal(view)
	}
	raw, _ := json.Marshal(view)
	if bytes.Contains(raw, []byte("8.8.")) {
		t.Fatal("IP leaked")
	}
	page := data(f.request(t, "GET", "/licenses?suspected_sharing=true&sort_by=updated_at", owner, nil, 200))
	if fmt.Sprint(page["total"]) != "1" || page["items"].([]any)[0].(map[string]any)["suspected_sharing"] != true {
		t.Fatal(page)
	}
	overview := func() map[string]any {
		return data(f.request(t, "GET", "/stats/overview", owner, nil, 200))["counts"].(map[string]any)
	}
	if fmt.Sprint(overview()["suspected_sharing"]) != "1" {
		t.Fatal("missing overview count")
	}
	after := data(f.call(t, "verify", f.input(activation), "OK"))
	if _, ok := after["suspected_sharing"]; ok {
		t.Fatal("client response enriched with admin warning")
	}
	var l model.License
	f.db.First(&l, f.license.ID)
	if l.Status != "active" {
		t.Fatal("sharing changed license status")
	}
	view = data(f.request(t, "POST", path+"/ignore", owner, gin.H{}, 200))
	if view["flagged"] != false || view["ignored"] != true {
		t.Fatal(view)
	}
	if e := s.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	if v, e := s.Get(context.Background(), f.license.ID); e != nil || v.Flagged || !v.Ignored {
		t.Fatal(v, e)
	}
	page = data(f.request(t, "GET", "/licenses?suspected_sharing=true", owner, nil, 200))
	if fmt.Sprint(page["total"]) != "0" || fmt.Sprint(overview()["suspected_sharing"]) != "0" {
		t.Fatal("ignored still visible")
	}
	var audit model.AuditLog
	if e := f.db.Where("action=?", "license.sharing.ignore").Last(&audit).Error; e != nil || audit.StatusCode != 200 || audit.ResourceID != fmt.Sprint(f.license.ID) {
		t.Fatal(audit, e)
	}
	f.clock.add(30 * 24 * time.Hour)
	owner = f.login(t, "owner", "initial-password", "")["access_token"].(string)
	seed()
	if e := s.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	if v, e := s.Get(context.Background(), f.license.ID); e != nil || !v.Flagged {
		t.Fatal(v, e)
	}
	lookup.enabled = false
	view = data(f.request(t, "GET", path, owner, nil, 200))
	if view["available"] != false || view["flagged"] != false || view["flagged_at"] == nil {
		t.Fatal(view)
	}
	page = data(f.request(t, "GET", "/licenses?suspected_sharing=true", owner, nil, 200))
	if fmt.Sprint(page["total"]) != "0" || fmt.Sprint(overview()["suspected_sharing"]) != "0" {
		t.Fatal(page)
	}
	page = data(f.request(t, "GET", "/licenses", owner, nil, 200))
	if _, ok := page["items"].([]any)[0].(map[string]any)["suspected_sharing"]; ok {
		t.Fatal("optional field not omitted")
	}
	f.request(t, "POST", path+"/ignore", owner, gin.H{}, 409)
	f.request(t, "GET", "/licenses?suspected_sharing=invalid", owner, nil, 400)
	f.request(t, "GET", "/licenses/999999999999/sharing", owner, nil, 404)
}

type sharingQueryLog struct {
	logger.Interface
	queries int
}

func (q *sharingQueryLog) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	sql, _ := fc()
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "SELECT") {
		q.queries++
	}
}
func TestSharingLicenseListUsesFixedQueryBudget(t *testing.T) {
	f, s, _ := sharingFixture(t)
	spy := &sharingQueryLog{Interface: logger.Default}
	previous := f.db.Logger
	f.db.Logger = spy
	defer func() { f.db.Logger = previous }()
	query := func() int {
		spy.queries = 0
		q, e := responseListSharing()
		if e != nil {
			t.Fatal(e)
		}
		items, _, e := f.licensing.List(context.Background(), q)
		if e != nil || len(items) == 0 {
			t.Fatal(items, e)
		}
		return spy.queries
	}
	small := query()
	for i := 0; i < 20; i++ {
		usercenterLicense(t, f, f.app.ID, *f.license.UserID)
	}
	for i := 0; i < 4; i++ {
		usercenterCreate(t, f, &model.VerifyLog{LicenseID: &f.license.ID, Action: "verify", Success: true, IP: fmt.Sprintf("8.8.0.%d", i+1), CreatedAt: f.clock.now()})
	}
	if e := s.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	large := query()
	if large > small || large > 6 {
		t.Fatalf("sharing introduced N+1: one=%d many=%d", small, large)
	}
}

func responseListSharing() (licensing.Filter, error) {
	q, e := response.ParseList(url.Values{"page_size": {"100"}}, "id", "updated_at")
	return licensing.Filter{Query: q}, e
}
