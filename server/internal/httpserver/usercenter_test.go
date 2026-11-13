package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"authgo/internal/auth"
	"authgo/internal/catalog"
	"authgo/internal/config"
	"authgo/internal/dockerhub"
	"authgo/internal/enduser"
	"authgo/internal/ipinfo"
	"authgo/internal/licensing"
	"authgo/internal/model"
	"authgo/internal/portal"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func usercenterCreate[T any](t *testing.T, f *portalFixture, row *T) {
	t.Helper()
	if e := f.db.Create(row).Error; e != nil {
		t.Fatal(e)
	}
}
func usercenterLicense(t *testing.T, f *portalFixture, app, user uint64) licensing.LicenseInfo {
	t.Helper()
	l, e := f.licensing.Create(context.Background(), licensing.CreateInput{AppID: app, UserID: &user, VerifyMethods: ptr([]string{"KEY", "FLOATING"})})
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func usercenterVersion(t *testing.T, f *portalFixture, app uint64, version string, at time.Time, disabled bool, source string) {
	t.Helper()
	if e := f.db.Model(&model.Application{}).Where("id=?", app).Update("docker_image", "example-org/public-app").Error; e != nil {
		t.Fatal(e)
	}
	var st dockerhub.State
	e := f.db.First(&st, "app_id=?", app).Error
	if e != nil {
		st = dockerhub.State{AppID: app, Image: "example-org/public-app", TagsJSON: "{}", NextSyncAt: f.clock.now()}
	}
	tags := map[string]string{}
	_ = json.Unmarshal([]byte(st.TagsJSON), &tags)
	tags[version] = version
	raw, _ := json.Marshal(tags)
	st.TagsJSON = string(raw)
	st.Image = "example-org/public-app"
	if e := f.db.Save(&st).Error; e != nil {
		t.Fatal(e)
	}

	usercenterCreate(t, f, &model.AppVersion{AppID: app, Version: version, PublishedAt: &at, Disabled: disabled, Source: source, Changelog: "<script>alert('plain text')</script> 发布说明"})
}
func usercenterSafe(t *testing.T, value any) {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	var check func(any)
	check = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for key, x := range v {
				switch key {
				case "activation_token", "token", "download_url", "url", "fingerprint", "fingerprint_detail", "device", "note", "metadata", "private_key", "app_secret", "protection_level":
					t.Fatalf("private field %s in %s", key, raw)
				}
				check(x)
			}
		case []any:
			for _, x := range v {
				check(x)
			}
		}
	}
	var v any
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	check(v)
	for _, secret := range []string{"FOREIGN-PRIVATE-APP", "FOREIGN-ADMIN-NOTE", "PRIVATE-FINGERPRINT", "ACTIVATION-SECRET", "private-download.example"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("leaked %s", secret)
		}
	}
}
func TestUserIsolationFiltersAndLicenseScopeRejection(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, func(in *licensing.CreateInput) { in.VerifyMethods = ptr([]string{"KEY", "FLOATING"}) })
	token := userPassword(t, f)
	scoped := f.password(t)
	other, e := (enduser.Service{DB: f.db}).Create(context.Background(), enduser.Input{Name: ptr("other"), Email: ptr("other@example.com"), PortalPassword: ptr("other-password123")})
	if e != nil {
		t.Fatal(e)
	}
	appB, e := f.catalog.CreateApplication(context.Background(), catalog.ApplicationInput{Name: ptr("FOREIGN-PRIVATE-APP")})
	if e != nil {
		t.Fatal(e)
	}
	foreign := usercenterLicense(t, f, appB.ID, other.ID)
	shared := usercenterLicense(t, f, f.app.ID, other.ID)
	if e = f.db.Model(&model.License{}).Where("id IN ?", []uint64{foreign.ID, shared.ID}).Update("note", "FOREIGN-ADMIN-NOTE").Error; e != nil {
		t.Fatal(e)
	}
	now := f.clock.now()
	lease := now.Add(time.Hour)
	for _, l := range []licensing.LicenseInfo{f.license, foreign, shared} {
		usercenterCreate(t, f, &model.Activation{LicenseID: l.ID, Kind: "floating", Value: fmt.Sprintf("PRIVATE-FINGERPRINT-%d", l.ID), Token: fmt.Sprintf("ACTIVATION-SECRET-%d", l.ID), Status: "active", ClientVersion: "1.0.0", LastIP: "8.8.8.8", LeaseExpiresAt: &lease})
		usercenterCreate(t, f, &model.VerifyLog{LicenseID: &l.ID, AppID: &l.AppID, CreatedAt: now, IP: "8.8.8.8", Code: "OK", Device: "PRIVATE-FINGERPRINT"})
	}
	usercenterCreate(t, f, &model.Announcement{AppID: f.app.ID, Title: "own", Content: "safe", PublishedAt: &now})
	usercenterCreate(t, f, &model.Announcement{AppID: appB.ID, Title: "FOREIGN-PRIVATE-APP", PublishedAt: &now})
	usercenterVersion(t, f, f.app.ID, "1.0.0", now, false, "manual")
	usercenterVersion(t, f, appB.ID, "9.0.0", now, false, "manual")
	paths := []string{"/user/attention", "/user/logs", "/user/updates", "/user/announcements", "/user/instances", "/licenses", fmt.Sprintf("/licenses/%d", f.license.ID)}
	for _, path := range paths {
		view := data(f.p(t, "GET", path, token, nil, "OK"))
		usercenterSafe(t, view)
		if path != "/user/attention" && !strings.HasPrefix(path, "/licenses/") && fmt.Sprint(view["total"]) != "1" {
			t.Fatalf("%s: %+v", path, view)
		}
		f.p(t, "GET", path, scoped, nil, "PORTAL_UNAUTHORIZED")
	}
	for _, path := range []string{fmt.Sprintf("/user/logs?license_id=%d", foreign.ID), fmt.Sprintf("/user/instances?license_id=%d", foreign.ID), fmt.Sprintf("/user/announcements?app_id=%d", appB.ID), fmt.Sprintf("/user/updates?app_id=%d", appB.ID), fmt.Sprintf("/user/attention?license_id=%d", foreign.ID), fmt.Sprintf("/licenses?app_id=%d", appB.ID)} {
		view := data(f.p(t, "GET", path, token, nil, "OK"))
		if fmt.Sprint(view["total"]) != "0" {
			t.Fatal("foreign filter not isolated", path, view)
		}
	}
	for _, l := range []licensing.LicenseInfo{foreign, shared} {
		f.p(t, "GET", fmt.Sprintf("/licenses/%d", l.ID), token, nil, "NOT_FOUND")
		f.p(t, "POST", "/switch", token, gin.H{"license_id": l.ID}, "NOT_FOUND")
	}
	selected := data(f.p(t, "POST", "/switch", token, gin.H{"license_id": f.license.ID}, "OK"))["portal_token"].(string)
	for _, path := range []string{"/activations", "/logs", "/user/instances"} {
		view := data(f.p(t, "GET", path, selected, nil, "OK"))
		raw, _ := json.Marshal(view)
		if bytes.Contains(raw, []byte("PRIVATE-FINGERPRINT")) || bytes.Contains(raw, []byte("ACTIVATION-SECRET")) {
			t.Fatalf("private user projection leaked: %s", raw)
		}
	}
	view := data(f.p(t, "GET", "/announcements", token, nil, "OK"))
	if fmt.Sprint(view["total"]) != "1" {
		t.Fatal("email announcements not global", view)
	}
	otherToken := data(f.p(t, "POST", "/user/login", "", gin.H{"email": "other@example.com", "password": "other-password123"}, "OK"))["portal_token"].(string)
	f.p(t, "GET", fmt.Sprintf("/licenses/%d", f.license.ID), otherToken, nil, "NOT_FOUND")
	f.p(t, "POST", "/switch", otherToken, gin.H{"license_id": f.license.ID}, "NOT_FOUND")
	ignored := data(f.p(t, "GET", fmt.Sprintf("/user/logs?user_id=%d", other.ID), token, nil, "OK"))
	if fmt.Sprint(ignored["total"]) != "1" {
		t.Fatal("caller controlled the user scope", ignored)
	}
	if e = f.db.Model(&model.License{}).Where("id=?", foreign.ID).Update("expires_at", now).Error; e != nil {
		t.Fatal(e)
	}
	filtered := data(f.p(t, "GET", "/licenses?status=expired", token, nil, "OK"))
	if fmt.Sprint(filtered["total"]) != "0" {
		t.Fatal("OR filter escaped ownership", filtered)
	}
	// A stale selected session must not preserve ownership after reassignment.
	if e = f.db.Model(&model.License{}).Where("id=?", f.license.ID).Update("user_id", other.ID).Error; e != nil {
		t.Fatal(e)
	}
	f.p(t, "GET", fmt.Sprintf("/licenses/%d", f.license.ID), selected, nil, "NOT_FOUND")
	f.p(t, "POST", "/switch", selected, gin.H{"license_id": f.license.ID}, "NOT_FOUND")
	view = data(f.p(t, "GET", "/user/logs", selected, nil, "OK"))
	if fmt.Sprint(view["total"]) != "0" {
		t.Fatal("stale ownership", view)
	}
}

func TestPaginationDefaultsAndAnnouncementWindows(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	token := userPassword(t, f)
	now := f.clock.now()
	_ = usercenterLicense(t, f, f.app.ID, *f.license.UserID) // Same app must not duplicate announcements.
	for i := 0; i < 15; i++ {
		at := now.Add(-time.Duration(i) * time.Minute)
		usercenterCreate(t, f, &model.VerifyLog{LicenseID: &f.license.ID, CreatedAt: at, Code: "OK"})
		usercenterCreate(t, f, &model.Announcement{AppID: f.app.ID, Title: fmt.Sprintf("a%d", i), PublishedAt: &at})
	}
	future := now.Add(time.Second)
	past := now.Add(-time.Second)
	usercenterCreate(t, f, &model.Announcement{AppID: f.app.ID, Title: "draft"})
	usercenterCreate(t, f, &model.Announcement{AppID: f.app.ID, Title: "future", PublishedAt: &future})
	usercenterCreate(t, f, &model.Announcement{AppID: f.app.ID, Title: "expired", PublishedAt: &past, ExpiresAt: &now})
	logs := data(f.p(t, "GET", "/user/logs", token, nil, "OK"))
	if len(logs["items"].([]any)) != 10 || fmt.Sprint(logs["page_size"]) != "10" || fmt.Sprint(logs["total"]) != "15" {
		t.Fatal(logs)
	}
	second := data(f.p(t, "GET", "/user/logs?page=2", token, nil, "OK"))
	if len(second["items"].([]any)) != 5 {
		t.Fatal(second)
	}
	announcements := data(f.p(t, "GET", "/user/announcements?page_size=2", token, nil, "OK"))
	if fmt.Sprint(announcements["total"]) != "15" || announcements["items"].([]any)[0].(map[string]any)["title"] != "a0" {
		t.Fatal(announcements)
	}
	for _, path := range []string{"/user/attention", "/user/logs", "/user/updates", "/user/announcements", "/user/instances", "/licenses"} {
		f.p(t, "GET", path+"?page_size=101", token, nil, "INVALID_REQUEST")
		f.p(t, "GET", path+"?page=0", token, nil, "INVALID_REQUEST")
	}
	for _, path := range []string{"/user/logs?license_id=-1", "/user/announcements?app_id=0", "/user/instances?app_id=bad", "/licenses?status=not-a-state", "/licenses/0", "/licenses/not-id"} {
		f.p(t, "GET", path, token, nil, "INVALID_REQUEST")
	}
}

func TestAttentionKindsPriorityAndBoundaries(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, func(in *licensing.CreateInput) { in.VerifyMethods = ptr([]string{"KEY", "FLOATING"}) })
	token := userPassword(t, f)
	now := f.clock.now()
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	f.request(t, "PATCH", "/system/support", owner, gin.H{"support_contact": "support@example.com"}, 200)
	expires := now.Add(10 * 24 * time.Hour)
	maintenanceAt := now.Add(15 * 24 * time.Hour)
	lease := now.Add(time.Hour)
	if e := f.db.Model(&model.License{}).Where("id=?", f.license.ID).Updates(map[string]any{"expires_at": expires, "maintenance_until": maintenanceAt}).Error; e != nil {
		t.Fatal(e)
	}
	usercenterCreate(t, f, &model.Activation{LicenseID: f.license.ID, Kind: "floating", Value: "running", Token: "running-only-test", Status: "active", ClientVersion: "1.0.0", LeaseExpiresAt: &lease})
	usercenterVersion(t, f, f.app.ID, "1.0.0", now.Add(-time.Hour), true, "manual")
	usercenterVersion(t, f, f.app.ID, "2.0.0", now, false, "manual")
	expired := usercenterLicense(t, f, f.app.ID, *f.license.UserID)
	suspended := usercenterLicense(t, f, f.app.ID, *f.license.UserID)
	if e := f.db.Model(&model.License{}).Where("id=?", expired.ID).Update("expires_at", now).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.db.Model(&model.License{}).Where("id=?", suspended.ID).Update("status", "suspended").Error; e != nil {
		t.Fatal(e)
	}
	view := data(f.p(t, "GET", "/user/attention", token, nil, "OK"))
	items := view["items"].([]any)
	want := []string{"version_disabled", "expired", "suspended", "expiring", "maintenance_expiring", "update_available"}
	if len(items) != len(want) {
		t.Fatalf("wanted seven types: %+v", view)
	}
	for i, item := range items {
		row := item.(map[string]any)
		if row["type"] != want[i] || row["support_contact"] != "support@example.com" || !strings.HasPrefix(row["href"].(string), "/portal/licenses/") {
			t.Fatal(i, row)
		}
		if i > 0 && fmt.Sprint(row["priority"]) <= fmt.Sprint(items[i-1].(map[string]any)["priority"]) {
			t.Fatal("not urgent-first", items)
		}
	}
	// A disabled build on an expired lease is not currently running.
	if e := f.db.Model(&model.Activation{}).Where("license_id=?", f.license.ID).Update("lease_expires_at", now).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.db.Model(&model.License{}).Where("id=?", f.license.ID).Updates(map[string]any{"expires_at": now.Add(30 * 24 * time.Hour), "maintenance_until": now.Add(30 * 24 * time.Hour)}).Error; e != nil {
		t.Fatal(e)
	}
	view = data(f.p(t, "GET", fmt.Sprintf("/user/attention?license_id=%d", f.license.ID), token, nil, "OK"))
	raw, _ := json.Marshal(view)
	if bytes.Contains(raw, []byte("version_disabled")) || !bytes.Contains(raw, []byte(`"type":"expiring"`)) || !bytes.Contains(raw, []byte(`"type":"maintenance_expiring"`)) {
		t.Fatal(string(raw))
	}
	if e := f.db.Model(&model.License{}).Where("id=?", f.license.ID).Updates(map[string]any{"expires_at": now.Add(30*24*time.Hour + time.Second), "maintenance_until": now.Add(30*24*time.Hour + time.Second)}).Error; e != nil {
		t.Fatal(e)
	}
	view = data(f.p(t, "GET", fmt.Sprintf("/user/attention?license_id=%d", f.license.ID), token, nil, "OK"))
	raw, _ = json.Marshal(view)
	if bytes.Contains(raw, []byte(`"type":"expiring"`)) || bytes.Contains(raw, []byte(`"type":"maintenance_expiring"`)) {
		t.Fatal("outside boundary", string(raw))
	}
}

func TestVersionEntitlementsDockerDeploymentAndTrialFields(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, func(in *licensing.CreateInput) { in.VerifyMethods = ptr([]string{"KEY", "FLOATING"}) })
	token := userPassword(t, f)
	now := f.clock.now()
	until := now.Add(-30 * 24 * time.Hour)
	if e := f.db.Model(&model.Application{}).Where("id=?", f.app.ID).Update("docker_image", "example-org/public-app").Error; e != nil {
		t.Fatal(e)
	}
	if e := f.db.Model(&model.License{}).Where("id=?", f.license.ID).Updates(map[string]any{"maintenance_until": until, "note": "PRIVATE-FINGERPRINT-admin-note"}).Error; e != nil {
		t.Fatal(e)
	}
	for i, days := range []int{60, 10, 1} {
		usercenterVersion(t, f, f.app.ID, fmt.Sprintf("%d.0.0", i+1), now.Add(-time.Duration(days)*24*time.Hour), false, "docker")
	}
	usercenterVersion(t, f, f.app.ID, "4.0.0", now, true, "docker")
	usercenterVersion(t, f, f.app.ID, "9.0.0", now.Add(time.Hour), false, "docker")
	usercenterDockerTags(t, f, `{"1.0.0":"1.0.0","2.0.0":"v2.0.0","3.0.0":"v3.0.0","4.0.0":"4.0.0","9.0.0":"9.0.0"}`)
	foreign := model.EndUser{Name: "other", Status: "active"}
	usercenterCreate(t, f, &foreign)
	_ = usercenterLicense(t, f, f.app.ID, foreign.ID)
	list := data(f.p(t, "GET", "/licenses", token, nil, "OK"))
	card := list["items"].([]any)[0].(map[string]any)
	if card["latest_version"] != "3.0.0" || card["latest_entitled_version"] != "1.0.0" || card["renewal_required"] != true || card["docker_pull"] != "docker pull example-org/public-app:1.0.0" {
		t.Fatal(card)
	}
	if _, ok := card["compose"]; ok {
		t.Fatal("compose in list")
	}
	usercenterSafe(t, list)
	detail := data(f.p(t, "GET", fmt.Sprintf("/licenses/%d", f.license.ID), token, nil, "OK"))
	deployment := detail["deployment"].(map[string]any)
	compose := deployment["compose"].(string)
	if deployment["available"] != true || deployment["tag"] != "1.0.0" || !strings.Contains(compose, f.license.Key) || !strings.Contains(compose, "example-org/public-app:1.0.0") || strings.Contains(compose, "v3.0.0") || strings.Contains(compose, "AUTHGO_CONFIG") {
		t.Fatal(deployment)
	}
	for _, part := range []string{"restart: unless-stopped", "read_only: true", "cap_drop: [ALL]", "no-new-privileges:true", "authgo_cache:/var/lib/authgo"} {
		if !strings.Contains(compose, part) {
			t.Fatal("unsafe/missing compose setting", part)
		}
	}
	if deployment["ports_hint"] != "如程序需要对外提供服务，请按软件文档添加 ports" {
		t.Fatal("missing port guidance", deployment)
	}
	guide := deployment["guide"].(string)
	if !strings.Contains(guide, "缓存卷、扩容与席位") || !strings.Contains(guide, "docker compose up -d") || strings.Contains(guide, "给开发者") {
		t.Fatal("wrong customer guide", guide)
	}
	// A second owned license can raise the entitlement; another user's cannot.
	second := usercenterLicense(t, f, f.app.ID, *f.license.UserID)
	later := now.Add(-5 * 24 * time.Hour)
	if e := f.db.Model(&model.License{}).Where("id=?", second.ID).Update("maintenance_until", later).Error; e != nil {
		t.Fatal(e)
	}
	updates := data(f.p(t, "GET", "/user/updates", token, nil, "OK"))
	if fmt.Sprint(updates["total"]) != "1" {
		t.Fatal("one row per app", updates)
	}
	row := updates["items"].([]any)[0].(map[string]any)
	if row["version"] != "3.0.0" || row["latest_entitled_version"] != "2.0.0" || fmt.Sprint(row["license_id"]) != fmt.Sprint(second.ID) || row["docker_pull"] != "docker pull example-org/public-app:v2.0.0" || row["renewal_required"] != true {
		t.Fatal(row)
	}
	usercenterSafe(t, updates)
	trialUntil := now.Add(25 * time.Hour)
	if e := f.db.Model(&model.License{}).Where("id=?", second.ID).Updates(map[string]any{"type": "trial", "expires_at": trialUntil}).Error; e != nil {
		t.Fatal(e)
	}
	detail = data(f.p(t, "GET", fmt.Sprintf("/licenses/%d", second.ID), token, nil, "OK"))
	if detail["type"] != "trial" || fmt.Sprint(detail["trial_remaining_days"]) != "2" || detail["trial_conversion_required"] != true || !strings.Contains(detail["trial_hint"].(string), "转正") {
		t.Fatal(detail)
	}

}

func TestInstancesIPPrivacyOnlineQuotaAndComposeNotLogged(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, func(in *licensing.CreateInput) {
		in.VerifyMethods = ptr([]string{"KEY", "FLOATING"})
		in.MaxActivations = ptr(4)
	})
	token := userPassword(t, f)
	now := f.clock.now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Second)
	if e := f.db.Model(&model.Application{}).Where("id=?", f.app.ID).Update("docker_image", "example-org/public-app").Error; e != nil {
		t.Fatal(e)
	}
	usercenterVersion(t, f, f.app.ID, "1.0.0", now, false, "docker")
	usercenterDockerTags(t, f, `{"1.0.0":"v1.0.0"}`)
	for i, lease := range []*time.Time{&future, &past, nil} {
		usercenterCreate(t, f, &model.Activation{LicenseID: f.license.ID, Kind: "floating", Value: fmt.Sprintf("PRIVATE-FINGERPRINT-%d", i), Token: fmt.Sprintf("ACTIVATION-SECRET-%d", i), Status: "active", LastIP: "8.8.8.8", LeaseExpiresAt: lease})
	}
	ips, e := ipinfo.New(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer ips.Close()
	city, e := os.ReadFile("../ipinfo/testdata/city.mmdb")
	if e != nil {
		t.Fatal(e)
	}
	if e = ips.Upload(context.Background(), "city", bytes.NewReader(city)); e != nil {
		t.Fatal(e)
	}
	var logs bytes.Buffer
	identity, e := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := f.db.DB()
	f.r, e = NewRouter(config.Config{}, slog.New(slog.NewJSONHandler(&logs, nil)), pool.PingContext, WithAdmin(identity, f.db), WithPortal(f.portalService), WithIPInfo(ips))
	if e != nil {
		t.Fatal(e)
	}
	view := data(f.p(t, "GET", "/user/instances", token, nil, "OK"))
	if fmt.Sprint(view["total"]) != "3" {
		t.Fatal(view)
	}
	onlineCount := 0
	for _, raw := range view["items"].([]any) {
		row := raw.(map[string]any)
		if row["online"] == true {
			onlineCount++
		}
		if row["last_ip"] != "8.8.*.*" || row["ip_info"].(map[string]any)["city"] != "上海" {
			t.Fatal(row)
		}
	}
	if onlineCount != 1 {
		t.Fatal("online is a live floating lease only", view)
	}
	usercenterSafe(t, view)
	summary := data(f.p(t, "GET", "/user", token, nil, "OK"))
	if fmt.Sprint(summary["online_instances"]) != "1" {
		t.Fatal(summary)
	}
	list := data(f.p(t, "GET", "/licenses", token, nil, "OK"))
	card := list["items"].([]any)[0].(map[string]any)
	if fmt.Sprint(card["online_instances"]) != "1" || fmt.Sprint(card["max_activations"]) != "4" {
		t.Fatal(card)
	}
	detail := data(f.p(t, "GET", fmt.Sprintf("/licenses/%d", f.license.ID), token, nil, "OK"))
	if !strings.Contains(detail["deployment"].(map[string]any)["compose"].(string), f.license.Key) {
		t.Fatal("no personalized compose")
	}
	if strings.Contains(logs.String(), f.license.Key) || strings.Contains(logs.String(), token) {
		t.Fatal("compose/license/token written to HTTP logs", logs.String())
	}
	var audits []model.AuditLog
	if e = f.db.Find(&audits).Error; e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(audits)
	if bytes.Contains(raw, []byte(f.license.Key)) {
		t.Fatal("compose leaked to audit")
	}
}

func TestSupportSettingValidationScopesAndNoMigration(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	token := userPassword(t, f)
	scoped := f.password(t)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	var migrations int64
	if e := f.db.Model(&model.SchemaMigration{}).Count(&migrations).Error; e != nil {
		t.Fatal(e)
	}
	if data(f.request(t, "GET", "/system/support", owner, nil, 200))["support_contact"] != "" {
		t.Fatal("not optional by default")
	}
	contact := "支持邮箱 support@example.com\n工单：https://support.example.com <纯文本>"
	f.request(t, "PATCH", "/system/support", owner, gin.H{"support_contact": contact}, 200)
	if data(f.request(t, "GET", "/system/support", owner, nil, 200))["support_contact"] != contact {
		t.Fatal("setting not persisted")
	}
	for _, tkn := range []string{token, scoped} {
		view := data(f.p(t, "GET", "/session", tkn, nil, "OK"))
		if view["support_contact"] != contact {
			t.Fatal("footer contact missing", view)
		}
		f.request(t, "GET", "/system/support", tkn, nil, 401)
		f.request(t, "PATCH", "/system/support", tkn, gin.H{"support_contact": "replace"}, 401)
	}
	for _, body := range []any{gin.H{}, gin.H{"support_contact": nil}, gin.H{"support_contact": strings.Repeat("中", 201)}, gin.H{"support_contact": "bad\x00control"}, gin.H{"support_contact": "ok", "extra": true}} {
		f.request(t, "PATCH", "/system/support", owner, body, 400)
	}
	if data(f.request(t, "GET", "/system/support", owner, nil, 200))["support_contact"] != contact {
		t.Fatal("validation replaced old value")
	}
	f.request(t, "PATCH", "/system/support", owner, gin.H{"support_contact": strings.Repeat("中", 200)}, 200)
	f.request(t, "PATCH", "/system/support", owner, gin.H{"support_contact": ""}, 200)
	if _, ok := data(f.p(t, "GET", "/session", token, nil, "OK"))["support_contact"]; ok {
		t.Fatal("cleared optional field returned")
	}
	var after, audits int64
	f.db.Model(&model.SchemaMigration{}).Count(&after)
	f.db.Model(&model.AuditLog{}).Where("action='system.support.update' AND status_code=200").Count(&audits)
	if after != migrations || audits != 3 {
		t.Fatal("migration or missing audit", migrations, after, audits)
	}
}

func TestListQueriesAreBatchedAndEmptyUsersStayUsable(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	token := userPassword(t, f)
	var queries atomic.Int64
	name := "usercenter-count-queries"
	if e := f.db.Callback().Query().After("gorm:query").Register(name, func(*gorm.DB) { queries.Add(1) }); e != nil {
		t.Fatal(e)
	}
	defer f.db.Callback().Query().Remove(name)
	seed := func(lid uint64) {
		usercenterCreate(t, f, &model.Activation{LicenseID: lid, Kind: "floating", Value: fmt.Sprint(lid), Token: fmt.Sprintf("batch-%d", lid), Status: "active"})
		usercenterCreate(t, f, &model.VerifyLog{LicenseID: &lid, Code: "OK", CreatedAt: f.clock.now()})
	}
	seed(f.license.ID)
	usercenterVersion(t, f, f.app.ID, "1.0.0", f.clock.now(), false, "manual")
	paths := []string{"/licenses", "/user/attention", "/user/updates", "/user/logs", "/user/instances", "/user/announcements"}
	count := func(path string) int64 {
		queries.Store(0)
		f.p(t, "GET", path+"?page_size=100", token, nil, "OK")
		return queries.Load()
	}
	small := map[string]int64{}
	for _, path := range paths {
		small[path] = count(path)
	}
	for i := 0; i < 12; i++ {
		l := usercenterLicense(t, f, f.app.ID, *f.license.UserID)
		seed(l.ID)
	}
	for _, path := range paths {
		large := count(path)
		if large > small[path]+1 {
			t.Fatalf("%s N+1 queries: one license=%d thirteen=%d", path, small[path], large)
		}
	}
	empty, e := (enduser.Service{DB: f.db}).Create(context.Background(), enduser.Input{Name: ptr("empty"), Email: ptr("empty@example.com"), PortalPassword: ptr("empty-password123")})
	if e != nil {
		t.Fatal(e)
	}
	_ = empty
	emptyToken := data(f.p(t, "POST", "/user/login", "", gin.H{"email": "empty@example.com", "password": "empty-password123"}, "OK"))["portal_token"].(string)
	for _, path := range []string{"/licenses", "/user/attention", "/user/logs", "/user/updates", "/user/announcements", "/user/instances", "/announcements"} {
		view := data(f.p(t, "GET", path, emptyToken, nil, "OK"))
		if fmt.Sprint(view["total"]) != "0" || len(view["items"].([]any)) != 0 {
			t.Fatal("empty account not usable", path, view)
		}
	}
}

func usercenterDockerTags(t *testing.T, f *portalFixture, tags string) {
	t.Helper()
	result := f.db.Model(&dockerhub.State{}).Where("app_id=? AND image=?", f.app.ID, "example-org/public-app").Update("tags_json", tags)
	if result.Error != nil || result.RowsAffected != 1 {
		t.Fatalf("seed existing Docker sync state: rows=%d err=%v", result.RowsAffected, result.Error)
	}
}
