package httpserver

import (
	"authgo/internal/enduser"
	"authgo/internal/licensing"
	"authgo/internal/model"
	"authgo/internal/portal"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"testing"
	"time"
)

func userPassword(t *testing.T, f *portalFixture) string {
	t.Helper()
	s := enduser.Service{DB: f.db}
	if _, e := s.Update(context.Background(), *f.license.UserID, enduser.Input{PortalPassword: ptr("user-password123")}); e != nil {
		t.Fatal(e)
	}
	return data(f.p(t, "POST", "/user/login", "", gin.H{"email": "USER@example.com", "password": "user-password123"}, "OK"))["portal_token"].(string)
}
func TestUserCenterLoginSwitchOwnershipPasswordAndDevices(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	token := userPassword(t, f)
	f.p(t, "GET", "/license", token, nil, "LICENSE_NOT_SELECTED")
	view := data(f.p(t, "GET", "/user", token, nil, "OK"))
	if fmt.Sprint(view["license_count"]) != "1" {
		t.Fatal(view)
	}
	_, e := f.licensing.Create(context.Background(), licensing.CreateInput{AppID: f.app.ID, UserID: f.license.UserID})
	if e != nil {
		t.Fatal(e)
	}
	page := data(f.p(t, "GET", "/licenses", token, nil, "OK"))
	if fmt.Sprint(page["total"]) != "2" {
		t.Fatal(page)
	}
	other := model.EndUser{Name: "他人"}
	f.db.Create(&other)
	license, e := f.licensing.Create(context.Background(), licensing.CreateInput{AppID: f.app.ID, UserID: &other.ID})
	if e != nil {
		t.Fatal(e)
	}
	f.p(t, "POST", "/switch", token, gin.H{"license_id": license.ID}, "NOT_FOUND")
	selected := data(f.p(t, "POST", "/switch", token, gin.H{"license_id": f.license.ID}, "OK"))
	selectedToken := selected["portal_token"].(string)
	f.p(t, "GET", "/license", selectedToken, nil, "OK")
	// License-only credentials cannot enumerate or switch between user's licenses.
	scoped := f.password(t)
	f.p(t, "GET", "/licenses", scoped, nil, "PORTAL_UNAUTHORIZED")
	f.p(t, "POST", "/switch", scoped, gin.H{"license_id": f.license.ID}, "PORTAL_UNAUTHORIZED")
	// Owned instances are projected without leaking private activation credentials.
	a := model.Activation{LicenseID: f.license.ID, Kind: "floating", Value: "device", Token: "user-device", Hostname: "电脑", FirstIP: "192.0.2.1", LastIP: "192.0.2.1"}
	f.db.Create(&a)
	devices := data(f.p(t, "GET", "/user/instances", token, nil, "OK"))
	items := devices["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["last_ip"] != "192.0.*.*" {
		t.Fatal(devices)
	}
	f.p(t, "POST", fmt.Sprintf("/user/instances/%d/release-seat", a.ID), token, gin.H{}, "OK")
	var stored model.License
	f.db.First(&stored, f.license.ID)
	f.p(t, "POST", "/password", token, gin.H{"old_password": "wrong", "new_password": "new-password123"}, "INVALID_CREDENTIALS")
	f.p(t, "POST", "/password", token, gin.H{"old_password": "user-password123", "new_password": "new-password123"}, "OK")
	for _, old := range []string{token, selectedToken, scoped} {
		f.p(t, "GET", "/session", old, nil, "PORTAL_UNAUTHORIZED")
	}
	f.p(t, "POST", "/user/login", "", gin.H{"email": "user@example.com", "password": "new-password123"}, "OK")
}
func TestUserCenterEnumerationCodesAndCredentialInvalidation(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	token := userPassword(t, f)
	f.enableSMTP(t)
	wrong := f.p(t, "POST", "/user/login", "", gin.H{"email": "user@example.com", "password": "wrong"}, "INVALID_CREDENTIALS")
	absent := f.p(t, "POST", "/user/login", "", gin.H{"email": "nobody@example.com", "password": "wrong"}, "INVALID_CREDENTIALS")
	if wrong["message"] != absent["message"] || wrong["signature"] != absent["signature"] {
		t.Fatal("account enumeration")
	}
	known := f.p(t, "POST", "/user/login/code", "", gin.H{"email": "user@example.com"}, "OK")
	missing := f.p(t, "POST", "/user/login/code", "", gin.H{"email": "nobody@example.com"}, "OK")
	if fmt.Sprint(known["data"]) != fmt.Sprint(missing["data"]) {
		t.Fatal("code enumeration")
	}
	f.p(t, "POST", "/user/login/code", "", gin.H{"email": "nobody@example.com"}, "CODE_COOLDOWN")
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.mails)
		f.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no code mail")
		}
		time.Sleep(time.Millisecond)
	}
	code := f.latestCode(t)
	for {
		_, _, e := f.portalService.UserLogin(context.Background(), portal.UserLoginInput{Email: "user@example.com", Code: code}, "192.0.2.10")
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(e)
		}
		time.Sleep(time.Millisecond)
	}
	// Version keeps tokens invalid even if an admin later restores original values.
	s := enduser.Service{DB: f.db}
	for _, in := range []enduser.Input{{Status: ptr("disabled")}, {Status: ptr("active")}, {Email: ptr("new@example.com")}, {Email: ptr("user@example.com")}, {PortalPassword: ptr("changed-password")}} {
		if _, e := s.Update(context.Background(), *f.license.UserID, in); e != nil {
			t.Fatal(e)
		}
		f.p(t, "GET", "/session", token, nil, "PORTAL_UNAUTHORIZED")
	}
}
func TestUserCenterFailureLockAndAssignment(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	userPassword(t, f)
	for i := 0; i < 5; i++ {
		want := "INVALID_CREDENTIALS"
		if i == 4 {
			want = "LOGIN_LOCKED"
		}
		f.p(t, "POST", "/user/login", "", gin.H{"email": "user@example.com", "password": "wrong"}, want)
	}
	f.p(t, "POST", "/user/login", "", gin.H{"email": "user@example.com", "password": "user-password123"}, "LOGIN_LOCKED")
	f.clock.add(15 * time.Minute)
	token := data(f.p(t, "POST", "/user/login", "", gin.H{"email": "user@example.com", "password": "user-password123"}, "OK"))["portal_token"].(string)
	scoped := f.password(t)
	selected := data(f.p(t, "POST", "/switch", token, gin.H{"license_id": f.license.ID}, "OK"))["portal_token"].(string)
	other := model.EndUser{Name: "受让人"}
	f.db.Create(&other)
	if _, e := f.licensing.Assign(context.Background(), f.license.ID, licensing.AssignmentInput{UserID: &other.ID}); e != nil {
		t.Fatal(e)
	}
	f.p(t, "GET", "/license", selected, nil, "PORTAL_UNAUTHORIZED")
	f.p(t, "GET", "/license", scoped, nil, "PORTAL_UNAUTHORIZED")
	selectedSession := data(f.p(t, "GET", "/session", selected, nil, "OK"))
	if fmt.Sprint(selectedSession["selected_license_id"]) != "0" {
		t.Fatal("selected old owner retained license")
	}
	page := data(f.p(t, "GET", "/licenses", token, nil, "OK"))
	if fmt.Sprint(page["total"]) != "0" {
		t.Fatal("old owner retained license")
	}
}

func TestUserCenterSummaryAndOtherDeviceIsolation(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	expiry := f.clock.now().Add(24 * time.Hour)
	if e := f.db.Model(&model.License{}).Where("id=?", f.license.ID).Update("expires_at", expiry).Error; e != nil {
		t.Fatal(e)
	}
	token := userPassword(t, f)
	view := data(f.p(t, "GET", "/user", token, nil, "OK"))
	if view["next_expires_at"] == nil || fmt.Sprint(view["instances_total"]) != "0" {
		t.Fatal(view)
	}
	other := model.EndUser{Name: "其他用户"}
	f.db.Create(&other)
	grant, e := f.licensing.Create(context.Background(), licensing.CreateInput{AppID: f.app.ID, UserID: &other.ID})
	if e != nil {
		t.Fatal(e)
	}
	a := model.Activation{LicenseID: grant.ID, Kind: "floating", Value: "other", Token: "other-token"}
	f.db.Create(&a)
	f.p(t, "POST", fmt.Sprintf("/user/instances/%d/release-seat", a.ID), token, gin.H{}, "NOT_FOUND")
}

func TestUserCodeChangeInvalidatesChallenge(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	f.enableSMTP(t)
	userPassword(t, f)
	f.p(t, "POST", "/user/login/code", "", gin.H{"email": "user@example.com"}, "OK")
	deadline := time.Now().Add(time.Second)
	for {
		f.mu.Lock()
		n := len(f.mails)
		f.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no user OTP mail")
		}
		time.Sleep(time.Millisecond)
	}
	code := f.latestCode(t)
	s := enduser.Service{DB: f.db}
	if _, e := s.Update(context.Background(), *f.license.UserID, enduser.Input{Email: ptr("changed@example.com")}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Update(context.Background(), *f.license.UserID, enduser.Input{Email: ptr("user@example.com")}); e != nil {
		t.Fatal(e)
	}
	f.p(t, "POST", "/user/login", "", gin.H{"email": "user@example.com", "code": code}, "INVALID_CREDENTIALS")
}

func TestUserCenterWithoutAnyLicenses(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	user, e := (enduser.Service{DB: f.db}).Create(context.Background(), enduser.Input{Name: ptr("无授权用户"), Email: ptr("empty@example.com"), PortalPassword: ptr("empty-password")})
	if e != nil {
		t.Fatal(e)
	}
	token := data(f.p(t, "POST", "/user/login", "", gin.H{"email": user.Email, "password": "empty-password"}, "OK"))["portal_token"].(string)
	info := data(f.p(t, "GET", "/user", token, nil, "OK"))
	if fmt.Sprint(info["license_count"]) != "0" || fmt.Sprint(info["instances_total"]) != "0" || info["next_expires_at"] != nil {
		t.Fatal(info)
	}
	for _, path := range []string{"/licenses", "/user/instances"} {
		page := data(f.p(t, "GET", path, token, nil, "OK"))
		if fmt.Sprint(page["total"]) != "0" || len(page["items"].([]any)) != 0 {
			t.Fatal(page)
		}
	}
	session := data(f.p(t, "GET", "/session", token, nil, "OK"))
	if session["scope"] != "user" || fmt.Sprint(session["selected_license_id"]) != "0" {
		t.Fatal(session)
	}
}

func TestUserDetailDisplayProjections(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	a := model.Activation{LicenseID: f.license.ID, Kind: "floating", Value: "device", Token: "projection-device", Hostname: "电脑"}
	if e := f.db.Create(&a).Error; e != nil {
		t.Fatal(e)
	}
	lid := f.license.ID
	log := model.VerifyLog{LicenseID: &lid, Code: "OK", Action: "verify"}
	if e := f.db.Create(&log).Error; e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/activations", "/verify-logs"} {
		page := data(f.request(t, "GET", fmt.Sprintf("%s?user_id=%d", path, *f.license.UserID), owner, nil, 200))
		items := page["items"].([]any)
		if len(items) != 1 || items[0].(map[string]any)["license_key"] != f.license.Key {
			t.Fatal(path, page)
		}
	}
	token := f.password(t)
	view := data(f.p(t, "GET", "/license", token, nil, "OK"))
	if view["key"] != f.license.Key {
		t.Fatal("missing portal license key", view)
	}
}

func TestUserCenterLicenseListActiveInstancesExcludesKey(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, func(in *licensing.CreateInput) { in.VerifyMethods = ptr([]string{"KEY"}) })
	token := userPassword(t, f)
	second, err := f.licensing.Create(context.Background(), licensing.CreateInput{AppID: f.app.ID, UserID: f.license.UserID})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		a := model.Activation{LicenseID: f.license.ID, Kind: "key", Value: fmt.Sprint(i), Token: fmt.Sprintf("summary-key-%d", i), Status: "active"}
		if err = f.db.Create(&a).Error; err != nil {
			t.Fatal(err)
		}
	}
	check := func(want string) {
		page := data(f.p(t, "GET", "/licenses", token, nil, "OK"))
		items := page["items"].([]any)
		if len(items) != 2 {
			t.Fatal(page)
		}
		for _, raw := range items {
			item := raw.(map[string]any)
			expected := want
			if fmt.Sprint(item["id"]) == fmt.Sprint(f.license.ID) {
				expected = "0"
			}
			if fmt.Sprint(item["active_instances"]) != expected || item["app_name"] != f.app.Name {
				t.Fatal(item)
			}
			if _, found := item["active_activations"]; found {
				t.Fatal("portal leaked manager counter", item)
			}
		}
	}
	check("0")
	view := data(f.p(t, "GET", "/user", token, nil, "OK"))
	if fmt.Sprint(view["instances_total"]) != "0" {
		t.Fatal(view)
	}
	devices := data(f.p(t, "GET", "/user/instances", token, nil, "OK"))
	if fmt.Sprint(devices["total"]) != "0" {
		t.Fatal(devices)
	}
	for i, status := range []string{"active", "active", "unbound"} {
		a := model.Activation{LicenseID: second.ID, Kind: "floating", Value: fmt.Sprint(i), Token: fmt.Sprintf("summary-device-%d", i), Status: status}
		if err = f.db.Create(&a).Error; err != nil {
			t.Fatal(err)
		}
	}
	check("2")
	view = data(f.p(t, "GET", "/user", token, nil, "OK"))
	if fmt.Sprint(view["instances_total"]) != "2" {
		t.Fatal(view)
	}
	f.p(t, "GET", "/licenses", f.password(t), nil, "PORTAL_UNAUTHORIZED")
}
