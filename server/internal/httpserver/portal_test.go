package httpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"authgo/internal/auth"
	"authgo/internal/automation"
	"authgo/internal/client"
	"authgo/internal/config"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/ipinfo"
	"authgo/internal/licensing"
	"authgo/internal/mailer"
	"authgo/internal/model"
	"authgo/internal/portal"
	"authgo/internal/service"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type portalFixture struct {
	*clientFixture
	notifications *automation.Service
	portalService *portal.Service
	grants        *service.Service
	mu            sync.Mutex
	mails         []mailer.Message
	sendError     error
}

func newPortalFixture(t *testing.T, opts portal.Options, edit func(*licensing.CreateInput)) *portalFixture {
	t.Helper()
	c := newClientFixture(t, client.Options{IPBurst: 300, LicenseBurst: 300}, func(in *licensing.CreateInput) {
		in.PortalPassword = ptr("portal-password123")
		in.MaxActivations = ptr(2)
		if edit != nil {
			edit(in)
		}
	})
	f := &portalFixture{clientFixture: c}
	if e := f.db.Model(&model.EndUser{}).Where("id=?", *f.license.UserID).Updates(map[string]any{"name": "门户用户", "email": "user@example.com"}).Error; e != nil {
		t.Fatal(e)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var e error
	f.notifications, e = automation.New(f.db, make([]byte, 32), log, automation.Options{Now: f.clock.now, SendMail: func(ctx context.Context, c mailer.Config, m mailer.Message) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.sendError != nil {
			return f.sendError
		}
		f.mails = append(f.mails, m)
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	f.grants, e = service.New(f.db, make([]byte, 32), log, service.Options{Now: f.clock.now})
	if e != nil {
		t.Fatal(e)
	}
	opts.Now = f.clock.now
	if opts.IPBurst == 0 {
		opts.IPBurst = 300
	}
	if opts.LicenseBurst == 0 {
		opts.LicenseBurst = 300
	}
	f.portalService, e = portal.New(f.db, make([]byte, 32), f.notifications, f.grants, opts)
	if e != nil {
		t.Fatal(e)
	}
	identity, e := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	ips, e := ipinfo.New(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = ips.Close() })
	pool, _ := f.db.DB()
	f.r, e = NewRouter(config.Config{}, log, pool.PingContext, WithAdmin(identity, f.db), WithCatalog(f.catalog), WithLicensing(f.licensing), WithClient(f.service), WithAutomation(f.notifications), WithPortal(f.portalService), WithIPInfo(ips))
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *portalFixture) enableSMTP(t *testing.T) {
	t.Helper()
	_, e := f.notifications.UpdateSettings(context.Background(), automation.SettingsInput{SMTP: &automation.SMTPInput{Enabled: ptr(true), Host: ptr("smtp.example.com"), From: ptr("from@example.com")}})
	if e != nil {
		t.Fatal(e)
	}
}
func (f *portalFixture) latestCode(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.mails) == 0 {
		t.Fatal("no email")
	}
	code := regexp.MustCompile(`[0-9]{6}`).FindString(f.mails[len(f.mails)-1].Body)
	if code == "" {
		t.Fatal(f.mails)
	}
	return code
}
func (f *portalFixture) p(t *testing.T, method, path, token string, body any, want string) map[string]any {
	return f.pIP(t, method, path, token, body, want, "198.51.100.8:1234")
}
func (f *portalFixture) pIP(t *testing.T, method, path, token string, body any, want, ip string) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/v1/portal"+path, reader)
	req.RemoteAddr = ip
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "portal-integration")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	var r map[string]any
	d := json.NewDecoder(w.Body)
	d.UseNumber()
	if e := d.Decode(&r); e != nil {
		t.Fatal(e, w.Body.String())
	}
	if r["code"] != want {
		t.Fatalf("%s %s: HTTP %d %+v want %s", method, path, w.Code, r, want)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable portal response")
	}
	if want == "OK" && w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, k := range []string{"code", "message", "data", "signature"} {
		if _, ok := r[k]; !ok {
			t.Fatal("missing " + k)
		}
	}
	if sig, ok := r["signature"].(string); ok {
		payload, e := cryptoutil.CanonicalJSON(map[string]any{"code": r["code"], "data": r["data"], "ts": r["ts"]})
		if e != nil {
			t.Fatal(e)
		}
		signature, _ := base64.StdEncoding.DecodeString(sig)
		pub, _ := base64.StdEncoding.DecodeString(f.app.PublicKey)
		if !cryptoutil.Verify(pub, payload, signature) {
			t.Fatal("invalid portal signature")
		}
	}
	return r
}
func (f *portalFixture) password(t *testing.T) string {
	t.Helper()
	return data(f.p(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "password": "portal-password123"}, "OK"))["portal_token"].(string)
}
func TestPortalPasswordLoginIsolationAndExpiry(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	options := data(f.p(t, "GET", "/login/options", "", nil, "OK"))
	if options["smtp_configured"] != false || len(options["methods"].([]any)) != 1 {
		t.Fatal(options)
	}
	f.p(t, "POST", "/login/code", "", gin.H{"license_key": f.license.Key, "email": "user@example.com"}, "SMTP_NOT_CONFIGURED")
	token := f.password(t)
	info := data(f.p(t, "GET", "/license", token, nil, "OK"))
	if fmt.Sprint(info["remaining_activations"]) != "2" || fmt.Sprint(info["features"].(map[string]any)["quota"]) != "18446744073709551615" {
		t.Fatal(info)
	}
	f.request(t, "GET", "/auth/me", token, nil, 401)

	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	f.p(t, "GET", "/license", owner, nil, "PORTAL_UNAUTHORIZED")
	f.clock.add(2 * time.Hour)
	f.p(t, "GET", "/license", token, nil, "PORTAL_UNAUTHORIZED")
	token = f.password(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("changed-password"), bcrypt.DefaultCost)
	f.db.Model(&model.License{}).Where("id=?", f.license.ID).Update("portal_password_hash", string(hash))
	f.p(t, "GET", "/license", token, nil, "PORTAL_UNAUTHORIZED")
}
func TestPortalEmailCodeCooldownOneTimeExpiryAndLock(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	f.enableSMTP(t)
	f.p(t, "POST", "/login/code", "", gin.H{"license_key": f.license.Key, "email": "wrong@example.com"}, "INVALID_CREDENTIALS")
	f.p(t, "POST", "/login/code", "", gin.H{"license_key": f.license.Key, "email": "USER@example.com"}, "OK")
	code := f.latestCode(t)
	f.p(t, "POST", "/login/code", "", gin.H{"license_key": f.license.Key, "email": "user@example.com"}, "CODE_COOLDOWN")
	token := data(f.p(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "code": code}, "OK"))["portal_token"].(string)
	f.p(t, "GET", "/license", token, nil, "OK")
	f.p(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "code": code}, "INVALID_CREDENTIALS")
	f.clock.add(time.Minute)
	f.p(t, "POST", "/login/code", "", gin.H{"license_key": f.license.Key, "email": "user@example.com"}, "OK")
	code = f.latestCode(t)
	f.clock.add(10 * time.Minute)
	f.p(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "code": code}, "INVALID_CREDENTIALS")
	// A successful password login resets this IP's failure counter.
	f.password(t)
	for i := 1; i <= 5; i++ {
		want := "INVALID_CREDENTIALS"
		if i == 5 {
			want = "LOGIN_LOCKED"
		}
		f.p(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "password": "bad"}, want)
	}
	f.p(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "password": "portal-password123"}, "LOGIN_LOCKED")
	f.pIP(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "password": "portal-password123"}, "OK", "198.51.100.9:123")
	f.clock.add(15 * time.Minute)
	f.password(t)
}

func TestPortalIndependentRateLimits(t *testing.T) {
	f := newPortalFixture(t, portal.Options{IPRate: 1, IPBurst: 1, LicenseRate: 1, LicenseBurst: 1}, nil)
	f.p(t, "GET", "/login/options", "", nil, "OK")
	f.p(t, "GET", "/login/options", "", nil, "RATE_LIMITED")
	f.clock.add(time.Second)
	f.password(t)
	f.pIP(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "password": "portal-password123"}, "RATE_LIMITED", "198.51.100.9:321")
	// Independent client/admin buckets are not depleted by portal calls.
	f.call(t, "activate", f.input(""), "OK")
	f.login(t, "owner", "initial-password", "")
}

func TestPortalCodeConcurrentConsumptionDeliveryFailureAndGlobalCooldown(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	f.enableSMTP(t)
	body := gin.H{"license_key": f.license.Key, "email": "user@example.com"}
	f.p(t, "POST", "/login/code", "", body, "OK")
	code := f.latestCode(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, e := f.portalService.Login(context.Background(), portal.LoginInput{LicenseKey: f.license.Key, Code: code}, "198.51.100.8")
			if e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("OTP not one-time", success)
	}
	var first model.License
	f.db.First(&first, f.license.ID)
	other, e := f.licensing.Create(context.Background(), licensing.CreateInput{AppID: f.app.ID, UserID: first.UserID})
	if e != nil {
		t.Fatal(e)
	}
	f.p(t, "POST", "/login/code", "", gin.H{"license_key": other.Key, "email": "user@example.com"}, "CODE_COOLDOWN")
	f.clock.add(time.Minute)
	f.mu.Lock()
	f.sendError = fmt.Errorf("SMTP backend detail must not leak")
	f.mu.Unlock()
	f.p(t, "POST", "/login/code", "", body, "SMTP_SEND_FAILED")
	f.p(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "code": code}, "INVALID_CREDENTIALS")
}

func TestPortalUserEmailChangeInvalidatesCodeAndToken(t *testing.T) {
	f := newPortalFixture(t, portal.Options{}, nil)
	f.enableSMTP(t)
	token := f.password(t)
	f.p(t, "POST", "/login/code", "", gin.H{"license_key": f.license.Key, "email": "USER@example.com"}, "OK")
	oldCode := f.latestCode(t)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	path := "/users/" + strconv.FormatUint(*f.license.UserID, 10)
	changed := data(f.request(t, "PATCH", path, owner, gin.H{"name": "新用户", "email": "NEW@EXAMPLE.COM"}, 200))
	if changed["email"] != "new@example.com" {
		t.Fatal(changed)
	}
	f.p(t, "GET", "/license", token, nil, "PORTAL_UNAUTHORIZED")
	f.p(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "code": oldCode}, "INVALID_CREDENTIALS")
	f.clock.add(time.Minute)
	f.p(t, "POST", "/login/code", "", gin.H{"license_key": f.license.Key, "email": "user@example.com"}, "INVALID_CREDENTIALS")
	f.p(t, "POST", "/login/code", "", gin.H{"license_key": f.license.Key, "email": "NEW@example.com"}, "OK")
	login := data(f.p(t, "POST", "/login", "", gin.H{"license_key": f.license.Key, "code": f.latestCode(t)}, "OK"))
	f.p(t, "GET", "/license", login["portal_token"].(string), nil, "OK")
	var audits []model.AuditLog
	f.db.Where("action=?", "user.update").Find(&audits)
	if len(audits) != 1 || audits[0].StatusCode != 200 {
		t.Fatal(audits)
	}
}
