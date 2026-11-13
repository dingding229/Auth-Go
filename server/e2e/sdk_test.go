package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"authgo/internal/auth"
	"authgo/internal/automation"
	"authgo/internal/bootstrap"
	"authgo/internal/catalog"
	"authgo/internal/client"
	"authgo/internal/config"
	"authgo/internal/db"
	"authgo/internal/httpserver"
	"authgo/internal/licensing"
	"authgo/internal/portal"
	"authgo/internal/service"
	"authgo/sdk"
)

type fixture struct {
	server                      *httptest.Server
	appKey, secret, public, jwt string
	gateway                     []byte
}

func setup(t *testing.T) *fixture {
	t.Helper()
	database, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := database.DB()
	if e := db.Migrate(database); e != nil {
		t.Fatal(e)
	}
	if _, e := bootstrap.EnsureAdmin(database, "owner", "initial-password"); e != nil {
		t.Fatal(e)
	}
	master := make([]byte, 32)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	identity, e := auth.NewService(database, master)
	if e != nil {
		t.Fatal(e)
	}
	cat, e := catalog.NewService(database, master)
	if e != nil {
		t.Fatal(e)
	}
	clients, e := client.NewService(database, master, log, client.Options{IPBurst: 1000, LicenseBurst: 1000})
	if e != nil {
		t.Fatal(e)
	}
	offline, e := service.New(database, master, log, service.Options{})
	if e != nil {
		t.Fatal(e)
	}
	notifications, e := automation.New(database, master, log, automation.Options{})
	if e != nil {
		t.Fatal(e)
	}
	portalService, e := portal.New(database, master, notifications, offline, portal.Options{})
	if e != nil {
		t.Fatal(e)
	}
	router, e := httpserver.NewRouter(config.Config{}, log, pool.PingContext, httpserver.WithAdmin(identity, database), httpserver.WithCatalog(cat), httpserver.WithLicensing(licensing.NewService(database)), httpserver.WithClient(clients), httpserver.WithPortal(portalService))
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{server: httptest.NewServer(router)}
	t.Cleanup(func() {
		f.server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := offline.Close(ctx); e != nil {
			t.Error(e)
		}
		if e := clients.Close(ctx); e != nil {
			t.Error(e)
		}
		_ = pool.Close()
	})
	f.jwt = f.admin(t, "POST", "/auth/login", map[string]any{"username": "owner", "password": "initial-password"})["access_token"].(string)
	app := f.admin(t, "POST", "/applications", map[string]any{"name": "SDK端到端", "next_check_in": 1, "heartbeat_interval": 5})
	f.appKey = app["app_key"].(string)
	f.public = app["public_key"].(string)
	f.secret = f.admin(t, "GET", "/applications/"+app["id"].(json.Number).String()+"/secret", nil)["app_secret"].(string)
	return f
}
func (f *fixture) request(t *testing.T, method, path string, in any) ([]byte, http.Header) {
	t.Helper()
	var reader io.Reader
	if in != nil {
		raw, e := json.Marshal(in)
		if e != nil {
			t.Fatal(e)
		}
		reader = bytes.NewReader(raw)
	}
	req, e := http.NewRequest(method, f.server.URL+"/api/v1/admin"+path, reader)
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/json")
	if f.jwt != "" {
		req.Header.Set("Authorization", "Bearer "+f.jwt)
	}
	response, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(response.Body)
	if e != nil {
		t.Fatal(e)
	}
	if response.StatusCode != 200 {
		t.Fatalf("admin %s %s got %d %s", method, path, response.StatusCode, raw)
	}
	return raw, response.Header
}
func (f *fixture) admin(t *testing.T, method, path string, in any) map[string]any {
	t.Helper()
	raw, _ := f.request(t, method, path, in)
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if e := decoder.Decode(&result); e != nil {
		t.Fatal(e)
	}
	return result["data"].(map[string]any)
}
func (f *fixture) issue(t *testing.T, methods ...string) (uint64, string) {
	t.Helper()
	v := f.admin(t, "POST", "/licenses", map[string]any{"app_id": f.appID(t), "user_id": f.admin(t, "POST", "/users", map[string]any{"name": "SDK用户"})["id"], "verify_methods": methods, "validity_rule": "after_activation", "duration_days": 1, "max_activations": 1, "features": map[string]any{"quota": json.Number("18446744073709551615"), "export": true}})
	id, e := strconv.ParseUint(v["id"].(json.Number).String(), 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	return id, v["key"].(string)
}
func (f *fixture) appID(t *testing.T) json.Number {
	t.Helper()
	v := f.admin(t, "GET", "/applications", nil)
	return v["items"].([]any)[0].(map[string]any)["id"].(json.Number)
}
func (f *fixture) client(t *testing.T, fingerprint string) *sdk.Client {
	t.Helper()
	public, e := sdk.ParsePublicKey(f.public)
	if e != nil {
		t.Fatal(e)
	}
	if len(f.gateway) == 0 {
		info := f.admin(t, "GET", "/applications/gateway", nil)
		f.gateway, _ = base64.RawURLEncoding.DecodeString(info["public_key"].(string))
	}
	gateway := f.gateway
	return &sdk.Client{GatewayKey: gateway, BaseURL: f.server.URL, AppKey: f.appKey, AppSecret: f.secret, PublicKey: public, CacheDir: t.TempDir(), FingerprintFunc: func() (string, error) { return fingerprint, nil }}
}
func TestSDKLifecycleAndNetworkGrace(t *testing.T) {
	f := setup(t)
	_, key := f.issue(t, "KEY", "FLOATING")
	ctx := context.Background()
	a := f.client(t, strings.Repeat("a", 64))
	b := f.client(t, strings.Repeat("b", 64))
	grant, e := a.Activate(ctx, key, sdk.ActivateOptions{ClientVersion: "1.2.3"})
	if e != nil || grant.Offline {
		t.Fatal(grant, e)
	}
	if grant.Features["quota"].(json.Number) != "18446744073709551615" {
		t.Fatal("feature precision lost")
	}
	if _, e := a.Verify(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Heartbeat(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Activate(ctx, key, sdk.ActivateOptions{}); !errors.Is(e, sdk.ErrFloatingLimitReached) {
		t.Fatal("device quota", e)
	}
	if e := a.Deactivate(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := a.Verify(ctx); !errors.Is(e, sdk.ErrNotActivated) {
		t.Fatal(e)
	}
	if _, e := b.Activate(ctx, key, sdk.ActivateOptions{}); e != nil {
		t.Fatal(e)
	}
	if e := b.Deactivate(ctx); e != nil {
		t.Fatal(e)
	}
	// Separate license for a real TCP outage and cache restoration across clients.
	_, graceKey := f.issue(t, "KEY", "FLOATING")
	grace := f.client(t, strings.Repeat("e", 64))
	positive, e := grace.Activate(ctx, graceKey, sdk.ActivateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	f.server.Close()
	cached, e := grace.Verify(ctx)
	if e != nil || !cached.Offline || cached.GraceUntil != positive.GraceUntil {
		t.Fatal(cached, e)
	}
	restored := f.client(t, strings.Repeat("e", 64))
	restored.CacheDir = grace.CacheDir
	cached, e = restored.Verify(ctx)
	if e != nil || !cached.Offline {
		t.Fatal(cached, e)
	}
}
func TestSDKFloatingAndAutomaticChecks(t *testing.T) {
	f := setup(t)
	_, key := f.issue(t, "KEY", "FLOATING")
	ctx := context.Background()
	a := f.client(t, strings.Repeat("a", 64))
	b := f.client(t, strings.Repeat("b", 64))
	first, e := a.Activate(ctx, key, sdk.ActivateOptions{})
	if e != nil || first.LeaseExpiresAt == nil {
		t.Fatal(first, e)
	}
	if _, e := b.Activate(ctx, key, sdk.ActivateOptions{}); !errors.Is(e, sdk.ErrFloatingLimitReached) {
		t.Fatal(e)
	}
	heartbeat, e := a.Heartbeat(ctx)
	if e != nil || heartbeat.LeaseExpiresAt == nil || !heartbeat.GraceUntil.After(*heartbeat.LeaseExpiresAt) || heartbeat.ExpiresAt != nil && heartbeat.GraceUntil.After(*heartbeat.ExpiresAt) {
		t.Fatal(heartbeat, e)
	}
	autoCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	calls := 0
	e = a.StartAutoCheck(autoCtx, func(r *sdk.Result, e error) {
		if e != nil {
			t.Error(e)
		}
		calls++
	})
	if !errors.Is(e, context.DeadlineExceeded) || calls < 2 {
		t.Fatal("automatic verify did not run", calls, e)
	}
	if e := a.Deactivate(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Activate(ctx, key, sdk.ActivateOptions{}); e != nil {
		t.Fatal(e)
	}
}
func TestSDKExplicitRefusalCannotUseOldGrace(t *testing.T) {
	f := setup(t)
	id, key := f.issue(t, "KEY", "FLOATING")
	ctx := context.Background()
	a := f.client(t, strings.Repeat("a", 64))
	if _, e := a.Activate(ctx, key, sdk.ActivateOptions{}); e != nil {
		t.Fatal(e)
	}
	f.admin(t, "POST", "/licenses/"+strconv.FormatUint(id, 10)+"/suspend", nil)
	if _, e := a.Verify(ctx); !errors.Is(e, sdk.ErrLicenseSuspended) {
		t.Fatal(e)
	}
	f.server.Close()
	if r, e := a.Verify(ctx); r != nil || e == nil {
		t.Fatal("explicit suspension downgraded", r, e)
	}
	restored := f.client(t, strings.Repeat("a", 64))
	restored.CacheDir = a.CacheDir
	if r, e := restored.Verify(ctx); r != nil || e == nil {
		t.Fatal("refusal lost across restart", r, e)
	}
}

func TestSDKQuickstartConfigurationAndCheck(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	appID := f.appID(t).String()
	encoded := f.admin(t, "POST", "/applications/"+appID+"/connection", map[string]any{"url": f.server.URL})["config"].(string)
	dir := t.TempDir()
	options := []sdk.Option{sdk.WithCacheDir(dir), sdk.WithFingerprint(func() (string, error) { return strings.Repeat("a", 64), nil })}
	a, e := sdk.New(encoded, options...)
	if e != nil {
		t.Fatal(e)
	}
	_, key := f.issue(t, "KEY", "FLOATING")
	if _, e = a.Check(ctx, key); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Check(ctx, key); e != nil {
		t.Fatal(e)
	}
	restored, e := sdk.New(encoded, options...)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restored.Check(ctx, key); e != nil {
		t.Fatal("restore check", e)
	}
	_, other := f.issue(t, "KEY", "FLOATING")
	if _, e = a.Check(ctx, other); e != nil {
		t.Fatal("switch", e)
	}
	f.server.Close()
	if r, e := a.Check(ctx, other); e != nil || !r.Offline {
		t.Fatal("grace", r, e)
	}
	if _, e = a.Check(ctx, key); e == nil {
		t.Fatal("switched key reused old proof")
	}
}

func TestSDKDisabledUserRefusalNoGraceAndRecovery(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id, key := f.issue(t, "KEY", "FLOATING")
	c := f.client(t, strings.Repeat("a", 64))
	if _, e := c.Check(ctx, key); e != nil {
		t.Fatal(e)
	}
	details := f.admin(t, "GET", "/licenses/"+strconv.FormatUint(id, 10), nil)
	uid := details["user_id"].(json.Number).String()
	f.admin(t, "PATCH", "/users/"+uid, map[string]any{"status": "disabled"})
	if _, e := c.Heartbeat(ctx); !errors.Is(e, sdk.ErrUserDisabled) {
		t.Fatal("heartbeat", e)
	}
	otherClient := f.client(t, strings.Repeat("b", 64))
	if _, e := otherClient.Check(ctx, key); !errors.Is(e, sdk.ErrUserDisabled) {
		t.Fatal("activate", e)
	}
	if r, e := c.Check(ctx, key); r != nil || !errors.Is(e, sdk.ErrUserDisabled) {
		t.Fatal("disabled user", r, e)
	}
	f.admin(t, "PATCH", "/users/"+uid, map[string]any{"status": "active"})
	if _, e := c.Check(ctx, key); e != nil {
		t.Fatal("reenable", e)
	}
	f.admin(t, "PATCH", "/users/"+uid, map[string]any{"status": "disabled"})
	if _, e := c.Check(ctx, key); !errors.Is(e, sdk.ErrUserDisabled) {
		t.Fatal(e)
	}
	f.server.Close()
	if r, e := c.Check(ctx, key); r != nil || e == nil {
		t.Fatal("business refusal downgraded to grace", r, e)
	}
}

func TestSDKAnnouncementsBeforeAndAfterActivation(t *testing.T) {
	f := setup(t)
	appID := f.appID(t).String()
	f.admin(t, "POST", "/applications/"+appID+"/announcements", map[string]any{"title": "SDK公告", "content": "公告接口联调", "published_at": time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)})
	c := f.client(t, strings.Repeat("a", 64))
	items, e := c.Announcements(context.Background())
	if e != nil || len(items) != 1 || items[0].Title != "SDK公告" {
		t.Fatal("pre-activation news", items, e)
	}
	_, key := f.issue(t, "KEY", "FLOATING")
	if _, e := c.Check(context.Background(), key); e != nil {
		t.Fatal(e)
	}
	items, e = c.Announcements(context.Background())
	if e != nil || len(items) != 1 {
		t.Fatal(e)
	}
	f.server.Close()
	if r, e := c.Check(context.Background(), key); e != nil || r.Status != "grace" {
		t.Fatal("news interfered with grant", e)
	}
}
