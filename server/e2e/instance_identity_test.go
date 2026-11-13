package e2e

import (
	"authgo/sdk"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type instanceTransport func(*http.Request) (*http.Response, error)

func (f instanceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func instanceClient(t *testing.T, f *fixture, secure *httptest.Server, cache, fp, version string) *sdk.Client {
	t.Helper()
	v := f.admin(t, "POST", "/applications/"+f.appID(t).String()+"/connection", map[string]any{"url": secure.URL})
	c, e := sdk.New(v["config"].(string), sdk.WithCacheDir(cache), sdk.WithFingerprint(func() (string, error) { return strings.Repeat(fp, 64), nil }), sdk.WithClientVersion(version))
	if e != nil {
		t.Fatal(e)
	}
	c.HTTPClient = secure.Client()
	return c
}
func TestReleaseAndDisabledVersionOverTLS(t *testing.T) {
	f := setup(t)
	secure := httptest.NewTLSServer(f.server.Config.Handler)
	defer secure.Close()
	ctx := context.Background()
	_, key := f.issue(t, "KEY", "FLOATING")
	cache := t.TempDir()
	a := instanceClient(t, f, secure, cache, "a", "1.0.0")
	if _, e := a.Check(ctx, key); e != nil {
		t.Fatal(e)
	}
	if u, e := a.CheckUpdate(ctx, "1.0.0"); e != nil || u.Available {
		t.Fatal("floating update carrier lookup", u, e)
	}
	paths, e := filepath.Glob(filepath.Join(cache, "*.cache"))
	if e != nil || len(paths) != 1 {
		t.Fatal(paths, e)
	}
	before, _ := os.ReadFile(paths[0])
	other := instanceClient(t, f, secure, t.TempDir(), "b", "1.0.0")
	if _, e := other.Check(ctx, key); !errors.Is(e, sdk.ErrFloatingLimitReached) {
		t.Fatal("full seat allowed", e)
	}
	if e = a.ReleaseSeat(ctx); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(paths[0])
	if string(before) != string(after) {
		t.Fatal("release rewrote proof")
	}
	restored := instanceClient(t, f, secure, cache, "a", "1.0.0")
	restored.HTTPClient = &http.Client{Transport: instanceTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("test offline") })}
	if r, e := restored.Verify(ctx); e != nil || r.Status != "grace" {
		t.Fatal("release prevented outage restart", r, e)
	}
	if _, e = other.Check(ctx, key); e != nil {
		t.Fatal("release did not free seat", e)
	}
	if _, e = a.Heartbeat(ctx); !errors.Is(e, sdk.ErrFloatingLimitReached) {
		t.Fatal("recovery did not compete", e)
	}
	// Reported disabled versions fail; the running old version can still discover updates.
	_, versionKey := f.issue(t, "KEY")
	current := instanceClient(t, f, secure, t.TempDir(), "c", "1.0.0")
	if _, e = current.Check(ctx, versionKey); e != nil {
		t.Fatal(e)
	}
	app := "/applications/" + f.appID(t).String()
	now := time.Now().UTC().Add(-time.Second).Format(time.RFC3339)
	v := f.admin(t, "POST", app+"/versions", map[string]any{"version": "1.0.0", "published_at": now})
	id := v["id"].(interface{ String() string }).String()
	f.admin(t, "POST", app+"/versions", map[string]any{"version": "2.1.0", "published_at": now})
	f.admin(t, "PATCH", "/versions/"+id, map[string]any{"disabled": true})
	if _, e = current.Verify(ctx); !errors.Is(e, sdk.ErrVersionDisabled) {
		t.Fatal(e)
	} else {
		var detail *sdk.Error
		if !errors.As(e, &detail) || detail.LatestVersion != "2.1.0" {
			t.Fatal("missing latest version", e)
		}
	}
	// No Docker image/tag evidence means there is no update, even with manual metadata.
	update, e := current.CheckUpdate(ctx, "1.0.0")
	if e != nil || update.Available {
		t.Fatal(update, e)
	}
}
