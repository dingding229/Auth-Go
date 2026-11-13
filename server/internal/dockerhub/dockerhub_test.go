package dockerhub

import (
	"authgo/internal/apperror"
	"authgo/internal/db"
	"authgo/internal/model"
	"authgo/internal/updater"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	dbService *Service
	app       model.Application
	hub       *httptest.Server
	clock     atomic.Int64
	requests  atomic.Int64
}

func newFixture(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *fixture {
	t.Helper()
	d, err := db.Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := d.DB()
	t.Cleanup(func() { pool.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	f := &fixture{app: model.Application{Name: "Hub", AppKey: "hub", Status: "active", DockerImage: "docker.io/example-org/example-app"}}
	f.clock.Store(time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC).UnixNano())
	if err := d.Create(&f.app).Error; err != nil {
		t.Fatal(err)
	}
	updates, err := updater.New(d, make([]byte, 32), f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.hub = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != "GET" || r.URL.Path != "/v2/namespaces/example-org/repositories/example-app/tags" || r.URL.Query().Get("page_size") != "100" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected request method/path/credentials")
		}
		handler(w, r)
	}))
	t.Cleanup(f.hub.Close)
	f.dbService = New(d, updates, f.now)
	f.dbService.api = f.hub.URL
	return f
}
func (f *fixture) now() time.Time      { return time.Unix(0, f.clock.Load()).UTC() }
func (f *fixture) add(d time.Duration) { f.clock.Add(int64(d)) }
func responsePage(w http.ResponseWriter, tags []map[string]any, next any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"count": 123, "next": next, "results": tags})
}
func good(name string) map[string]any {
	return map[string]any{"name": name, "tag_last_pushed": "2025-01-02T03:04:05Z"}
}
func status(t *testing.T, err error, want int) {
	t.Helper()
	var e *apperror.Error
	if !errors.As(err, &e) || e.Status != want {
		t.Fatalf("status want %d: %v", want, err)
	}
}
func countVersions(t *testing.T, f *fixture, want int64) {
	t.Helper()
	var n int64
	if err := f.dbService.db.Model(&model.AppVersion{}).Count(&n).Error; err != nil || n != want {
		t.Fatal(n, want, err)
	}
}
func version(t *testing.T, f *fixture, name string) model.AppVersion {
	t.Helper()
	var v model.AppVersion
	if err := f.dbService.db.Where("app_id=? AND version=?", f.app.ID, name).First(&v).Error; err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPaginationStrictTagsAndReadOnlyConnection(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			responsePage(w, []map[string]any{good("v1.2.3"), good("latest"), good("1.2"), good("1.2.3-amd64"), good("1.2.3-rc.1"), good("1.2.3+build"), good("01.2.3"), {"name": "4.0.0"}}, "https://attacker.invalid/steal")
			return
		}
		if r.URL.Query().Get("page") != "2" {
			t.Error("unexpected pagination")
		}
		responsePage(w, []map[string]any{{"name": "2.0.0", "last_updated": "2024-03-02T01:00:00Z"}}, nil)
	})
	test, err := f.dbService.TestConnection(context.Background(), f.app.ID)
	if err != nil || test.TotalTags != 123 || test.AcceptedTags != 1 || test.IgnoredTags != 7 || f.requests.Load() != 1 {
		t.Fatal(test, err, f.requests.Load())
	}
	var states int64
	f.dbService.db.Model(&State{}).Count(&states)
	if states != 1 {
		t.Fatal("connection test created or deleted state")
	}
	var untouched State
	f.dbService.db.Where("app_id=?", f.app.ID).First(&untouched)
	if untouched.LastSyncAt != nil || untouched.Collected != 0 || untouched.LastError != "" || untouched.LastResult != "等待同步" {
		t.Fatal("connection test updated state")
	}
	countVersions(t, f, 0)
	if err := f.dbService.Sync(context.Background(), f.app.ID); err != nil {
		t.Fatal(err)
	}
	countVersions(t, f, 2)
	v := version(t, f, "1.2.3")
	if v.Source != "docker" || v.PublishedAt == nil || v.PublishedAt.Year() != 2025 {
		t.Fatal(v)
	}
	st, _ := f.dbService.Status(context.Background(), f.app.ID)
	if st.Collected != 2 || st.Ignored != 7 || !strings.Contains(st.TagsJSON, "v1.2.3") {
		t.Fatal(st)
	}
	if version(t, f, "2.0.0").PublishedAt.Year() != 2024 {
		t.Fatal("last_updated fallback missing")
	}
}
func TestWithdrawalRestoreFailureLimitAndImmutableTime(t *testing.T) {
	mode := atomic.Int32{}
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 1:
			responsePage(w, []map[string]any{}, nil)
		case 2:
			if r.URL.Query().Get("page") == "1" {
				responsePage(w, []map[string]any{}, "https://irrelevant.invalid/")
			} else {
				http.Error(w, "private response must not leak", 500)
			}
		case 3:
			responsePage(w, []map[string]any{}, "https://irrelevant.invalid/")
		case 4:
			responsePage(w, []map[string]any{{"name": "1.0.0", "tag_last_pushed": "2026-10-01T00:00:00Z"}}, nil)
		default:
			responsePage(w, []map[string]any{good("1.0.0")}, nil)
		}
	})
	ctx := context.Background()
	if err := f.dbService.Sync(ctx, f.app.ID); err != nil {
		t.Fatal(err)
	}
	first := version(t, f, "1.0.0")
	mode.Store(2)
	status(t, f.dbService.Sync(ctx, f.app.ID), 502)
	if version(t, f, "1.0.0").Withdrawn {
		t.Fatal("partial failure retracted")
	}
	st, _ := f.dbService.Status(ctx, f.app.ID)
	if st.LastResult != "同步成功" || st.LastError == "" || strings.Contains(st.LastError, "private response") {
		t.Fatal(st)
	}
	mode.Store(3)
	before := f.requests.Load()
	if err := f.dbService.Sync(ctx, f.app.ID); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load()-before != 10 || version(t, f, "1.0.0").Withdrawn {
		t.Fatal("page cap retracted or overrun")
	}
	mode.Store(1)
	if err := f.dbService.Sync(ctx, f.app.ID); err != nil {
		t.Fatal(err)
	}
	if !version(t, f, "1.0.0").Withdrawn {
		t.Fatal("disappearance not withdrawn")
	}
	mode.Store(4)
	if err := f.dbService.Sync(ctx, f.app.ID); err != nil {
		t.Fatal(err)
	}
	restored := version(t, f, "1.0.0")
	if restored.Withdrawn || !restored.PublishedAt.Equal(*first.PublishedAt) {
		t.Fatal("restore or publication time changed")
	}
}
func httptestURL(t *testing.T, handler http.HandlerFunc) string {
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	return s.URL
}
func Test404RateHeadersBackoffAndNoBodyLeak(t *testing.T) {
	for _, header := range []string{"Retry-After", "X-Retry-After"} {
		for _, absolute := range []bool{false, true} {
			t.Run(fmt.Sprint(header, absolute), func(t *testing.T) {
				var value string
				f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set(header, value)
					http.Error(w, "secret-body", 429)
				})
				value = "120"
				if absolute {
					value = strconv.FormatInt(f.now().Add(120*time.Second).Unix(), 10)
				}
				ctx := context.Background()
				status(t, f.dbService.Sync(ctx, f.app.ID), 429)
				st, _ := f.dbService.Status(ctx, f.app.ID)
				if st.RetryAt == nil || !st.RetryAt.Equal(f.now().Add(120*time.Second)) || strings.Contains(st.LastError, "secret-body") {
					t.Fatal(st)
				}
				calls := f.requests.Load()
				status(t, f.dbService.Sync(ctx, f.app.ID), 429)
				status(t, f.dbService.TestConnectionError(ctx, f.app.ID), 429)
				_ = f.dbService.Tick(ctx)
				if f.requests.Load() != calls {
					t.Fatal("request before retry")
				}
				// Persisted sync limits also survive construction of another service.
				other := New(f.dbService.db, f.dbService.updates, f.now)
				other.api = f.hub.URL
				status(t, other.Sync(ctx, f.app.ID), 429)
				f.add(121 * time.Second)
				status(t, other.Sync(ctx, f.app.ID), 429)
				if f.requests.Load() != calls+1 {
					t.Fatal("retry never happened")
				}
			})
		}
	}
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "token and body", 404) })
	err := f.dbService.Sync(context.Background(), f.app.ID)
	status(t, err, 404)
	if !strings.Contains(err.Error(), "仓库不存在或不是公开仓库") || strings.Contains(err.Error(), "token") {
		t.Fatal(err)
	}
}

// A test-only helper keeps status assertions concise without adding production API.
func (s *Service) TestConnectionError(ctx context.Context, id uint64) error {
	_, err := s.TestConnection(ctx, id)
	return err
}
func TestResetClearConcurrentAndTick(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		responsePage(w, []map[string]any{good("1.0.0")}, nil)
	})
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- f.dbService.Sync(ctx, f.app.ID) }()
	<-entered
	status(t, f.dbService.Sync(ctx, f.app.ID), 409)
	f.dbService.db.Model(&f.app).Update("docker_image", "")
	close(release)
	status(t, <-done, 409)
	countVersions(t, f, 0)
	state, err := f.dbService.Status(ctx, f.app.ID)
	if err != nil || state.Configured {
		t.Fatal(state, err)
	}
	calls := f.requests.Load()
	if err := f.dbService.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != calls {
		t.Fatal("cleared image still polled")
	}
	f.dbService.api = httptestURL(t, func(w http.ResponseWriter, r *http.Request) { responsePage(w, []map[string]any{good("1.0.0")}, nil) })
	f.dbService.db.Model(&f.app).Update("docker_image", "example-org/example-app")
	if err := f.dbService.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	countVersions(t, f, 1)
	state, _ = f.dbService.Status(ctx, f.app.ID)
	if state.LastSyncAt == nil || state.Collected != 1 {
		t.Fatal(state)
	}
	f.dbService.db.Model(&f.app).Update("docker_image", "")
	countVersions(t, f, 1)
	if version(t, f, "1.0.0").Withdrawn {
		t.Fatal("clearing image withdrew versions")
	}
}
func TestRedirectOversizedTimeoutAndImageParsing(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://attacker.invalid/", 302) })
	status(t, f.dbService.Sync(context.Background(), f.app.ID), 502)
	f.dbService.api = httptestURL(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", maxBody+1)) })
	status(t, f.dbService.Sync(context.Background(), f.app.ID), 502)
	f.dbService.api = httptestURL(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
		responsePage(w, []map[string]any{}, nil)
	})
	f.dbService.http.Timeout = 10 * time.Millisecond
	status(t, f.dbService.Sync(context.Background(), f.app.ID), 502)
	for _, raw := range []string{"", "https://hub.docker.com/org/repo", "org/repo:tag", "../repo", "org/../repo", "org/repo?next=bad", "user:password/repo"} {
		if _, err := Image(raw); err == nil {
			t.Fatal("invalid image accepted")
		}
	}
	if v, err := Image("docker.io/org/repo"); err != nil || v != "org/repo" {
		t.Fatal(v, err)
	}
	now := f.now()
	headers := http.Header{"Retry-After": []string{"10"}, "X-Retry-After": []string{strconv.FormatInt(now.Add(time.Minute).Unix(), 10)}}
	if !retryTime(headers, now).Equal(now.Add(time.Minute)) {
		t.Fatal("header precedence")
	}
}

func TestPortalPullUsesOriginalTag(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		responsePage(w, []map[string]any{good("v1.0.0"), good("2.0.0")}, nil)
	})
	ctx := context.Background()
	if err := f.dbService.Sync(ctx, f.app.ID); err != nil {
		t.Fatal(err)
	}
	user := model.EndUser{Name: "user", Status: "active"}
	f.dbService.db.Create(&user)
	lic := model.License{AppID: f.app.ID, UserID: &user.ID, Key: "portal-own", Status: "unused"}
	f.dbService.db.Create(&lic)
	out, err := f.dbService.ForPortal(ctx, lic.ID, "")
	if err != nil || !out.Available || out.DockerPull != "docker pull example-org/example-app:2.0.0" {
		t.Fatal(out, err)
	}
	out, err = f.dbService.ForPortal(ctx, lic.ID, "1.0.0")
	if err != nil || out.Version != "2.0.0" {
		t.Fatal(out, err)
	}
	v := version(t, f, "2.0.0")
	f.dbService.db.Model(&v).Update("disabled", true)
	out, err = f.dbService.ForPortal(ctx, lic.ID, "")
	if err != nil || out.Version != "1.0.0" {
		t.Fatal(out, err)
	}
	// Metadata-only Docker updates never produce an external download link.
	f.dbService.db.Model(&v).Update("disabled", false)
	sdk, err := f.dbService.ForPortal(ctx, lic.ID, "")
	if err != nil || sdk.Version != "2.0.0" {
		t.Fatal(sdk, err)
	}
	for _, state := range []string{"revoked", "suspended"} {
		f.dbService.db.Model(&lic).Update("status", state)
		_, err = f.dbService.ForPortal(ctx, lic.ID, "")
		status(t, err, 403)
	}
	f.dbService.db.Model(&lic).Update("status", "active")
	f.dbService.db.Model(&user).Update("status", "disabled")
	_, err = f.dbService.ForPortal(ctx, lic.ID, "")
	status(t, err, 403)
}

func TestLastPageAtLimitNeverRetractsAndTest429IsReadOnly(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "10" {
			responsePage(w, []map[string]any{}, nil)
		} else {
			responsePage(w, []map[string]any{}, "https://not-followed.invalid/")
		}
	})
	at := f.now()
	v := model.AppVersion{AppID: f.app.ID, Version: "9.0.0", Source: "docker", PublishedAt: &at}
	f.dbService.db.Create(&v)
	if err := f.dbService.Sync(context.Background(), f.app.ID); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != 10 || version(t, f, "9.0.0").Withdrawn {
		t.Fatal("terminal page 10 was treated as authoritative")
	}
	g := newFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "120"); w.WriteHeader(429) })
	status(t, g.dbService.TestConnectionError(context.Background(), g.app.ID), 429)
	var n int64
	g.dbService.db.Model(&State{}).Count(&n)
	if n != 1 {
		t.Fatal("test failure created/deleted state")
	}
	var untouched State
	g.dbService.db.Where("app_id=?", g.app.ID).First(&untouched)
	if untouched.LastSyncAt != nil || untouched.RetryAt != nil || untouched.LastError != "" {
		t.Fatal("test failure updated state")
	}
	status(t, g.dbService.Sync(context.Background(), g.app.ID), 429)
	if g.requests.Load() != 1 {
		t.Fatal("test connection limit not respected by sync")
	}
}
func TestPollIntervalRestartAndImageABA(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { responsePage(w, []map[string]any{good("1.0.0")}, nil) })
	settings, _ := f.dbService.updates.CurrentSettings()
	settings.PollMinutes = 5
	if err := f.dbService.updates.SaveSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	if err := f.dbService.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, _ := f.dbService.Status(context.Background(), f.app.ID)
	if !first.NextSyncAt.Equal(f.now().Add(5 * time.Minute)) {
		t.Fatal("poll minutes ignored")
	}
	restarted := New(f.dbService.db, f.dbService.updates, f.now)
	restarted.api = f.hub.URL
	calls := f.requests.Load()
	_ = restarted.Tick(context.Background())
	if f.requests.Load() != calls {
		t.Fatal("restart ignored due time")
	}
	f.add(5 * time.Minute)
	_ = restarted.Tick(context.Background())
	if f.requests.Load() != calls+1 {
		t.Fatal("restart did not resume")
	}
	f.dbService.db.Model(&f.app).Update("docker_image", "other/repo")
	f.dbService.db.Model(&f.app).Update("docker_image", "docker.io/example-org/example-app")
	latest, _ := f.dbService.Status(context.Background(), f.app.ID)
	if latest.ID == first.ID || latest.Collected != 0 || latest.LastSyncAt != nil || latest.LastError != "" {
		t.Fatal("A-B-A reused old state", latest)
	}
}

func TestMissingTimestampIsIgnoredNotEvidenceOfDeletion(t *testing.T) {
	missing := atomic.Bool{}
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if missing.Load() {
			responsePage(w, []map[string]any{{"name": "1.0.0"}}, nil)
		} else {
			responsePage(w, []map[string]any{good("1.0.0")}, nil)
		}
	})
	if err := f.dbService.Sync(context.Background(), f.app.ID); err != nil {
		t.Fatal(err)
	}
	missing.Store(true)
	if err := f.dbService.Sync(context.Background(), f.app.ID); err != nil {
		t.Fatal(err)
	}
	if version(t, f, "1.0.0").Withdrawn {
		t.Fatal("missing timestamp incorrectly treated as deletion")
	}
	st, _ := f.dbService.Status(context.Background(), f.app.ID)
	if st.Ignored != 1 {
		t.Fatal(st)
	}
}

func TestDatabaseFailureRollsBackAndRecordsSafeError(t *testing.T) {
	second := atomic.Bool{}
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		tags := []map[string]any{good("1.0.0")}
		if second.Load() {
			tags = append(tags, good("2.0.0"))
		}
		responsePage(w, tags, nil)
	})
	ctx := context.Background()
	if err := f.dbService.Sync(ctx, f.app.ID); err != nil {
		t.Fatal(err)
	}
	second.Store(true)
	err := f.dbService.db.Callback().Create().Before("gorm:create").Register("hub_test_failure", func(tx *gorm.DB) {
		if tx.Statement.Table == "app_versions" {
			tx.AddError(errors.New("sensitive database detail"))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.dbService.db.Callback().Create().Remove("hub_test_failure")
	status(t, f.dbService.Sync(ctx, f.app.ID), 502)
	countVersions(t, f, 1)
	if version(t, f, "1.0.0").Withdrawn {
		t.Fatal("failed transaction changed withdrawal")
	}
	st, err := f.dbService.Status(ctx, f.app.ID)
	if err != nil || st.LastResult != "同步成功" || st.LastError != "Docker Hub版本保存失败，请稍后重试" {
		t.Fatal(st, err)
	}
}

// Inspect the outer I/O deadline without waiting for it to expire. Disabling
// http.Client.Timeout here prevents its five-second deadline masking that budget.
type deadlineRoundTripper func(*http.Request) (*http.Response, error)

func (f deadlineRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSyncAndConnectionTimeoutBudgets(t *testing.T) {
	for _, tc := range []struct {
		name       string
		budget     time.Duration
		connection bool
	}{
		{name: "full_sync", budget: 90 * time.Second},
		{name: "test_connection", budget: 15 * time.Second, connection: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				responsePage(w, []map[string]any{good("1.0.0")}, nil)
			})
			if f.dbService.http.Timeout != 5*time.Second {
				t.Fatalf("per-request timeout = %v, want 5s", f.dbService.http.Timeout)
			}
			f.dbService.http.Timeout = 0
			observed := false
			f.dbService.http.Transport = deadlineRoundTripper(func(r *http.Request) (*http.Response, error) {
				observed = true
				deadline, ok := r.Context().Deadline()
				if !ok {
					t.Fatal("Hub read has no deadline")
				}
				if remaining := time.Until(deadline); remaining < tc.budget-time.Second || remaining > tc.budget {
					t.Fatalf("Hub read budget = %v, want approximately %v", remaining, tc.budget)
				}
				return http.DefaultTransport.RoundTrip(r)
			})
			var err error
			if tc.connection {
				_, err = f.dbService.TestConnection(context.Background(), f.app.ID)
			} else {
				err = f.dbService.Sync(context.Background(), f.app.ID)
			}
			if err != nil || !observed {
				t.Fatalf("request observed = %v, error = %v", observed, err)
			}
		})
	}
}

func TestManualVersionsAreNotOverwritten(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { responsePage(w, []map[string]any{good("2.0.0")}, nil) })
	at := f.now().Add(-time.Hour)
	manual := model.AppVersion{AppID: f.app.ID, Version: "2.0.0", Source: "manual", Changelog: "manual notes", PublishedAt: &at, Disabled: true, Mandatory: true}
	if e := f.dbService.db.Create(&manual).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.dbService.Sync(context.Background(), f.app.ID); e != nil {
		t.Fatal(e)
	}
	got := version(t, f, "2.0.0")
	if got.Source != "manual" || got.Changelog != manual.Changelog || !got.Disabled || !got.Mandatory || !got.PublishedAt.Equal(at) {
		t.Fatal(got)
	}
}
