package dockerhub

import (
	"authgo/internal/model"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAnonymousPaginationPreservesPartialSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name          string
		forbiddenPage int
		wantPages     int64
		wantVersions  int
		wantResult    string
	}{
		{
			name:          "page_10_has_next_page_11_would_be_forbidden",
			forbiddenPage: 11,
			wantPages:     10,
			wantVersions:  1000,
			wantResult:    "标签超过1000个，只收录最新的1000个，未撤回旧版本",
		},
		{
			name:          "page_2_forbidden",
			forbiddenPage: 2,
			wantPages:     2,
			wantVersions:  100,
			wantResult:    "Docker Hub限制了后续分页，只收录已读取的标签，未撤回旧版本",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				page, err := strconv.Atoi(r.URL.Query().Get("page"))
				if err != nil || page < 1 {
					t.Error("invalid page")
				}
				if page >= tc.forbiddenPage {
					http.Error(w, `{"message":"pagination offset too large for anonymous requests; sign in to page further"}`, http.StatusForbidden)
					return
				}
				tags := make([]map[string]any, 100)
				for i := range tags {
					tags[i] = good(fmt.Sprintf("1.%d.%d", page, i))
				}
				responsePage(w, tags, "https://not-followed.invalid/next")
			})
			at := f.now().Add(-time.Hour)
			old := model.AppVersion{AppID: f.app.ID, Version: "9.0.0", Source: "docker", PublishedAt: &at}
			if err := f.dbService.db.Create(&old).Error; err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := f.dbService.Sync(ctx, f.app.ID); err != nil {
				t.Fatal(err)
			}
			if f.requests.Load() != tc.wantPages {
				t.Fatalf("requests = %d, want %d (must not request page 11)", f.requests.Load(), tc.wantPages)
			}
			countVersions(t, f, int64(tc.wantVersions+1))
			if version(t, f, "9.0.0").Withdrawn {
				t.Fatal("partial snapshot withdrew an unseen old version")
			}
			for _, name := range []string{"1.1.0", fmt.Sprintf("1.%d.99", tc.wantVersions/100)} {
				if version(t, f, name).Withdrawn {
					t.Fatalf("read version %s is withdrawn", name)
				}
			}
			st, err := f.dbService.Status(ctx, f.app.ID)
			if err != nil || st.LastSyncAt == nil || st.LastResult != tc.wantResult || st.LastError != "" || st.Collected != tc.wantVersions || st.RetryAt != nil {
				t.Fatalf("partial success status = %+v, error = %v", st, err)
			}
		})
	}
}

func TestFirstPageForbiddenRemainsFailure(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "private-body-must-not-leak", http.StatusForbidden)
	})
	at := f.now()
	old := model.AppVersion{AppID: f.app.ID, Version: "9.0.0", Source: "docker", PublishedAt: &at}
	if err := f.dbService.db.Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, call := range []func() error{
		func() error { return f.dbService.Sync(ctx, f.app.ID) },
		func() error { return f.dbService.TestConnectionError(ctx, f.app.ID) },
	} {
		err := call()
		status(t, err, http.StatusBadGateway)
		if !strings.Contains(err.Error(), "Docker Hub拒绝访问，请确认仓库是公开仓库") || strings.Contains(err.Error(), "private-body") {
			t.Fatalf("unsafe or incorrect access-denied error: %v", err)
		}
	}
	countVersions(t, f, 1)
	if version(t, f, "9.0.0").Withdrawn {
		t.Fatal("first-page failure withdrew old version")
	}
	st, err := f.dbService.Status(ctx, f.app.ID)
	if err != nil || st.LastError != "Docker Hub拒绝访问，请确认仓库是公开仓库" {
		t.Fatalf("failure status = %+v, error = %v", st, err)
	}
}

func TestRateLimitResetChoosesLatestAndBlocksRequests(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		retry, xretry, reset, want int64
	}{
		{name: "reset_only", reset: 180, want: 180},
		{name: "reset_latest", retry: 10, xretry: 120, reset: 180, want: 180},
		{name: "retry_latest", retry: 240, xretry: 120, reset: 180, want: 240},
		{name: "xretry_latest", retry: 10, xretry: 300, reset: 180, want: 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var now time.Time
			f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.retry > 0 {
					w.Header().Set("Retry-After", strconv.FormatInt(tc.retry, 10))
				}
				if tc.xretry > 0 {
					w.Header().Set("X-Retry-After", strconv.FormatInt(now.Add(time.Duration(tc.xretry)*time.Second).Unix(), 10))
				}
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(now.Add(time.Duration(tc.reset)*time.Second).Unix(), 10))
				w.WriteHeader(http.StatusTooManyRequests)
			})
			now = f.now()
			ctx := context.Background()
			status(t, f.dbService.Sync(ctx, f.app.ID), 429)
			st, err := f.dbService.Status(ctx, f.app.ID)
			if err != nil || st.RetryAt == nil || !st.RetryAt.Equal(now.Add(time.Duration(tc.want)*time.Second)) {
				t.Fatalf("retry status = %+v, error = %v", st, err)
			}
			f.add(time.Duration(tc.want-1) * time.Second)
			status(t, f.dbService.Sync(ctx, f.app.ID), 429)
			status(t, f.dbService.TestConnectionError(ctx, f.app.ID), 429)
			if f.requests.Load() != 1 {
				t.Fatal("Hub requested before latest retry deadline")
			}
			f.add(time.Second)
			status(t, f.dbService.Sync(ctx, f.app.ID), 429)
			if f.requests.Load() != 2 {
				t.Fatal("Hub not retried after deadline")
			}
		})
	}
}

func TestRateLimitResetIsUnixSeconds(t *testing.T) {
	now := time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)
	for _, raw := range []string{"120", "invalid", strconv.FormatInt(now.Add(-time.Minute).Unix(), 10)} {
		h := http.Header{}
		h.Set("X-RateLimit-Reset", raw)
		if got := retryTime(h, now); !got.Equal(now.Add(time.Minute)) {
			t.Fatalf("invalid/past reset %q produced %v", raw, got)
		}
	}
}
