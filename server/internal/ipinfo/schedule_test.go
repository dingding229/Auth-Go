package ipinfo

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPersistedScheduleDBIPAtomicFailureAndRetry(t *testing.T) {
	dir := t.TempDir()
	s, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Date(2026, 11, 15, 2, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	upload(t, s, "city", "city-other")
	upload(t, s, "asn", "asn")
	var calls atomic.Int32
	var fail atomic.Bool
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() && r.URL.Path == "/asn" {
			w.WriteHeader(500)
			return
		}
		kind := strings.TrimPrefix(r.URL.Path, "/")
		_, _ = w.Write(compressed(fixture(t, kind)))
	}))
	defer source.Close()
	s.download = func(ctx context.Context, kind string, month time.Time) (*prepared, error) {
		client := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
			copy := req.Clone(req.Context())
			copy.URL, _ = url.Parse(source.URL + "/" + kind)
			return source.Client().Transport.RoundTrip(copy)
		})}
		return s.fetch(ctx, client, downloadURL(kind, month), kind)
	}
	plan := SyncPlan{Enabled: true, Cron: "0 3 * * *"}
	if e = s.SaveSchedule(context.Background(), plan); e != nil {
		t.Fatal(e)
	}
	due := *s.Status().Schedule.NextRunAt
	if due.Hour() != 3 || s.autoDue() {
		t.Fatal("wrong next UTC time", due)
	}
	now = due
	s.tick(context.Background())
	got := s.Status()
	if calls.Load() != 2 || got.City.Source != "db-ip" || got.Schedule.LastResult != "成功" || !got.Schedule.NextRunAt.After(now) {
		t.Fatal(got, calls.Load())
	}
	s.tick(context.Background())
	if calls.Load() != 2 {
		t.Fatal("duplicate due run")
	}
	old := s.snapshot()
	now = *got.Schedule.NextRunAt
	fail.Store(true)
	s.tick(context.Background())
	got = s.Status()
	if got.Schedule.LastResult != "失败" || got.Schedule.Failures != 1 || !got.Schedule.NextRunAt.Equal(now.Add(5*time.Minute)) || s.snapshot().City.File != old.City.File || s.snapshot().ASN.File != old.ASN.File {
		t.Fatal("failed pair replaced original", got)
	}
	s.tick(context.Background())
	if calls.Load() != 4 {
		t.Fatal("retry ignored backoff")
	}
	restarted, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	restarted.now = func() time.Time { return now }
	if restarted.Status().Schedule.NextRunAt == nil || !restarted.Status().Schedule.NextRunAt.Equal(got.Schedule.NextRunAt.UTC()) || restarted.autoDue() {
		t.Fatal("restart lost persisted retry")
	}
	now = *got.Schedule.NextRunAt
	fail.Store(false)
	s.tick(context.Background())
	if s.Status().Schedule.Failures != 0 || s.Status().Schedule.LastResult != "成功" {
		t.Fatal(s.Status())
	}
}
func TestScheduleBoundariesValidationAndNoDuplicateInFlight(t *testing.T) {
	for _, expression := range []string{"0 3 * * *", "0 3 * * 1", "0 3 1 * *"} {
		now := time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC)
		at := nextScheduled(now, SyncPlan{Cron: expression})
		if !at.After(now) || at.Hour() != 3 || expression == "0 3 * * 1" && at.Weekday() != time.Monday || expression == "0 3 1 * *" && at.Day() != 1 {
			t.Fatal(expression, at)
		}
	}
	for _, expression := range []string{"", "@monthly", "@every 1h", "0 0 3 * * *", "CRON_TZ=UTC 0 3 * * *", "0 24 * * *", "0 3 30 2 *", "*/30 * * * *", "0,59 3 * * *", "59,0 3 * * *"} {
		if validatePlan(SyncPlan{Cron: expression}) == nil {
			t.Fatalf("invalid plan accepted: %s", expression)
		}
	}
	for _, expression := range []string{"0 * * * *", "0 3 * * *", "0 3 * * 1", "0 3 1 * *", "0 3 29 2 *"} {
		if err := validatePlan(SyncPlan{Cron: expression}); err != nil {
			t.Fatal(expression, err)
		}
	}

	s := testService(t)
	now := time.Date(2026, 11, 15, 2, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if e := s.SaveSchedule(context.Background(), SyncPlan{Enabled: true, Cron: "0 3 * * *"}); e != nil {
		t.Fatal(e)
	}
	now = *s.Status().Schedule.NextRunAt
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s.download = func(ctx context.Context, kind string, _ time.Time) (*prepared, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return s.prepare(ctx, kind, "db-ip", bytes.NewReader(fixture(t, kind)))
	}
	done := make(chan struct{})
	go func() { s.tick(context.Background()); close(done) }()
	<-entered
	s.tick(context.Background())
	if calls.Load() != 1 {
		t.Fatal("overlapping schedule")
	}
	close(release)
	<-done
	if calls.Load() != 2 {
		t.Fatal("one pair was not downloaded")
	}
}

func TestScheduledSyncReplacesUploadedDatabases(t *testing.T) {
	s := testService(t)
	upload(t, s, "city", "city-other")
	upload(t, s, "asn", "asn")
	old := s.snapshot()
	if err := s.SaveSchedule(context.Background(), SyncPlan{Enabled: true, Cron: "0 3 * * *"}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	s.download = func(ctx context.Context, kind string, _ time.Time) (*prepared, error) {
		calls.Add(1)
		return s.prepare(ctx, kind, "db-ip", bytes.NewReader(fixture(t, kind)))
	}
	if err := s.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := s.snapshot()
	if calls.Load() != 2 || got.City.File == old.City.File || got.City.Source != "db-ip" || got.ASN.Source != "db-ip" {
		t.Fatal("scheduled upload replacement failed", calls.Load(), got)
	}
}

func TestInvalidPersistedPlanFallsBackToDefault(t *testing.T) {
	for _, plan := range []string{
		`{"enabled":true,"frequency":"daily","hour":5,"next_run_at":"2026-01-01T00:00:00Z"}`,
		`{"enabled":true,"cron":"@hourly"}`,
		`{"enabled":true,"cron":"*/5 * * * *"}`,
	} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "ipdb"), 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "ipdb", "state.json")
		raw := []byte(`{"schedule":` + plan + `}`)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		s, err := New(dir)
		if err != nil {
			t.Fatal(err)
		}
		status := s.Status()
		_ = s.Close()
		if status.Schedule.Enabled || status.Schedule.Cron != "0 3 1 * *" || status.Schedule.NextRunAt != nil {
			t.Fatal("invalid state did not reset plan", status)
		}
		retained, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, retained) {
			t.Fatal("fallback rewrote persisted files", err)
		}
	}
}
