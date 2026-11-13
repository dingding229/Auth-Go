package dockerhub

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackgroundSyncSurvivesRequestAndQueriesMultiPageResult(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var page atomic.Int32
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		n := page.Add(1)
		if n == 1 {
			close(entered)
			<-release
		}
		if n == 1 {
			responsePage(w, []map[string]any{good("1.0.0")}, "?page=2")
		} else {
			responsePage(w, []map[string]any{good("2.0.0")}, nil)
		}
	})
	releaseHub := sync.OnceFunc(func() { close(release) })
	defer releaseHub()
	ctx, cancel := context.WithCancel(context.Background())
	st, err := f.dbService.StartSync(ctx, f.app.ID)
	cancel()
	if err != nil || !st.Running {
		t.Fatalf("start: %+v %v", st, err)
	}
	<-entered
	st, err = f.dbService.Status(context.Background(), f.app.ID)
	if err != nil || !st.Running {
		t.Fatal(st, err)
	}
	_, err = f.dbService.StartSync(context.Background(), f.app.ID)
	status(t, err, 409)
	releaseHub()
	waitBackground(t, f)
	st, err = f.dbService.Status(context.Background(), f.app.ID)
	if err != nil || st.Running || st.Collected != 2 || st.LastError != "" || st.LastResult != "同步成功" {
		t.Fatal(st, err)
	}
	countVersions(t, f, 2)
}
func waitBackground(t *testing.T, f *fixture) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		st, err := f.dbService.Status(context.Background(), f.app.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !st.Running {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("background task did not finish")
		case <-tick.C:
		}
	}
}
func TestBackgroundSyncFailureIsQueryable(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	if _, err := f.dbService.StartSync(context.Background(), f.app.ID); err != nil {
		t.Fatal(err)
	}
	waitBackground(t, f)
	st, err := f.dbService.Status(context.Background(), f.app.ID)
	if err != nil || st.LastError == "" || st.NextSyncAt.IsZero() {
		t.Fatal(st, err)
	}
}
