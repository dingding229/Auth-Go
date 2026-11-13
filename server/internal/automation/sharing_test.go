package automation

import (
	"context"
	"testing"
	"time"
)

func TestSharingHookRunsOnStartupAndStopsWithAutomation(t *testing.T) {
	f := setup(t)
	called := make(chan struct{}, 1)
	f.s.SetSharing(func(ctx context.Context) error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.s.Start(ctx)
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("sharing did not run at startup")
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if e := f.s.Close(shutdown); e != nil {
		t.Fatal(e)
	}
}
