package bootstrap

import (
	"authgo/internal/db"
	"authgo/internal/model"
	"context"
	"errors"
	"gorm.io/gorm"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSetupTokenAndConcurrency(t *testing.T) {
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	s, token, e := NewSetup(d)
	if e != nil || token == "" {
		t.Fatal(e)
	}
	ctx := context.Background()
	for _, bad := range []string{"", "wrong"} {
		if e = s.Complete(ctx, bad, "owner", "password123", "ip", nil); e == nil {
			t.Fatal("accepted bad token")
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.Complete(ctx, token, "owner", "password123", "other", nil) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("success=%d", success)
	}
	var n int64
	d.Model(&model.Admin{}).Count(&n)
	if n != 1 {
		t.Fatal(n)
	}
	if e = s.Complete(ctx, token, "again", "password123", "third", nil); e == nil {
		t.Fatal("reused token")
	}
	if ok, _ := s.Available(ctx); ok {
		t.Fatal("still available")
	}
	_, token, e = NewSetup(d)
	if e != nil || token != "" {
		t.Fatal("regenerated token", e)
	}
}

func TestSetupRateAndRollback(t *testing.T) {
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := d.DB()
	defer p.Close()
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	s, token, e := NewSetup(d)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	for range 5 {
		if e = s.Complete(ctx, "bad", "owner", "password123", "abuse", nil); e == nil {
			t.Fatal("accepted")
		}
	}
	if e = s.Complete(ctx, token, "owner", "password123", "abuse", nil); e == nil || !strings.Contains(e.Error(), "频繁") {
		t.Fatal(e)
	}
	sentinel := errors.New("session failed")
	e = s.Complete(ctx, token, "owner", "password123", "good", func(*gorm.DB, model.Admin) error { return sentinel })
	if !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	if ok, _ := s.Initialized(ctx); ok {
		t.Fatal("account survived failed session")
	}
	if e = s.Complete(ctx, token, "owner", "password123", "good", nil); e != nil {
		t.Fatal(e)
	}
}
