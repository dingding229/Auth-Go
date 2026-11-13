package auth

import (
	"authgo/internal/apperror"
	"authgo/internal/bootstrap"
	"authgo/internal/db"
	"authgo/internal/model"
	"context"
	"errors"
	"gorm.io/gorm"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu    sync.Mutex
	value time.Time
}

func (c *testClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.value }
func (c *testClock) add(d time.Duration) { c.mu.Lock(); c.value = c.value.Add(d); c.mu.Unlock() }

type fixture struct {
	s        *Service
	database *gorm.DB
	clock    *testClock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	database, err := db.Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := database.DB()
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.EnsureAdmin(database, "owner", "initial-password"); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{value: time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)}
	s, err := NewServiceWithClock(database, make([]byte, 32), clock.now)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{s, database, clock}
}
func (f *fixture) login(t *testing.T) *TokenPair {
	t.Helper()
	pair, err := f.s.Login(context.Background(), "owner", "initial-password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	var safe *apperror.Error
	if !errors.As(err, &safe) || safe.Status != status {
		t.Fatalf("error=%v, expected status %d", err, status)
	}
}

func TestSessionsRefreshAndLogout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	pair := f.login(t)
	if pair.ExpiresIn != 900 || pair.RefreshExpiresIn != 604800 {
		t.Fatalf("wrong TTL: %+v", pair)
	}
	p, err := f.s.Authenticate(ctx, pair.AccessToken)
	if err != nil || p.Username != "owner" {
		t.Fatal("authenticate", err)
	}
	if _, err := f.s.Authenticate(ctx, pair.RefreshToken); err == nil {
		t.Fatal("refresh accepted as access")
	}
	var row model.AdminSession
	if err := f.database.First(&row, "id = ?", pair.SessionID).Error; err != nil {
		t.Fatal(err)
	}
	if row.TokenHash == pair.RefreshToken || len(row.TokenHash) != 64 {
		t.Fatal("plaintext refresh stored")
	}
	f.clock.add(15 * time.Minute)
	_, err = f.s.Authenticate(ctx, pair.AccessToken)
	wantStatus(t, err, 401)
	rotated, err := f.s.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RefreshToken == pair.RefreshToken || rotated.RefreshExpiresIn != int64((RefreshTTL-15*time.Minute)/time.Second) {
		t.Fatal("rotation or absolute expiry failed")
	}
	_, err = f.s.Refresh(ctx, pair.RefreshToken)
	wantStatus(t, err, 401)
	p, err = f.s.Authenticate(ctx, rotated.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.Logout(ctx, p); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Authenticate(ctx, rotated.AccessToken)
	wantStatus(t, err, 401)
	_, err = f.s.Refresh(ctx, rotated.RefreshToken)
	wantStatus(t, err, 401)
}

func TestConcurrentRefreshOnlyOneSucceeds(t *testing.T) {
	f := newFixture(t)
	pair := f.login(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Go(func() { _, err := f.s.Refresh(ctx, pair.RefreshToken); results <- err })
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			wantStatus(t, err, 401)
		}
	}
	if success != 1 {
		t.Fatalf("refresh winners %d", success)
	}
}

func TestLoginLockout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		_, err := f.s.Login(ctx, "owner", "wrong-password", "1.2.3.4")
		status := 401
		if i == 5 {
			status = 429
		}
		wantStatus(t, err, status)
	}
	_, err := f.s.Login(ctx, "owner", "initial-password", "1.2.3.4")
	wantStatus(t, err, 429)
	if _, err := f.s.Login(ctx, "owner", "initial-password", "1.2.3.5"); err != nil {
		t.Fatal("other IP locked", err)
	}
	_, err = f.s.Login(ctx, "missing", "wrong-password", "1.2.3.4")
	wantStatus(t, err, 401)
	f.clock.add(15 * time.Minute)
	if _, err := f.s.Login(ctx, "owner", "initial-password", "1.2.3.4"); err != nil {
		t.Fatal("lock not expired", err)
	}
	for i := 0; i < 4; i++ {
		_, err := f.s.Login(ctx, "owner", "wrong-password", "1.2.3.4")
		wantStatus(t, err, 401)
	}
}

func TestPasswordRevokesAllCredentials(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	pair := f.login(t)
	other := f.login(t)
	p := pair.Principal()
	wantStatus(t, f.s.ChangePassword(ctx, p, "wrong", "replacement-password"), 401)
	if err := f.s.ChangePassword(ctx, p, "initial-password", "replacement-password"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{pair.AccessToken, other.AccessToken} {
		_, err := f.s.Authenticate(ctx, raw)
		wantStatus(t, err, 401)
	}
	_, err := f.s.Refresh(ctx, other.RefreshToken)
	wantStatus(t, err, 401)
	if _, err := f.s.Login(ctx, "owner", "replacement-password", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshAbsoluteExpiryAndPasswordReset(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	pair := f.login(t)

	if err := f.s.ChangePassword(ctx, pair.Principal(), "initial-password", "changed-password"); err != nil {
		t.Fatal(err)
	}
	var admin model.Admin
	if err := f.database.First(&admin, pair.Admin.ID).Error; err != nil {
		t.Fatal(err)
	}

	pair, err := f.s.Login(ctx, "owner", "changed-password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	f.clock.add(RefreshTTL)
	_, err = f.s.Refresh(ctx, pair.RefreshToken)
	wantStatus(t, err, 401)
}
