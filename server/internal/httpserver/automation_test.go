package httpserver

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"authgo/internal/auth"
	"authgo/internal/automation"
	"authgo/internal/client"
	"authgo/internal/config"
	"authgo/internal/mailer"

	"github.com/gin-gonic/gin"
)

func automationFixture(t *testing.T) (*clientFixture, *automation.Service) {
	t.Helper()
	f := newClientFixture(t, client.Options{}, nil)
	var files []struct {
		Name string
		File string
	}
	if e := f.db.Raw("PRAGMA database_list").Scan(&files).Error; e != nil {
		t.Fatal(e)
	}
	dir := ""
	for _, file := range files {
		if file.Name == "main" {
			dir = filepath.Dir(file.File)
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, e := automation.New(f.db, make([]byte, 32), log, automation.Options{Now: f.clock.now, DataDir: dir})
	if e != nil {
		t.Fatal(e)
	}
	s.SetApply(func(v automation.Settings) {
		f.service.ConfigureRateLimits(v.IPQueryRate, v.IPBurst, v.LicenseRate, v.LicenseBurst)
	})
	identity, e := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := f.db.DB()
	f.r, e = NewRouter(config.Config{}, log, pool.PingContext, WithAdmin(identity, f.db), WithCatalog(f.catalog), WithLicensing(f.licensing), WithClient(f.service), WithAutomation(s))
	if e != nil {
		t.Fatal(e)
	}
	return f, s
}

func TestAutomationSMTPTestHTTP(t *testing.T) {
	f := newAdminFixture(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sent := 0
	s, e := automation.New(f.db, make([]byte, 32), log, automation.Options{Now: f.clock.now, SendMail: func(ctx context.Context, c mailer.Config, m mailer.Message) error {
		sent++
		if c.Password != "password-secret" || m.To != "user@example.com" {
			t.Fatal(c, m)
		}
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	a, _ := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	pool, _ := f.db.DB()
	f.r, e = NewRouter(config.Config{}, log, pool.PingContext, WithAdmin(a, f.db), WithAutomation(s))
	if e != nil {
		t.Fatal(e)
	}
	token := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	f.request(t, "PATCH", "/system/settings", token, gin.H{"smtp": gin.H{"enabled": true, "host": "smtp.example.com", "from": "sender@example.com", "password": "password-secret"}}, 200)
	f.request(t, "POST", "/system/smtp/test", token, gin.H{"to": "user@example.com"}, 200)
	f.request(t, "POST", "/system/smtp/test", token, gin.H{"to": "bad\r\naddress"}, 400)
	if sent != 1 {
		t.Fatal(sent)
	}
}
