package automation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"authgo/internal/config"
	"authgo/internal/db"
	"authgo/internal/mailer"
	"authgo/internal/model"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *fakeClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *fakeClock) add(d time.Duration) { c.mu.Lock(); c.at = c.at.Add(d); c.mu.Unlock() }

type fixture struct {
	db    *gorm.DB
	s     *Service
	clock *fakeClock
	dir   string
	app   model.Application
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	database, e := db.Open(dir, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := database.DB()
	t.Cleanup(func() { _ = pool.Close() })
	if e := db.Migrate(database); e != nil {
		t.Fatal(e)
	}
	cl := &fakeClock{at: time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)}
	s, e := New(database, make([]byte, 32), slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Now: cl.now, DataDir: dir})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if e := s.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	app := model.Application{Name: "通知测试", AppKey: "app_test", AppSecretEncrypted: "cipher", PrivateKeyEncrypted: "cipher", PublicKey: "public"}
	if e := database.Create(&app).Error; e != nil {
		t.Fatal(e)
	}
	return &fixture{database, s, cl, dir, app}
}
func ptr[T any](v T) *T { return &v }

func TestSchedulerExpiryWindowsDedupeCleanupLeaseAndMail(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	settings := SettingsInput{SMTP: &SMTPInput{Enabled: ptr(true), Host: ptr("smtp.example.com"), From: ptr("sender@example.com"), Password: ptr("smtp-secret")}}
	if _, e := f.s.UpdateSettings(ctx, settings); e != nil {
		t.Fatal(e)
	}
	var sent atomic.Int64
	f.s.sendMail = func(ctx context.Context, c mailer.Config, m mailer.Message) error {
		if c.Password != "smtp-secret" || !strings.Contains(m.Subject, "授权到期提醒") {
			t.Error("bad SMTP/message")
		}
		sent.Add(1)
		return nil
	}
	end := f.clock.now().Add(7 * 24 * time.Hour)
	u := model.EndUser{Name: "用户", Email: "contact@example.com"}
	f.db.Create(&u)
	l := model.License{UserID: &u.ID, AppID: f.app.ID, Key: "AUTH-SECRET-LICENSE", Status: "active", ExpiresAt: &end}
	f.db.Create(&l)
	expiredLease := f.clock.now().Add(-time.Second)
	activation := model.Activation{LicenseID: l.ID, Kind: "floating", Value: "seat", Status: "active", Token: "generation", LeaseExpiresAt: &expiredLease}
	f.db.Create(&activation)
	old := f.clock.now().AddDate(0, 0, -91)
	f.db.Create(&model.VerifyLog{CreatedAt: old, Code: "OK"})
	f.db.Create(&model.VerifyLog{CreatedAt: f.clock.now(), Code: "OK"})
	for _, advance := range []time.Duration{0, 0, 4 * 24 * time.Hour, 2 * 24 * time.Hour, 24 * time.Hour} {
		f.clock.add(advance)
		if e := f.s.Tick(ctx); e != nil {
			t.Fatal(e)
		}
	}
	var updated model.License
	f.db.First(&updated, l.ID)
	if updated.Status != "expired" {
		t.Fatal(updated.Status)
	}
	var count int64
	f.db.Model(&model.MailDelivery{}).Count(&count)
	if count != 3 {
		t.Fatal("mail windows", count)
	}
	f.db.Model(&model.VerifyLog{}).Count(&count)
	if count != 1 {
		t.Fatal("retention", count)
	}
	var reclaimed model.Activation
	f.db.First(&reclaimed, activation.ID)
	if reclaimed.LeaseExpiresAt != nil || reclaimed.Token != "generation" || reclaimed.OfflineAt != nil {
		t.Fatal(reclaimed)
	}
	if e := f.s.processMail(ctx); e != nil {
		t.Fatal(e)
	}
	if sent.Load() != 3 {
		t.Fatal(sent.Load())
	}
}
func TestBackupRestorationRetentionAndPathSafety(t *testing.T) {
	f := setup(t)
	for range 9 {
		if _, e := f.s.Backup(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	rows, e := f.s.ListBackups()
	if e != nil || len(rows) != 7 {
		t.Fatal(len(rows), e)
	}
	path := filepath.Join(f.dir, "backups", rows[0].Name)
	readOnly, e := gorm.Open(sqlite.Open("file:"+filepath.ToSlash(path)+"?mode=ro"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := readOnly.DB()
	defer pool.Close()
	var app model.Application
	if e := readOnly.First(&app, f.app.ID).Error; e != nil || app.AppKey != f.app.AppKey {
		t.Fatal(app, e)
	}
	var integrity string
	readOnly.Raw("PRAGMA integrity_check").Scan(&integrity)
	if integrity != "ok" {
		t.Fatal(integrity)
	}
	if _, e := f.s.OpenBackup("../authgo.db"); e == nil {
		t.Fatal("traversal accepted")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm()&0077 != 0 {
		t.Fatal("unsafe backup permissions")
	}
}
func TestSettingsRedactionPersistenceAndProxyChain(t *testing.T) {
	f := setup(t)
	value, e := f.s.UpdateSettings(context.Background(), SettingsInput{SiteName: ptr("中文站点"), TrustedProxies: ptr([]string{"127.0.0.1", "10.0.0.0/8"}), IPRate: ptr(1), SMTP: &SMTPInput{Password: ptr("never-log-me")}})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(value)
	if strings.Contains(string(raw), "never-log-me") || strings.Contains(string(raw), "v1:") || !value.SMTP.HasPassword {
		t.Fatal(string(raw))
	}
	var setting model.Setting
	f.db.First(&setting, "key=?", "system.v1")
	if strings.Contains(setting.Value, "never-log-me") {
		t.Fatal("plaintext SMTP password")
	}
	next, e := New(f.db, make([]byte, 32), nil, Options{Now: f.clock.now})
	if e != nil || next.Current().SiteName != "中文站点" {
		t.Fatal(e)
	}
	if ip := next.ResolveIP("127.0.0.1:1", "203.0.113.7, 10.0.0.2", ""); ip != "203.0.113.7" {
		t.Fatal(ip)
	}
	if ip := next.ResolveIP("198.51.100.7:1", "203.0.113.7", ""); ip != "198.51.100.7" {
		t.Fatal(ip)
	}
	if _, e := f.s.UpdateSettings(context.Background(), SettingsInput{TrustedProxies: ptr([]string{"invalid"})}); e == nil {
		t.Fatal("invalid proxy accepted")
	}
}

func TestMailRetryAndPortalCodeSettings(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	_, e := f.s.UpdateSettings(ctx, SettingsInput{SMTP: &SMTPInput{Enabled: ptr(true), Host: ptr("smtp.example.com"), From: ptr("from@example.com"), Password: ptr("preserve-password")}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.s.UpdateSettings(ctx, SettingsInput{SiteName: ptr("改名")})
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := f.s.smtpConfig()
	if e != nil || cfg.Password != "preserve-password" {
		t.Fatal(cfg, e)
	}
	calls := 0
	f.s.sendMail = func(ctx context.Context, c mailer.Config, m mailer.Message) error {
		calls++
		return fmt.Errorf("private SMTP failure")
	}
	row := model.MailDelivery{Recipient: "to@example.com", Subject: "提醒", Body: "内容", Status: "pending"}
	if e := f.db.Create(&row).Error; e != nil {
		t.Fatal(e)
	}
	for attempt := 1; attempt <= 6; attempt++ {
		if e := f.s.ProcessDue(ctx); e != nil {
			t.Fatal(e)
		}
		f.db.First(&row, row.ID)
		if row.Attempts != attempt || strings.Contains(row.LastError, "private") {
			t.Fatal(row)
		}
		if attempt < 6 {
			if row.Status != "retrying" || row.NextRetryAt == nil || !row.NextRetryAt.Equal(f.clock.now().Add(mailBackoff(attempt))) {
				t.Fatal(row)
			}
			f.clock.add(mailBackoff(attempt))
		}
	}
	if calls != 6 || row.Status != "failed" {
		t.Fatal(row, calls)
	}
	f.s.sendMail = func(ctx context.Context, c mailer.Config, m mailer.Message) error {
		if !strings.Contains(m.Body, "123456") {
			t.Fatal(m)
		}
		return nil
	}
	if e := f.s.SendPortalCode(ctx, "to@example.com", "123456", f.clock.now().Add(10*time.Minute)); e != nil {
		t.Fatal(e)
	}
	var n int64
	f.db.Model(&model.MailDelivery{}).Count(&n)
	if n != 1 {
		t.Fatal("portal codes must not persist in mail queue")
	}
	_, e = f.s.UpdateSettings(ctx, SettingsInput{SMTP: &SMTPInput{Password: ptr("")}})
	if e != nil || f.s.PublicSettings().SMTP.HasPassword {
		t.Fatal(e)
	}
}

func TestRuntimeSettingsConcurrentSnapshots(t *testing.T) {
	f := setup(t)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 25 {
			if _, e := f.s.UpdateSettings(context.Background(), SettingsInput{TrustedProxies: ptr([]string{"::ffff:127.0.0.1/128"}), IPRate: ptr(2)}); e != nil {
				t.Error(e)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 500 {
			f.s.ResolveIP("127.0.0.1:123", "203.0.113.1", "")
			v := f.s.Current()
			v.TrustedProxies = append(v.TrustedProxies, "bad")
			f.s.PublicSettings()
		}
	}()
	wg.Wait()
	if f.s.ResolveIP("127.0.0.1:123", "203.0.113.1", "") != "203.0.113.1" {
		t.Fatal("mapped prefix mismatch")
	}
}

func TestSchedulerClockDailyBackup(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for range 2 {
		if e := f.s.Tick(ctx); e != nil {
			t.Fatal(e)
		}
	}
	files, e := f.s.ListBackups()
	if e != nil || len(files) != 1 {
		t.Fatal(files, e)
	}
	f.clock.add(24 * time.Hour)
	if e := f.s.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	files, e = f.s.ListBackups()
	if e != nil || len(files) != 2 {
		t.Fatal(files, e)
	}
	var day model.Setting
	if e := f.db.First(&day, "key=?", "jobs.backup_day").Error; e != nil || day.Value != f.clock.now().UTC().Format("2006-01-02") {
		t.Fatal(day, e)
	}
}

func TestExpiryContactEmailAndAdminRecipients(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	recipients := []string{"ADMIN@EXAMPLE.COM", "contact@example.com"}
	_, err := f.s.UpdateSettings(ctx, SettingsInput{AdminNotificationEmails: &recipients, SMTP: &SMTPInput{Enabled: ptr(true), Host: ptr("smtp.example.com"), From: ptr("sender@example.com")}})
	if err != nil {
		t.Fatal(err)
	}
	expiry := f.clock.now().Add(7 * 24 * time.Hour)
	u := model.EndUser{Name: "用户", Email: "contact@example.com"}
	f.db.Create(&u)
	l := model.License{UserID: &u.ID, AppID: f.app.ID, Key: "AUTH-CONTACT", Status: "active", ExpiresAt: &expiry}
	if e := f.db.Create(&l).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.s.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	if e := f.s.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	var deliveries []model.MailDelivery
	f.db.Find(&deliveries)
	if len(deliveries) != 2 {
		t.Fatal("missing contact/admin or duplicate", deliveries)
	}
	seen := map[string]bool{}
	for _, d := range deliveries {
		seen[d.Recipient] = true
		if !strings.Contains(d.Subject, "授权到期提醒") {
			t.Fatal(d.Subject)
		}
	}
	if !seen["admin@example.com"] || !seen[u.Email] {
		t.Fatal(seen)
	}
	var sent int
	f.s.sendMail = func(_ context.Context, _ mailer.Config, m mailer.Message) error {
		if !seen[m.To] {
			t.Error("wrong recipient", m.To)
		}
		sent++
		return nil
	}
	if e := f.s.ProcessDue(ctx); e != nil || sent != 2 {
		t.Fatal(sent, e)
	}
}
func TestMailRetentionProtectsInFlightAndReceipt(t *testing.T) {
	f := setup(t)
	now := f.clock.now()
	old := now.AddDate(0, 0, -40)
	for _, v := range []struct {
		key, status string
		attempts    int
	}{{"done", "sent", 1}, {"exhausted", "failed", 6}, {"pending", "pending", 0}, {"retry", "failed", 2}, {"sending", "sending", 1}} {
		receipt := model.NotificationReceipt{Key: "expiring:" + v.key, CreatedAt: old}
		f.db.Create(&receipt)
		f.db.Create(&model.MailDelivery{Base: model.Base{CreatedAt: old, UpdatedAt: old}, ReceiptKey: receipt.Key, Status: v.status, Attempts: v.attempts})
	}
	if e := f.s.cleanupNotifications(context.Background(), now); e != nil {
		t.Fatal(e)
	}
	var mailCount, receiptCount int64
	f.db.Model(&model.MailDelivery{}).Count(&mailCount)
	f.db.Model(&model.NotificationReceipt{}).Count(&receiptCount)
	if mailCount != 3 || receiptCount != 3 {
		t.Fatal(mailCount, receiptCount)
	}
}

func TestBackupBundleAndPublicURL(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, e := f.s.UpdateSettings(ctx, SettingsInput{PublicURL: ptr("https://auth.example.com/")}); e != nil {
		t.Fatal(e)
	}
	if f.s.Current().PublicURL != "https://auth.example.com" {
		t.Fatal("url not normalized")
	}
	if _, e := f.s.UpdateSettings(ctx, SettingsInput{PublicURL: ptr("https://secret@example.com")}); e == nil {
		t.Fatal("url accepted credentials")
	}
	info, e := f.s.Backup(ctx)
	if e != nil || !info.BundleReady {
		t.Fatal(e)
	}
	file, e := f.s.OpenBackup(info.Name)
	if e != nil {
		t.Fatal(e)
	}
	file.Close()
	rows, _ := f.s.ListBackups()
	if !rows[0].BundleReady {
		t.Fatal("missing bundle marker")
	}
}

func TestDeploymentProxySurvivesOldEmptySettings(t *testing.T) {
	f := setup(t)
	_, e := f.s.UpdateSettings(context.Background(), SettingsInput{TrustedProxies: ptr([]string{})})
	if e != nil {
		t.Fatal(e)
	}
	next, e := New(f.db, make([]byte, 32), nil, Options{Now: f.clock.now, Defaults: config.Config{TrustedProxies: []string{"10.0.0.0/8"}, PublicURL: "https://external.example"}})
	if e != nil {
		t.Fatal(e)
	}
	if got := next.ResolveIP("10.1.2.3:8080", "203.0.113.8", ""); got != "203.0.113.8" {
		t.Fatal(got)
	}
	if got := next.ResolveIP("198.51.100.8:8080", "203.0.113.8", ""); got != "198.51.100.8" {
		t.Fatal("forged XFF", got)
	}
	if next.Current().PublicURL != "https://external.example" {
		t.Fatal("external URL fallback lost")
	}
}
