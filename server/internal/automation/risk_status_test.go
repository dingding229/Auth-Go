package automation

import (
	"authgo/internal/model"
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestBackupDownloadReminderPersists(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	initial, err := f.s.BackupStatus(ctx)
	if err != nil || initial.DownloadOverdue || initial.LastDownloadedAt != nil {
		t.Fatal(initial, err)
	}
	f.clock.add(8 * 24 * time.Hour)
	status, err := f.s.BackupStatus(ctx)
	if err != nil || !status.DownloadOverdue || status.DaysWithoutDownload != 8 {
		t.Fatal(status, err)
	}
	f.s.RecordBackupDownload()
	status, err = f.s.BackupStatus(ctx)
	if err != nil || status.DownloadOverdue || status.LastDownloadedAt == nil {
		t.Fatal(status, err)
	}
	restarted, err := New(f.db, bytes.Repeat([]byte{0}, 32), slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Now: f.clock.now, DataDir: f.dir})
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.BackupStatus(ctx)
	if err != nil || !got.StartedAt.Equal(initial.StartedAt) || got.LastDownloadedAt == nil || !got.LastDownloadedAt.Equal(*status.LastDownloadedAt) {
		t.Fatal(got, err)
	}
	f.clock.add(7 * 24 * time.Hour)
	got, _ = restarted.BackupStatus(ctx)
	if got.DownloadOverdue {
		t.Fatal("exact seven days is not overdue")
	}
	f.clock.add(time.Second)
	got, _ = restarted.BackupStatus(ctx)
	if !got.DownloadOverdue || got.DaysWithoutDownload != 7 {
		t.Fatal(got)
	}
}
func TestCloudflareDetectionOnlyReadsRecentLogs(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := f.db.Create(&model.VerifyLog{IP: "172.69.224.203"}).Error; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if err := f.db.Create(&model.VerifyLog{IP: "8.8.8.8"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	settings, err := f.s.ReadSettings(ctx)
	if err != nil || settings.CloudflareIPSeen {
		t.Fatal(settings, err)
	}
	if err := f.db.Create(&model.VerifyLog{IP: "2606:4700::1"}).Error; err != nil {
		t.Fatal(err)
	}
	settings, err = f.s.ReadSettings(ctx)
	if err != nil || !settings.CloudflareIPSeen || settings.ServerVersion == "" || settings.PackImageTag == "" {
		t.Fatal(settings, err)
	}
}

func TestBackupReminderStartsFromInstallation(t *testing.T) {
	f := setup(t)
	past := f.clock.now().Add(-8 * 24 * time.Hour)
	if err := f.db.Exec("UPDATE schema_migrations SET applied_at=?", past).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Where("key=?", backupStartedKey).Delete(&model.Setting{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.s.initBackupStatus(); err != nil {
		t.Fatal(err)
	}
	status, err := f.s.BackupStatus(t.Context())
	if err != nil || !status.DownloadOverdue || !status.StartedAt.Equal(past) {
		t.Fatal("upgrade reset instance age", status, err)
	}
}
