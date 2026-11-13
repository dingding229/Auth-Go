package automation

import (
	"authgo/internal/model"
	"context"
	"errors"
	"gorm.io/gorm"
	"testing"
	"time"
)

func TestAuditRetention365DaysDailyBoundaryAndRetry(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := f.clock.now()
	cutoff := now.AddDate(0, 0, -365)
	add := func(at time.Time) model.AuditLog {
		t.Helper()
		row := model.AuditLog{CreatedAt: at, Action: "test", Resource: "test", Summary: "test"}
		if e := f.db.Create(&row).Error; e != nil {
			t.Fatal(e)
		}
		return row
	}
	old := add(cutoff.Add(-time.Second))
	boundary := add(cutoff)
	recent := add(now)
	if e := f.s.cleanupAuditLogs(ctx, now); e != nil {
		t.Fatal(e)
	}
	count := func(id uint64) int64 {
		var n int64
		f.db.Model(&model.AuditLog{}).Where("id=?", id).Count(&n)
		return n
	}
	if count(old.ID) != 0 || count(boundary.ID) != 1 || count(recent.ID) != 1 {
		t.Fatal("365 day boundary wrong")
	}
	late := add(cutoff.Add(-time.Hour))
	if e := f.s.cleanupAuditLogs(ctx, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if count(late.ID) != 1 {
		t.Fatal("cleanup ran twice same day")
	}
	f.db.Callback().Delete().Before("gorm:delete").Register("contract_fail", func(tx *gorm.DB) {
		if tx.Statement.Table == "audit_logs" {
			tx.AddError(errors.New("injected"))
		}
	})
	tomorrow := now.Add(24 * time.Hour)
	if e := f.s.cleanupAuditLogs(ctx, tomorrow); e == nil {
		t.Fatal("delete failure hidden")
	}
	var receipt model.Setting
	f.db.First(&receipt, "key=?", "jobs.audit_cleanup_day")
	if receipt.Value != now.Format("2006-01-02") {
		t.Fatal("failure consumed retry receipt")
	}
	f.db.Callback().Delete().Remove("contract_fail")
	if e := f.s.cleanupAuditLogs(ctx, tomorrow); e != nil {
		t.Fatal(e)
	}
	if count(late.ID) != 0 || count(boundary.ID) != 0 || count(recent.ID) != 1 {
		t.Fatal("next day/retry retention wrong")
	}
}

func TestAuditRetentionRunsFromScheduler(t *testing.T) {
	f := setup(t)
	row := model.AuditLog{CreatedAt: f.clock.now().AddDate(0, 0, -366), Action: "expired"}
	if e := f.db.Create(&row).Error; e != nil {
		t.Fatal(e)
	}
	if e := f.s.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	var n int64
	f.db.Model(&model.AuditLog{}).Where("id=?", row.ID).Count(&n)
	if n != 0 {
		t.Fatal("scheduler did not clean expired audit")
	}
}
