package automation

import (
	"context"
	"errors"
	"gorm.io/gorm"
	"testing"
)

func TestDailyBackupIndependentOfCleanupFailure(t *testing.T) {
	f := setup(t)
	f.db.Callback().Delete().Before("gorm:delete").Register("contract_fail_cleanup", func(tx *gorm.DB) {
		if tx.Statement.Table == "audit_logs" {
			tx.AddError(errors.New("injected maintenance failure"))
		}
	})
	if e := f.s.Tick(context.Background()); e == nil {
		t.Fatal("maintenance failure hidden")
	}
	files, e := f.s.ListBackups()
	if e != nil || len(files) != 1 {
		t.Fatal("backup blocked by maintenance", files, e)
	}
	if e := f.s.Tick(context.Background()); e == nil {
		t.Fatal("maintenance failure hidden on retry")
	}
	files, e = f.s.ListBackups()
	if e != nil || len(files) != 1 {
		t.Fatal("daily backup duplicated", files, e)
	}
	f.db.Callback().Delete().Remove("contract_fail_cleanup")
	if e = f.s.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
}
