package client

import (
	"authgo/internal/code"
	"authgo/internal/licensing"
	"authgo/internal/model"
	"authgo/internal/verify"
	"context"
	"testing"
)

func TestDeletedLicenseReturnsAuthenticatedNotFoundAndKeepsLateLogs(t *testing.T) {
	f := newUnlockFixture(t)
	s := licensing.NewService(f.db)
	if _, err := s.ChangeState(context.Background(), f.l.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delete(context.Background(), f.l.ID); err != nil {
		t.Fatal(err)
	}
	// A result queued before deletion must survive the FK race too.
	f.service.logs.trySubmit(model.VerifyLog{LicenseID: &f.l.ID, AppID: &f.app.ID, Code: code.LicenseRevoked, Reason: "late result"})
	if result := f.service.process(context.Background(), f.app, verify.Verify, "203.0.113.7", f.in, f.clock.now(), policyOptions{}); result.Code != code.LicenseNotFound {
		t.Fatal(result.Code)
	}
	if result := f.signedUnlock(t); result.Code != code.LicenseNotFound {
		t.Fatal(result.Code)
	}
	f.drain(t)
	var logs []model.VerifyLog
	if err := f.db.Find(&logs).Error; err != nil {
		t.Fatal(err)
	}
	late, missing := false, false
	for _, log := range logs {
		if log.Reason == model.DeletedLicenseReason+"late result" {
			late = true
			if log.LicenseID != nil {
				t.Fatal(log)
			}
		}
		if log.Code == code.LicenseNotFound {
			missing = true
		}
	}
	if !late || !missing || f.service.DroppedLogEntries() != 0 {
		t.Fatal("deleted license logging failed", logs)
	}
}
