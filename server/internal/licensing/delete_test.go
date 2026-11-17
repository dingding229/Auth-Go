package licensing

import (
	"authgo/internal/model"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func deletionFixture(t *testing.T) (*fixture, LicenseInfo, model.Activation) {
	t.Helper()
	f := newFixture(t)
	l := f.create(t)
	if _, err := f.s.ChangeState(context.Background(), l.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	a := model.Activation{LicenseID: l.ID, Kind: "floating", Value: "device", Token: "retained-token", Status: "revoked"}
	if err := f.db.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	session := model.ClientSession{ID: "session", AppID: f.app.ID, LicenseID: l.ID, TokenHash: "hash"}
	if err := f.db.Create(&session).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&model.ClientSessionBinding{SessionID: session.ID, ActivationID: a.ID, Generation: "old"}).Error; err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		fmt.Sprintf("INSERT INTO activation_instance_sessions VALUES (%d,'instance')", a.ID),
		fmt.Sprintf("INSERT INTO license_sharing(license_id,updated_at) VALUES (%d,CURRENT_TIMESTAMP)", l.ID),
	} {
		if err := f.db.Exec(sql).Error; err != nil {
			t.Fatal(err)
		}
	}
	log := model.VerifyLog{AppID: &f.app.ID, LicenseID: &l.ID, ActivationID: &a.ID, Action: "verify", Code: "LICENSE_REVOKED", Reason: "original reason", IP: "203.0.113.1"}
	if err := f.db.Create(&log).Error; err != nil {
		t.Fatal(err)
	}
	return f, l, a
}

func TestDeleteRevokedPreservesLogsAndNotificationHistory(t *testing.T) {
	f, l, _ := deletionFixture(t)
	receipt := fmt.Sprintf("expiring:%d:old:7", l.ID)
	if err := f.db.Create(&model.NotificationReceipt{Key: receipt, CreatedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Create(&model.MailDelivery{ReceiptKey: receipt, Recipient: "user@example.com", Subject: "history", Status: "sent"}).Error; err != nil {
		t.Fatal(err)
	}
	out, err := f.s.Delete(context.Background(), l.ID)
	if err != nil || out.ID != l.ID || out.KeySuffix != l.Key[len(l.Key)-4:] {
		t.Fatal(out, err)
	}
	for _, table := range []string{"licenses", "activations", "client_sessions", "client_session_bindings", "activation_instance_sessions", "license_sharing"} {
		var count int64
		if err := f.db.Table(table).Count(&count).Error; err != nil || count != 0 {
			t.Fatal(table, count, err)
		}
	}
	var logs []model.VerifyLog
	if err := f.db.Find(&logs).Error; err != nil || len(logs) != 1 {
		t.Fatal(logs, err)
	}
	if logs[0].LicenseID != nil || logs[0].ActivationID != nil || logs[0].AppID == nil || logs[0].Reason != model.DeletedLicenseReason+"original reason" || logs[0].Code != "LICENSE_REVOKED" {
		t.Fatal(logs)
	}
	for _, table := range []string{"notification_receipts", "mail_deliveries"} {
		var count int64
		if err := f.db.Table(table).Count(&count).Error; err != nil || count != 1 {
			t.Fatal(table, count, err)
		}
	}
}
func TestDeleteRejectsOtherStatesAndTrials(t *testing.T) {
	for _, state := range []string{"unused", "active", "expired", "suspended", "revoked-trial", "converted"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			l := f.create(t)
			kind, statusValue := "standard", state
			if state == "revoked-trial" {
				kind, statusValue = "trial", "revoked"
			}
			if state == "converted" {
				statusValue = "revoked"
			}
			if err := f.db.Model(&model.License{}).Where("id=?", l.ID).Updates(map[string]any{"type": kind, "status": statusValue}).Error; err != nil {
				t.Fatal(err)
			}
			if state == "converted" {
				if err := f.db.Exec("INSERT INTO trial_claims(app_id,ip_key,instance_id,license_id,created_at) VALUES (?,'ip','instance',?,CURRENT_TIMESTAMP)", f.app.ID, l.ID).Error; err != nil {
					t.Fatal(err)
				}
			}
			_, err := f.s.Delete(context.Background(), l.ID)
			status(t, err, 400)
			want := "只能删除已吊销的授权"
			if state == "revoked-trial" || state == "converted" {
				want = "试用授权不能删除"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatal(err)
			}
			var count int64
			if err := f.db.Model(&model.License{}).Where("id=?", l.ID).Count(&count).Error; err != nil || count != 1 {
				t.Fatal(count, err)
			}
		})
	}
}
func TestPurgeRevokedIsScopedAndPaged(t *testing.T) {
	f := newFixture(t)
	admin := model.Admin{Username: "owner", PasswordHash: "hash"}
	if err := f.db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	other := model.Application{Name: "other", AppKey: "other"}
	if err := f.db.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	rows := make([]model.License, 205)
	for i := range rows {
		rows[i] = model.License{AppID: f.app.ID, Key: fmt.Sprintf("purge-%04d", i), Status: "revoked"}
	}
	rows[201].AppID = other.ID
	rows[202].Type = "trial"
	rows[203].Status = "active"
	if err := f.db.CreateInBatches(&rows, 100).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Exec("INSERT INTO trial_claims(app_id,ip_key,instance_id,license_id,created_at) VALUES (?,'ip','instance',?,CURRENT_TIMESTAMP)", f.app.ID, rows[204].ID).Error; err != nil {
		t.Fatal(err)
	}
	out, err := f.s.PurgeRevoked(context.Background(), PurgeInput{AppID: &f.app.ID}, DeleteActor{ID: admin.ID, Name: admin.Username})
	if err != nil || out.Count != 201 {
		t.Fatal(out, err)
	}
	var remain int64
	if err := f.db.Model(&model.License{}).Count(&remain).Error; err != nil || remain != 4 {
		t.Fatal(remain, err)
	}
	var audits []model.AuditLog
	if err := f.db.Find(&audits).Error; err != nil || len(audits) != 201 {
		t.Fatal(len(audits), err)
	}
	for _, audit := range audits {
		if len(audit.Details["key_suffix"].(string)) != 4 || strings.Contains(audit.Summary, "purge-") {
			t.Fatal(audit)
		}
	}
	out, err = f.s.PurgeRevoked(context.Background(), PurgeInput{}, DeleteActor{ID: admin.ID, Name: admin.Username})
	if err != nil || out.Count != 1 {
		t.Fatal(out, err)
	}
}
func TestDeletionRollback(t *testing.T) {
	f, l, a := deletionFixture(t)
	if err := f.db.Exec("CREATE TRIGGER reject_license_delete BEFORE DELETE ON licenses BEGIN SELECT RAISE(ABORT,'unavailable'); END").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Delete(context.Background(), l.ID); err == nil {
		t.Fatal("failed delete accepted")
	}
	var log model.VerifyLog
	if err := f.db.First(&log).Error; err != nil || log.LicenseID == nil || log.ActivationID == nil || *log.ActivationID != a.ID || log.Reason != "original reason" {
		t.Fatal(log, err)
	}
	for _, table := range []string{"licenses", "activations", "client_sessions", "client_session_bindings", "activation_instance_sessions", "license_sharing"} {
		var count int64
		if err := f.db.Table(table).Count(&count).Error; err != nil || count != 1 {
			t.Fatal(table, count, err)
		}
	}
}

func TestPurgeRollsBackWhenAuditCannotBeWritten(t *testing.T) {
	f := newFixture(t)
	admin := model.Admin{Username: "owner", PasswordHash: "hash"}
	if err := f.db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	rows := make([]model.License, 201)
	for i := range rows {
		rows[i] = model.License{AppID: f.app.ID, Key: fmt.Sprintf("rollback-%04d", i), Status: "revoked"}
	}
	if err := f.db.CreateInBatches(&rows, 100).Error; err != nil {
		t.Fatal(err)
	}
	if err := f.db.Exec(fmt.Sprintf("CREATE TRIGGER fail_deletion_audit BEFORE INSERT ON audit_logs WHEN NEW.resource_id='%d' BEGIN SELECT RAISE(ABORT,'unavailable'); END", rows[200].ID)).Error; err != nil {
		t.Fatal(err)
	}
	out, err := f.s.PurgeRevoked(context.Background(), PurgeInput{}, DeleteActor{ID: admin.ID})
	if err == nil || out.Count != 0 {
		t.Fatal(out, err)
	}
	var licenses, audits int64
	if err := f.db.Model(&model.License{}).Count(&licenses).Error; err != nil || licenses != 201 {
		t.Fatal(licenses, err)
	}
	if err := f.db.Model(&model.AuditLog{}).Count(&audits).Error; err != nil || audits != 0 {
		t.Fatal(audits, err)
	}
}
