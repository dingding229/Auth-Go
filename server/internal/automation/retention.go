package automation

import (
	"authgo/internal/mailer"
	"authgo/internal/model"
	"context"
	"errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"strings"
	"time"
)

// Pending, sending, retrying and not-yet-exhausted records are never pruned.
func (s *Service) cleanupNotifications(ctx context.Context, now time.Time) error {
	cutoff := now.AddDate(0, 0, -s.Current().NotificationRetentionDays)
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("(status='sent' OR (status='failed' AND COALESCE(attempts,0)>=6)) AND COALESCE(sent_at,updated_at,created_at) < ?", cutoff).Delete(&model.MailDelivery{}).Error; err != nil {
			return err
		}
		return tx.Where(`created_at < ? AND NOT EXISTS (SELECT 1 FROM mail_deliveries m WHERE m.receipt_key=notification_receipts.key)`, cutoff).Delete(&model.NotificationReceipt{}).Error
	})
}

// Called directly by the scheduler, atomically with its deduplication receipt.
func (s *Service) queueExpiryMail(tx *gorm.DB, l model.License, days int, receipt string) error {
	inserted := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.NotificationReceipt{Key: receipt, CreatedAt: s.now().UTC()})
	if inserted.Error != nil {
		return inserted.Error
	}
	if inserted.RowsAffected == 0 {
		return nil
	}
	settings := s.Current()
	if !settings.SMTP.Enabled || l.ExpiresAt == nil {
		return nil
	}
	var app model.Application
	if err := tx.First(&app, l.AppID).Error; err != nil {
		return err
	}
	recipients := append([]string{}, settings.AdminNotificationEmails...)
	var user model.EndUser
	if l.UserID != nil {
		if e := tx.First(&user, *l.UserID).Error; e != nil {
			return e
		}
	}
	if address, err := mailer.Address(user.Email); err == nil {
		recipients = append(recipients, address)
	}
	seen := map[string]bool{}
	parts := strings.Split(l.Key, "-")
	masked := "***"
	if len(parts) > 1 {
		masked = parts[0] + "-*****-*****-*****-" + parts[len(parts)-1]
	}
	for _, to := range recipients {
		to = strings.ToLower(to)
		if seen[to] {
			continue
		}
		seen[to] = true
		message := mailer.Expiring(settings.SiteName, app.Name, masked, days, *l.ExpiresAt, to)
		now := s.now().UTC()
		if err := tx.Create(&model.MailDelivery{Base: model.Base{CreatedAt: now}, ReceiptKey: receipt, Recipient: to, Subject: message.Subject, Body: message.Body, Status: "pending", NextRetryAt: &now}).Error; err != nil {
			return err
		}
	}
	return nil
}

// Audit retention is fixed at 365 UTC days and runs at most once per day.
// Delete and receipt commit atomically; failures retry on the next scheduler tick.
func (s *Service) cleanupAuditLogs(ctx context.Context, now time.Time) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var receipt model.Setting
		err := tx.First(&receipt, "key=?", "jobs.audit_cleanup_day").Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		day := now.UTC().Format("2006-01-02")
		if err == nil && receipt.Value == day {
			return nil
		}
		if err := tx.Where("created_at < ?", now.UTC().AddDate(0, 0, -365)).Delete(&model.AuditLog{}).Error; err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&model.Setting{Key: "jobs.audit_cleanup_day", Value: day}).Error
	})
}
