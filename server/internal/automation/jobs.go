package automation

import (
	"authgo/internal/model"
	"context"
	"errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"math"
	"strconv"
	"time"
)

// Tick is a single-instance bounded scan, independently runnable with an injected clock.
func (s *Service) Tick(ctx context.Context) error {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	now := s.now().UTC()
	maintenanceErr := func() error {
		if e := s.cleanupAuditLogs(ctx, now); e != nil {
			return e
		}
		if e := s.scanLicenses(ctx, now); e != nil {
			return e
		}
		// Expired lease rows stay bound (and keep generations) so a valid session can
		// reacquire via heartbeat; capacity already counts only live leases in client.
		if e := s.db.WithContext(ctx).Model(&model.Activation{}).Where("kind='floating' AND status='active' AND lease_expires_at<=? AND offline_at IS NULL", now).Update("lease_expires_at", nil).Error; e != nil {
			return e
		}
		if e := s.db.WithContext(ctx).Where("created_at < ?", now.AddDate(0, 0, -s.Current().LogRetentionDays)).Delete(&model.VerifyLog{}).Error; e != nil {
			return e
		}
		if e := s.cleanupNotifications(ctx, now); e != nil {
			return e
		}

		return nil
	}()
	backupErr := func() error {

		if s.dataDir != "" {
			var state model.Setting
			e := s.db.WithContext(ctx).First(&state, "key=?", "jobs.backup_day").Error
			if e != nil && !errors.Is(e, gorm.ErrRecordNotFound) {
				return e
			}
			day := now.Format("2006-01-02")
			if state.Value != day {
				if _, e := s.Backup(ctx); e != nil {
					return e
				}
				if e := s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&model.Setting{Key: "jobs.backup_day", Value: day}).Error; e != nil {
					return e
				}
			}
		}
		return nil
	}()
	return errors.Join(maintenanceErr, backupErr)
}
func (s *Service) scanLicenses(ctx context.Context, now time.Time) error {
	var after uint64
	for {
		var rows []model.License
		if e := s.db.WithContext(ctx).Where("id>? AND status IN ('unused','active') AND expires_at IS NOT NULL AND expires_at<=?", after, now.Add(7*24*time.Hour)).Order("id").Limit(100).Find(&rows).Error; e != nil {
			return e
		}
		for _, l := range rows {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			after = l.ID
			if e := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				// Re-read inside the write transaction: concurrent renewal/revoke wins.
				var current model.License
				if e := tx.First(&current, l.ID).Error; e != nil {
					return e
				}
				l = current
				if l.ExpiresAt == nil || l.Status == "revoked" {
					return nil
				}
				if !now.Before(*l.ExpiresAt) {
					if l.Status != "active" && l.Status != "unused" && l.Status != "expired" {
						return nil
					}
					if l.Status != "expired" {
						if e := tx.Model(&l).Update("status", "expired").Error; e != nil {
							return e
						}
					}
					return nil
				}
				if l.Status != "active" && l.Status != "unused" {
					return nil
				}
				days := int(math.Ceil(l.ExpiresAt.Sub(now).Hours() / 24))
				if days != 7 && days != 3 && days != 1 {
					return nil
				}
				receipt := "expiring:" + idString(l.ID) + ":" + l.ExpiresAt.UTC().Format(time.RFC3339Nano) + ":" + idString(uint64(days))
				var exists int64
				if e := tx.Model(&model.NotificationReceipt{}).Where("key=?", receipt).Count(&exists).Error; e != nil {
					return e
				}
				if exists > 0 {
					return nil
				}
				if e := s.queueExpiryMail(tx, l, days, receipt); e != nil {
					return e
				}
				return nil
			}); e != nil {
				return e
			}
		}
		if len(rows) < 100 {
			return nil
		}
	}
}

func idString(v uint64) string { return strconv.FormatUint(v, 10) }
