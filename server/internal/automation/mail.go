package automation

import (
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/mailer"
	"authgo/internal/model"
	"context"
	"gorm.io/gorm"
	"time"
)

func (s *Service) processMail(ctx context.Context) error {
	now := s.now().UTC()
	if e := s.db.WithContext(ctx).Model(&model.MailDelivery{}).Where("status='sending' AND claim_until<=?", now).Updates(map[string]any{"status": "retrying", "next_retry_at": now, "claim_until": nil, "claim_token": ""}).Error; e != nil {
		return e
	}
	var rows []model.MailDelivery
	if e := s.db.WithContext(ctx).Where("status IN ? AND (next_retry_at IS NULL OR next_retry_at<=?)", []string{"pending", "retrying"}, now).Order("id").Limit(20).Find(&rows).Error; e != nil {
		return e
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if row.Attempts >= 6 {
			if e := s.db.WithContext(ctx).Model(&row).Updates(map[string]any{"status": "failed", "next_retry_at": nil, "updated_at": s.now().UTC()}).Error; e != nil {
				return e
			}
			continue
		}
		cfg, e := s.smtpConfig()
		if e != nil {
			return e
		}
		if !cfg.Enabled {
			continue
		}
		token, e := cryptoutil.RandomString(16)
		if e != nil {
			return e
		}
		until := s.now().Add(time.Minute)
		result := s.db.WithContext(ctx).Model(&row).Where("status IN ?", []string{"pending", "retrying"}).Updates(map[string]any{"status": "sending", "attempts": gorm.Expr("attempts+1"), "claim_token": token, "claim_until": until})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			continue
		}
		row.Attempts++
		sendError := s.sendMail(ctx, cfg, mailer.Message{To: row.Recipient, Subject: row.Subject, Body: row.Body})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		updates := map[string]any{"updated_at": s.now().UTC(), "claim_token": "", "claim_until": nil, "last_error": ""}
		if sendError == nil {
			updates["status"] = "sent"
			updates["sent_at"] = s.now().UTC()
			updates["next_retry_at"] = nil
		} else {
			updates["last_error"] = "SMTP 投递失败"
			if row.Attempts >= 6 {
				updates["status"] = "failed"
				updates["next_retry_at"] = nil
			} else {
				updates["status"] = "retrying"
				updates["next_retry_at"] = s.now().Add(mailBackoff(row.Attempts))
			}
		}
		if e := s.db.WithContext(ctx).Model(&row).Where("claim_token=?", token).Updates(updates).Error; e != nil {
			return e
		}
	}
	return nil
}

func mailBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 5 {
		attempt = 5
	}
	return time.Minute * time.Duration(1<<uint(attempt-1))
}
