package automation

import (
	"authgo/internal/model"
	"context"
	"time"

	"gorm.io/gorm/clause"
)

const backupStartedKey = "backup.started_at.v1"
const backupDownloadedKey = "backup.downloaded_at.v1"

type BackupStatus struct {
	StartedAt           time.Time  `json:"started_at"`
	LastDownloadedAt    *time.Time `json:"last_downloaded_at"`
	DaysWithoutDownload int        `json:"days_without_download"`
	DownloadOverdue     bool       `json:"download_overdue"`
}

func (s *Service) initBackupStatus() error {
	var first struct{ AppliedAt time.Time }
	if err := s.db.Table("schema_migrations").Select("applied_at").Order("version ASC").Limit(1).Scan(&first).Error; err != nil {
		return err
	}
	started := s.now().UTC()
	// Installation metadata keeps the age from resetting when the service is upgraded.
	if !first.AppliedAt.IsZero() && first.AppliedAt.Before(started) {
		started = first.AppliedAt.UTC()
	}
	return s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.Setting{Key: backupStartedKey, Value: started.Format(time.RFC3339Nano)}).Error
}
func (s *Service) BackupStatus(ctx context.Context) (BackupStatus, error) {
	var records []model.Setting
	if err := s.db.WithContext(ctx).Where("key IN ?", []string{backupStartedKey, backupDownloadedKey}).Find(&records).Error; err != nil {
		return BackupStatus{}, err
	}
	var status BackupStatus
	for _, row := range records {
		at, err := time.Parse(time.RFC3339Nano, row.Value)
		if err != nil {
			return status, err
		}
		if row.Key == backupStartedKey {
			status.StartedAt = at
		} else {
			status.LastDownloadedAt = &at
		}
	}
	since := status.StartedAt
	if status.LastDownloadedAt != nil {
		since = *status.LastDownloadedAt
	}
	elapsed := s.now().Sub(since)
	if !since.IsZero() && elapsed > 0 {
		status.DaysWithoutDownload = int(elapsed / (24 * time.Hour))
		status.DownloadOverdue = elapsed > 7*24*time.Hour
	}
	return status, nil
}
func (s *Service) RecordBackupDownload() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&model.Setting{Key: backupDownloadedKey, Value: s.now().UTC().Format(time.RFC3339Nano)}).Error; err != nil {
		s.log.Error("无法记录备份下载时间")
	}
}
