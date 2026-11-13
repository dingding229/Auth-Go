package client

import (
	"authgo/internal/catalog"
	"authgo/internal/model"
	"context"
	"github.com/Masterminds/semver/v3"
	"gorm.io/gorm"
	"time"
)

func (s *Service) announcements(ctx context.Context, id uint64, now time.Time) ([]catalog.AnnouncementInfo, error) {
	var rows []model.Announcement
	err := s.db.WithContext(ctx).Where("app_id = ? AND published_at IS NOT NULL AND published_at <= ? AND (expires_at IS NULL OR expires_at > ?)", id, now, now).Order("published_at DESC, id DESC").Limit(20).Find(&rows).Error
	out := make([]catalog.AnnouncementInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, catalog.AnnouncementDTO(r))
	}
	return out, err
}
func (s *Service) latestVersion(ctx context.Context, id uint64, now time.Time) (catalog.VersionInfo, error) {
	// Page through metadata to bound memory; compare semantic versions, not text.
	var best model.AppVersion
	var bv *semver.Version
	var after uint64
	for {
		var rows []model.AppVersion
		if e := s.db.WithContext(ctx).Where("app_id = ? AND (source = 'manual' OR (source = 'docker' AND EXISTS (SELECT 1 FROM applications WHERE applications.id = app_versions.app_id AND applications.docker_image <> ''))) AND withdrawn=0 AND disabled=0 AND published_at IS NOT NULL AND published_at <= ? AND id > ?", id, now, after).Order("id ASC").Limit(100).Find(&rows).Error; e != nil {
			return catalog.VersionInfo{}, e
		}
		for _, r := range rows {
			v, e := semver.StrictNewVersion(r.Version)
			if e != nil {
				continue
			}
			if bv == nil || v.GreaterThan(bv) || v.Equal(bv) && r.ID > best.ID {
				bv = v
				best = r
			}
			after = r.ID
		}
		if len(rows) < 100 {
			break
		}
	}
	if bv == nil {
		return catalog.VersionInfo{}, gorm.ErrRecordNotFound
	}
	return catalog.VersionDTO(best), nil
}
