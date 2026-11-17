package catalog

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"encoding/json"
	"github.com/Masterminds/semver/v3"
	"gorm.io/gorm"
	"strings"
	"time"
)

type AnnouncementInfo struct {
	Level string `json:"level"`
	BaseInfo
	AppID       uint64     `json:"app_id"`
	Title       string     `json:"title"`
	Content     string     `json:"content"`
	PublishedAt *time.Time `json:"published_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

func AnnouncementDTO(v model.Announcement) AnnouncementInfo {
	return AnnouncementInfo{v.Level, baseInfo(v.Base), v.AppID, v.Title, v.Content, v.PublishedAt, v.ExpiresAt}
}

type AnnouncementInput struct {
	Level       *string         `json:"level"`
	Title       *string         `json:"title"`
	Content     *string         `json:"content"`
	PublishedAt json.RawMessage `json:"published_at" swaggertype:"string" format:"date-time"`
	ExpiresAt   json.RawMessage `json:"expires_at" swaggertype:"string" format:"date-time"`
}

func updateTime(raw json.RawMessage, dst **time.Time) error {
	if len(raw) == 0 {
		return nil
	}
	if string(raw) == "null" {
		*dst = nil
		return nil
	}
	var t time.Time
	if err := json.Unmarshal(raw, &t); err != nil || t.Year() < 1 || t.Year() > 9999 {
		return apperror.Invalid("时间必须为 RFC3339 格式或 null")
	}
	t = t.UTC()
	*dst = &t
	return nil
}
func applyAnnouncement(v model.Announcement, in AnnouncementInput) (model.Announcement, error) {
	if v.Level == "" {
		v.Level = "info"
	}
	if in.Level != nil {
		v.Level = *in.Level
	}
	if v.Level != "info" && v.Level != "warning" && v.Level != "critical" {
		return v, apperror.Invalid("公告级别无效")
	}

	if in.Title != nil {
		v.Title = strings.TrimSpace(*in.Title)
	}
	if in.Content != nil {
		v.Content = *in.Content
	}
	if err := updateTime(in.PublishedAt, &v.PublishedAt); err != nil {
		return v, err
	}
	if err := updateTime(in.ExpiresAt, &v.ExpiresAt); err != nil {
		return v, err
	}
	if !validName(v.Title) || len(v.Content) > 32768 {
		return v, apperror.Invalid("公告标题不能为空且最多 128 字节，正文最多 32768 字节")
	}
	if v.ExpiresAt != nil && v.PublishedAt != nil && !v.ExpiresAt.After(*v.PublishedAt) {
		return v, apperror.Invalid("公告失效时间必须晚于发布时间")
	}
	return v, nil
}
func (s *Service) ListAnnouncements(ctx context.Context, appID uint64, q response.ListQuery) ([]AnnouncementInfo, int64, error) {
	if _, e := application(s.db.WithContext(ctx), appID); e != nil {
		return nil, 0, e
	}
	query := likeQuery(s.db.WithContext(ctx).Model(&model.Announcement{}).Where("app_id = ?", appID), q.Q, "title", "content")
	return response.ListPage(query, q, AnnouncementDTO)
}
func (s *Service) GetAnnouncement(ctx context.Context, id uint64) (AnnouncementInfo, error) {
	return getRelease(s.db.WithContext(ctx), id, AnnouncementDTO, "公告")
}
func (s *Service) CreateAnnouncement(ctx context.Context, appID uint64, in AnnouncementInput) (AnnouncementInfo, error) {
	v, e := applyAnnouncement(model.Announcement{AppID: appID}, in)
	if e != nil {
		return AnnouncementInfo{}, e
	}
	e = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, e := application(tx, appID); e != nil {
			return e
		}
		return tx.Create(&v).Error
	})
	return AnnouncementDTO(v), e
}
func (s *Service) UpdateAnnouncement(ctx context.Context, id uint64, in AnnouncementInput) (AnnouncementInfo, error) {
	if in.Title == nil && in.Content == nil && len(in.PublishedAt) == 0 && len(in.ExpiresAt) == 0 {
		return AnnouncementInfo{}, apperror.Invalid("至少提供一个修改字段")
	}
	var v model.Announcement
	e := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := tx.First(&v, id).Error; e != nil {
			return missing(e, "公告")
		}
		var e error
		v, e = applyAnnouncement(v, in)
		if e != nil {
			return e
		}
		return tx.Omit("Application").Save(&v).Error
	})
	return AnnouncementDTO(v), e
}
func (s *Service) DeleteAnnouncement(ctx context.Context, id uint64) error {
	return deleteRelease[model.Announcement](s.db.WithContext(ctx), id, "公告")
}

type VersionInfo struct {
	BuildVerified     bool       `json:"build_verified"`
	Encrypted         bool       `json:"encrypted"`
	BuiltAt           *time.Time `json:"built_at"`
	Disabled          bool       `json:"disabled"`
	Source            string     `json:"source"`
	Withdrawn         bool       `json:"withdrawn"`
	MandatoryOverride bool       `json:"mandatory_override"`
	BaseInfo
	AppID       uint64     `json:"app_id"`
	Version     string     `json:"version"`
	Changelog   string     `json:"changelog"`
	Mandatory   bool       `json:"mandatory"`
	PublishedAt *time.Time `json:"published_at"`
}

func VersionDTO(v model.AppVersion) VersionInfo {
	return VersionInfo{v.BuildVerified, v.Encrypted, v.BuiltAt, v.Disabled, v.Source, v.Withdrawn, v.MandatoryOverride, baseInfo(v.Base), v.AppID, v.Version, v.Changelog, v.Mandatory, v.PublishedAt}
}

type VersionInput struct {
	Encrypted   *bool           `json:"encrypted"`
	BuiltAt     json.RawMessage `json:"built_at" swaggertype:"string" format:"date-time"`
	Disabled    *bool           `json:"disabled"`
	Version     *string         `json:"version"`
	Changelog   *string         `json:"changelog"`
	Mandatory   *bool           `json:"mandatory"`
	PublishedAt json.RawMessage `json:"published_at" swaggertype:"string" format:"date-time"`
}

func applyVersion(v model.AppVersion, in VersionInput) (model.AppVersion, error) {
	// Authenticated build metadata cannot be overwritten by manual edits.
	if !v.BuildVerified {
		if in.Encrypted != nil {
			v.Encrypted = *in.Encrypted
		}
		if err := updateTime(in.BuiltAt, &v.BuiltAt); err != nil {
			return v, err
		}
		if v.Encrypted && v.BuiltAt == nil {
			return v, apperror.Invalid("启用代码加密必须填写构建时间（仅展示，不用于授权）")
		}
		if !v.Encrypted {
			v.BuiltAt = nil
		}
	}
	if in.Disabled != nil {
		v.Disabled = *in.Disabled
	}
	if in.Version != nil {
		v.Version = *in.Version
	}
	if in.Changelog != nil {
		v.Changelog = *in.Changelog
	}
	if in.Mandatory != nil {
		v.Mandatory = *in.Mandatory
	}
	if err := updateTime(in.PublishedAt, &v.PublishedAt); err != nil {
		return v, err
	}
	if len(v.Version) > 128 {
		return v, apperror.Invalid("版本号最多 128 字节")
	}
	if _, e := semver.StrictNewVersion(v.Version); e != nil {
		return v, apperror.Invalid("版本号必须为严格 semver")
	}
	if len(v.Changelog) > 32768 {
		return v, apperror.Invalid("更新说明过长")
	}

	return v, nil
}
func versionDuplicate(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return apperror.Conflict("该软件已存在此版本号")
	}
	return err
}
func (s *Service) ListVersions(ctx context.Context, appID uint64, q response.ListQuery) ([]VersionInfo, int64, error) {
	if _, e := application(s.db.WithContext(ctx), appID); e != nil {
		return nil, 0, e
	}
	query := likeQuery(s.db.WithContext(ctx).Model(&model.AppVersion{}).Where("app_id = ?", appID), q.Q, "version", "changelog")
	return response.ListPage(query, q, VersionDTO)
}
func (s *Service) GetVersion(ctx context.Context, id uint64) (VersionInfo, error) {
	return getRelease(s.db.WithContext(ctx), id, VersionDTO, "软件版本")
}
func (s *Service) CreateVersion(ctx context.Context, appID uint64, in VersionInput) (VersionInfo, error) {
	v, e := applyVersion(model.AppVersion{AppID: appID}, in)
	if e != nil {
		return VersionInfo{}, e
	}
	e = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, e := application(tx, appID); e != nil {
			return e
		}
		return tx.Create(&v).Error
	})
	return VersionDTO(v), versionDuplicate(e)
}
func (s *Service) UpdateVersion(ctx context.Context, id uint64, in VersionInput) (VersionInfo, error) {
	if in.Encrypted == nil && len(in.BuiltAt) == 0 && in.Disabled == nil && in.Version == nil && in.Changelog == nil && in.Mandatory == nil && len(in.PublishedAt) == 0 {
		return VersionInfo{}, apperror.Invalid("至少提供一个修改字段")
	}
	var v model.AppVersion
	e := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := tx.First(&v, id).Error; e != nil {
			return missing(e, "软件版本")
		}
		var e error
		v, e = applyVersion(v, in)
		if e != nil {
			return e
		}
		return tx.Omit("Application").Save(&v).Error
	})
	return VersionDTO(v), versionDuplicate(e)
}
func (s *Service) DeleteVersion(ctx context.Context, id uint64) error {
	return deleteRelease[model.AppVersion](s.db.WithContext(ctx), id, "软件版本")
}

func getRelease[M, D any](db *gorm.DB, id uint64, dto func(M) D, kind string) (D, error) {
	var v M
	err := db.First(&v, id).Error
	return dto(v), missing(err, kind)
}
func deleteRelease[M any](db *gorm.DB, id uint64, kind string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var v M
		if err := tx.First(&v, id).Error; err != nil {
			return missing(err, kind)
		}
		return tx.Delete(&v).Error
	})
}
