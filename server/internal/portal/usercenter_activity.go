package portal

import (
	"authgo/internal/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (s *Service) userLogs(c *gin.Context, id identity) (any, error) {
	page, e := userPage(c, 10)
	if e != nil {
		return nil, e
	}
	tx := s.db.WithContext(c.Request.Context())
	owned := ownedLicenses(tx, id.User.ID)
	for _, key := range []string{"app_id", "license_id"} {
		v, e := userID(c, key)
		if e != nil {
			return nil, e
		}
		if v != 0 {
			field := "app_id"
			if key == "license_id" {
				field = "id"
			}
			owned = owned.Where(field+"=?", v)
		}
	}
	query := tx.Model(&model.VerifyLog{}).Where("license_id IN (?)", owned.Select("id"))
	var total int64
	if e = query.Count(&total).Error; e != nil {
		return nil, e
	}
	rows := []model.VerifyLog{}
	if e = query.Order("created_at DESC,id DESC").Offset(page.Offset()).Limit(page.Size).Preload("License.Application").Find(&rows).Error; e != nil {
		return nil, e
	}
	ips := []string{}
	for _, r := range rows {
		ips = append(ips, r.IP)
	}
	locations := s.ipinfo.LookupBatch(ips)
	out := []UserLog{}
	for _, r := range rows {
		if r.License == nil || r.License.UserID == nil || *r.License.UserID != id.User.ID {
			continue
		}
		out = append(out, UserLog{ID: r.ID, LicenseID: r.LicenseID, AppID: r.License.AppID, AppName: r.License.Application.Name, CreatedAt: r.CreatedAt, Action: r.Action, Code: r.Code, Success: r.Success, IP: MaskIP(r.IP), IPInfo: locations[r.IP], ClientVersion: r.ClientVersion, DurationMS: r.DurationMS})
	}
	return page.Data(out, total), nil
}
func (s *Service) userAnnouncements(c *gin.Context, id identity) (any, error) {
	page, e := userPage(c, 20)
	if e != nil {
		return nil, e
	}
	tx := s.db.WithContext(c.Request.Context())
	apps := ownedLicenses(tx, id.User.ID)
	app, e := userID(c, "app_id")
	if e != nil {
		return nil, e
	}
	if app != 0 {
		apps = apps.Where("app_id=?", app)
	}
	license, e := userID(c, "license_id")
	if e != nil {
		return nil, e
	}
	if license != 0 {
		apps = apps.Where("id=?", license)
	}
	now := s.now().UTC()
	query := tx.Model(&model.Announcement{}).Where("app_id IN (?)", apps.Select("app_id")).Where("published_at IS NOT NULL AND published_at<=? AND (expires_at IS NULL OR expires_at>?)", now, now)
	var total int64
	if e = query.Count(&total).Error; e != nil {
		return nil, e
	}
	rows := []model.Announcement{}
	if e = query.Order("published_at DESC,id DESC").Offset(page.Offset()).Limit(page.Size).Preload("Application", func(db *gorm.DB) *gorm.DB { return db.Select("id,name") }).Find(&rows).Error; e != nil {
		return nil, e
	}
	out := []UserAnnouncement{}
	for _, r := range rows {
		out = append(out, UserAnnouncement{ID: r.ID, AppID: r.AppID, AppName: r.Application.Name, Title: r.Title, Content: r.Content, PublishedAt: r.PublishedAt, ExpiresAt: r.ExpiresAt})
	}
	return page.Data(out, total), nil
}
