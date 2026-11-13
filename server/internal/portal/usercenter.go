package portal

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strconv"
)

type userEndpoint func(*gin.Context, identity) (any, error)

func (s *Service) userOnly(fn userEndpoint) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.MustGet("portal_identity").(identity)
		if !id.UserScope || id.User == nil {
			s.reply(c, &id, nil, unauthorized())
			return
		}
		v, e := fn(c, id)
		s.reply(c, &id, v, e)
	}
}
func userID(c *gin.Context, key string) (uint64, error) {
	raw := c.Query(key)
	if raw == "" {
		return 0, nil
	}
	id, e := strconv.ParseUint(raw, 10, 63)
	if e != nil || id == 0 {
		return 0, apperror.Invalid("筛选编号必须为正整数")
	}
	return id, nil
}
func pathID(c *gin.Context) (uint64, error) {
	id, e := strconv.ParseUint(c.Param("id"), 10, 63)
	if e != nil || id == 0 {
		return 0, apperror.Invalid("授权编号必须为正整数")
	}
	return id, nil
}
func userPage(c *gin.Context, defaultSize int) (response.Page, error) {
	q := c.Request.URL.Query()
	if !q.Has("page_size") {
		q.Set("page_size", strconv.Itoa(defaultSize))
	}
	return response.ParsePage(q)
}
func ownedLicenses(db *gorm.DB, user uint64) *gorm.DB {
	return db.Model(&model.License{}).Where("user_id=?", user)
}
func (s *Service) allUserLicenses(c *gin.Context, user uint64) ([]model.License, error) {
	query := ownedLicenses(s.db.WithContext(c.Request.Context()), user)
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
			query = query.Where(field+"=?", v)
		}
	}
	out := []model.License{}
	e := query.Preload("Application").Order("id").Find(&out).Error
	return out, e
}
func (s *Service) ownedIdentity(ctx context.Context, user, license uint64) (identity, error) {
	selected, e := s.identity(ctx, s.db.Where("id=? AND user_id=?", license, user))
	if e != nil {
		var safe *apperror.Error
		if errors.As(e, &safe) && safe.Status == 401 {
			return selected, apperror.NotFound()
		}
		return selected, e
	}
	selected.UserScope = true
	return selected, nil
}
func (s *Service) registerUserOverview(root *gin.RouterGroup) {
	root.GET("/user/attention", s.userOnly(s.userAttention))
	root.GET("/user/logs", s.userOnly(s.userLogs))
	root.GET("/user/updates", s.userOnly(s.userUpdates))
	root.GET("/user/announcements", s.userOnly(s.userAnnouncements))
	root.GET("/licenses/:id", s.userOnly(s.userLicenseDetail))
	root.GET("/user/instances", s.userOnly(s.userInstances))
}
func (s *Service) userLicenses(c *gin.Context, id identity) (any, error) {
	now := s.now().UTC()
	q, e := response.ParseList(c.Request.URL.Query(), "id", "created_at", "expires_at")
	if e != nil {
		return nil, e
	}
	tx := s.db.WithContext(c.Request.Context())
	query := ownedLicenses(tx, id.User.ID)
	switch status := c.Query("status"); status {
	case "":
	case "expired":
		query = query.Where("(status='expired' OR (status IN ? AND expires_at<=?))", []string{"active", "unused"}, now)
	case "active", "unused":
		query = query.Where("status=? AND (expires_at IS NULL OR expires_at>?)", status, now)
	case "suspended", "revoked":
		query = query.Where("status=?", status)
	default:
		return nil, apperror.Invalid("授权状态筛选无效")
	}
	app, e := userID(c, "app_id")
	if e != nil {
		return nil, e
	}
	if app != 0 {
		query = query.Where("app_id=?", app)
	}
	var n int64
	if e = query.Count(&n).Error; e != nil {
		return nil, e
	}
	licenses := []model.License{}
	if e = q.Apply(query).Preload("Application").Find(&licenses).Error; e != nil {
		return nil, e
	}
	snapshot, e := s.userSnapshot(c.Request.Context(), licenses)
	if e != nil {
		return nil, e
	}
	out := make([]UserLicense, 0, len(licenses))
	for _, l := range licenses {
		out = append(out, snapshot.card(l, now))
	}
	return q.Data(out, n), nil
}
func (s *Service) userLicenseDetail(c *gin.Context, id identity) (any, error) {
	now := s.now().UTC()
	lid, e := pathID(c)
	if e != nil {
		return nil, e
	}
	selected, e := s.ownedIdentity(c.Request.Context(), id.User.ID, lid)
	if e != nil {
		return nil, e
	}
	l := selected.License
	l.Application = selected.App
	snapshot, e := s.userSnapshot(c.Request.Context(), []model.License{l})
	if e != nil {
		return nil, e
	}
	contact, e := supportContact(c.Request.Context(), s.db)
	if e != nil {
		return nil, e
	}
	card := snapshot.card(l, now)
	choice := snapshot.choose(l, now)
	return UserLicenseDetail{UserLicense: card, Features: l.Features, StartsAt: l.StartsAt, MatchMode: l.MatchMode, SupportContact: contact, Deployment: s.deployment(card, choice, usable(l, now))}, nil
}
func (s *Service) userInstances(c *gin.Context, id identity) (any, error) {
	now := s.now().UTC()
	q, e := userPage(c, 20)
	if e != nil {
		return nil, e
	}
	tx := s.db.WithContext(c.Request.Context())
	owned := ownedLicenses(tx, id.User.ID)
	app, e := userID(c, "app_id")
	if e != nil {
		return nil, e
	}
	if app != 0 {
		owned = owned.Where("app_id=?", app)
	}
	license, e := userID(c, "license_id")
	if e != nil {
		return nil, e
	}
	if license != 0 {
		owned = owned.Where("id=?", license)
	}
	query := tx.Model(&model.Activation{}).Where("kind='floating' AND license_id IN (?)", owned.Select("id"))
	var n int64
	if e = query.Count(&n).Error; e != nil {
		return nil, e
	}
	rows := []model.Activation{}
	if e = query.Order("id DESC").Offset(q.Offset()).Limit(q.Size).Find(&rows).Error; e != nil {
		return nil, e
	}
	ids := []uint64{}
	ips := []string{}
	for _, r := range rows {
		ids = append(ids, r.LicenseID)
		ips = append(ips, r.LastIP)
	}
	licenses := []model.License{}
	if len(ids) > 0 {
		if e = ownedLicenses(tx, id.User.ID).Where("id IN ?", ids).Preload("Application").Find(&licenses).Error; e != nil {
			return nil, e
		}
	}
	byID := map[uint64]model.License{}
	for _, l := range licenses {
		byID[l.ID] = l
	}
	locations := s.ipinfo.LookupBatch(ips)
	out := []UserInstance{}
	for _, a := range rows {
		l, ok := byID[a.LicenseID]
		if !ok {
			continue
		}
		out = append(out, UserInstance{ID: a.ID, LicenseID: a.LicenseID, AppID: l.AppID, AppName: l.Application.Name, Hostname: a.Hostname, OS: a.OS, Kind: a.Kind, Status: a.Status, Online: online(a, now), ClientVersion: a.ClientVersion, LastIP: MaskIP(a.LastIP), IPInfo: locations[a.LastIP], LastSeenAt: a.LastSeenAt, LeaseExpiresAt: a.LeaseExpiresAt})
	}
	return q.Data(out, n), nil
}
