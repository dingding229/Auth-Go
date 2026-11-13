package licensing

import (
	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"errors"
	"gorm.io/gorm"
	"strconv"
	"time"
)

type LicenseInfo struct {
	SuspectedSharing  bool          `json:"suspected_sharing,omitempty"`
	OnlineInstances   int64         `json:"online_instances"`
	AppName           string        `json:"app_name"`
	ActiveActivations int64         `json:"active_activations"`
	ID                uint64        `json:"id"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
	AppID             uint64        `json:"app_id"`
	UserID            *uint64       `json:"user_id"`
	UserName          string        `json:"user_name"`
	UserEmail         string        `json:"user_email"`
	Key               string        `json:"key"`
	BatchID           string        `json:"batch_id"`
	Type              string        `json:"type"`
	Status            string        `json:"status"`
	VerifyMethods     []string      `json:"verify_methods"`
	MatchMode         string        `json:"match_mode"`
	MaxActivations    int           `json:"max_activations"`
	Features          model.JSONMap `json:"features"`
	ValidityRule      string        `json:"validity_rule"`
	StartsAt          *time.Time    `json:"starts_at"`
	ExpiresAt         *time.Time    `json:"expires_at"`
	DurationDays      int           `json:"duration_days"`
	HasPortalPassword bool          `json:"has_portal_password"`
	Note              string        `json:"note"`
	Metadata          model.JSONMap `json:"metadata"`
	MaintenanceUntil  *time.Time    `json:"maintenance_until"`
	Source            string        `json:"source"`
	ConvertedAt       *time.Time    `json:"converted_at"`
}

func info(l model.License) LicenseInfo {
	methods := l.VerifyMethods
	if methods == nil {
		methods = []string{}
	}
	features, metadata := l.Features, l.Metadata
	if features == nil {
		features = model.JSONMap{}
	}
	if metadata == nil {
		metadata = model.JSONMap{}
	}
	userName, userEmail := "", ""
	if l.User != nil {
		userName, userEmail = l.User.Name, l.User.Email
	}
	return LicenseInfo{false, 0, l.Application.Name, 0, l.ID, l.CreatedAt, l.UpdatedAt, l.AppID, l.UserID, userName, userEmail, l.Key, l.BatchID, l.Type, l.Status, methods, l.MatchMode, l.MaxActivations, features, l.ValidityRule, l.StartsAt, l.ExpiresAt, l.DurationDays, l.PortalPasswordHash != "", l.Note, metadata, l.MaintenanceUntil, l.Source, l.ConvertedAt}
}
func (s *Service) Create(ctx context.Context, in CreateInput) (LicenseInfo, error) {
	if in.UserID == nil {
		return LicenseInfo{}, apperror.Invalid("单个发放必须选择用户")
	}
	l, prefix, err := s.prepare(ctx, in)
	if err != nil {
		return LicenseInfo{}, err
	}
	l.Key, err = s.generate(prefix)
	if err != nil {
		return LicenseInfo{}, err
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error { return tx.Omit("User", "Application").Create(&l).Error })
	return info(l), writeError(err)
}
func writeError(err error) error {
	if duplicate(err) {
		return apperror.New(409, "CONFLICT", "授权码或绑定值已存在")
	}
	var coded interface{ Code() int }
	if err != nil && errors.As(err, &coded) && (coded.Code() == 787 || coded.Code() == 1811) {
		return apperror.New(409, "CONFLICT", "关联数据发生变化，请重新提交")
	}
	return err
}

type BatchResult struct {
	BatchID string `json:"batch_id"`
	Count   int    `json:"count"`
}

func (s *Service) Batch(ctx context.Context, in BatchInput) (BatchResult, error) {
	if in.Count == 1 && in.UserID == nil {
		return BatchResult{}, apperror.Invalid("单个发放必须选择用户")
	}
	if in.Count < 1 || in.Count > MaxBatch {
		return BatchResult{}, apperror.Invalid("批量数量必须为 1 至 10000")
	}
	template, prefix, err := s.prepare(ctx, in.CreateInput)
	if err != nil {
		return BatchResult{}, err
	}
	batch, err := cryptoutil.RandomString(18)
	if err != nil {
		return BatchResult{}, err
	}
	batch = "batch_" + batch
	rows := make([]model.License, 0, in.Count)
	seen := make(map[string]bool, in.Count)
	for i := 0; i < in.Count; i++ {
		if err := ctx.Err(); err != nil {
			return BatchResult{}, err
		}
		var key string
		for tries := 0; tries < 16; tries++ {
			key, err = s.generate(prefix)
			if err != nil {
				return BatchResult{}, err
			}
			if !seen[key] {
				break
			}
			key = ""
		}
		if key == "" {
			return BatchResult{}, apperror.New(500, "KEY_GENERATION_FAILED", "无法生成唯一授权码")
		}
		seen[key] = true
		l := template
		l.Base = model.Base{}
		l.Key = key
		l.BatchID = batch
		rows = append(rows, l)
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error { return tx.Omit("User", "Application").CreateInBatches(&rows, 200).Error })
	if err != nil {
		return BatchResult{}, writeError(err)
	}
	return BatchResult{batch, in.Count}, nil
}

type Filter struct {
	SuspectedSharing              bool
	Query                         response.ListQuery
	AppID                         *uint64
	UserID                        *uint64
	Status, Type, BatchID, Source string
	ExpiresFrom, ExpiresTo        *time.Time
}

func filterQuery(tx *gorm.DB, f Filter) *gorm.DB {
	q := tx.Model(&model.License{})
	if f.UserID != nil {
		q = q.Where("licenses.user_id=?", *f.UserID)
	}
	if f.AppID != nil {
		q = q.Where("licenses.app_id = ?", *f.AppID)
	}

	if f.Source != "" {
		q = q.Where("licenses.source=?", f.Source)
	}
	if f.Status != "" {
		q = q.Where("licenses.status = ?", f.Status)
	}
	if f.Type != "" {
		q = q.Where("licenses.type = ?", f.Type)
	}
	if f.BatchID != "" {
		q = q.Where("licenses.batch_id = ?", f.BatchID)
	}
	if f.ExpiresFrom != nil {
		q = q.Where("licenses.expires_at >= ?", *f.ExpiresFrom)
	}
	if f.ExpiresTo != nil {
		q = q.Where("licenses.expires_at <= ?", *f.ExpiresTo)
	}
	if f.Query.Q != "" {
		p := like(f.Query.Q)
		q = q.Where(`(licenses.key LIKE ? ESCAPE '\' OR licenses.note LIKE ? ESCAPE '\' OR EXISTS (SELECT 1 FROM end_users WHERE end_users.id=licenses.user_id AND (end_users.name LIKE ? ESCAPE '\' OR end_users.email LIKE ? ESCAPE '\')))`, p, p, p, p)
	}
	return q
}
func (s *Service) List(ctx context.Context, f Filter) ([]LicenseInfo, int64, error) {
	q := s.sharingFilter(filterQuery(s.db.WithContext(ctx), f), f)
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	type listLicense struct {
		model.License
		SharingFlag bool `gorm:"column:sharing_flag"`
	}
	var rows []listLicense
	q = q.Select("licenses.*")
	if s.sharing.Available() {
		q = s.sharing.WithFlag(q, s.now().UTC())
	}
	if err := f.Query.Apply(q).Preload("User").Preload("Application", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", "name") }).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	ids := make([]uint64, 0, len(rows))
	for _, l := range rows {
		ids = append(ids, l.ID)
	}
	counts, err := activationUsageCounts(s.db.WithContext(ctx), ids, s.now().UTC())
	if err != nil {
		return nil, 0, err
	}
	result := make([]LicenseInfo, 0, len(rows))
	for _, l := range rows {
		item := info(l.License)
		item.SuspectedSharing = l.SharingFlag
		item.ActiveActivations = counts[l.ID].Active
		item.OnlineInstances = counts[l.ID].Online
		result = append(result, item)
	}
	return result, total, nil
}

type Detail struct {
	LicenseInfo
	Activations          []ActivationInfo `json:"activations"`
	ActivationsTotal     int64            `json:"activations_total"`
	ActivationsTruncated bool             `json:"activations_truncated"`
}

func (s *Service) Get(ctx context.Context, id uint64) (Detail, error) {
	tx := s.db.WithContext(ctx)
	l, err := findLicense(tx, id)
	if err != nil {
		return Detail{}, err
	}
	var total int64
	if err := tx.Model(&model.Activation{}).Where("license_id = ?", id).Count(&total).Error; err != nil {
		return Detail{}, err
	}
	var rows []model.Activation
	if err := tx.Where("license_id = ?", id).Order("id DESC").Limit(1000).Find(&rows).Error; err != nil {
		return Detail{}, err
	}
	activations := make([]ActivationInfo, 0, len(rows))
	for _, a := range rows {
		activations = append(activations, activationInfo(a))
	}
	s.enrichActivations(activations)
	counts, err := activationUsageCounts(tx, []uint64{id}, s.now().UTC())
	if err != nil {
		return Detail{}, err
	}
	detail := info(l)
	detail.OnlineInstances = counts[id].Online
	detail.ActiveActivations = counts[id].Active
	return Detail{detail, activations, total, total > 1000}, nil
}
func validStatus(status string) bool {
	switch status {
	case "unused", "active", "expired", "suspended", "revoked":
		return true
	}
	return false
}
func validType(value string) bool {
	switch value {
	case "trial", "standard", "subscription", "perpetual", "floating":
		return true
	}
	return false
}
func batchIDValid(value string) bool {
	return len(value) == 30 && value[:6] == "batch_" && validBatchSuffix(value[6:])
}
func validBatchSuffix(value string) bool {
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func idString(id uint64) string { return strconv.FormatUint(id, 10) }

type activationUsage struct {
	LicenseID uint64
	Active    int64
	Online    int64
}

// activationUsageCounts keeps KEY usage and online floating leases in one grouped read.
func activationUsageCounts(tx *gorm.DB, ids []uint64, now time.Time) (map[uint64]activationUsage, error) {
	counts := map[uint64]activationUsage{}
	if len(ids) == 0 {
		return counts, nil
	}
	var rows []activationUsage
	err := tx.Model(&model.Activation{}).Select("license_id, COUNT(*) AS active, SUM(CASE WHEN kind='floating' AND offline_at IS NULL AND lease_expires_at>? THEN 1 ELSE 0 END) AS online", now).Where("license_id IN ? AND status='active'", ids).Group("license_id").Scan(&rows).Error
	for _, row := range rows {
		counts[row.LicenseID] = row
	}
	return counts, err
}
