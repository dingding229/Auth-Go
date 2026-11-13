package licensing

import (
	"authgo/internal/apperror"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/ipinfo"
	"authgo/internal/model"
	"authgo/internal/response"
	"authgo/internal/seats"
	"context"
	"errors"
	"gorm.io/gorm"
	"time"
)

type ActivationInfo struct {
	IPInfo         *ipinfo.Info `json:"ip_info,omitempty"`
	InstanceID     string       `json:"instance_id"`
	LicenseKey     string       `json:"license_key"`
	ID             uint64       `json:"id"`
	LicenseID      uint64       `json:"license_id"`
	Kind           string       `json:"kind"`
	Hostname       string       `json:"hostname"`
	OS             string       `json:"os"`
	ClientVersion  string       `json:"client_version"`
	FirstIP        string       `json:"first_ip"`
	LastIP         string       `json:"last_ip"`
	LastSeenAt     *time.Time   `json:"last_seen_at"`
	Status         string       `json:"status"`
	LeaseExpiresAt *time.Time   `json:"lease_expires_at"`
	OfflineAt      *time.Time   `json:"offline_at"`
	CreatedAt      time.Time    `json:"created_at"`
}

func activationInfo(a model.Activation) ActivationInfo {
	return ActivationInfo{IPInfo: nil, InstanceID: a.Value, LicenseKey: a.License.Key, ID: a.ID, LicenseID: a.LicenseID, Kind: a.Kind, Hostname: a.Hostname, OS: a.OS, ClientVersion: a.ClientVersion, FirstIP: a.FirstIP, LastIP: a.LastIP, LastSeenAt: a.LastSeenAt, Status: a.Status, LeaseExpiresAt: a.LeaseExpiresAt, OfflineAt: a.OfflineAt, CreatedAt: a.CreatedAt}
}

type ActivationFilter struct {
	Kind   string
	UserID *uint64
}

func (s *Service) ListActivations(ctx context.Context, q response.ListQuery, licenseID *uint64, filters ...ActivationFilter) ([]ActivationInfo, int64, error) {
	tx := s.db.WithContext(ctx)
	if licenseID != nil {
		if _, err := findLicense(tx, *licenseID); err != nil {
			return nil, 0, err
		}
	}
	query := tx.Model(&model.Activation{}).Where("kind IN ?", []string{"floating", "key"})
	if len(filters) > 0 {
		switch filters[0].Kind {
		case "":
		case "floating", "key":
			query = query.Where("kind=?", filters[0].Kind)
		default:
			return nil, 0, apperror.Invalid("实例记录类型无效")
		}
		if filters[0].UserID != nil {
			query = query.Where("license_id IN (SELECT id FROM licenses WHERE user_id=?)", *filters[0].UserID)
		}

	}
	if licenseID != nil {
		query = query.Where("license_id = ?", *licenseID)
	}
	if q.Q != "" {
		p := like(q.Q)
		query = query.Where(`(hostname LIKE ? ESCAPE '\' OR value LIKE ? ESCAPE '\' OR last_ip LIKE ? ESCAPE '\')`, p, p, p)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []model.Activation
	if err := q.Apply(query).Preload("License", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", "key") }).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	// Request-style PHP instances store the session ID in Value. Resolve their
	// actual fingerprint in one batch without changing the binding itself.
	values := make([]string, 0, len(rows))
	for _, a := range rows {
		values = append(values, a.Value)
	}
	sessions := []model.ClientSession{}
	if len(values) > 0 {
		if err := tx.Select("id", "license_id", "device").Where("id IN ?", values).Find(&sessions).Error; err != nil {
			return nil, 0, err
		}
	}
	sessionDevices := map[string]model.ClientSession{}
	for _, session := range sessions {
		sessionDevices[session.ID] = session
	}
	items := make([]ActivationInfo, 0, len(rows))
	for _, a := range rows {
		item := activationInfo(a)
		if session, ok := sessionDevices[a.Value]; ok && session.LicenseID == a.LicenseID && session.Device != "" {
			item.InstanceID = session.Device
		}
		items = append(items, item)
	}
	s.enrichActivations(items)
	return items, total, nil
}
func (s *Service) ManageActivation(ctx context.Context, id uint64, unbind bool) (ActivationInfo, error) {
	var result model.Activation
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var a model.Activation
		if err := tx.First(&a, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return apperror.NotFound()
			}
			return err
		}
		if a.Status != "active" {
			return apperror.New(409, "INVALID_TRANSITION", "仅活动激活可以停用或标记下线")
		}
		token, err := cryptoutil.RandomString(32)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		// Administrative force operations revoke every session bound to this carrier;
		// a later heartbeat must not reacquire through an already revoked proof.
		if err := tx.Model(&model.ClientSession{}).Where("id IN (SELECT session_id FROM client_session_bindings WHERE activation_id=?) AND revoked_at IS NULL", a.ID).Update("revoked_at", now).Error; err != nil {
			return err
		}
		values := map[string]any{"token": "invalidated_" + token, "offline_at": now, "lease_expires_at": now}
		if unbind {
			values["status"] = "unbound"
			values["unbound_at"] = now
		}
		if err := tx.Model(&model.Activation{}).Where("id = ?", id).Updates(values).Error; err != nil {
			return err
		}
		return tx.First(&result, id).Error
	})

	return activationInfo(result), err
}

// ReleaseSeat deletes the floating instance and audits it in the same transaction.
// A running program may compete for a seat again at its next heartbeat.
func (s *Service) ReleaseSeat(ctx context.Context, id uint64) (ActivationInfo, error) {
	var a model.Activation
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Preload("License").First(&a, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return apperror.NotFound()
			}
			return err
		}
		if a.Kind != "floating" || a.Status != "active" {
			return apperror.New(409, "INVALID_TRANSITION", "仅活动运行实例可以释放席位")
		}
		now := s.now().UTC()
		if err := seats.Release(tx, a, now, "admin"); err != nil {
			return err
		}
		a.LeaseExpiresAt = &now
		return nil
	})
	return activationInfo(a), err
}

func (s *Service) enrichActivations(rows []ActivationInfo) {
	ips := make([]string, 0, len(rows))
	for _, r := range rows {
		ips = append(ips, r.LastIP)
	}
	locations := s.ipinfo.LookupBatch(ips)
	for i := range rows {
		rows[i].IPInfo = locations[rows[i].LastIP]
	}
}
