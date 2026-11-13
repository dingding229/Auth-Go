package client

import (
	"authgo/internal/model"
	"gorm.io/gorm"
	"time"
)

// Count only sessions whose every generation is still live. Admin force-offline,
// unbind and revoke already change those generations in license.
func liveOthers(tx *gorm.DB, licenseID uint64, excluding string, activationID *uint64) (int64, error) {
	q := tx.Table("client_sessions AS s").Where("s.license_id = ? AND s.id <> ? AND s.revoked_at IS NULL", licenseID, excluding).
		Where(`EXISTS (SELECT 1 FROM client_session_bindings k JOIN activations a ON a.id=k.activation_id WHERE k.session_id=s.id AND a.kind='key' AND a.value=s.id)`).
		Where(`NOT EXISTS (SELECT 1 FROM client_session_bindings b JOIN activations a ON a.id=b.activation_id WHERE b.session_id=s.id AND (a.status <> 'active' OR a.offline_at IS NOT NULL OR a.token <> b.generation))`)
	if activationID != nil {
		q = q.Where("EXISTS (SELECT 1 FROM client_session_bindings r WHERE r.session_id=s.id AND r.activation_id=?)", *activationID)
	}
	var n int64
	err := q.Count(&n).Error
	return n, err
}
func deactivate(tx *gorm.DB, l *model.License, s model.ClientSession, rows []model.Activation, now time.Time) (string, error) {
	var refs []model.ClientSessionBinding
	if err := tx.Where("session_id = ?", s.ID).Find(&refs).Error; err != nil {
		return "", err
	}
	release := []model.Activation{}
	for _, ref := range refs {
		for _, a := range rows {
			if a.ID != ref.ActivationID {
				continue
			}
			n, err := liveOthers(tx, l.ID, s.ID, &a.ID)
			if err != nil {
				return "", err
			}
			if n == 0 {
				release = append(release, a)
			}
		}
	}
	if err := tx.Model(&s).Updates(map[string]any{"revoked_at": now, "updated_at": now}).Error; err != nil {
		return "", err
	}
	for _, a := range release {
		g, err := generation()
		if err != nil {
			return "", err
		}
		updates := map[string]any{"status": "unbound", "token": g, "unbound_at": now, "lease_expires_at": now}
		if err := tx.Model(&a).Updates(updates).Error; err != nil {
			return "", err
		}
	}
	return "", nil
}
