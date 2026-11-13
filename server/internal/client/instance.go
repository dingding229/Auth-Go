package client

import (
	"authgo/internal/code"
	"authgo/internal/model"
	"gorm.io/gorm"
)

// The carrier key binds a cached activation; floating rows additionally bind the
// stable instance fingerprint when a fresh activation token is issued.
func ownsInstance(a model.Activation, sessionID, device string) bool {
	return a.Kind == "key" && a.Value == sessionID || a.Kind == "floating" && (a.Value == sessionID || a.Value == device)
}
func instanceCheck(tx *gorm.DB, rows []model.Activation, sessionID, device, incoming string, takeover bool) (string, error) {
	if incoming == "" {
		return "", nil
	}
	for _, a := range rows {
		if !ownsInstance(a, sessionID, device) || a.InstanceSession == incoming {
			continue
		}
		var seen int64
		if e := tx.Table("activation_instance_sessions").Where("activation_id=? AND session=?", a.ID, incoming).Count(&seen).Error; e != nil {
			return "", e
		}
		if seen > 0 || !takeover {
			return code.InstanceReplaced, nil
		}
	}
	return "", nil
}
func rememberInstance(tx *gorm.DB, id uint64, session string) error {
	if session == "" {
		return nil
	}
	if e := tx.Exec("INSERT INTO activation_instance_sessions(activation_id,session) VALUES (?,?) ON CONFLICT DO NOTHING", id, session).Error; e != nil {
		return e
	}
	return tx.Exec(`DELETE FROM activation_instance_sessions WHERE activation_id=? AND rowid NOT IN
        (SELECT rowid FROM activation_instance_sessions WHERE activation_id=? ORDER BY rowid DESC LIMIT 32)`, id, id).Error
}
func claimInstances(tx *gorm.DB, rows []model.Activation, sessionID, device, incoming string) error {
	if incoming == "" {
		return nil
	}
	for i := range rows {
		a := &rows[i]
		if !ownsInstance(*a, sessionID, device) || a.InstanceSession == incoming {
			continue
		}
		if e := rememberInstance(tx, a.ID, a.InstanceSession); e != nil {
			return e
		}
		if e := rememberInstance(tx, a.ID, incoming); e != nil {
			return e
		}
		if e := tx.Model(&model.Activation{}).Where("id=?", a.ID).Update("instance_session", incoming).Error; e != nil {
			return e
		}
		a.InstanceSession = incoming
	}
	return nil
}
