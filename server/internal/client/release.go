package client

import (
	"authgo/internal/model"
	"authgo/internal/seats"
	"gorm.io/gorm"
	"time"
)

// Delete the floating instance while preserving the independent session anchor.
func releaseSeat(tx *gorm.DB, rows []model.Activation, sessionID, device string, now time.Time) (bool, error) {
	released := false
	for _, a := range rows {
		if a.Kind != "floating" || !ownsInstance(a, sessionID, device) {
			continue
		}
		if e := seats.Release(tx, a, now, "sdk"); e != nil {
			return false, e
		}
		released = true
	}
	return released, nil
}
