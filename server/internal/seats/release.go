package seats

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"gorm.io/gorm"
	"strconv"
	"time"
)

// Release removes the visible instance and its generation references atomically.
// The independent KEY anchor remains: the same signed session can compete again
// on a later heartbeat, without rotating credentials or expanding grace.
func Release(tx *gorm.DB, a model.Activation, now time.Time, source string) error {
	if a.Kind != "floating" || a.Status != "active" {
		return apperror.New(409, "INVALID_TRANSITION", "仅活动运行实例可以释放席位")
	}
	audit := model.AuditLog{CreatedAt: now, Action: "instance.release", Resource: "instance", ResourceID: strconv.FormatUint(a.ID, 10), Operator: source, IP: a.LastIP, StatusCode: 200, Summary: "实例已释放并删除", Details: map[string]any{"license_id": a.LicenseID}}
	if err := tx.Create(&audit).Error; err != nil {
		return err
	}
	if err := tx.Where("activation_id=?", a.ID).Delete(&model.ClientSessionBinding{}).Error; err != nil {
		return err
	}
	// Historical verification rows survive, without a dangling instance FK.
	if err := tx.Model(&model.VerifyLog{}).Where("activation_id=?", a.ID).Update("activation_id", nil).Error; err != nil {
		return err
	}
	return tx.Delete(&a).Error
}
