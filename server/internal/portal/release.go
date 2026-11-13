package portal

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"authgo/internal/seats"
	"context"
	"errors"
	"gorm.io/gorm"
)

func (s *Service) releaseSelf(ctx context.Context, lid, aid uint64, uid ...uint64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var l model.License
		if e := tx.Preload("User").First(&l, lid).Error; e != nil {
			if errors.Is(e, gorm.ErrRecordNotFound) {
				return apperror.NotFound()
			}
			return e
		}
		if len(uid) > 0 && (l.UserID == nil || *l.UserID != uid[0]) {
			return apperror.NotFound()
		}
		if l.UserID != nil && (l.User == nil || l.User.Status != "active") {
			return apperror.New(403, "USER_DISABLED", "用户已停用")
		}
		var a model.Activation
		if e := tx.Where("id=? AND license_id=?", aid, lid).First(&a).Error; e != nil {
			if errors.Is(e, gorm.ErrRecordNotFound) {
				return apperror.NotFound()
			}
			return e
		}
		return seats.Release(tx, a, s.now().UTC(), "portal")
	})
}
