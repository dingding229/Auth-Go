package service

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"authgo/internal/seats"
	"context"
	"errors"
	"gorm.io/gorm"
	"log/slog"
	"time"
)

type Options struct{ Now func() time.Time }
type Service struct {
	db  *gorm.DB
	now func() time.Time
}

func New(d *gorm.DB, _ []byte, _ *slog.Logger, o Options) (*Service, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{d, o.Now}, nil
}
func (s *Service) Close(context.Context) error { return nil }
func (s *Service) ReleaseSelf(ctx context.Context, lid, aid uint64, uid ...uint64) error {
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
