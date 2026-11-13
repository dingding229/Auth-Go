package auth

import (
	"authgo/internal/bootstrap"
	"authgo/internal/model"
	"context"
	"gorm.io/gorm"
	"time"
)

// Setup issues the initial JWT pair in the same transaction as account creation,
// avoiding a half-initialized result or interference from login-failure counters.
func (s *Service) Setup(ctx context.Context, setup *bootstrap.Setup, token, username, password, ip string) (*TokenPair, error) {
	var pair *TokenPair
	err := setup.Complete(ctx, token, username, password, ip, func(tx *gorm.DB, a model.Admin) error {
		sid, err := randomToken(24)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		pair, err = s.pair(a, sid, now.Add(RefreshTTL))
		if err != nil {
			return err
		}
		return tx.Create(&model.AdminSession{ID: sid, AdminID: a.ID, TokenHash: hashToken(pair.RefreshToken), AuthVersion: a.AuthVersion, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour)}).Error
	})
	return pair, err
}
