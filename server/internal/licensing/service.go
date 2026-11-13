// Package licensing implements management-side issuance and state changes only.
// Client activation, policy evaluation and heartbeat renewal belong to client.
package licensing

import (
	"authgo/internal/apperror"
	"authgo/internal/ipinfo"
	"authgo/internal/licensekey"
	"authgo/internal/model"
	"authgo/internal/sharing"
	"errors"
	"gorm.io/gorm"
	"strings"
	"time"
)

const MaxBatch = 10000
const MaxCSVBytes = 16 << 20

type Service struct {
	sharing  *sharing.Service
	ipinfo   *ipinfo.Service
	db       *gorm.DB
	now      func() time.Time
	generate func(string) (string, error)
}

func NewService(database *gorm.DB) *Service { return NewServiceWithClock(database, time.Now) }
func NewServiceWithClock(database *gorm.DB, now func() time.Time) *Service {
	return &Service{db: database, now: now, generate: licensekey.Generate}
}
func findLicense(tx *gorm.DB, id uint64) (model.License, error) {
	var l model.License
	err := tx.Preload("User").Preload("Application", func(tx *gorm.DB) *gorm.DB { return tx.Select("id", "name") }).First(&l, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = apperror.NotFound()
	}
	return l, err
}
func transitionError() error {
	return apperror.New(409, "INVALID_TRANSITION", "当前授权状态不允许此操作")
}
func like(query string) string {
	return "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(query) + "%"
}
func duplicate(err error) bool {
	var coded interface{ Code() int }
	return errors.As(err, &coded) && (coded.Code() == 2067 || coded.Code() == 1555)
}

func (s *Service) SetIPInfo(v *ipinfo.Service) { s.ipinfo = v }

func (s *Service) SetSharing(v *sharing.Service) { s.sharing = v }
func (s *Service) sharingFilter(q *gorm.DB, f Filter) *gorm.DB {
	if f.SuspectedSharing {
		return s.sharing.Filter(q, s.now().UTC())
	}
	return q
}
