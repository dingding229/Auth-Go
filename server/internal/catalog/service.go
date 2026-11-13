// Package catalog manages applications and releases. HTTP authorization
// and auditing are enforced by the management router before these operations.
package catalog

import (
	"authgo/internal/apperror"
	"authgo/internal/channel"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"errors"
	"gorm.io/gorm"
	"strings"
	"time"
	"unicode"
)

type Service struct {
	channel *channel.Store
	db      *gorm.DB
	cipher  *cryptoutil.Cipher
}

func NewService(database *gorm.DB, master []byte) (*Service, error) {
	box, err := cryptoutil.NewCipher(master)
	if err != nil {
		return nil, err
	}
	keys, err := channel.New(database, master)
	if err != nil {
		return nil, err
	}
	return &Service{db: database, cipher: box, channel: keys}, nil
}

type BaseInfo struct {
	ID        uint64    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func baseInfo(base model.Base) BaseInfo { return BaseInfo{base.ID, base.CreatedAt, base.UpdatedAt} }
func missing(err error, label string) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apperror.New(404, "NOT_FOUND", label+"不存在")
	}
	return err
}
func inUse(message string) error { return apperror.New(409, "RESOURCE_IN_USE", message) }
func deleteError(err error, message string) error {
	var coded interface{ Code() int }
	if errors.As(err, &coded) && (coded.Code() == 787 || coded.Code() == 1811) {
		return inUse(message)
	} // SQLite FOREIGNKEY / RESTRICT-trigger constraints.
	return err
}
func validText(value string, max int) bool {
	if len(value) > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func validName(value string) bool { return strings.TrimSpace(value) != "" && validText(value, 128) }
func likeQuery(db *gorm.DB, query string, columns ...string) *gorm.DB {
	if query == "" {
		return db
	}
	query = strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(query)
	parts := make([]string, 0, len(columns))
	args := make([]any, 0, len(columns))
	for _, column := range columns {
		parts = append(parts, column+` LIKE ? ESCAPE '\'`)
		args = append(args, "%"+query+"%")
	}
	return db.Where("("+strings.Join(parts, " OR ")+")", args...)
}
func exists(tx *gorm.DB, entity any, column string, id uint64) (bool, error) {
	var count int64
	err := tx.Model(entity).Where(column+" = ?", id).Count(&count).Error
	return count > 0, err
}
func application(tx *gorm.DB, id uint64) (model.Application, error) {
	var a model.Application
	err := tx.First(&a, id).Error
	return a, missing(err, "软件")
}

func aad(appKey, purpose string) []byte { return []byte("application:" + appKey + ":" + purpose) }

// ListQuery comes only from response.ParseList: columns/order are allowlisted,
// keyword values are bound parameters and %/_ are treated as literal text.
func (s *Service) ListApplications(ctx context.Context, query response.ListQuery, status string) ([]ApplicationInfo, int64, error) {
	q := likeQuery(s.db.WithContext(ctx).Model(&model.Application{}), query.Q, "name", "app_key", "description")
	if status != "" {
		if status != "active" && status != "disabled" {
			return nil, 0, apperror.Invalid("软件状态必须为 active 或 disabled")
		}
		q = q.Where("status = ?", status)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []model.Application
	if err := query.Apply(q).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	items := make([]ApplicationInfo, 0, len(rows))
	for _, a := range rows {
		items = append(items, applicationInfo(a))
	}
	return items, total, nil
}
func (s *Service) GetApplication(ctx context.Context, id uint64) (ApplicationInfo, error) {
	a, err := application(s.db.WithContext(ctx), id)
	return applicationInfo(a), err
}
