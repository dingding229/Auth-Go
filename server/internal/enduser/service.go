package enduser

import (
	"authgo/internal/apperror"
	"authgo/internal/mailer"
	"authgo/internal/model"
	"authgo/internal/response"
	"context"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"strings"
	"unicode"
)

type Input struct {
	Name           *string `json:"name"`
	Email          *string `json:"email"`
	Note           *string `json:"note"`
	Status         *string `json:"status"`
	PortalPassword *string `json:"portal_password"`
}
type Info struct {
	ID                uint64 `json:"id"`
	Name              string `json:"name"`
	Email             string `json:"email"`
	Note              string `json:"note"`
	Status            string `json:"status"`
	HasPortalPassword bool   `json:"has_portal_password"`
	LicenseCount      int64  `json:"license_count"`
}

func DTO(u model.EndUser) Info {
	return Info{ID: u.ID, Name: u.Name, Email: u.Email, Note: u.Note, Status: u.Status, HasPortalPassword: u.PortalPasswordHash != ""}
}
func Normalize(name, email string) (string, string, error) {
	name = strings.TrimSpace(name)
	email = strings.ToLower(strings.TrimSpace(email))
	if name == "" || len(name) > 128 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", "", apperror.Invalid("用户姓名必填，且不能超过128字节或包含控制字符")
	}
	if email != "" {
		v, e := mailer.Address(email)
		if e != nil {
			return "", "", apperror.Invalid("用户邮箱格式无效")
		}
		email = v
	}
	return name, email, nil
}
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	if len(password) < 8 || len(password) > 72 {
		return "", apperror.Invalid("用户中心密码须为8至72字节")
	}
	b, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), e
}
func apply(u *model.EndUser, in Input) error {
	if in.Name != nil {
		u.Name = *in.Name
	}
	if in.Email != nil {
		u.Email = *in.Email
	}
	if in.Note != nil {
		u.Note = strings.TrimSpace(*in.Note)
	}
	if in.Status != nil {
		u.Status = *in.Status
	}
	var e error
	u.Name, u.Email, e = Normalize(u.Name, u.Email)
	if e != nil {
		return e
	}
	if len(u.Note) > 4096 {
		return apperror.Invalid("备注不得超过4096字节")
	}
	if u.Status != "active" && u.Status != "disabled" {
		return apperror.Invalid("用户状态无效")
	}
	if in.PortalPassword != nil {
		u.PortalPasswordHash, e = HashPassword(*in.PortalPassword)
	}
	return e
}
func Error(e error) error {
	var c interface{ Code() int }
	if errors.As(e, &c) && (c.Code() == 2067 || c.Code() == 1555) {
		return apperror.New(409, "CONFLICT", "该邮箱已属于其他用户")
	}
	return e
}

type Service struct{ DB *gorm.DB }

func (s Service) Create(ctx context.Context, in Input) (Info, error) {
	u := model.EndUser{Status: "active"}
	if e := apply(&u, in); e != nil {
		return Info{}, e
	}
	e := s.DB.WithContext(ctx).Create(&u).Error
	return DTO(u), Error(e)
}
func (s Service) Get(ctx context.Context, id uint64) (Info, error) {
	var u model.EndUser
	e := s.DB.WithContext(ctx).First(&u, id).Error
	if errors.Is(e, gorm.ErrRecordNotFound) {
		return Info{}, apperror.NotFound()
	}
	v := DTO(u)
	if e == nil {
		e = s.DB.WithContext(ctx).Model(&model.License{}).Where("user_id=?", id).Count(&v.LicenseCount).Error
	}
	return v, e
}
func (s Service) Update(ctx context.Context, id uint64, in Input) (Info, error) {
	if in == (Input{}) {
		return Info{}, apperror.Invalid("至少提供一个字段")
	}
	var u model.EndUser
	e := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if e := tx.First(&u, id).Error; e != nil {
			if errors.Is(e, gorm.ErrRecordNotFound) {
				return apperror.NotFound()
			}
			return e
		}
		before := u
		if e := apply(&u, in); e != nil {
			return e
		}
		if before.Email != u.Email || before.Status != u.Status || before.PortalPasswordHash != u.PortalPasswordHash {
			u.AuthVersion++
		}
		return tx.Save(&u).Error
	})
	return DTO(u), Error(e)
}
func (s Service) Delete(ctx context.Context, id uint64) error {
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var u model.EndUser
		if e := tx.First(&u, id).Error; e != nil {
			if errors.Is(e, gorm.ErrRecordNotFound) {
				return apperror.NotFound()
			}
			return e
		}
		var n int64
		if e := tx.Model(&model.License{}).Where("user_id=?", id).Count(&n).Error; e != nil {
			return e
		}
		if n > 0 {
			return apperror.New(409, "RESOURCE_IN_USE", "该用户仍有授权，只能停用，不能删除")
		}
		return tx.Delete(&u).Error
	})
}
func (s Service) List(ctx context.Context, q response.ListQuery, status string) ([]Info, int64, error) {
	tx := s.DB.WithContext(ctx).Model(&model.EndUser{})
	if status != "" {
		if status != "active" && status != "disabled" {
			return nil, 0, apperror.Invalid("状态无效")
		}
		tx = tx.Where("status=?", status)
	}
	if q.Q != "" {
		p := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(q.Q) + "%"
		tx = tx.Where(`(name LIKE ? ESCAPE '\' OR email LIKE ? ESCAPE '\')`, p, p)
	}
	var n int64
	if e := tx.Count(&n).Error; e != nil {
		return nil, 0, e
	}
	var users []model.EndUser
	if e := q.Apply(tx).Find(&users).Error; e != nil {
		return nil, 0, e
	}
	out := []Info{}
	for _, u := range users {
		v := DTO(u)
		if e := s.DB.WithContext(ctx).Model(&model.License{}).Where("user_id=?", u.ID).Count(&v.LicenseCount).Error; e != nil {
			return nil, 0, e
		}
		out = append(out, v)
	}
	return out, n, nil
}
