package licensing

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"context"
	"errors"
	"math"

	"gorm.io/gorm"
)

type TemplateInput struct {
	TemplateID uint64 `json:"template_id"`
}

// ApplyTemplate replaces only features and their recorded source.
func (s *Service) ApplyTemplate(ctx context.Context, id uint64, in TemplateInput) (LicenseInfo, error) {
	var l model.License
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		l, err = findLicense(tx, id)
		if err != nil {
			return err
		}
		if l.Type == model.LicenseTrial {
			return apperror.Invalid("试用授权不能套用功能模板")
		}
		if in.TemplateID == 0 || in.TemplateID > math.MaxInt64 {
			return apperror.Invalid("模板编号无效")
		}
		var source model.FeatureTemplate
		if err := tx.Where("id=? AND app_id=?", in.TemplateID, l.AppID).First(&source).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return apperror.Invalid("模板不存在或不属于此软件")
			}
			return err
		}
		l.Features, l.TemplateID, l.Template = source.Features, &source.ID, &source
		return tx.Model(&model.License{}).Where("id=?", id).
			Updates(map[string]any{"features": source.Features, "template_id": source.ID}).Error
	})
	return info(l), err
}
