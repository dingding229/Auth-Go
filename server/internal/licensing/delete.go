package licensing

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"context"
	"math"
	"strconv"

	"gorm.io/gorm"
)

type DeleteInfo struct {
	ID        uint64 `json:"id"`
	KeySuffix string `json:"key_suffix"`
}
type PurgeInput struct {
	AppID *uint64 `json:"app_id"`
}
type PurgeResult struct {
	Count int64 `json:"count"`
}
type DeleteActor struct {
	ID       uint64
	Name, IP string
}

func deletable(q *gorm.DB) *gorm.DB {
	return q.Where("licenses.status='revoked' AND licenses.type<>'trial' AND NOT EXISTS (SELECT 1 FROM trial_claims WHERE trial_claims.license_id=licenses.id)")
}

func (s *Service) Delete(ctx context.Context, id uint64) (DeleteInfo, error) {
	var out DeleteInfo
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row model.License
		if err := tx.First(&row, id).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return apperror.NotFound()
			}
			return err
		}
		var claims int64
		if err := tx.Table("trial_claims").Where("license_id=?", id).Count(&claims).Error; err != nil {
			return err
		}
		if row.Type == model.LicenseTrial || claims > 0 {
			return apperror.Invalid("试用授权不能删除")
		}
		if row.Status != "revoked" {
			return apperror.Invalid("只能删除已吊销的授权")
		}
		out = deletedInfo(row)
		return deleteLicenses(tx, []uint64{id})
	})
	return out, err
}
func deletedInfo(row model.License) DeleteInfo {
	suffix := row.Key
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}
	return DeleteInfo{row.ID, suffix}
}

func (s *Service) PurgeRevoked(ctx context.Context, in PurgeInput, actor DeleteActor) (PurgeResult, error) {
	var out PurgeResult
	if in.AppID != nil && (*in.AppID == 0 || *in.AppID > math.MaxInt64) {
		return out, apperror.Invalid("软件编号无效")
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for {
			var rows []model.License
			q := deletable(tx.Select("id", "key").Model(&model.License{}))
			if in.AppID != nil {
				q = q.Where("app_id=?", *in.AppID)
			}
			if err := q.Order("id ASC").Limit(200).Find(&rows).Error; err != nil {
				return err
			}
			if len(rows) == 0 {
				return nil
			}
			ids := make([]uint64, 0, len(rows))
			audits := make([]model.AuditLog, 0, len(rows))
			for _, row := range rows {
				ids = append(ids, row.ID)
				info := deletedInfo(row)
				audits = append(audits, model.AuditLog{AdminID: &actor.ID, Operator: actor.Name, IP: actor.IP, Action: "license.delete", Resource: "license", ResourceID: strconv.FormatUint(row.ID, 10), Summary: "清理已吊销授权", StatusCode: 200, CreatedAt: s.now().UTC(), Details: model.JSONMap{"key_suffix": info.KeySuffix}})
			}
			if err := deleteLicenses(tx, ids); err != nil {
				return err
			}
			if err := tx.Create(&audits).Error; err != nil {
				return err
			}
			out.Count += int64(len(rows))
		}
	})
	if err != nil {
		return PurgeResult{}, err
	}
	return out, nil
}

func deleteLicenses(tx *gorm.DB, ids []uint64) error {
	activations := tx.Model(&model.Activation{}).Select("id").Where("license_id IN ?", ids)
	sessions := tx.Model(&model.ClientSession{}).Select("id").Where("license_id IN ?", ids)
	if err := tx.Where("activation_id IN (?) OR session_id IN (?)", activations, sessions).Delete(&model.ClientSessionBinding{}).Error; err != nil {
		return err
	}
	// Retain the original reason while distinguishing deleted from unrecognized keys.
	if err := tx.Model(&model.VerifyLog{}).Where("license_id IN ? OR activation_id IN (?)", ids, activations).Updates(map[string]any{"license_id": nil, "activation_id": nil, "reason": gorm.Expr("? || COALESCE(reason,'')", model.DeletedLicenseReason)}).Error; err != nil {
		return err
	}
	if err := tx.Where("license_id IN ?", ids).Delete(&model.Activation{}).Error; err != nil {
		return err
	}
	if err := tx.Where("license_id IN ?", ids).Delete(&model.ClientSession{}).Error; err != nil {
		return err
	}
	// Instance sessions and sharing data follow their existing ON DELETE CASCADE.
	return tx.Where("id IN ?", ids).Delete(&model.License{}).Error
}
