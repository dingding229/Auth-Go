package template

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"bytes"
	"context"
	"encoding/json"

	"gorm.io/gorm"
)

type SyncInput struct {
	Scope string `json:"scope" enums:"linked,all"`
}

type Counts struct {
	Linked int64 `json:"linked"`
	All    int64 `json:"all"`
}

type SyncResult struct {
	Count int64 `json:"count"`
}

func (s *Service) Counts(ctx context.Context, appID, id uint64) (Counts, error) {
	var out Counts
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := Find(tx, appID, id); err != nil {
			return err
		}
		return tx.Model(&model.License{}).Where("app_id=? AND type<>?", appID, model.LicenseTrial).
			Select("COUNT(*) AS `all`, COALESCE(SUM(CASE WHEN template_id=? THEN 1 ELSE 0 END),0) AS linked", id).Scan(&out).Error
	})
	return out, err
}

func (s *Service) Sync(ctx context.Context, appID, id uint64, in SyncInput) (SyncResult, error) {
	var out SyncResult
	if in.Scope != "linked" && in.Scope != "all" {
		return out, apperror.Invalid("同步范围必须为 linked 或 all")
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		source, err := Find(tx, appID, id)
		if err != nil {
			return err
		}
		target, err := json.Marshal(source.Features)
		if err != nil {
			return err
		}
		var after uint64
		for {
			var rows []model.License
			q := tx.Select("id", "features", "template_id").Where("app_id=? AND type<>? AND id>?", appID, model.LicenseTrial, after)
			if in.Scope == "linked" {
				q = q.Where("template_id=?", id)
			}
			if err := q.Order("id ASC").Limit(200).Find(&rows).Error; err != nil {
				return err
			}
			ids, relink := make([]uint64, 0, len(rows)), make([]uint64, 0)
			for _, row := range rows {
				after = row.ID
				if row.Features == nil {
					row.Features = model.JSONMap{}
				}
				current, err := json.Marshal(row.Features)
				if err != nil {
					return err
				}
				// Equal feature objects are not counted; scope "all" still links
				// them so later "linked" syncs include them.
				if !bytes.Equal(current, target) {
					ids = append(ids, row.ID)
				} else if row.TemplateID == nil || *row.TemplateID != source.ID {
					relink = append(relink, row.ID)
				}
			}
			if len(ids) > 0 {
				result := tx.Model(&model.License{}).Where("id IN ?", ids).
					Updates(map[string]any{"features": source.Features, "template_id": source.ID})
				if result.Error != nil {
					return result.Error
				}
				out.Count += result.RowsAffected
			}
			if len(relink) > 0 {
				if err := tx.Model(&model.License{}).Where("id IN ?", relink).Update("template_id", source.ID).Error; err != nil {
					return err
				}
			}
			if len(rows) < 200 {
				return nil
			}
		}
	})
	if err != nil {
		return SyncResult{}, err
	}
	return out, nil
}
