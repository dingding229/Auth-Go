package maintenance

import (
	"authgo/internal/apperror"
	"encoding/json"
	"time"
)

type Input struct {
	// Days are measured from the management operation; zero explicitly removes the limit.
	MaintenanceDays *int `json:"maintenance_days"`
	// Omitted preserves the existing value on renewal. Null explicitly removes it.
	MaintenanceUntil json.RawMessage `json:"maintenance_until" swaggertype:"string" format:"date-time"`
}

func (in Input) Resolve(now time.Time) (*time.Time, bool, error) {
	if in.MaintenanceDays != nil && in.MaintenanceUntil != nil {
		return nil, false, apperror.Invalid("维护天数和维护期到期时间只能填写一个")
	}
	if in.MaintenanceDays != nil {
		days := *in.MaintenanceDays
		if days < 0 || days > 36500 {
			return nil, false, apperror.Invalid("维护天数必须为0至36500，0表示不限")
		}
		if days == 0 {
			return nil, true, nil
		}
		at := now.UTC().AddDate(0, 0, days)
		if at.Year() > 9999 {
			return nil, false, apperror.Invalid("维护期超出可表示范围")
		}
		return &at, true, nil
	}
	if in.MaintenanceUntil == nil {
		return nil, false, nil
	}
	var at *time.Time
	if err := json.Unmarshal(in.MaintenanceUntil, &at); err != nil {
		return nil, false, apperror.Invalid("维护期到期时间格式无效")
	}
	if at != nil {
		v := at.UTC()
		if v.Year() < 1 || v.Year() > 9999 {
			return nil, false, apperror.Invalid("维护期超出可表示范围")
		}
		at = &v
	}
	return at, true, nil
}
