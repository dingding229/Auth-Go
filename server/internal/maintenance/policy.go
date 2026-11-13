// Package maintenance implements version publication entitlements, not license expiry.
package maintenance

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"github.com/Masterminds/semver/v3"
	"time"
)

func Allows(l model.License, v model.AppVersion) bool {
	return l.MaintenanceUntil == nil || v.PublishedAt == nil || !v.PublishedAt.After(*l.MaintenanceUntil)
}

// Latest only computes a recommendation when the license has a maintenance limit.
func Latest(a model.Application, l model.License, versions []model.AppVersion, now time.Time) string {
	if l.MaintenanceUntil == nil {
		return ""
	}
	var best *semver.Version
	name := ""
	for _, v := range versions {
		if v.Disabled || v.Withdrawn || v.PublishedAt == nil || v.PublishedAt.After(now) || !Allows(l, v) {
			continue
		}
		n, err := semver.StrictNewVersion(v.Version)
		if err != nil {
			continue
		}

		if best == nil || n.GreaterThan(best) {
			best = n
			name = v.Version
		}
	}
	return name
}

// Check does not use wall time to expire maintenance. Only the reported build's
// recorded publication time can deny use. Unrecorded builds are allowed.
func Check(l model.License, versions []model.AppVersion, current string) (expired, unknown bool) {
	if l.MaintenanceUntil == nil || current == "" {
		return false, false
	}
	for _, v := range versions {
		if v.Version == current {
			return !Allows(l, v), v.PublishedAt == nil
		}
	}
	return false, true
}

// Refusal carries signed gateway error details without changing common HTTP errors.
type Refusal struct {
	LatestEntitledVersion string
	MaintenanceUntil      *time.Time
}

func (e *Refusal) Unwrap() error {
	return apperror.New(403, "MAINTENANCE_EXPIRED", "当前授权的更新维护期已结束，此版本需要续期")
}
func (e *Refusal) Error() string { return e.Unwrap().Error() }
