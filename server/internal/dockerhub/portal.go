package dockerhub

import (
	"authgo/internal/apperror"
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"authgo/internal/updater"
	"context"
	"errors"
	"github.com/Masterminds/semver/v3"
	"gorm.io/gorm"
	"strings"
	"time"
)

type PortalUpdate struct {
	MaintenanceUntil      *time.Time `json:"maintenance_until,omitempty"`
	LatestEntitledVersion string     `json:"latest_entitled_version,omitempty"`
	RenewalRequired       bool       `json:"renewal_required,omitempty"`
	Available             bool       `json:"available"`
	DockerImage           string     `json:"docker_image"`
	DockerPull            string     `json:"docker_pull"`
	Version               string     `json:"version"`
	Changelog             string     `json:"changelog"`
	Mandatory             bool       `json:"mandatory"`
	PublishedAt           *time.Time `json:"published_at"`
}

// ForPortal is invoked only after the portal has authenticated ownership of the
// selected license. It also reuses update authorization and version constraints.
func (s *Service) ForPortal(ctx context.Context, licenseID uint64, current string) (PortalUpdate, error) {
	out := PortalUpdate{}
	if s.updates == nil {
		return out, apperror.Invalid("版本服务未启用")
	}
	l, a, err := s.updates.ValidateLicense(ctx, licenseID)
	if err != nil {
		return out, err
	}
	if a.DockerImage == "" {
		return out, nil
	}
	image, err := Image(a.DockerImage)
	if err != nil {
		return out, err
	}
	out.DockerImage = image
	out.MaintenanceUntil = l.MaintenanceUntil
	var before *semver.Version
	if current != "" {
		before, err = semver.StrictNewVersion(current)
		if err != nil {
			return out, apperror.Invalid("当前版本必须是合法semver")
		}
	}
	var st State
	if err := s.db.WithContext(ctx).Where("app_id=? AND image=?", a.ID, a.DockerImage).First(&st).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return out, nil
		}
		return out, err
	}
	tags := tagsOf(st)
	if len(tags) == 0 {
		return out, nil
	}
	var versions []model.AppVersion
	if err := s.db.WithContext(ctx).Where("app_id=? AND disabled=0 AND withdrawn=0 AND published_at IS NOT NULL AND published_at<=?", a.ID, s.now().UTC()).Find(&versions).Error; err != nil {
		return out, err
	}
	out.LatestEntitledVersion = maintenance.Latest(a, l, versions, s.now().UTC())
	var best *semver.Version
	for _, v := range versions {
		tag := tags[v.Version]
		if !tagPattern.MatchString(tag) || strings.TrimPrefix(tag, "v") != v.Version {
			continue
		}
		n, err := semver.StrictNewVersion(v.Version)
		if err != nil || !updater.VersionAllowed(a, l, v.Version) || before != nil && !n.GreaterThan(before) || best != nil && !n.GreaterThan(best) {
			continue
		}
		if !maintenance.Allows(l, v) {
			out.RenewalRequired = true
			continue
		}
		best = n
		out.Available = true
		out.Version = v.Version
		out.PublishedAt = v.PublishedAt
		out.Changelog = v.Changelog
		out.Mandatory = v.Mandatory
		out.DockerPull = "docker pull " + image + ":" + tag
	}
	return out, nil
}
