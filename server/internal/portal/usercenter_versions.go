package portal

import (
	"authgo/internal/dockerhub"
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"authgo/internal/updater"
	"context"
	"encoding/json"
	"github.com/Masterminds/semver/v3"
	"sort"
	"strings"
	"time"
)

type userSnapshot struct {
	versions    map[uint64][]model.AppVersion
	activations map[uint64][]model.Activation
	tags        map[uint64]map[string]string
}

// One fixed set of batch queries, regardless of the number of owned licenses.
func (s *Service) userSnapshot(ctx context.Context, licenses []model.License) (userSnapshot, error) {
	out := userSnapshot{versions: map[uint64][]model.AppVersion{}, activations: map[uint64][]model.Activation{}, tags: map[uint64]map[string]string{}}
	if len(licenses) == 0 {
		return out, nil
	}
	licenseIDs := make([]uint64, 0, len(licenses))
	apps := map[uint64]model.Application{}
	for _, l := range licenses {
		licenseIDs = append(licenseIDs, l.ID)
		apps[l.AppID] = l.Application
	}
	appIDs := make([]uint64, 0, len(apps))
	for id := range apps {
		appIDs = append(appIDs, id)
	}
	tx := s.db.WithContext(ctx)
	var versions []model.AppVersion
	if e := tx.Select("id,app_id,version,source,disabled,withdrawn,published_at,changelog,mandatory").Where("app_id IN ?", appIDs).Find(&versions).Error; e != nil {
		return out, e
	}
	for _, v := range versions {
		out.versions[v.AppID] = append(out.versions[v.AppID], v)
	}
	for appID := range out.versions {
		sort.SliceStable(out.versions[appID], func(i, j int) bool {
			a, ae := semver.StrictNewVersion(out.versions[appID][i].Version)
			b, be := semver.StrictNewVersion(out.versions[appID][j].Version)
			if ae != nil {
				return false
			}
			if be != nil {
				return true
			}
			return a.GreaterThan(b)
		})
	}
	var activations []model.Activation
	if e := tx.Select("id,license_id,kind,status,client_version,offline_at,lease_expires_at").Where("license_id IN ?", licenseIDs).Find(&activations).Error; e != nil {
		return out, e
	}
	for _, a := range activations {
		out.activations[a.LicenseID] = append(out.activations[a.LicenseID], a)
	}
	var states []dockerhub.State
	if e := tx.Select("app_id,image,tags_json").Where("app_id IN ?", appIDs).Find(&states).Error; e != nil {
		return out, e
	}
	for _, st := range states {
		if st.Image != apps[st.AppID].DockerImage {
			continue
		}
		var tags map[string]string
		if e := json.Unmarshal([]byte(st.TagsJSON), &tags); e != nil {
			continue
		}
		out.tags[st.AppID] = tags
	}

	return out, nil
}
func online(a model.Activation, now time.Time) bool {
	return a.Kind == "floating" && a.Status == "active" && a.OfflineAt == nil && a.LeaseExpiresAt != nil && now.Before(*a.LeaseExpiresAt)
}
func usable(l model.License, now time.Time) bool {
	return (l.Status == "active" || l.Status == "unused") && l.Application.Status == "active" && (l.StartsAt == nil || !now.Before(*l.StartsAt)) && (l.ExpiresAt == nil || now.Before(*l.ExpiresAt))
}
func effectiveStatus(l model.License, now time.Time) string {
	if (l.Status == "active" || l.Status == "unused") && l.ExpiresAt != nil && !now.Before(*l.ExpiresAt) {
		return "expired"
	}
	return l.Status
}
func remainingDays(at *time.Time, now time.Time) *int64 {
	if at == nil {
		return nil
	}
	seconds := at.Sub(now).Seconds()
	n := int64(0)
	if seconds > 0 {
		n = int64(seconds / 86400)
		if float64(n)*86400 < seconds {
			n++
		}
	}
	return &n
}
func (s userSnapshot) tag(l model.License, v model.AppVersion) string {
	tag := s.tags[l.AppID][v.Version]
	if strings.TrimPrefix(tag, "v") != v.Version {
		return ""
	}
	n, e := semver.StrictNewVersion(v.Version)
	if e != nil || n.Prerelease() != "" {
		return ""
	}
	return tag
}
func (s userSnapshot) candidates(l model.License, now time.Time) []model.AppVersion {
	out := []model.AppVersion{}
	for _, v := range s.versions[l.AppID] {
		if v.Disabled || v.Withdrawn || v.PublishedAt == nil || v.PublishedAt.After(now) || !updater.VersionAllowed(l.Application, l, v.Version) {
			continue
		}
		if l.Application.DockerImage != "" {
			if _, e := dockerhub.Image(l.Application.DockerImage); e != nil || s.tag(l, v) == "" {
				continue
			}
		} else {
			continue
		}

		out = append(out, v)
	}
	return out
}

type versionChoice struct {
	latest, entitled *model.AppVersion
	renewal          bool
	image, pull, tag string
	current          []string
	hasUpdate        bool
}

func (s userSnapshot) choose(l model.License, now time.Time) versionChoice {
	out := versionChoice{current: []string{}, renewal: effectiveStatus(l, now) == "expired"}
	for _, v := range s.candidates(l, now) {
		v := v
		if out.latest == nil {
			out.latest = &v
		}
		if out.entitled == nil && maintenance.Allows(l, v) {
			out.entitled = &v
		}
	}
	if l.Application.DockerImage != "" {
		out.image, _ = dockerhub.Image(l.Application.DockerImage)
	}
	if out.latest != nil {
		out.renewal = out.renewal || !maintenance.Allows(l, *out.latest)
	}
	currents := map[string]bool{}
	for _, a := range s.activations[l.ID] {
		if online(a, now) && a.ClientVersion != "" {
			currents[a.ClientVersion] = true
		}
	}
	for v := range currents {
		out.current = append(out.current, v)
	}
	sort.Strings(out.current)
	if out.entitled != nil && usable(l, now) {
		best, _ := semver.StrictNewVersion(out.entitled.Version)
		for _, v := range out.current {
			n, e := semver.StrictNewVersion(strings.TrimPrefix(v, "v"))
			if e == nil && n.LessThan(best) {
				out.hasUpdate = true
			}
		}
		if out.image != "" {
			out.tag = s.tag(l, *out.entitled)
			if out.tag != "" {
				out.pull = "docker pull " + out.image + ":" + out.tag
			}
		}
	}
	return out
}
func (s userSnapshot) card(l model.License, now time.Time) UserLicense {
	choice := s.choose(l, now)
	out := UserLicense{ID: l.ID, Key: l.Key, AppID: l.AppID, AppName: l.Application.Name, Status: effectiveStatus(l, now), Type: l.Type, ExpiresAt: l.ExpiresAt, RemainingDays: remainingDays(l.ExpiresAt, now), MaintenanceUntil: l.MaintenanceUntil, RenewalRequired: choice.renewal, DockerImage: choice.image, DockerPull: choice.pull, MaxActivations: l.MaxActivations, VerifyMethods: l.VerifyMethods}
	if out.VerifyMethods == nil {
		out.VerifyMethods = []string{}
	}
	out.UnlimitedInstances = len(l.VerifyMethods) > 0
	for _, m := range l.VerifyMethods {
		if m != "KEY" {
			out.UnlimitedInstances = false
		}
	}
	for _, a := range s.activations[l.ID] {
		if a.Status == "active" && a.Kind == "floating" {
			out.ActiveInstances++
		}
		if online(a, now) {
			out.OnlineInstances++
		}
	}
	if choice.latest != nil {
		out.LatestVersion = choice.latest.Version
	}
	if choice.entitled != nil {
		out.LatestEntitledVersion = choice.entitled.Version
	}
	if l.Type == "trial" {
		out.TrialRemainingDays = out.RemainingDays
		out.TrialConversionRequired = true
		out.TrialHint = "联系软件提供方转正"
	}
	return out
}
