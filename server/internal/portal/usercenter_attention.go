package portal

import (
	"fmt"
	"github.com/Masterminds/semver/v3"
	"github.com/gin-gonic/gin"
	"sort"
	"strings"
	"time"
)

func userHref(license uint64, tab string) string {
	return fmt.Sprintf("/portal/licenses/%d?tab=%s", license, tab)
}
func (s *Service) userUpdates(c *gin.Context, id identity) (any, error) {
	now := s.now().UTC()
	page, e := userPage(c, 20)
	if e != nil {
		return nil, e
	}
	licenses, e := s.allUserLicenses(c, id.User.ID)
	if e != nil {
		return nil, e
	}
	snapshot, e := s.userSnapshot(c.Request.Context(), licenses)
	if e != nil {
		return nil, e
	}
	byApp := map[uint64]*UserUpdate{}
	for _, l := range licenses {
		v := snapshot.choose(l, now)
		row := byApp[l.AppID]
		if row == nil {
			row = &UserUpdate{AppID: l.AppID, AppName: l.Application.Name, LicenseID: l.ID, CurrentVersions: []string{}, MaintenanceUntil: l.MaintenanceUntil, DockerImage: v.image, RenewalRequired: v.renewal, Href: userHref(l.ID, "updates")}
			byApp[l.AppID] = row
		}
		if v.latest != nil && higher(v.latest.Version, row.Version) {
			row.Version = v.latest.Version
			row.PublishedAt = v.latest.PublishedAt
			row.Changelog = v.latest.Changelog
			row.Mandatory = v.latest.Mandatory
		}
		if v.entitled != nil && (row.LatestEntitledVersion == "" || usable(l, now) && !row.Available || usable(l, now) == row.Available && higher(v.entitled.Version, row.LatestEntitledVersion)) {
			row.LatestEntitledVersion = v.entitled.Version
			row.LicenseID = l.ID
			row.MaintenanceUntil = l.MaintenanceUntil
			row.DockerPull = v.pull
			row.Available = usable(l, now)
			row.RenewalRequired = v.renewal
			row.Href = userHref(l.ID, "updates")
		}
		row.HasUpdate = row.HasUpdate || v.hasUpdate
		row.CurrentVersions = append(row.CurrentVersions, v.current...)
	}
	out := []UserUpdate{}
	for _, row := range byApp {
		row.RenewalRequired = row.RenewalRequired || higher(row.Version, row.LatestEntitledVersion) && row.MaintenanceUntil != nil
		seen := map[string]bool{}
		current := []string{}
		for _, v := range row.CurrentVersions {
			if !seen[v] {
				seen[v] = true
				current = append(current, v)
			}
		}
		sort.Strings(current)
		row.CurrentVersions = current
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AppID < out[j].AppID })
	return page.Data(pageSlice(out, page.Offset(), page.Size), int64(len(out))), nil
}
func higher(a, b string) bool {
	av, e := semver.StrictNewVersion(a)
	if e != nil {
		return false
	}
	bv, e := semver.StrictNewVersion(b)
	return e != nil || av.GreaterThan(bv)
}
func pageSlice[T any](items []T, offset, size int) []T {
	start := min(offset, len(items))
	return items[start:min(start+size, len(items))]
}
func (s *Service) userAttention(c *gin.Context, id identity) (any, error) {
	page, e := userPage(c, 20)
	if e != nil {
		return nil, e
	}
	licenses, e := s.allUserLicenses(c, id.User.ID)
	if e != nil {
		return nil, e
	}
	snapshot, e := s.userSnapshot(c.Request.Context(), licenses)
	if e != nil {
		return nil, e
	}
	contact, e := supportContact(c.Request.Context(), s.db)
	if e != nil {
		return nil, e
	}
	now := s.now().UTC()
	end := now.Add(30 * 24 * time.Hour)
	out := []Attention{}
	for _, l := range licenses {
		add := func(kind string, priority int, severity, title, tab string, deadline *time.Time, instance *uint64) {
			out = append(out, Attention{Type: kind, Priority: priority, Severity: severity, LicenseID: l.ID, AppID: l.AppID, AppName: l.Application.Name, InstanceID: instance, Title: title, Href: userHref(l.ID, tab), Deadline: deadline, SupportContact: contact})
		}
		disabled := map[string]bool{}
		for _, v := range snapshot.versions[l.AppID] {
			if v.Disabled {
				disabled[v.Version] = true
			}
		}
		bound := 0
		for _, a := range snapshot.activations[l.ID] {
			if a.Kind != "key" && a.Status == "active" {
				bound++
			}
			if online(a, now) && disabled[strings.TrimPrefix(a.ClientVersion, "v")] {
				aid := a.ID
				add("version_disabled", 10, "danger", "正在运行的版本已被禁用", "instances", nil, &aid)
			}
		}
		switch effectiveStatus(l, now) {
		case "expired":
			add("expired", 20, "danger", "授权已过期，请联系软件提供方续期", "overview", l.ExpiresAt, nil)
		case "suspended":
			add("suspended", 30, "danger", "授权已暂停，请联系软件提供方", "overview", nil, nil)
		}
		if (l.Status == "active" || l.Status == "unused") && l.ExpiresAt != nil && l.ExpiresAt.After(now) && !l.ExpiresAt.After(end) {
			add("expiring", 40, "warning", "授权将在 30 天内到期", "overview", l.ExpiresAt, nil)
		}
		if usable(l, now) && l.MaintenanceUntil != nil && !l.MaintenanceUntil.Before(now) && !l.MaintenanceUntil.After(end) {
			add("maintenance_expiring", 50, "warning", "更新维护期将在 30 天内到期", "updates", l.MaintenanceUntil, nil)
		}

		if v := snapshot.choose(l, now); v.hasUpdate {
			add("update_available", 70, "info", "有可用的新版本", "updates", nil, nil)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if (a.Deadline == nil) != (b.Deadline == nil) {
			return a.Deadline != nil
		}
		if a.Deadline != nil && b.Deadline != nil && !a.Deadline.Equal(*b.Deadline) {
			return a.Deadline.Before(*b.Deadline)
		}
		if a.LicenseID != b.LicenseID {
			return a.LicenseID < b.LicenseID
		}
		if a.InstanceID != nil && b.InstanceID != nil {
			return *a.InstanceID < *b.InstanceID
		}
		return a.Type < b.Type
	})
	return page.Data(pageSlice(out, page.Offset(), page.Size), int64(len(out))), nil
}
