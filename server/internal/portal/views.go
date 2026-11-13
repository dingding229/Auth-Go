package portal

import (
	"authgo/internal/catalog"
	"authgo/internal/ipinfo"
	"authgo/internal/model"
	"context"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func MaskIP(raw string) string {
	a, e := netip.ParseAddr(raw)
	if e != nil {
		return ""
	}
	a = a.Unmap()
	if a.Is4() {
		v := strings.Split(a.String(), ".")
		return v[0] + "." + v[1] + ".*.*"
	}
	return netip.PrefixFrom(a, 48).Masked().String()
}
func (s *Service) licenseView(ctx context.Context, id identity) (map[string]any, error) {
	l := id.License
	var rows []model.Activation
	if e := s.db.WithContext(ctx).Where("license_id=? AND status='active'", l.ID).Find(&rows).Error; e != nil {
		return nil, e
	}
	remaining := map[string]int{}
	capacity := l.MaxActivations
	alternatives := 0
	for _, method := range l.VerifyMethods {
		if method == "KEY" {
			continue
		}
		alternatives++
		used := 0
		for _, a := range rows {
			if strings.EqualFold(a.Kind, method) {
				if method == "FLOATING" && (a.OfflineAt != nil || a.LeaseExpiresAt == nil || !s.now().Before(*a.LeaseExpiresAt)) {
					continue
				}
				used++
			}
		}
		remaining[method] = max(0, l.MaxActivations-used)
		if l.MatchMode == "any" {
			if alternatives == 1 {
				capacity = remaining[method]
			} else {
				capacity = max(capacity, remaining[method])
			}
		} else {
			capacity = min(capacity, remaining[method])
		}
	}
	if alternatives == 0 {
		used := 0
		for _, a := range rows {
			if a.Kind == "key" && a.OfflineAt == nil {
				used++
			}
		}
		capacity = max(0, l.MaxActivations-used)
		remaining["KEY"] = capacity
	}
	status := l.Status
	if (status == "unused" || status == "active") && l.ExpiresAt != nil && !s.now().Before(*l.ExpiresAt) {
		status = "expired"
	}
	announcements, err := s.announcements(ctx, id.App.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"key": l.Key, "has_announcements": len(announcements) > 0, "id": l.ID, "app_name": id.App.Name, "app_key": id.App.AppKey, "public_key": id.App.PublicKey, "status": status, "type": l.Type, "expires_at": l.ExpiresAt, "maintenance_until": l.MaintenanceUntil, "starts_at": l.StartsAt, "features": l.Features, "verify_methods": l.VerifyMethods, "match_mode": l.MatchMode, "max_activations": l.MaxActivations, "remaining_activations": capacity, "remaining_by_method": remaining}, nil
}

type ActivationView struct {
	IPInfo         *ipinfo.Info `json:"ip_info,omitempty"`
	ID             uint64       `json:"id"`
	Kind           string       `json:"kind"`
	InstanceID     string       `json:"instance_id"`
	Hostname       string       `json:"hostname"`
	OS             string       `json:"os"`
	ClientVersion  string       `json:"client_version"`
	Status         string       `json:"status"`
	FirstIP        string       `json:"first_ip"`
	LastIP         string       `json:"last_ip"`
	LastSeenAt     *time.Time   `json:"last_seen_at"`
	LeaseExpiresAt *time.Time   `json:"lease_expires_at"`
	CreatedAt      time.Time    `json:"created_at"`
}

func (s *Service) activations(ctx context.Context, id uint64) ([]ActivationView, error) {
	var rows []model.Activation
	e := s.db.WithContext(ctx).Where("license_id=? AND kind='floating'", id).Order("id DESC").Find(&rows).Error
	addresses := make([]string, 0, len(rows))
	for _, a := range rows {
		addresses = append(addresses, a.LastIP)
	}
	locations := s.ipinfo.LookupBatch(addresses)
	out := []ActivationView{}
	for _, a := range rows {
		out = append(out, ActivationView{IPInfo: locations[a.LastIP], ID: a.ID, Kind: a.Kind, InstanceID: strconv.FormatUint(a.ID, 10), Hostname: a.Hostname, OS: a.OS, ClientVersion: a.ClientVersion, Status: a.Status, FirstIP: MaskIP(a.FirstIP), LastIP: MaskIP(a.LastIP), LastSeenAt: a.LastSeenAt, LeaseExpiresAt: a.LeaseExpiresAt, CreatedAt: a.CreatedAt})
	}
	return out, e
}

type VerificationLog struct {
	IPInfo        *ipinfo.Info `json:"ip_info,omitempty"`
	ID            uint64       `json:"id"`
	CreatedAt     time.Time    `json:"created_at"`
	Action        string       `json:"action"`
	Code          string       `json:"code"`
	Success       bool         `json:"success"`
	IP            string       `json:"ip"`
	Device        string       `json:"device"`
	ClientVersion string       `json:"client_version"`
	DurationMS    int64        `json:"duration_ms"`
}

func (s *Service) logs(ctx context.Context, id uint64) ([]VerificationLog, error) {
	var rows []model.VerifyLog
	e := s.db.WithContext(ctx).Where("license_id=?", id).Order("created_at DESC,id DESC").Limit(50).Find(&rows).Error
	addresses := make([]string, 0, len(rows))
	for _, r := range rows {
		addresses = append(addresses, r.IP)
	}
	locations := s.ipinfo.LookupBatch(addresses)
	out := []VerificationLog{}
	for _, r := range rows {
		out = append(out, VerificationLog{locations[r.IP], r.ID, r.CreatedAt, r.Action, r.Code, r.Success, MaskIP(r.IP), r.Device, r.ClientVersion, r.DurationMS})
	}
	return out, e
}
func (s *Service) announcements(ctx context.Context, appID uint64) ([]catalog.AnnouncementInfo, error) {
	var rows []model.Announcement
	now := s.now().UTC()
	e := s.db.WithContext(ctx).Where("app_id=? AND published_at IS NOT NULL AND published_at<=? AND (expires_at IS NULL OR expires_at>?)", appID, now, now).Order("published_at DESC,id DESC").Limit(50).Find(&rows).Error
	out := []catalog.AnnouncementInfo{}
	for _, r := range rows {
		out = append(out, catalog.AnnouncementDTO(r))
	}
	return out, e
}
