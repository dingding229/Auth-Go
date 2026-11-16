package automation

import (
	"authgo/internal/buildinfo"
	"authgo/internal/model"
	"authgo/internal/netpolicy"
	"context"
)

type SystemSettings struct {
	Settings
	ServerVersion    string `json:"server_version"`
	PackImageTag     string `json:"pack_image_tag"`
	CloudflareIPSeen bool   `json:"cloudflare_ip_seen"`
}

func (s *Service) ReadSettings(ctx context.Context) (SystemSettings, error) {
	out := SystemSettings{Settings: s.PublicSettings(), ServerVersion: buildinfo.Version, PackImageTag: buildinfo.PackImageTag()}
	var ips []string
	// The primary-key order bounds the query even on large verification logs.
	if err := s.db.WithContext(ctx).Model(&model.VerifyLog{}).Order("id DESC").Limit(200).Pluck("ip", &ips).Error; err != nil {
		return out, err
	}
	for _, ip := range ips {
		if netpolicy.CloudflareIP(ip) {
			out.CloudflareIPSeen = true
			break
		}
	}
	return out, nil
}
