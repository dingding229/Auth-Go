package portal

import (
	"authgo/internal/ipinfo"
	"authgo/internal/model"
	"time"
)

// All user-center responses are explicit projections, never serialized models.
type UserLicense struct {
	ID                      uint64     `json:"id"`
	Key                     string     `json:"key"`
	AppID                   uint64     `json:"app_id"`
	AppName                 string     `json:"app_name"`
	Status                  string     `json:"status"`
	Type                    string     `json:"type"`
	ExpiresAt               *time.Time `json:"expires_at"`
	RemainingDays           *int64     `json:"remaining_days"`
	MaintenanceUntil        *time.Time `json:"maintenance_until"`
	LatestVersion           string     `json:"latest_version"`
	LatestEntitledVersion   string     `json:"latest_entitled_version"`
	RenewalRequired         bool       `json:"renewal_required"`
	DockerImage             string     `json:"docker_image"`
	DockerPull              string     `json:"docker_pull"`
	MaxActivations          int        `json:"max_activations"`
	VerifyMethods           []string   `json:"verify_methods"`
	ActiveInstances         int64      `json:"active_instances"`
	OnlineInstances         int64      `json:"online_instances"`
	UnlimitedInstances      bool       `json:"unlimited_instances"`
	TrialRemainingDays      *int64     `json:"trial_remaining_days,omitempty"`
	TrialConversionRequired bool       `json:"trial_conversion_required"`
	TrialHint               string     `json:"trial_hint,omitempty"`
}
type UserLicenseDetail struct {
	UserLicense
	Features       model.JSONMap `json:"features"`
	StartsAt       *time.Time    `json:"starts_at"`
	MatchMode      string        `json:"match_mode"`
	SupportContact string        `json:"support_contact"`
	Deployment     Deployment    `json:"deployment"`
}
type Deployment struct {
	Available   bool     `json:"available"`
	DockerImage string   `json:"docker_image"`
	Tag         string   `json:"tag"`
	DockerPull  string   `json:"docker_pull"`
	Compose     string   `json:"compose"`
	Reason      string   `json:"reason,omitempty"`
	Steps       []string `json:"steps"`
	Guide       string   `json:"guide"`
	PortsHint   string   `json:"ports_hint"`
}
type UserInstance struct {
	ID             uint64       `json:"id"`
	LicenseID      uint64       `json:"license_id"`
	AppID          uint64       `json:"app_id"`
	AppName        string       `json:"app_name"`
	Hostname       string       `json:"hostname"`
	OS             string       `json:"os"`
	Kind           string       `json:"kind"`
	Status         string       `json:"status"`
	Online         bool         `json:"online"`
	ClientVersion  string       `json:"client_version"`
	LastIP         string       `json:"last_ip"`
	IPInfo         *ipinfo.Info `json:"ip_info,omitempty"`
	LastSeenAt     *time.Time   `json:"last_seen_at"`
	LeaseExpiresAt *time.Time   `json:"lease_expires_at"`
}
type UserLog struct {
	ID            uint64       `json:"id"`
	LicenseID     *uint64      `json:"license_id"`
	AppID         uint64       `json:"app_id"`
	AppName       string       `json:"app_name"`
	CreatedAt     time.Time    `json:"created_at"`
	Action        string       `json:"action"`
	Code          string       `json:"code"`
	Success       bool         `json:"success"`
	IP            string       `json:"ip"`
	IPInfo        *ipinfo.Info `json:"ip_info,omitempty"`
	ClientVersion string       `json:"client_version"`
	DurationMS    int64        `json:"duration_ms"`
}
type UserAnnouncement struct {
	ID          uint64     `json:"id"`
	AppID       uint64     `json:"app_id"`
	AppName     string     `json:"app_name"`
	Title       string     `json:"title"`
	Content     string     `json:"content"`
	PublishedAt *time.Time `json:"published_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}
type UserUpdate struct {
	AppID                 uint64     `json:"app_id"`
	AppName               string     `json:"app_name"`
	LicenseID             uint64     `json:"license_id"`
	Version               string     `json:"version"`
	LatestEntitledVersion string     `json:"latest_entitled_version"`
	PublishedAt           *time.Time `json:"published_at"`
	Changelog             string     `json:"changelog"`
	Mandatory             bool       `json:"mandatory"`
	Available             bool       `json:"available"`
	// HasUpdate is true only if an online instance is below its license's latest entitled version.
	HasUpdate        bool       `json:"has_update"`
	RenewalRequired  bool       `json:"renewal_required"`
	MaintenanceUntil *time.Time `json:"maintenance_until"`
	DockerImage      string     `json:"docker_image"`
	DockerPull       string     `json:"docker_pull"`
	CurrentVersions  []string   `json:"current_versions"`
	Href             string     `json:"href"`
}
type Attention struct {
	Type           string     `json:"type"`
	Priority       int        `json:"priority"`
	Severity       string     `json:"severity"`
	LicenseID      uint64     `json:"license_id"`
	AppID          uint64     `json:"app_id"`
	AppName        string     `json:"app_name"`
	InstanceID     *uint64    `json:"instance_id,omitempty"`
	Title          string     `json:"title"`
	Href           string     `json:"href"`
	Deadline       *time.Time `json:"deadline,omitempty"`
	SupportContact string     `json:"support_contact,omitempty"`
}
