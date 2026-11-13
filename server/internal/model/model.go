// Package model contains the initial single-team SQLite schema.
// Users own licenses; client authentication still uses license keys.
package model

import (
	"time"
)

type Base struct {
	ID        uint64 `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Admin struct {
	Base
	Username             string `gorm:"not null;uniqueIndex"`
	PasswordHash         string `gorm:"not null" json:"-"`
	TOTPSecret           string `json:"-"` // AES-GCM ciphertext, bound to the administrator and active purpose.
	LastLoginAt          *time.Time
	AuthVersion          uint64     `gorm:"not null;default:0" json:"-"`
	TOTPEnabled          bool       `gorm:"not null;default:false"`
	PendingTOTPSecret    string     `json:"-"`
	PendingTOTPExpiresAt *time.Time `json:"-"`
	LastTOTPStep         int64      `gorm:"not null;default:0" json:"-"`
}

type Application struct {
	TrialTemplateID       *uint64
	TrialEnabled          bool   `gorm:"not null;default:false"`
	TrialDays             int    `gorm:"not null;default:14"`
	DockerImage           string `gorm:"not null;default:''"`
	UnlockSecretEncrypted string `json:"-"`
	LicenseSalt           string `json:"-"`
	Base
	Name                string `gorm:"not null"`
	AppKey              string `gorm:"not null;uniqueIndex"`
	AppSecretEncrypted  string `gorm:"not null" json:"-"`
	PrivateKeyEncrypted string `gorm:"not null" json:"-"`
	PublicKey           string `gorm:"not null"`
	Status              string `gorm:"not null;default:active;index"`
	Description         string
	PreviousPublicKey   string
	NextCheckIn         int `gorm:"not null;default:3600"`
	GraceHours          int `gorm:"not null;default:72"`
	HeartbeatInterval   int `gorm:"not null;default:60"`
}

type EndUser struct {
	Base
	Name               string `gorm:"not null"`
	Email              string `gorm:"not null;default:''"`
	Note               string
	Status             string `gorm:"not null;default:active;index"`
	PortalPasswordHash string `json:"-"`
	AuthVersion        uint64 `gorm:"not null;default:0" json:"-"`
}

type License struct {
	Source           string `gorm:"not null;default:''"`
	ConvertedAt      *time.Time
	MaintenanceUntil *time.Time
	Base
	AppID              uint64      `gorm:"not null;index"`
	Application        Application `gorm:"foreignKey:AppID;constraint:OnDelete:RESTRICT"`
	UserID             *uint64     `gorm:"index"`
	User               *EndUser    `gorm:"foreignKey:UserID;constraint:OnDelete:RESTRICT"`
	Key                string      `gorm:"not null;uniqueIndex"`
	BatchID            string      `gorm:"index"`
	ValidityRule       string      `gorm:"not null;default:perpetual"`
	Type               string      `gorm:"not null;default:standard;index"`
	Status             string      `gorm:"not null;default:unused;index"`
	VerifyMethods      []string    `gorm:"serializer:json;type:text"`
	MatchMode          string      `gorm:"not null;default:all"`
	MaxActivations     int         `gorm:"not null;default:1"`
	Features           JSONMap     `gorm:"type:text"`
	StartsAt           *time.Time
	ExpiresAt          *time.Time `gorm:"index"`
	DurationDays       int
	PortalPasswordHash string `json:"-"`
	Note               string
	Metadata           JSONMap `gorm:"type:text"`
}

type Activation struct {
	InstanceSession string `gorm:"not null;default:''" json:"-"`
	Base
	LicenseID         uint64         `gorm:"not null;uniqueIndex:idx_activation_binding,priority:1;index"`
	License           License        `gorm:"constraint:OnDelete:RESTRICT"`
	Kind              string         `gorm:"not null;uniqueIndex:idx_activation_binding,priority:2"`
	Value             string         `gorm:"not null;uniqueIndex:idx_activation_binding,priority:3"`
	FingerprintDetail map[string]any `gorm:"serializer:json;type:text"`
	Hostname          string
	OS                string
	ClientVersion     string
	FirstIP           string
	LastIP            string
	LastSeenAt        *time.Time `gorm:"index"`
	Status            string     `gorm:"not null;default:active;index"`
	OfflineAt         *time.Time `gorm:"index"`
	UnboundAt         *time.Time
	Token             string     `gorm:"not null;uniqueIndex" json:"-"`
	LeaseExpiresAt    *time.Time `gorm:"index"`
}

type VerifyLog struct {
	ID            uint64       `gorm:"primaryKey"`
	CreatedAt     time.Time    `gorm:"index"`
	AppID         *uint64      `gorm:"index"`
	Application   *Application `gorm:"foreignKey:AppID;constraint:OnDelete:RESTRICT"`
	LicenseID     *uint64      `gorm:"index"`
	License       *License     `gorm:"constraint:OnDelete:RESTRICT"`
	ActivationID  *uint64      `gorm:"index"`
	Activation    *Activation  `gorm:"constraint:OnDelete:RESTRICT"`
	Action        string
	Code          string `gorm:"index"`
	Success       bool
	Reason        string
	IP            string `gorm:"index"`
	Device        string
	ClientVersion string
	DurationMS    int64
}

type AuditLog struct {
	ID         uint64    `gorm:"primaryKey"`
	CreatedAt  time.Time `gorm:"index"`
	AdminID    *uint64   `gorm:"index"`
	Admin      *Admin    `gorm:"constraint:OnDelete:RESTRICT"`
	Action     string    `gorm:"not null;index"`
	Resource   string    `gorm:"index"`
	ResourceID string    `gorm:"index"`
	IP         string    `gorm:"index"`
	Operator   string    `gorm:"index"`
	UserAgent  string
	Summary    string
	StatusCode int            `gorm:"index"`
	Details    map[string]any `gorm:"serializer:json;type:text"`
}

type Setting struct {
	Key       string `gorm:"primaryKey"`
	Value     string `gorm:"not null"`
	UpdatedAt time.Time
}

type Announcement struct {
	Base
	AppID       uint64      `gorm:"not null;index"`
	Application Application `gorm:"foreignKey:AppID;constraint:OnDelete:RESTRICT"`
	Title       string      `gorm:"not null"`
	Content     string
	PublishedAt *time.Time `gorm:"index"`
	ExpiresAt   *time.Time
}

type AppVersion struct {
	Encrypted         bool `gorm:"not null;default:false"`
	BuiltAt           *time.Time
	Disabled          bool   `gorm:"not null;default:false"`
	Source            string `gorm:"not null;default:manual"`
	Withdrawn         bool
	MandatoryOverride bool
	Base
	AppID       uint64      `gorm:"not null;uniqueIndex:idx_app_version,priority:1"`
	Application Application `gorm:"foreignKey:AppID;constraint:OnDelete:RESTRICT"`
	Version     string      `gorm:"not null;uniqueIndex:idx_app_version,priority:2"`
	Changelog   string
	Mandatory   bool
	PublishedAt *time.Time
}

// SchemaMigration identifies the supported database baseline.
type SchemaMigration struct {
	Version   int       `gorm:"primaryKey;autoIncrement:false"`
	Name      string    `gorm:"not null"`
	AppliedAt time.Time `gorm:"not null"`
}

// AdminSession stores only a refresh JWT's SHA-256 hash, never its plaintext.
// Access JWTs bind to this row so logout is immediately effective.
type AdminSession struct {
	ID          string `gorm:"primaryKey"`
	AdminID     uint64 `gorm:"not null;index"`
	Admin       Admin  `gorm:"constraint:OnDelete:RESTRICT"`
	TokenHash   string `gorm:"not null;uniqueIndex" json:"-"`
	AuthVersion uint64 `gorm:"not null"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ExpiresAt   time.Time  `gorm:"not null;index"`
	RevokedAt   *time.Time `gorm:"index"`
}

// ClientSession contains only the SHA-256 of the external activation_token.
type ClientSession struct {
	ID          string      `gorm:"primaryKey"`
	AppID       uint64      `gorm:"not null;index"`
	Application Application `gorm:"foreignKey:AppID;constraint:OnDelete:RESTRICT"`
	LicenseID   uint64      `gorm:"not null;index"`
	License     License     `gorm:"constraint:OnDelete:RESTRICT"`
	TokenHash   string      `gorm:"not null;uniqueIndex" json:"-"`
	Device      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	RevokedAt   *time.Time `gorm:"index"`
}
type ClientSessionBinding struct {
	SessionID    string        `gorm:"primaryKey"`
	Session      ClientSession `gorm:"foreignKey:SessionID;constraint:OnDelete:RESTRICT"`
	ActivationID uint64        `gorm:"primaryKey;index"`
	Activation   Activation    `gorm:"constraint:OnDelete:RESTRICT"`
	Generation   string        `gorm:"not null" json:"-"`
}

// NotificationReceipt deduplicates scheduled notifications by license + expiry + window.
type NotificationReceipt struct {
	Key       string `gorm:"primaryKey"`
	CreatedAt time.Time
}
type MailDelivery struct {
	ReceiptKey string `gorm:"index" json:"-"`
	Base
	Recipient   string
	Subject     string
	Body        string
	Status      string `gorm:"not null;default:pending;index"`
	Attempts    int
	LastError   string
	NextRetryAt *time.Time `gorm:"index"`
	ClaimUntil  *time.Time `gorm:"index"`
	ClaimToken  string     `json:"-"`
	SentAt      *time.Time
}
