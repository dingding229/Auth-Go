package wire

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"time"
)

const TicketDomain = "authgo-ticket-v2\x00"

type Grant struct {
	IsTrial               bool            `json:"is_trial,omitempty"`
	MaintenanceUntil      *time.Time      `json:"maintenance_until,omitempty"`
	LatestEntitledVersion string          `json:"latest_entitled_version,omitempty"`
	V                     int             `json:"v"`
	AppKey                string          `json:"app_key"`
	Challenge             string          `json:"challenge"`
	LicenseID             uint64          `json:"license_id"`
	LicenseRef            string          `json:"license_ref"`
	DeviceHash            string          `json:"device_hash"`
	Status                string          `json:"status"`
	IssuedAt              time.Time       `json:"issued_at"`
	StartsAt              *time.Time      `json:"starts_at"`
	ExpiresAt             *time.Time      `json:"expires_at"`
	Features              json.RawMessage `json:"features"`
	NextCheckIn           int             `json:"next_check_in"`
	GraceUntil            time.Time       `json:"grace_until"`
	LeaseExpiresAt        *time.Time      `json:"lease_expires_at"`
	Floating              bool            `json:"floating"`
	UnlockHash            string          `json:"unlock_hash"`
}

func Sign(domain string, payload []byte, private ed25519.PrivateKey) string {
	return B64.EncodeToString(ed25519.Sign(private, append([]byte(domain), payload...)))
}
func Verify(domain string, payload []byte, signature string, public ed25519.PublicKey) bool {
	sig, e := decode(signature, ed25519.SignatureSize)
	return e == nil && len(public) == 32 && ed25519.Verify(public, append([]byte(domain), payload...), sig)
}
func EncodeTicket(g Grant, private ed25519.PrivateKey) (string, error) {
	raw, e := json.Marshal(g)
	if e != nil {
		return "", e
	}
	return B64.EncodeToString(raw) + "." + Sign(TicketDomain, raw, private), nil
}
func DecodeTicket(ticket string, public ed25519.PublicKey) (Grant, error) {
	var g Grant
	p := strings.Split(ticket, ".")
	if len(p) != 2 {
		return g, ErrInvalid
	}
	raw, e := decode(p[0], 0)
	if e != nil || !Verify(TicketDomain, raw, p[1], public) {
		return g, ErrInvalid
	}
	e = json.Unmarshal(raw, &g)
	return g, e
}

// ResourceKey derives internal cache material. It is not a resource product API.
func ResourceKey(seed []byte, label string) []byte {
	return HKDF(seed, nil, []byte("authgo-unlock-v2\x00"+label), 32)
}
