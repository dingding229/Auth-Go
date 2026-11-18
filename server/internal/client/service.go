// Package client implements the authenticated client protocol around the pure
// verify engine. All policy mutations happen in a single SQLite transaction.
package client

import (
	"authgo/internal/channel"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/dockerhub"
	"authgo/internal/model"
	"authgo/internal/payloadkey"
	"authgo/internal/ratelimit"
	"authgo/internal/trial"
	"authgo/internal/updater"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"log/slog"
	"sync/atomic"
	"time"
)

// trialRefreshOverlap covers in-flight refreshes, never offline grace.
const trialRefreshOverlap = 30 * time.Second

type Options struct {
	Now                   func() time.Time
	IPRate, LicenseRate   float64
	IPBurst, LicenseBurst int
	LogCapacity           int
}
type Service struct {
	payloadKeys  *payloadkey.Service
	payloadOpen  func(*gorm.DB, model.Application, payloadkey.Payload) ([]byte, error)
	payloadLimit *ratelimit.Limiter
	trials       *trial.Service
	updates      *updater.Service
	hub          *dockerhub.Service
	channel      *channel.Store
	sampledLogs  atomic.Uint64
	logSamples   *ratelimit.Limiter
	db           *gorm.DB
	cipher       *cryptoutil.Cipher
	now          func() time.Time
	log          *slog.Logger
	ip, license  *ratelimit.Limiter
	nonces       nonceCache
	logs         *logWriter
}

func NewService(db *gorm.DB, master []byte, log *slog.Logger, opts Options) (*Service, error) {
	box, err := cryptoutil.NewCipher(master)
	if err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.IPRate <= 0 {
		opts.IPRate = 10
	}
	if opts.LicenseRate <= 0 {
		opts.LicenseRate = 5
	}
	if opts.IPBurst <= 0 {
		opts.IPBurst = 60
	}
	if opts.LicenseBurst <= 0 {
		opts.LicenseBurst = 30
	}
	if opts.LogCapacity <= 0 {
		opts.LogCapacity = 4096
	}
	if log == nil {
		log = slog.Default()
	}
	s := &Service{db: db, cipher: box, now: opts.Now, log: log, ip: ratelimit.Tokens(opts.IPRate, opts.IPBurst, 50000, true), license: ratelimit.Tokens(opts.LicenseRate, opts.LicenseBurst, 50000, true), nonces: nonceCache{entries: map[string]time.Time{}, limit: 100000}}
	s.trials = trial.New(db, s.now)
	s.payloadKeys = payloadkey.New(db, box)
	s.payloadOpen = s.payloadKeys.Open
	s.payloadLimit = ratelimit.Tokens(payloadUnlockRate, payloadUnlockBurst, 50000, true)
	s.channel, err = channel.New(db, master)
	if err != nil {
		return nil, err
	}
	s.updates = updater.New(db, s.now)
	s.hub = dockerhub.New(db, s.updates, s.now)
	s.logSamples = ratelimit.Tokens(1.0/60, 1, 50000, true)
	s.logs = newLogWriter(db, log, opts.LogCapacity)
	return s, nil
}
func (s *Service) Close(ctx context.Context) error { return s.logs.close(ctx) }

// DroppedLogEntries counts queue/closed-writer and persistence losses, not denied requests.
func (s *Service) DroppedLogEntries() uint64 { return s.logs.dropped.Load() }

// SampledLogRequests counts noisy requests intentionally omitted by sampling.
func (s *Service) SampledLogRequests() uint64 { return s.sampledLogs.Load() }

func aad(key, purpose string) []byte { return []byte("application:" + key + ":" + purpose) }
func (s *Service) privateKey(a model.Application) (ed25519.PrivateKey, error) {
	raw, err := s.cipher.Decrypt(a.PrivateKeyEncrypted, aad(a.AppKey, "ed25519_private_key"))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("软件签名私钥无效")
	}
	pub, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil {
		return nil, err
	}
	proof, err := cryptoutil.Sign(ed25519.PrivateKey(raw), []byte("authgo/key-check"))
	if err != nil || !cryptoutil.Verify(pub, []byte("authgo/key-check"), proof) {
		return nil, errors.New("软件签名密钥不匹配")
	}
	return ed25519.PrivateKey(raw), nil
}

type Input struct {
	historyLimit       *int
	historyBefore      string
	Payload            json.RawMessage `json:"payload,omitempty"`
	EphemeralPublicKey string          `json:"ephemeral_public_key,omitempty"`
	InstanceSession    string          `json:"instance_session"`
	CurrentVersion     string          `json:"current_version"`
	Challenge          string          `json:"challenge"`
	LicenseKey         string          `json:"license_key"`
	ActivationToken    string          `json:"activation_token"`
	Device             string          `json:"device_fingerprint"`
	Version            string          `json:"client_version"`
	Hostname           string          `json:"hostname"`
	OS                 string          `json:"os"`
}
type outcome struct {
	Code                    string
	PayloadVersion          string
	MaintenanceUnknown      bool
	Data                    map[string]any
	LicenseID, ActivationID *uint64
}

func denied(c string) outcome { return outcome{Code: c, Data: map[string]any{"errors": []string{c}}} }
func token() (string, error)  { v, e := cryptoutil.RandomString(32); return "act_" + v, e }
func generation() (string, error) {
	v, e := cryptoutil.RandomString(32)
	return cryptoutil.SHA256([]byte(v)), e
}
func validToken(v string) bool {
	if len(v) != 47 || v[:4] != "act_" {
		return false
	}
	b, e := base64.RawURLEncoding.DecodeString(v[4:])
	return e == nil && len(b) == 32
}

func sessionValid(tx *gorm.DB, id string, rows []model.Activation) (bool, error) {
	var refs []model.ClientSessionBinding
	if err := tx.Where("session_id = ?", id).Find(&refs).Error; err != nil {
		return false, err
	}
	anchor := false
	for _, ref := range refs {
		ok := false
		for _, a := range rows {
			if a.ID == ref.ActivationID && a.Status == "active" && a.OfflineAt == nil && a.Token == ref.Generation {
				ok = true
				if a.Kind == "key" && a.Value == id {
					anchor = true
				}
				break
			}
		}
		if !ok {
			return false, nil
		}
	}
	return anchor, nil
}

func (s *Service) ConfigureRateLimits(ipRate, ipBurst, licenseRate, licenseBurst int) {
	s.ip.Configure(float64(ipRate), ipBurst)
	s.license.Configure(float64(licenseRate), licenseBurst)
}

func (s *Service) Updates() *updater.Service { return s.updates }

func (s *Service) SetDockerHub(h *dockerhub.Service) { s.hub = h }
