// Package client implements the authenticated client protocol around the pure
// verify engine. All policy mutations happen in a single SQLite transaction.
package client

import (
	"authgo/internal/channel"
	"authgo/internal/code"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/dockerhub"
	"authgo/internal/model"
	"authgo/internal/payloadkey"
	"authgo/internal/trial"
	"authgo/internal/updater"
	"authgo/internal/verify"
	"authgo/sdk/wire"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"log/slog"
	"slices"
	"strconv"
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
	payloadLimit *limiter
	trials       *trial.Service
	updates      *updater.Service
	hub          *dockerhub.Service
	channel      *channel.Store
	sampledLogs  atomic.Uint64
	logSamples   *limiter
	db           *gorm.DB
	cipher       *cryptoutil.Cipher
	now          func() time.Time
	log          *slog.Logger
	ip, license  *limiter
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
	s := &Service{db: db, cipher: box, now: opts.Now, log: log, ip: newLimiter(opts.IPRate, opts.IPBurst, 50000), license: newLimiter(opts.LicenseRate, opts.LicenseBurst, 50000), nonces: nonceCache{entries: map[string]time.Time{}, limit: 100000}}
	s.trials = trial.New(db, s.now)
	s.payloadKeys = payloadkey.New(db, box)
	s.payloadOpen = s.payloadKeys.Open
	s.payloadLimit = newLimiter(payloadUnlockRate, payloadUnlockBurst, 50000)
	s.channel, err = channel.New(db, master)
	if err != nil {
		return nil, err
	}
	s.updates, err = updater.New(db, master, s.now)
	if err != nil {
		return nil, err
	}
	s.hub = dockerhub.New(db, s.updates, s.now)
	s.logSamples = newLimiter(1.0/60, 1, 50000)
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

func (s *Service) process(ctx context.Context, app model.Application, op, ip string, in Input, now time.Time) outcome {
	return s.processPolicy(ctx, app, op, ip, in, now, false)
}

// Updating checks all authorization and binding policy except the running version.
// Only the target version is constrained by updater.Check/asset. Never exposed as input.
func (s *Service) processPolicy(ctx context.Context, app model.Application, op, ip string, in Input, now time.Time, updating bool) outcome {
	return s.processPolicyPayload(ctx, app, op, ip, in, now, updating, false)
}

func (s *Service) processPolicyPayload(ctx context.Context, app model.Application, op, ip string, in Input, now time.Time, updating, unlocking bool) outcome {
	result := denied(code.InternalError)
	var payloadData map[string]any
	var lid uint64
	var activationID *uint64
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Refresh mutable application policy under the same transaction as capacity.
		var a model.Application
		if err := tx.First(&a, app.ID).Error; err != nil {
			return err
		}
		if a.AppSecretEncrypted != app.AppSecretEncrypted {
			result = denied(code.SignatureInvalid)
			return nil
		}
		if a.Status != "active" {
			result = denied(code.AppDisabled)
			return nil
		}
		var l model.License
		if err := tx.Preload("User").Where("app_id = ? AND key = ?", a.ID, in.LicenseKey).First(&l).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				result = denied(code.LicenseNotFound)
				return nil
			}
			return err
		}
		lid = l.ID
		result.LicenseID = &lid
		if l.UserID != nil && (l.User == nil || l.User.Status != "active") {
			result = denied(code.UserDisabled)
			result.LicenseID = &lid
			return nil
		}

		if unlocking {
			if v := verify.LicenseValidity(a, l, verify.Request{Operation: op, Key: in.LicenseKey, Now: s.now().UTC()}); !v.Pass {
				result = denied(v.Errors[0])
				return nil
			}
		}
		req := verify.Request{SkipVersionCheck: updating, Operation: op, Key: in.LicenseKey, IP: ip, Device: in.Device, Version: in.Version, InstanceSession: in.InstanceSession, Now: now}
		normalized, problem := verify.Normalize(req)
		req = normalized
		// Active snapshots plus matching historical carriers for unique-row reuse;
		// unrelated unbound key/lease history need not be loaded on every check.
		var rows []model.Activation
		if err := tx.Where("license_id = ? AND (status = 'active' OR (kind = 'floating' AND value = ?))", l.ID, req.Device).Find(&rows).Error; err != nil {
			return err
		}

		var session model.ClientSession
		if op == verify.Activate {
			id, e := cryptoutil.RandomString(24)
			if e != nil {
				return e
			}
			session.ID = id
			req.SessionID = session.ID
		} else if problem == "" {
			if !validToken(in.ActivationToken) {
				problem = code.ActivationInvalid
			} else {
				e := tx.Where("token_hash = ? AND app_id = ? AND license_id = ? AND revoked_at IS NULL", cryptoutil.SHA256([]byte(in.ActivationToken)), a.ID, l.ID).First(&session).Error
				if errors.Is(e, gorm.ErrRecordNotFound) {
					problem = code.ActivationInvalid
				} else if e != nil {
					return e
				}
				req.SessionID = session.ID
				if problem == "" && session.Device != req.Device {
					problem = code.ActivationInvalid
				}
				if problem == "" {
					ok, e := sessionValid(tx, session.ID, rows)
					if e != nil {
						return e
					}
					if !ok {
						problem = code.ActivationInvalid
					} else {
						for _, v := range rows {
							if v.Kind == "key" && v.Value == session.ID {
								id := v.ID
								activationID = &id
								break
							}
						}
					}
				}
			}
		}
		// Re-evaluate wall time after waiting for the SQLite transaction/queries;
		// a queued request must not validate against its earlier arrival time.
		now = s.now().UTC()
		req.Now = now
		var decision verify.Result
		if problem != "" {
			decision.Errors = []string{problem}
		} else if op == "deactivate" || op == "release-seat" {
			if l.Status == "revoked" {
				decision.Errors = []string{code.LicenseRevoked}
			} else {
				decision.Pass = true
			}
		} else {
			var versions []model.AppVersion
			if !updating && (req.Version != "" || l.MaintenanceUntil != nil) {
				if e := tx.Select("version", "disabled", "withdrawn", "published_at").Where("app_id=?", a.ID).Find(&versions).Error; e != nil {
					return e
				}
			}
			decision = verify.Evaluate(verify.Input{Application: a, License: l, Request: req, Activations: rows, Versions: versions})
		}

		if op == verify.Activate && decision.Pass {
			var count int64
			if e := tx.Model(&model.ClientSession{}).Where("license_id = ? AND revoked_at IS NULL", l.ID).Count(&count).Error; e != nil {
				return e
			}
			if count >= 10000 {
				decision = verify.Result{Errors: []string{code.ActivationLimitReached}}
			}
		}
		// Unlock always requires its existing floating lease, even if an ANY
		// instance policy otherwise succeeds. Never acquire a seat here.
		if unlocking && decision.Pass && slices.Contains(l.VerifyMethods, "FLOATING") && !slices.Contains(decision.Satisfied, "FLOATING") {
			decision = verify.Result{Errors: []string{code.LeaseExpired}}
		}
		if decision.Pass || len(decision.Errors) > 0 && (decision.Errors[0] == code.LeaseExpired || decision.Errors[0] == code.FloatingLimitReached || decision.Errors[0] == code.VersionDisabled || decision.Errors[0] == code.MaintenanceExpired || decision.Errors[0] == code.VersionNotAllowed) {
			takeover := !unlocking && (op == verify.Activate || op == verify.Verify || op == verify.Heartbeat)
			problem, e := instanceCheck(tx, rows, session.ID, req.Device, in.InstanceSession, takeover)
			if e != nil {
				return e
			}
			if problem != "" {
				decision = verify.Result{Errors: []string{problem}}
			}
		}
		if !decision.Pass {
			if len(decision.Errors) == 0 {
				decision.Errors = []string{code.InternalError}
			}
			result = denied(decision.Errors[0])
			result.Data["errors"] = decision.Errors
			if decision.Errors[0] == code.VersionDisabled {
				result.Data["latest_version"] = decision.LatestVersion
			}
			if decision.Errors[0] == code.MaintenanceExpired {
				result.Data["latest_entitled_version"] = decision.LatestEntitledVersion
				result.Data["is_trial"] = l.Type == "trial"
				result.Data["type"] = l.Type
				result.Data["maintenance_until"] = l.MaintenanceUntil
			}
			result.LicenseID = &lid
			if !unlocking && result.Code == code.LicenseExpired && (l.Status == "active" || l.Status == "unused") {
				if err := tx.Model(&l).Update("status", "expired").Error; err != nil {
					return err
				}
			}
			return nil
		}
		if unlocking {
			checked := s.unlockPayload(tx, a, l, in, req, now)
			if checked.Code != code.OK {
				result = checked
				return nil
			}
			result.PayloadVersion = checked.PayloadVersion
			payloadData = checked.Data
			decision.LatestEntitledVersion, _ = checked.Data["latest_entitled_version"].(string)
			req.Version = checked.Data["version"].(string)
		}
		if op == "release-seat" {
			released, e := releaseSeat(tx, rows, session.ID, req.Device, now)
			if e != nil {
				return e
			}
			result = outcome{Code: code.OK, Data: map[string]any{"released": released}, LicenseID: &lid}
			return nil
		}
		if op == "deactivate" {
			c, e := deactivate(tx, &l, session, rows, now)
			if e != nil {
				return e
			}
			if c != "" {
				result = denied(c)
				result.LicenseID = &lid
				return nil
			}
			result = outcome{Code: code.OK, Data: map[string]any{"deactivated": true}, LicenseID: &lid}
			return nil
		}
		if !unlocking {
			if e := claimInstances(tx, rows, session.ID, req.Device, in.InstanceSession); e != nil {
				return e
			}
		}
		if op == verify.Activate {
			raw, e := token()
			if e != nil {
				return e
			}
			session.AppID = a.ID
			session.LicenseID = l.ID
			session.TokenHash = cryptoutil.SHA256([]byte(raw))
			session.Device = req.Device
			session.CreatedAt = now
			session.UpdatedAt = now
			if e := tx.Create(&session).Error; e != nil {
				return e
			}
			result.Data = map[string]any{"activation_token": raw}
			decision.Writes = append(decision.Writes, verify.Mutation{Kind: "key", Value: session.ID})
		} else {
			result.Data = map[string]any{}
		}
		for _, m := range decision.Writes {
			var activation model.Activation
			if m.ID != 0 {
				for _, row := range rows {
					if row.ID == m.ID {
						activation = row
						break
					}
				}
			}
			fresh := activation.ID == 0 || activation.Status != "active" || activation.OfflineAt != nil
			if fresh {
				g, e := generation()
				if e != nil {
					return e
				}
				activation.Token = g
			}
			activation.LicenseID = l.ID
			activation.Kind = m.Kind
			if !unlocking && in.InstanceSession != "" && (m.Kind == "key" || m.Kind == "floating") {
				activation.InstanceSession = in.InstanceSession
			}
			activation.Value = m.Value
			activation.Status = "active"
			activation.OfflineAt = nil
			activation.UnboundAt = nil
			if activation.FirstIP == "" {
				activation.FirstIP = ip
			}
			activation.LastIP = ip
			activation.LastSeenAt = &now
			activation.ClientVersion = req.Version
			activation.Hostname = in.Hostname
			activation.OS = in.OS
			activation.LeaseExpiresAt = m.LeaseExpiresAt
			if activation.ID == 0 {
				activation.CreatedAt = now
			}
			activation.UpdatedAt = now
			if e := tx.Omit("License").Save(&activation).Error; e != nil {
				return e
			}
			if (op == verify.Activate || fresh) && in.InstanceSession != "" && (m.Kind == "key" || m.Kind == "floating") {
				if e := rememberInstance(tx, activation.ID, in.InstanceSession); e != nil {
					return e
				}
			}
			if m.Kind == "key" {
				id := activation.ID
				result.ActivationID = &id
			}
			if op == verify.Activate || (fresh && m.Kind == "floating") {
				ref := model.ClientSessionBinding{SessionID: session.ID, ActivationID: activation.ID, Generation: activation.Token}
				if e := tx.Create(&ref).Error; e != nil {
					return e
				}
			}
		}
		if op != verify.Activate {
			if e := tx.Model(&model.Activation{}).Where("license_id = ? AND kind = 'key' AND value = ?", l.ID, session.ID).Updates(map[string]any{"last_seen_at": now, "last_ip": ip, "client_version": req.Version}).Error; e != nil {
				return e
			}
			if e := tx.Model(&session).Update("updated_at", now).Error; e != nil {
				return e
			}
		}
		if op == verify.Activate {
			updates := map[string]any{"status": "active"}
			if decision.StartsAt != nil {
				updates["starts_at"] = decision.StartsAt
				l.StartsAt = decision.StartsAt
			}
			if decision.ExpiresAt != nil {
				updates["expires_at"] = decision.ExpiresAt
				l.ExpiresAt = decision.ExpiresAt
			}
			if e := tx.Model(&l).Updates(updates).Error; e != nil {
				return e
			}
		}
		if op == verify.Activate {
			if e := trial.ConvertOnActivation(tx, l, req.Device, now); e != nil {
				return e
			}
		}
		grace := now.Add(time.Duration(a.GraceHours) * time.Hour)
		if l.Type == "trial" {
			grace = now.Add(time.Duration(a.NextCheckIn)*time.Second + trialRefreshOverlap)
		}
		if l.ExpiresAt != nil && grace.After(*l.ExpiresAt) {
			grace = *l.ExpiresAt
		}
		for k, v := range payloadData {
			result.Data[k] = v
		}
		result.Code = code.OK
		result.MaintenanceUnknown = decision.MaintenanceUnknown
		result.Data["is_trial"] = l.Type == "trial"
		result.Data["type"] = l.Type
		result.Data["maintenance_until"] = l.MaintenanceUntil
		result.Data["latest_entitled_version"] = decision.LatestEntitledVersion
		result.LicenseID = &lid
		for k, v := range map[string]any{"license_id": l.ID, "status": "active", "expires_at": l.ExpiresAt, "starts_at": l.StartsAt, "features": l.Features, "next_check_in": a.NextCheckIn, "grace_until": grace, "heartbeat_interval": a.HeartbeatInterval, "satisfied_methods": decision.Satisfied} {
			result.Data[k] = v
		}
		for _, m := range decision.Writes {
			if m.Kind == "floating" {
				result.Data["lease_expires_at"] = m.LeaseExpiresAt
			}
		}

		private, e := s.privateKey(a)
		if e != nil {
			return e
		}
		seed, e := s.cipher.Decrypt(a.UnlockSecretEncrypted, aad(a.AppKey, "unlock_secret"))
		if e != nil {
			return e
		}
		features, e := json.Marshal(l.Features)
		if e != nil {
			return e
		}
		grant := wire.Grant{IsTrial: l.Type == "trial", MaintenanceUntil: l.MaintenanceUntil, LatestEntitledVersion: decision.LatestEntitledVersion, V: 2, AppKey: a.AppKey, Challenge: in.Challenge, LicenseID: l.ID, LicenseRef: wire.Hash([]byte("authgo-license-v1\x00" + a.LicenseSalt + "\x00" + strconv.FormatUint(l.ID, 10))), DeviceHash: wire.Hash([]byte(req.Device)), Status: "active", IssuedAt: now, StartsAt: l.StartsAt, ExpiresAt: l.ExpiresAt, Features: features, NextCheckIn: a.NextCheckIn, GraceUntil: grace, UnlockHash: wire.Hash(seed)}
		if l.Type == "trial" {
		}
		for _, m := range decision.Writes {
			if m.Kind == "floating" {
				grant.Floating = true
				grant.LeaseExpiresAt = m.LeaseExpiresAt
			}
		}
		ticket, e := wire.EncodeTicket(grant, private)
		if e != nil {
			return e
		}
		result.Data["ticket"] = ticket
		result.Data["unlock_seed"] = wire.B64.EncodeToString(seed)
		return nil
	})
	if err != nil {
		s.log.Error("客户端验证事务失败", "error", err)
		return denied(code.InternalError)
	}
	if unlocking && lid != 0 {
		result.LicenseID = &lid
	}
	if result.ActivationID == nil {
		result.ActivationID = activationID
	}
	return result
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
	s.ip.configure(float64(ipRate), ipBurst)
	s.license.configure(float64(licenseRate), licenseBurst)
}

func (s *Service) Updates() *updater.Service { return s.updates }

func (s *Service) SetDockerHub(h *dockerhub.Service) { s.hub = h }
