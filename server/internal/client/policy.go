package client

import (
	"authgo/internal/code"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/internal/trial"
	"authgo/internal/verify"
	"authgo/sdk/wire"
	"context"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"slices"
	"strconv"
	"time"
)

type policyOptions struct{ updating, unlocking bool }
type policyRun struct {
	service         *Service
	tx              *gorm.DB
	incoming, app   model.Application
	license         model.License
	input           Input
	op, ip, problem string
	now             time.Time
	options         policyOptions
	request         verify.Request
	activations     []model.Activation
	session         model.ClientSession
	decision        verify.Result
	result          outcome
	licenseID       uint64
	activationID    *uint64
	payloadData     map[string]any
}

// process keeps policy checks and all instance mutations in one SQLite transaction.
func (s *Service) process(ctx context.Context, app model.Application, op, ip string, in Input, now time.Time, options policyOptions) outcome {
	p := policyRun{service: s, incoming: app, op: op, ip: ip, input: in, now: now, options: options, result: denied(code.InternalError)}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		p.tx = tx
		ready, err := p.loadPolicy()
		if err != nil || !ready {
			return err
		}
		if err := p.evaluate(); err != nil {
			return err
		}
		if !p.decision.Pass {
			return p.reject()
		}
		if done, err := p.terminalAction(); done || err != nil {
			return err
		}
		for _, step := range []func() error{p.claimSession, p.writeActivations, p.updateActivity, p.buildSuccess} {
			if err := step(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.Error("客户端验证事务失败", "error", err)
		return denied(code.InternalError)
	}
	if options.unlocking && p.licenseID != 0 {
		p.result.LicenseID = &p.licenseID
	}
	if p.result.ActivationID == nil {
		p.result.ActivationID = p.activationID
	}
	return p.result
}

func (p *policyRun) loadPolicy() (bool, error) {
	// Refresh mutable application policy under the same transaction as capacity.
	if err := p.tx.First(&p.app, p.incoming.ID).Error; err != nil {
		return false, err
	}
	if p.app.AppSecretEncrypted != p.incoming.AppSecretEncrypted {
		p.result = denied(code.SignatureInvalid)
		return false, nil
	}
	if p.app.Status != model.StatusActive {
		p.result = denied(code.AppDisabled)
		return false, nil
	}
	if err := p.tx.Preload("User").Where("app_id = ? AND key = ?", p.app.ID, p.input.LicenseKey).First(&p.license).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			p.result = denied(code.LicenseNotFound)
			return false, nil
		}
		return false, err
	}
	p.licenseID = p.license.ID
	p.result.LicenseID = &p.licenseID
	if p.license.UserID != nil && (p.license.User == nil || p.license.User.Status != model.StatusActive) {
		p.result = denied(code.UserDisabled)
		p.result.LicenseID = &p.licenseID
		return false, nil
	}

	if p.options.unlocking {
		if v := verify.LicenseValidity(p.app, p.license, verify.Request{Operation: p.op, Key: p.input.LicenseKey, Now: p.service.now().UTC()}); !v.Pass {
			p.result = denied(v.Errors[0])
			return false, nil
		}
	}

	return true, nil
}

func (p *policyRun) evaluate() error {
	p.request = verify.Request{SkipVersionCheck: p.options.updating, Operation: p.op, Key: p.input.LicenseKey, IP: p.ip, Device: p.input.Device, Version: p.input.Version, InstanceSession: p.input.InstanceSession, Now: p.now}
	p.request, p.problem = verify.Normalize(p.request)
	// Active snapshots plus matching historical carriers for unique-row reuse;
	// unrelated unbound key/lease history need not be loaded on every check.
	if err := p.tx.Where("license_id = ? AND (status = 'active' OR (kind = 'floating' AND value = ?))", p.license.ID, p.request.Device).Find(&p.activations).Error; err != nil {
		return err
	}

	if p.op == verify.Activate {
		id, e := cryptoutil.RandomString(24)
		if e != nil {
			return e
		}
		p.session.ID = id
		p.request.SessionID = p.session.ID
	} else if p.problem == "" {
		if !validToken(p.input.ActivationToken) {
			p.problem = code.ActivationInvalid
		} else {
			e := p.tx.Where("token_hash = ? AND app_id = ? AND license_id = ? AND revoked_at IS NULL", cryptoutil.SHA256([]byte(p.input.ActivationToken)), p.app.ID, p.license.ID).First(&p.session).Error
			if errors.Is(e, gorm.ErrRecordNotFound) {
				p.problem = code.ActivationInvalid
			} else if e != nil {
				return e
			}
			p.request.SessionID = p.session.ID
			if p.problem == "" && p.session.Device != p.request.Device {
				p.problem = code.ActivationInvalid
			}
			if p.problem == "" {
				ok, e := sessionValid(p.tx, p.session.ID, p.activations)
				if e != nil {
					return e
				}
				if !ok {
					p.problem = code.ActivationInvalid
				} else {
					for _, v := range p.activations {
						if v.Kind == "key" && v.Value == p.session.ID {
							id := v.ID
							p.activationID = &id
							break
						}
					}
				}
			}
		}
	}
	// Re-evaluate wall time after waiting for the SQLite transaction/queries;
	// a queued request must not validate against its earlier arrival time.
	p.now = p.service.now().UTC()
	p.request.Now = p.now
	if p.problem != "" {
		p.decision.Errors = []string{p.problem}
	} else if p.op == "deactivate" || p.op == "release-seat" {
		if p.license.Status == "revoked" {
			p.decision.Errors = []string{code.LicenseRevoked}
		} else {
			p.decision.Pass = true
		}
	} else {
		var versions []model.AppVersion
		if !p.options.updating && (p.request.Version != "" || p.license.MaintenanceUntil != nil) {
			if e := p.tx.Select("version", "disabled", "withdrawn", "published_at").Where("app_id=?", p.app.ID).Find(&versions).Error; e != nil {
				return e
			}
		}
		p.decision = verify.Evaluate(verify.Input{Application: p.app, License: p.license, Request: p.request, Activations: p.activations, Versions: versions})
	}

	if p.op == verify.Activate && p.decision.Pass {
		var count int64
		if e := p.tx.Model(&model.ClientSession{}).Where("license_id = ? AND revoked_at IS NULL", p.license.ID).Count(&count).Error; e != nil {
			return e
		}
		if count >= 10000 {
			p.decision = verify.Result{Errors: []string{code.ActivationLimitReached}}
		}
	}
	// Unlock always requires its existing floating lease, even if an ANY
	// instance policy otherwise succeeds. Never acquire a seat here.
	if p.options.unlocking && p.decision.Pass && slices.Contains(p.license.VerifyMethods, "FLOATING") && !slices.Contains(p.decision.Satisfied, "FLOATING") {
		p.decision = verify.Result{Errors: []string{code.LeaseExpired}}
	}
	if p.decision.Pass || len(p.decision.Errors) > 0 && (p.decision.Errors[0] == code.LeaseExpired || p.decision.Errors[0] == code.FloatingLimitReached || p.decision.Errors[0] == code.VersionDisabled || p.decision.Errors[0] == code.MaintenanceExpired || p.decision.Errors[0] == code.VersionNotAllowed) {
		takeover := !p.options.unlocking && (p.op == verify.Activate || p.op == verify.Verify || p.op == verify.Heartbeat)
		instanceProblem, e := instanceCheck(p.tx, p.activations, p.session.ID, p.request.Device, p.input.InstanceSession, takeover)
		if e != nil {
			return e
		}
		if instanceProblem != "" {
			p.decision = verify.Result{Errors: []string{instanceProblem}}
		}
	}

	return nil
}

func (p *policyRun) reject() error {

	if len(p.decision.Errors) == 0 {
		p.decision.Errors = []string{code.InternalError}
	}
	p.result = denied(p.decision.Errors[0])
	p.result.Data["errors"] = p.decision.Errors
	if p.decision.Errors[0] == code.VersionDisabled {
		p.result.Data["latest_version"] = p.decision.LatestVersion
	}
	if p.decision.Errors[0] == code.MaintenanceExpired {
		p.result.Data["latest_entitled_version"] = p.decision.LatestEntitledVersion
		p.result.Data["is_trial"] = p.license.Type == model.LicenseTrial
		p.result.Data["type"] = p.license.Type
		p.result.Data["maintenance_until"] = p.license.MaintenanceUntil
	}
	p.result.LicenseID = &p.licenseID
	if !p.options.unlocking && p.result.Code == code.LicenseExpired && (p.license.Status == model.StatusActive || p.license.Status == model.StatusUnused) {
		if err := p.tx.Model(&p.license).Update("status", "expired").Error; err != nil {
			return err
		}
	}
	return nil
}

func (p *policyRun) terminalAction() (bool, error) {
	if p.options.unlocking {
		checked := p.service.unlockPayload(p.tx, p.app, p.license, p.input, p.request, p.now)
		if checked.Code != code.OK {
			p.result = checked
			return true, nil
		}
		p.result.PayloadVersion = checked.PayloadVersion
		p.payloadData = checked.Data
		p.decision.LatestEntitledVersion, _ = checked.Data["latest_entitled_version"].(string)
		p.request.Version = checked.Data["version"].(string)
	}
	if p.op == "release-seat" {
		released, e := releaseSeat(p.tx, p.activations, p.session.ID, p.request.Device, p.now)
		if e != nil {
			return true, e
		}
		p.result = outcome{Code: code.OK, Data: map[string]any{"released": released}, LicenseID: &p.licenseID}
		return true, nil
	}
	if p.op == "deactivate" {
		c, e := deactivate(p.tx, &p.license, p.session, p.activations, p.now)
		if e != nil {
			return true, e
		}
		if c != "" {
			p.result = denied(c)
			p.result.LicenseID = &p.licenseID
			return true, nil
		}
		p.result = outcome{Code: code.OK, Data: map[string]any{"deactivated": true}, LicenseID: &p.licenseID}
		return true, nil
	}

	return false, nil
}

func (p *policyRun) claimSession() error {
	if !p.options.unlocking {
		if e := claimInstances(p.tx, p.activations, p.session.ID, p.request.Device, p.input.InstanceSession); e != nil {
			return e
		}
	}
	if p.op == verify.Activate {
		raw, e := token()
		if e != nil {
			return e
		}
		p.session.AppID = p.app.ID
		p.session.LicenseID = p.license.ID
		p.session.TokenHash = cryptoutil.SHA256([]byte(raw))
		p.session.Device = p.request.Device
		p.session.CreatedAt = p.now
		p.session.UpdatedAt = p.now
		if e := p.tx.Create(&p.session).Error; e != nil {
			return e
		}
		p.result.Data = map[string]any{"activation_token": raw}
		p.decision.Writes = append(p.decision.Writes, verify.Mutation{Kind: "key", Value: p.session.ID})
	} else {
		p.result.Data = map[string]any{}
	}

	return nil
}

func (p *policyRun) writeActivations() error {
	for _, m := range p.decision.Writes {
		var activation model.Activation
		if m.ID != 0 {
			for _, row := range p.activations {
				if row.ID == m.ID {
					activation = row
					break
				}
			}
		}
		fresh := activation.ID == 0 || activation.Status != model.StatusActive || activation.OfflineAt != nil
		if fresh {
			g, e := generation()
			if e != nil {
				return e
			}
			activation.Token = g
		}
		activation.LicenseID = p.license.ID
		activation.Kind = m.Kind
		if !p.options.unlocking && p.input.InstanceSession != "" && (m.Kind == "key" || m.Kind == model.ActivationFloating) {
			activation.InstanceSession = p.input.InstanceSession
		}
		activation.Value = m.Value
		activation.Status = model.StatusActive
		activation.OfflineAt = nil
		activation.UnboundAt = nil
		if activation.FirstIP == "" {
			activation.FirstIP = p.ip
		}
		activation.LastIP = p.ip
		activation.LastSeenAt = &p.now
		activation.ClientVersion = p.request.Version
		activation.Hostname = p.input.Hostname
		activation.OS = p.input.OS
		activation.LeaseExpiresAt = m.LeaseExpiresAt
		if activation.ID == 0 {
			activation.CreatedAt = p.now
		}
		activation.UpdatedAt = p.now
		if e := p.tx.Omit("License").Save(&activation).Error; e != nil {
			return e
		}
		if (p.op == verify.Activate || fresh) && p.input.InstanceSession != "" && (m.Kind == "key" || m.Kind == model.ActivationFloating) {
			if e := rememberInstance(p.tx, activation.ID, p.input.InstanceSession); e != nil {
				return e
			}
		}
		if m.Kind == "key" {
			id := activation.ID
			p.result.ActivationID = &id
		}
		if p.op == verify.Activate || (fresh && m.Kind == model.ActivationFloating) {
			ref := model.ClientSessionBinding{SessionID: p.session.ID, ActivationID: activation.ID, Generation: activation.Token}
			if e := p.tx.Create(&ref).Error; e != nil {
				return e
			}
		}
	}

	return nil
}

func (p *policyRun) updateActivity() error {
	if p.op != verify.Activate {
		if e := p.tx.Model(&model.Activation{}).Where("license_id = ? AND kind = 'key' AND value = ?", p.license.ID, p.session.ID).Updates(map[string]any{"last_seen_at": p.now, "last_ip": p.ip, "client_version": p.request.Version}).Error; e != nil {
			return e
		}
		if e := p.tx.Model(&p.session).Update("updated_at", p.now).Error; e != nil {
			return e
		}
	}
	if p.op == verify.Activate {
		updates := map[string]any{"status": model.StatusActive}
		if p.decision.StartsAt != nil {
			updates["starts_at"] = p.decision.StartsAt
			p.license.StartsAt = p.decision.StartsAt
		}
		if p.decision.ExpiresAt != nil {
			updates["expires_at"] = p.decision.ExpiresAt
			p.license.ExpiresAt = p.decision.ExpiresAt
		}
		if e := p.tx.Model(&p.license).Updates(updates).Error; e != nil {
			return e
		}
	}
	if p.op == verify.Activate {
		if e := trial.ConvertOnActivation(p.tx, p.license, p.request.Device, p.now); e != nil {
			return e
		}
	}

	return nil
}

func (p *policyRun) buildSuccess() error {
	grace := p.now.Add(time.Duration(p.app.GraceHours) * time.Hour)
	if p.license.Type == model.LicenseTrial {
		grace = p.now.Add(time.Duration(p.app.NextCheckIn)*time.Second + trialRefreshOverlap)
	}
	if p.license.ExpiresAt != nil && grace.After(*p.license.ExpiresAt) {
		grace = *p.license.ExpiresAt
	}
	for k, v := range p.payloadData {
		p.result.Data[k] = v
	}
	p.result.Code = code.OK
	p.result.MaintenanceUnknown = p.decision.MaintenanceUnknown
	p.result.Data["is_trial"] = p.license.Type == model.LicenseTrial
	p.result.Data["type"] = p.license.Type
	p.result.Data["maintenance_until"] = p.license.MaintenanceUntil
	p.result.Data["latest_entitled_version"] = p.decision.LatestEntitledVersion
	p.result.LicenseID = &p.licenseID
	for k, v := range map[string]any{"license_id": p.license.ID, "status": model.StatusActive, "expires_at": p.license.ExpiresAt, "starts_at": p.license.StartsAt, "features": p.license.Features, "next_check_in": p.app.NextCheckIn, "grace_until": grace, "heartbeat_interval": p.app.HeartbeatInterval, "satisfied_methods": p.decision.Satisfied} {
		p.result.Data[k] = v
	}
	for _, m := range p.decision.Writes {
		if m.Kind == model.ActivationFloating {
			p.result.Data["lease_expires_at"] = m.LeaseExpiresAt
		}
	}

	private, e := p.service.privateKey(p.app)
	if e != nil {
		return e
	}
	seed, e := p.service.cipher.Decrypt(p.app.UnlockSecretEncrypted, aad(p.app.AppKey, "unlock_secret"))
	if e != nil {
		return e
	}
	features, e := json.Marshal(p.license.Features)
	if e != nil {
		return e
	}
	grant := wire.Grant{IsTrial: p.license.Type == model.LicenseTrial, MaintenanceUntil: p.license.MaintenanceUntil, LatestEntitledVersion: p.decision.LatestEntitledVersion, V: 2, AppKey: p.app.AppKey, Challenge: p.input.Challenge, LicenseID: p.license.ID, LicenseRef: wire.Hash([]byte("authgo-license-v1\x00" + p.app.LicenseSalt + "\x00" + strconv.FormatUint(p.license.ID, 10))), DeviceHash: wire.Hash([]byte(p.request.Device)), Status: model.StatusActive, IssuedAt: p.now, StartsAt: p.license.StartsAt, ExpiresAt: p.license.ExpiresAt, Features: features, NextCheckIn: p.app.NextCheckIn, GraceUntil: grace, UnlockHash: wire.Hash(seed)}
	for _, m := range p.decision.Writes {
		if m.Kind == model.ActivationFloating {
			grant.Floating = true
			grant.LeaseExpiresAt = m.LeaseExpiresAt
		}
	}
	ticket, e := wire.EncodeTicket(grant, private)
	if e != nil {
		return e
	}
	p.result.Data["ticket"] = ticket
	p.result.Data["unlock_seed"] = wire.B64.EncodeToString(seed)
	return nil
}
