package client

import (
	"authgo/internal/code"
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"authgo/internal/payloadkey"
	"authgo/internal/verify"
	"gorm.io/gorm"
	"time"
)

// Fixed policy, deliberately independent of ConfigureRateLimits.
const payloadUnlockRate = 6.0 / 60
const payloadUnlockBurst = 3

func (s *Service) PayloadKeys() *payloadkey.Service { return s.payloadKeys }
func (s *Service) unlockPayload(tx *gorm.DB, a model.Application, l model.License, in Input, req verify.Request, now time.Time) (out outcome) {
	defer func() {
		if out.Data != nil {
			out.Data["is_trial"] = l.Type == "trial"
		}
	}()
	p, e := payloadkey.Parse(in.Payload)
	if e != nil {
		return denied(code.PayloadInvalid)
	}
	key, e := s.payloadOpen(tx, a, p)
	if e != nil {
		return denied(code.PayloadInvalid)
	}
	defer clear(key)
	defer func() { out.PayloadVersion = p.Version }()
	var versions []model.AppVersion
	if e = tx.Select("version", "disabled", "withdrawn", "published_at").Where("app_id=?", a.ID).Find(&versions).Error; e != nil {
		return denied(code.InternalError)
	}
	// Publication dates are not trustworthy for encrypted builds: use authenticated built_at.
	req.Version = p.Version
	req.SkipVersionCheck = false
	v := verify.VersionDisabled(verify.Input{Application: a, License: l, Request: req, Versions: versions})
	if !v.Pass {
		out := denied(v.Errors[0])
		if v.Errors[0] == code.VersionDisabled {
			out.Data["latest_version"] = v.LatestVersion
		}
		return out
	}
	built, _ := time.Parse(time.RFC3339, p.BuiltAt)
	if l.MaintenanceUntil != nil && built.After(*l.MaintenanceUntil) {
		out := denied(code.MaintenanceExpired)
		out.Data["maintenance_until"] = l.MaintenanceUntil
		out.Data["latest_entitled_version"] = maintenance.Latest(a, l, versions, now)
		return out
	}
	if v := verify.VersionConstraints(verify.Input{Application: a, License: l, Request: req}); !v.Pass {
		return denied(v.Errors[0])
	}
	// Derive only after the existing authorization, instance, version and
	// authenticated built_at maintenance checks. Never derive from license text.
	watermark, e := s.payloadKeys.WatermarkForLicense(tx, a, p.KeyID, l.ID)
	if e != nil {
		return denied(code.PayloadInvalid)
	}
	wrapped, e := payloadkey.Rewrap(p, key, in.EphemeralPublicKey, in.Challenge)
	if e != nil {
		return denied(code.PayloadInvalid)
	}
	return outcome{Code: code.OK, Data: map[string]any{"e": wrapped.E, "n": wrapped.N, "c": wrapped.C, "watermark": watermark, "version": p.Version, "latest_entitled_version": maintenance.Latest(a, l, versions, now)}}
}
