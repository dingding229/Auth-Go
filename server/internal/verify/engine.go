// Package verify is a deterministic, IO-free policy engine. Inputs are snapshots;
// decisions describe writes but never mutate input models or perform database IO.
package verify

import (
	"authgo/internal/binding"
	"authgo/internal/code"
	"authgo/internal/maintenance"
	"authgo/internal/model"
	"encoding/hex"
	"github.com/Masterminds/semver/v3"
	"strings"
	"time"
)

const (
	Activate  = "activate"
	Verify    = "verify"
	Heartbeat = "heartbeat"
)

type Request struct {
	// Internal update authorization only; never populated from a client field.
	SkipVersionCheck                                                bool
	Operation, Key, IP, Device, Version, SessionID, InstanceSession string
	Now                                                             time.Time
}
type Input struct {
	Application model.Application
	License     model.License
	Request     Request
	Activations []model.Activation
	Versions    []model.AppVersion
}
type Mutation struct {
	ID             uint64
	Kind, Value    string
	LeaseExpiresAt *time.Time
}
type Result struct {
	Pass                  bool
	Errors                []string
	Writes                []Mutation
	StartsAt, ExpiresAt   *time.Time
	Satisfied             []string
	LatestVersion         string
	LatestEntitledVersion string
	MaintenanceUnknown    bool
}

func fail(codes ...string) Result { return Result{Errors: codes} }

func validFingerprint(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32
}
func Normalize(r Request) (Request, string) {
	var err error
	r.IP, err = binding.NormalizeIP(r.IP, false)
	if err != nil {
		return r, code.InvalidRequest
	}
	r.Device = strings.ToLower(r.Device)
	if r.Device != "" && !validFingerprint(r.Device) {
		return r, code.DeviceInvalid
	}

	if r.InstanceSession != "" && r.Device == "" {
		return r, code.DeviceInvalid
	}
	if !r.SkipVersionCheck && len(r.Version) > 128 {
		return r, code.VersionNotAllowed
	}
	return r, ""
}
func Evaluate(in Input) Result {
	a, l, r := in.Application, in.License, in.Request
	if out := licenseIdentity(a, l, r); !out.Pass {
		return out
	}
	if r.Operation != Activate && r.Operation != Verify && r.Operation != Heartbeat {
		return fail(code.InvalidRequest)
	}
	var invalid string
	r, invalid = Normalize(r)
	if invalid != "" {
		return fail(invalid)
	}
	if out := licenseDates(l, r); !out.Pass {
		return out
	}
	methods, valid := validPolicy(l, r)
	if !valid {
		return fail(code.InvalidPolicy)
	}
	if out := versionPolicy(in); !out.Pass {
		return out
	}

	result := Result{Pass: true, Errors: []string{}, Satisfied: []string{"KEY"}, ExpiresAt: copyTime(l.ExpiresAt), StartsAt: copyTime(l.StartsAt)}
	result.LatestEntitledVersion = maintenance.Latest(a, l, in.Versions, r.Now)
	_, result.MaintenanceUnknown = maintenance.Check(l, in.Versions, r.Version)
	writes := []Mutation{}
	if methods["FLOATING"] {
		pending, problem := floatingPolicy(in, r)
		if problem != "" {
			return fail(problem)
		}
		result.Satisfied = append(result.Satisfied, "FLOATING")
		writes = append(writes, pending...)
	}
	if r.Operation == Activate && l.ValidityRule == "after_activation" && l.StartsAt == nil {
		start := r.Now.UTC()
		end := start.AddDate(0, 0, l.DurationDays)
		if end.Year() > 9999 {
			return fail(code.InvalidPolicy)
		}
		result.StartsAt = &start
		result.ExpiresAt = &end
	}
	// Clamp newly acquired leases to a newly started activation-relative period.
	for i := range writes {
		if writes[i].LeaseExpiresAt != nil && result.ExpiresAt != nil && writes[i].LeaseExpiresAt.After(*result.ExpiresAt) {
			writes[i].LeaseExpiresAt = copyTime(result.ExpiresAt)
		}
	}
	result.Writes = writes
	return result
}
func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func latestEnabledVersion(in Input) string {
	var best *semver.Version
	out := ""
	for _, v := range in.Versions {
		if v.Disabled || v.Withdrawn || v.PublishedAt == nil || v.PublishedAt.After(in.Request.Now) || !maintenance.Allows(in.License, v) {
			continue
		}
		version, e := semver.StrictNewVersion(v.Version)
		if e != nil {
			continue
		}

		if best == nil || version.GreaterThan(best) {
			best = version
			out = v.Version
		}
	}
	return out
}

// LicenseValidity is shared by payload unlock before any private-key access.
func LicenseValidity(a model.Application, l model.License, r Request) Result {
	if out := licenseIdentity(a, l, r); !out.Pass {
		return out
	}
	return licenseDates(l, r)
}
func licenseIdentity(a model.Application, l model.License, r Request) Result {
	if l.UserID != nil && (l.User == nil || l.User.Status != model.StatusActive) {
		return fail(code.UserDisabled)
	}
	if a.Status != model.StatusActive {
		return fail(code.AppDisabled)
	}
	if l.AppID != a.ID || l.Key == "" || l.Key != r.Key || l.ID == 0 {
		return fail(code.LicenseNotFound)
	}
	switch l.Status {
	case "revoked":
		return fail(code.LicenseRevoked)
	case "suspended":
		return fail(code.LicenseSuspended)
	case "expired":
		return fail(code.LicenseExpired)
	case model.StatusUnused:
		if r.Operation != Activate {
			return fail(code.LicenseNotActivated)
		}
	case model.StatusActive:
	default:
		return fail(code.InvalidPolicy)
	}

	return Result{Pass: true}
}
func licenseDates(l model.License, r Request) Result {
	if l.StartsAt != nil && r.Now.Before(*l.StartsAt) {
		return fail(code.LicenseNotStarted)
	}
	if l.ExpiresAt != nil && !r.Now.Before(*l.ExpiresAt) {
		return fail(code.LicenseExpired)
	}
	if l.ValidityRule == "after_activation" && l.StartsAt == nil && r.Operation != Activate {
		return fail(code.LicenseNotActivated)
	}

	return Result{Pass: true}
}

// VersionDisabled checks only revocation of a known build, independently of maintenance.
func VersionDisabled(in Input) Result {
	for _, v := range in.Versions {
		if in.Request.Version != "" && v.Version == in.Request.Version && v.Disabled {
			out := fail(code.VersionDisabled)
			out.LatestVersion = latestEnabledVersion(in)
			return out
		}
	}
	return Result{Pass: true}
}

// VersionConstraints shares the normal version restrictions with authenticated payloads.
func VersionConstraints(in Input) Result {

	if in.Request.Version != "" {
		if _, e := semver.StrictNewVersion(in.Request.Version); e != nil {
			return fail(code.VersionNotAllowed)
		}
	}
	return Result{Pass: true}
}
func versionPolicy(in Input) Result {
	if in.Request.SkipVersionCheck {
		return Result{Pass: true}
	}
	if out := VersionDisabled(in); !out.Pass {
		return out
	}
	if expired, _ := maintenance.Check(in.License, in.Versions, in.Request.Version); expired {
		out := fail(code.MaintenanceExpired)
		out.LatestEntitledVersion = maintenance.Latest(in.Application, in.License, in.Versions, in.Request.Now)
		return out
	}
	return VersionConstraints(in)
}

func validPolicy(l model.License, r Request) (map[string]bool, bool) {
	if l.MaxActivations < 1 || l.MaxActivations > 1000000 || l.MatchMode != "all" && l.MatchMode != "any" || r.SessionID == "" {
		return nil, false
	}
	methods := map[string]bool{}
	for _, method := range l.VerifyMethods {
		switch method {
		case "KEY", "FLOATING":
		default:
			return nil, false
		}
		if methods[method] {
			return nil, false
		}
		methods[method] = true
	}
	if !methods["KEY"] {
		return nil, false
	}
	if l.ValidityRule != "perpetual" && l.ValidityRule != "fixed_days" && l.ValidityRule != "fixed_expiry" && l.ValidityRule != "after_activation" {
		return nil, false
	}
	if l.ValidityRule == "after_activation" && (l.DurationDays < 1 || l.DurationDays > 36500) {
		return nil, false
	}
	if l.ValidityRule != "perpetual" && l.ValidityRule != "after_activation" && l.ExpiresAt == nil {
		return nil, false
	}
	return methods, true
}

func floatingPolicy(in Input, r Request) ([]Mutation, string) {
	a, l := in.Application, in.License
	var pending []Mutation
	problem := ""
	if a.HeartbeatInterval < 1 || a.HeartbeatInterval > 3600 {
		return nil, code.InvalidPolicy
	}
	var own *model.Activation
	others := 0
	for i := range in.Activations {
		v := &in.Activations[i]
		if v.Kind != model.ActivationFloating {
			continue
		}
		if v.Value == r.SessionID || (r.InstanceSession != "" || r.SkipVersionCheck) && v.Value == r.Device {
			own = v
			continue
		}
		if v.Status == model.StatusActive && v.OfflineAt == nil && v.LeaseExpiresAt != nil && r.Now.Before(*v.LeaseExpiresAt) {
			others++
		}
	}
	live := own != nil && own.Status == model.StatusActive && own.OfflineAt == nil && own.LeaseExpiresAt != nil && r.Now.Before(*own.LeaseExpiresAt)
	// Explicit release deletes the floating row, but retains the
	// authenticated KEY anchor. A new process may recreate its seat,
	// just as it previously took over the retained expired row.
	// Internal update/unlock checks must never acquire capacity here.
	releasedTakeover := false
	if own == nil && r.InstanceSession != "" && !r.SkipVersionCheck {
		for _, anchor := range in.Activations {
			if anchor.Kind == "key" && anchor.Value == r.SessionID && anchor.Status == model.StatusActive && anchor.OfflineAt == nil && anchor.InstanceSession != r.InstanceSession {
				releasedTakeover = true
				break
			}
		}
	}
	if r.Operation == Verify && !live && !releasedTakeover && (r.InstanceSession == "" || own == nil || own.InstanceSession == r.InstanceSession) {
		return nil, code.LeaseExpired
	}
	if r.Operation == Verify && live {
		pending = []Mutation{{ID: own.ID, Kind: model.ActivationFloating, Value: own.Value, LeaseExpiresAt: copyTime(own.LeaseExpiresAt)}}
	} else if others >= l.MaxActivations {
		problem = code.FloatingLimitReached
	} else {
		end := r.Now.Add(time.Duration(a.HeartbeatInterval) * 2 * time.Second)
		if l.ExpiresAt != nil && end.After(*l.ExpiresAt) {
			end = *l.ExpiresAt
		}
		value := r.SessionID
		if r.InstanceSession != "" {
			value = r.Device
		}
		m := Mutation{Kind: model.ActivationFloating, Value: value, LeaseExpiresAt: &end}
		if own != nil {
			m.ID = own.ID
		}
		pending = []Mutation{m}
	}
	return pending, problem
}
