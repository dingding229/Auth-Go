// Package sdk is the standard-library-only Auth Go client.
package sdk

import "fmt"

const (
	OK                     = "OK"
	UserDisabled           = "USER_DISABLED"
	InvalidRequest         = "INVALID_REQUEST"
	VersionNotAllowed      = "VERSION_NOT_ALLOWED"
	PayloadInvalid         = "PAYLOAD_INVALID"
	InvalidLicenseKey      = "INVALID_LICENSE_KEY"
	AppNotFound            = "APP_NOT_FOUND"
	AppDisabled            = "APP_DISABLED"
	LicenseNotFound        = "LICENSE_NOT_FOUND"
	LicenseNotActivated    = "LICENSE_NOT_ACTIVATED"
	LicenseExpired         = "LICENSE_EXPIRED"
	LicenseNotStarted      = "LICENSE_NOT_STARTED"
	LicenseSuspended       = "LICENSE_SUSPENDED"
	LicenseRevoked         = "LICENSE_REVOKED"
	InvalidPolicy          = "INVALID_POLICY"
	InstanceReplaced       = "INSTANCE_REPLACED"
	VersionDisabled        = "VERSION_DISABLED"
	MaintenanceExpired     = "MAINTENANCE_EXPIRED"
	TrialDisabled          = "TRIAL_DISABLED"
	TrialIPLimit           = "TRIAL_IP_LIMIT"
	TrialQuotaExceeded     = "TRIAL_QUOTA_EXCEEDED"
	FloatingLimitReached   = "FLOATING_LIMIT_REACHED"
	LeaseExpired           = "LEASE_EXPIRED"
	ActivationInvalid      = "ACTIVATION_INVALID"
	ActivationLimitReached = "ACTIVATION_LIMIT_REACHED"
	SignatureInvalid       = "SIGNATURE_INVALID"
	TimestampInvalid       = "TIMESTAMP_INVALID"
	ReplayDetected         = "REPLAY_DETECTED"
	RateLimited            = "RATE_LIMITED"
	VersionNotFound        = "VERSION_NOT_FOUND"
	InternalError          = "INTERNAL_ERROR"
)

// SDK-local codes never masquerade as a signed server refusal.
const (
	ClockRollback            = "SDK_CLOCK_ROLLBACK"
	GraceExpired             = "SDK_GRACE_EXPIRED"
	InvalidConfig            = "SDK_INVALID_CONFIG"
	FingerprintUnavailable   = "SDK_FINGERPRINT_UNAVAILABLE"
	NotActivated             = "SDK_NOT_ACTIVATED"
	NetworkError             = "SDK_NETWORK_ERROR"
	ResponseInvalid          = "SDK_RESPONSE_INVALID"
	ResponseSignatureInvalid = "SDK_RESPONSE_SIGNATURE_INVALID"
	ResponseNonceInvalid     = "SDK_RESPONSE_NONCE_INVALID"
	ResponseTimestampInvalid = "SDK_RESPONSE_TIMESTAMP_INVALID"
	CacheInvalid             = "SDK_CACHE_INVALID"
	CacheUnavailable         = "SDK_CACHE_UNAVAILABLE"
	AutoCheckRunning         = "SDK_AUTO_CHECK_RUNNING"
)

type Error struct {
	Code                  string
	Message               string
	LatestVersion         string
	LatestEntitledVersion string
	HTTPStatus            int
	Err                   error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Code
}
func (e *Error) Unwrap() error { return e.Err }
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t != nil && e.Code != "" && t.Code == e.Code
}
func failure(code, message string, err error) *Error {
	return &Error{Code: code, Message: message, Err: err}
}

var (
	ErrVersionNotAllowed        = &Error{Code: VersionNotAllowed}
	ErrPayloadInvalid           = &Error{Code: PayloadInvalid}
	ErrInstanceReplaced         = &Error{Code: InstanceReplaced}
	ErrVersionDisabled          = &Error{Code: VersionDisabled}
	ErrMaintenanceExpired       = &Error{Code: MaintenanceExpired}
	ErrTrialDisabled            = &Error{Code: TrialDisabled}
	ErrTrialIPLimit             = &Error{Code: TrialIPLimit}
	ErrTrialQuotaExceeded       = &Error{Code: TrialQuotaExceeded}
	ErrClockRollback            = &Error{Code: ClockRollback}
	ErrUserDisabled             = &Error{Code: UserDisabled}
	ErrGraceExpired             = &Error{Code: GraceExpired}
	ErrOK                       = &Error{Code: OK}
	ErrInvalidRequest           = &Error{Code: InvalidRequest}
	ErrInvalidLicenseKey        = &Error{Code: InvalidLicenseKey}
	ErrAppNotFound              = &Error{Code: AppNotFound}
	ErrAppDisabled              = &Error{Code: AppDisabled}
	ErrLicenseNotFound          = &Error{Code: LicenseNotFound}
	ErrLicenseNotActivated      = &Error{Code: LicenseNotActivated}
	ErrLicenseExpired           = &Error{Code: LicenseExpired}
	ErrLicenseNotStarted        = &Error{Code: LicenseNotStarted}
	ErrLicenseSuspended         = &Error{Code: LicenseSuspended}
	ErrLicenseRevoked           = &Error{Code: LicenseRevoked}
	ErrInvalidPolicy            = &Error{Code: InvalidPolicy}
	ErrFloatingLimitReached     = &Error{Code: FloatingLimitReached}
	ErrLeaseExpired             = &Error{Code: LeaseExpired}
	ErrActivationInvalid        = &Error{Code: ActivationInvalid}
	ErrActivationLimitReached   = &Error{Code: ActivationLimitReached}
	ErrSignatureInvalid         = &Error{Code: SignatureInvalid}
	ErrTimestampInvalid         = &Error{Code: TimestampInvalid}
	ErrReplayDetected           = &Error{Code: ReplayDetected}
	ErrRateLimited              = &Error{Code: RateLimited}
	ErrVersionNotFound          = &Error{Code: VersionNotFound}
	ErrInternalError            = &Error{Code: InternalError}
	ErrInvalidConfig            = &Error{Code: InvalidConfig}
	ErrFingerprintUnavailable   = &Error{Code: FingerprintUnavailable}
	ErrNotActivated             = &Error{Code: NotActivated}
	ErrNetworkError             = &Error{Code: NetworkError}
	ErrResponseInvalid          = &Error{Code: ResponseInvalid}
	ErrResponseSignatureInvalid = &Error{Code: ResponseSignatureInvalid}
	ErrResponseNonceInvalid     = &Error{Code: ResponseNonceInvalid}
	ErrResponseTimestampInvalid = &Error{Code: ResponseTimestampInvalid}
	ErrCacheInvalid             = &Error{Code: CacheInvalid}
	ErrCacheUnavailable         = &Error{Code: CacheUnavailable}
	ErrAutoCheckRunning         = &Error{Code: AutoCheckRunning}
)
