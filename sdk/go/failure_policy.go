package sdk

import "errors"

// Only authenticate creates this marker, after decrypt/signature/nonce/time
// verification. Untrusted transports cannot manufacture a server refusal.
type authenticatedServerError struct{ original *Error }

func (e *authenticatedServerError) Error() string { return e.original.Error() }
func (e *authenticatedServerError) Unwrap() error { return e.original }

// Explicit allowlist shared with sdk/vectors/error-classification.json.
// Unknown authenticated codes are refusals, never silently recoverable.
func temporaryServerCode(code string) bool {
	switch code {
	case InternalError, RateLimited, ReplayDetected, TimestampInvalid, SignatureInvalid, InvalidRequest, PayloadInvalid:
		return true
	default:
		return false
	}
}
func explicitRefusal(err error) bool {
	var server *authenticatedServerError
	return errors.As(err, &server) && server.original.Code != OK && !temporaryServerCode(server.original.Code)
}

func isInstanceReplaced(err error) bool {
	var server *authenticatedServerError
	return errors.As(err, &server) && server.original.Code == InstanceReplaced
}
