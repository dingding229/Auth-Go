//go:build !linux && !darwin && !windows

package sdk

import "errors"

func platformIdentity() (string, string, string, error) {
	return "", "", "", errors.New("unsupported platform; supply FingerprintFunc")
}
