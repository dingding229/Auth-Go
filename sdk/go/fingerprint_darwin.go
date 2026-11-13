//go:build darwin

package sdk

import (
	"errors"
	"strings"
)

func platformIdentity() (string, string, string, error) {
	raw, err := runIdentityCommand("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return "", "", "", err
	}
	machine := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, `"IOPlatformUUID"`) {
			_, v, ok := strings.Cut(line, "=")
			if ok {
				machine = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	if machine == "" {
		return "", "", "", errors.New("platform UUID unavailable")
	}
	raw, err = runIdentityCommand("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string")
	if err != nil {
		raw, err = runIdentityCommand("/usr/sbin/sysctl", "-n", "hw.model")
	}
	if err != nil {
		return "", "", "", err
	}
	cpu := strings.TrimSpace(string(raw))
	preferred := ""
	route, _ := runIdentityCommand("/sbin/route", "-n", "get", "default")
	for _, line := range strings.Split(string(route), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == "interface" {
			preferred = strings.TrimSpace(v)
		}
	}
	return machine, cpu, preferred, nil
}
