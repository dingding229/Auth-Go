//go:build linux

package sdk

import (
	"errors"
	"os"
	"strings"
)

func platformIdentity() (string, string, string, error) {
	var machine []byte
	var err error
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		machine, err = os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(machine)) != "" {
			break
		}
	}
	if err != nil || strings.TrimSpace(string(machine)) == "" {
		return "", "", "", errors.New("machine-id unavailable")
	}
	raw, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", "", "", err
	}
	cpu := parseLinuxCPU(string(raw))
	if cpu == "" {
		return "", "", "", errors.New("CPU model unavailable")
	}
	preferred := ""
	route, _ := os.ReadFile("/proc/net/route")
	for _, line := range strings.Split(string(route), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[1] == "00000000" {
			preferred = f[0]
			break
		}
	}
	return strings.TrimSpace(string(machine)), cpu, preferred, nil
}
