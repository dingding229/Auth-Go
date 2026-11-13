package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Fingerprint hashes machine ID + primary NIC MAC + CPU model. No raw identity
// component is sent to Auth Go. Restricted/unsupported hosts must supply an override.
func Fingerprint() (string, error) {
	machine, cpu, preferred, err := platformIdentity()
	if err != nil {
		return "", failure(FingerprintUnavailable, "无法采集实例指纹，请显式提供指纹覆盖", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", failure(FingerprintUnavailable, "无法采集网卡", err)
	}
	mac, err := primaryMAC(interfaces, preferred)
	if err != nil {
		return "", failure(FingerprintUnavailable, "没有可用的主网卡 MAC", err)
	}
	return hashIdentity(machine, mac, cpu)
}
func hashIdentity(machine, mac, cpu string) (string, error) {
	machine = strings.ToLower(strings.TrimSpace(machine))
	cpu = strings.ToLower(strings.Join(strings.Fields(cpu), " "))
	parsed, e := net.ParseMAC(mac)
	if machine == "" || cpu == "" || e != nil || len(parsed) == 0 {
		return "", failure(FingerprintUnavailable, "实例指纹数据不完整", e)
	}
	sum := sha256.Sum256([]byte("authgo/fingerprint/v1\x00" + machine + "\x00" + parsed.String() + "\x00" + cpu))
	return hex.EncodeToString(sum[:]), nil
}
func primaryMAC(items []net.Interface, preferred string) (string, error) {
	sort.Slice(items, func(i, j int) bool { return items[i].Index < items[j].Index })
	usable := func(v net.Interface) bool {
		return v.Flags&net.FlagLoopback == 0 && len(v.HardwareAddr) > 0 && strings.Trim(v.HardwareAddr.String(), "0:") != ""
	}
	for _, v := range items {
		if usable(v) && (v.Name == preferred || strconv.Itoa(v.Index) == preferred) && preferred != "" {
			return v.HardwareAddr.String(), nil
		}
	}
	for _, up := range []bool{true, false} {
		for _, v := range items {
			if usable(v) && (v.Flags&net.FlagUp != 0) == up {
				return v.HardwareAddr.String(), nil
			}
		}
	}
	return "", errors.New("no hardware interface")
}
func runIdentityCommand(path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, args...).Output()
}

// parseLinuxCPU preserves stable identities before trying ARM/RISC-V fallbacks.
func parseLinuxCPU(raw string) string {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		k, v, ok := strings.Cut(line, ":")
		if ok && (strings.TrimSpace(k) == "model name" || strings.TrimSpace(k) == "Hardware" || strings.TrimSpace(k) == "cpu model") && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	implementer, part, uarch := "", "", ""
	armSeen, armDone := false, false
	for _, line := range lines {
		if strings.TrimSpace(line) == "" && armSeen {
			armDone = true
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "uarch" && uarch == "" {
			uarch = v
		}
		if !armDone {
			if k == "CPU implementer" {
				armSeen = true
				if implementer == "" {
					implementer = strings.ToLower(strings.Join(strings.Fields(v), ""))
				}
			}
			if k == "CPU part" {
				armSeen = true
				if part == "" {
					part = strings.ToLower(strings.Join(strings.Fields(v), ""))
				}
			}
		}
	}
	if implementer != "" && part != "" {
		return "arm:" + implementer + ":" + part
	}
	return uarch
}

func validFingerprint(value string) bool {
	raw, e := hex.DecodeString(value)
	return e == nil && len(raw) == 32
}
