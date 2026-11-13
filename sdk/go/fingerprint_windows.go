//go:build windows

package sdk

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func registryText(raw []byte, name string) string {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], name) && fields[1] == "REG_SZ" {
			return strings.Join(fields[2:], " ")
		}
	}
	return ""
}
func platformIdentity() (string, string, string, error) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	reg := filepath.Join(root, "System32", "reg.exe")
	raw, err := runIdentityCommand(reg, "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid", "/reg:64")
	if err != nil {
		return "", "", "", err
	}
	machine := registryText(raw, "MachineGuid")
	raw, err = runIdentityCommand(reg, "query", `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "/v", "ProcessorNameString")
	if err != nil {
		return "", "", "", err
	}
	cpu := registryText(raw, "ProcessorNameString")
	if machine == "" || cpu == "" {
		return "", "", "", errors.New("machine GUID or CPU model unavailable")
	}
	powershell := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	route, _ := runIdentityCommand(powershell, "-NoProfile", "-NonInteractive", "-Command", `Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex`)
	return machine, cpu, strings.TrimSpace(string(route)), nil
}
