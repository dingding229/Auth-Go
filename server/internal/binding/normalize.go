package binding

import (
	"authgo/internal/apperror"
	"net/netip"
	"strings"
)

func NormalizeIP(value string, cidr bool) (string, error) {
	value = strings.TrimSpace(value)
	if cidr {
		p, err := netip.ParsePrefix(value)
		if err != nil || p.Addr().Zone() != "" {
			return "", apperror.Invalid("CIDR 格式无效")
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return "", apperror.Invalid("IPv4 映射 CIDR 的前缀长度不得小于 96")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" {
		return "", apperror.Invalid("IP 格式无效，不允许端口或 zone")
	}
	return addr.Unmap().String(), nil
}
