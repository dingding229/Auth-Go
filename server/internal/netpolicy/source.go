package netpolicy

import "net/netip"

// SourceKey groups IPv6 privacy addresses by /64 and canonicalizes mapped IPv4.
// This is the same source boundary for client, anonymous-admin and login budgets.
func SourceKey(raw string) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return raw
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String()
	}
	return netip.PrefixFrom(ip, 64).Masked().String()
}
