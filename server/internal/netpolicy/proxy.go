package netpolicy

import (
	"net"
	"net/netip"
	"strings"
)

// InternalPeer includes only addresses that can be an internal immediate proxy.
func InternalPeer(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
func ResolveClientIP(remote, xff, real string, trusted func(netip.Addr) bool) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.WithZone("").Unmap()
	if !trusted(peer) {
		return peer.String()
	}
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 100 {
			return peer.String()
		}
		ips := make([]netip.Addr, 0, len(parts))
		for _, raw := range parts {
			ip, e := netip.ParseAddr(strings.TrimSpace(raw))
			if e != nil || ip.Zone() != "" {
				return peer.String()
			}
			ips = append(ips, ip.Unmap())
		}
		for i := len(ips) - 1; i >= 0; i-- {
			if !trusted(ips[i]) || i == 0 {
				return ips[i].String()
			}
		}
	}
	if ip, e := netip.ParseAddr(real); e == nil && ip.Zone() == "" {
		return ip.Unmap().String()
	}
	return peer.String()
}
