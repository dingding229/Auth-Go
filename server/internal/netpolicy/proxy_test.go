package netpolicy

import (
	"net/netip"
	"testing"
)

func TestResolvedClientIPDefaultAndExplicitTrust(t *testing.T) {
	for _, v := range []struct{ peer, xff, real, want string }{
		{"172.19.0.2:443", "203.0.113.9, 10.1.1.1", "", "203.0.113.9"},
		{"198.51.100.7:443", "203.0.113.9", "203.0.113.10", "198.51.100.7"},
		{"127.0.0.1:80", "", "203.0.113.9", "203.0.113.9"},
		{"[fd00::1]:443", "2001:db8::9, fe80::1", "", "2001:db8::9"},
		{"169.254.1.2:443", "198.51.100.2", "", "198.51.100.2"},
		{"10.0.0.1:443", "broken, 198.51.100.2", "203.0.113.3", "10.0.0.1"},
		{"192.168.1.2:80", "", "", "192.168.1.2"},
	} {
		if got := ResolveClientIP(v.peer, v.xff, v.real, InternalPeer); got != v.want {
			t.Fatalf("%+v: %s", v, got)
		}
	}
	explicit := func(ip netip.Addr) bool { return netip.MustParsePrefix("10.1.0.0/16").Contains(ip) }
	if got := ResolveClientIP("172.19.0.2:443", "203.0.113.9", "", explicit); got != "172.19.0.2" {
		t.Fatal("private peer bypassed explicit list", got)
	}
	if got := ResolveClientIP("10.1.0.2:443", "203.0.113.9,172.19.0.2", "", explicit); got != "172.19.0.2" {
		t.Fatal("unlisted private hop skipped", got)
	}
}
