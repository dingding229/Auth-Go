package netpolicy

import (
	"net/netip"
	"testing"
)

func TestPublicIP(t *testing.T) {
	for _, tt := range []struct {
		ip     string
		public bool
	}{{"8.8.8.8", true}, {"2001:4860:4860::8888", true}, {"127.0.0.1", false}, {"10.0.0.1", false}, {"169.254.1.1", false}, {"::1", false}, {"fc00::1", false}, {"fe80::1", false}, {"::ffff:127.0.0.1", false}} {
		if got := PublicIP(netip.MustParseAddr(tt.ip)); got != tt.public {
			t.Fatalf("%s: %v", tt.ip, got)
		}
	}
}
