package netpolicy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestCloudflareNetworksMatchFrontend(t *testing.T) {
	raw, err := os.ReadFile("../../../web/src/lib/trusted-proxies.ts")
	if err != nil {
		t.Fatal(err)
	}
	list := strings.SplitN(string(raw), "export const CLOUDFLARE_TRUSTED_PROXIES = [", 2)
	if len(list) != 2 {
		t.Fatal("frontend Cloudflare list missing")
	}
	block := strings.SplitN(list[1], "] as const", 2)[0]
	matches := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(block, -1)
	if len(matches) != len(cloudflareNetworks) {
		t.Fatal("Cloudflare list lengths differ")
	}
	for i, match := range matches {
		if match[1] != cloudflareNetworks[i].String() {
			t.Fatal("Cloudflare lists differ", match[1], cloudflareNetworks[i])
		}
	}
	for ip, want := range map[string]bool{"172.69.224.203": true, "2606:4700::1": true, "::ffff:172.69.224.203": true, "172.16.0.1": false, "8.8.8.8": false, "invalid": false} {
		if CloudflareIP(ip) != want {
			t.Fatal(ip, want)
		}
	}
}
