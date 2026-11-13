package client

import (
	"authgo/internal/code"
	"authgo/internal/licensekey"
	"authgo/internal/model"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestUnknownLicensesDoNotAllocateBucketsOrNonces(t *testing.T) {
	f := newLoggingFixture(t, Options{IPBurst: 3000, LicenseBurst: 3000})
	f.service.license.limit = 8
	f.service.nonces.limit = 8
	original := f.key
	for i := 0; i < 1000; i++ {
		key, e := licensekey.Generate("AUTH")
		if e != nil {
			t.Fatal(e)
		}
		f.key = key
		f.signed(t, "activate", "", fmt.Sprintf("unknown-key-%020d", i), code.LicenseNotFound)
	}
	if len(f.service.license.entries) != 0 || len(f.service.nonces.entries) != 0 {
		t.Fatal("unknown licenses allocated state", len(f.service.license.entries), len(f.service.nonces.entries))
	}
	f.key = original
	f.signed(t, "activate", "", "existing-key-replay-nonce", code.OK)
	f.signed(t, "activate", "", "existing-key-replay-nonce", code.ReplayDetected)
	if len(f.service.license.entries) != 1 || len(f.service.nonces.entries) != 1 {
		t.Fatal("existing license state missing")
	}
	f.signed(t, "public-key", "", "read-only-identical-nonce", code.OK)
	f.signed(t, "public-key", "", "read-only-identical-nonce", code.OK)
	if len(f.service.nonces.entries) != 1 {
		t.Fatal("read-only allocated nonce")
	}
	if e := f.service.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	var count int64
	f.db.Table("verify_logs").Where("code=?", code.LicenseNotFound).Count(&count)
	if count != 1 {
		t.Fatal("unknown-key logs were not sampled", count)
	}
}
func TestIPv6PrivacyAddressesShareLimit(t *testing.T) {
	f := newLoggingFixture(t, Options{IPBurst: 1, IPRate: 1})
	for i, ip := range []string{"2001:db8:1234:1::1", "2001:db8:1234:1::ffff", "2001:db8:1234:2::1"} {
		allowed := f.service.ip.allow(ipLimitKey(ip), f.clock.now())
		if allowed != (i != 1) {
			t.Fatal(ip, allowed)
		}
	}
	if ipLimitKey("::ffff:203.0.113.7") != "203.0.113.7" || ipLimitKey("203.0.113.8") == ipLimitKey("203.0.113.7") {
		t.Fatal("IPv4 grouping changed")
	}
}
func TestInstanceSessionWireValidation(t *testing.T) {
	for _, v := range []string{"x", strings.Repeat("a", 21), strings.Repeat("a", 24)} {
		raw, _ := json.Marshal(Input{InstanceSession: v})
		var in Input
		if decode(raw, &in) {
			t.Fatal("invalid session", v)
		}
	}
}

func TestIPv6NoisyLogsShareSamplingNetwork(t *testing.T) {
	f := newLoggingFixture(t, Options{})
	for _, ip := range []string{"2001:db8:1234:1::1", "2001:db8:1234:1::ffff"} {
		f.service.recordVerifyLog(model.VerifyLog{IP: ip, Code: code.RateLimited, CreatedAt: f.clock.now()}, true)
	}
	if e := f.service.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	var n int64
	f.db.Model(&model.VerifyLog{}).Count(&n)
	if n != 1 || len(f.service.logSamples.entries) != 1 {
		t.Fatal("IPv6 rotation bypassed log sampling", n)
	}
}
