package binding

import "testing"

func TestNormalization(t *testing.T) {
	for _, test := range []struct {
		in, want string
		cidr     bool
	}{{"2001:0db8::1", "2001:db8::1", false}, {"::ffff:192.0.2.1", "192.0.2.1", false}, {"192.0.2.42/24", "192.0.2.0/24", true}, {"::ffff:192.0.2.1/120", "192.0.2.0/24", true}} {
		got, err := NormalizeIP(test.in, test.cidr)
		if err != nil || got != test.want {
			t.Fatal(test, got, err)
		}
	}
	for _, value := range []string{"bad", "192.0.2.1:80", "fe80::1%en0"} {
		if _, err := NormalizeIP(value, false); err == nil {
			t.Fatal("invalid IP")
		}
	}
}
