package portal

import (
	"authgo/internal/automation"
	entitlements "authgo/internal/service"
	"testing"
	"time"
)

func TestPortalDefaultRateBudgets(t *testing.T) {
	s, err := New(nil, make([]byte, 32), &automation.Service{}, &entitlements.Service{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		bucket *limiter
		rate   float64
		burst  int
	}{
		{"anonymous IP", s.ip, 5, 30}, {"login identity", s.license, 2, 10},
		{"session identity", s.session, 10, 60}, {"authenticated IP", s.sessionIP, 20, 120},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.bucket.rate != tc.rate || tc.bucket.burst != tc.burst {
				t.Fatalf("rate=%v burst=%d", tc.bucket.rate, tc.bucket.burst)
			}
			now := time.Unix(1800000000, 0)
			for i := 0; i < tc.burst; i++ {
				if !tc.bucket.allow("one", now) {
					t.Fatalf("request %d rejected", i+1)
				}
			}
			if tc.bucket.allow("one", now) {
				t.Fatal("burst exceeded")
			}
			if !tc.bucket.allow("other", now) {
				t.Fatal("independent key rejected")
			}
			if !tc.bucket.allow("one", now.Add(time.Duration(float64(time.Second)/tc.rate))) {
				t.Fatal("one-token refill rejected")
			}
		})
	}
}
