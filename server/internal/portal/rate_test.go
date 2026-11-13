package portal

import (
	"authgo/internal/automation"
	"authgo/internal/ratelimit"
	"testing"
	"time"
)

func TestPortalDefaultRateBudgets(t *testing.T) {
	s, err := New(nil, make([]byte, 32), &automation.Service{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		bucket *ratelimit.Limiter
		rate   float64
		burst  int
	}{
		{"anonymous IP", s.ip, 5, 30}, {"login identity", s.license, 2, 10},
		{"session identity", s.session, 10, 60}, {"authenticated IP", s.sessionIP, 20, 120},
	} {
		t.Run(tc.name, func(t *testing.T) {

			now := time.Unix(1800000000, 0)
			for i := 0; i < tc.burst; i++ {
				if !tc.bucket.Allow("one", now) {
					t.Fatalf("request %d rejected", i+1)
				}
			}
			if tc.bucket.Allow("one", now) {
				t.Fatal("burst exceeded")
			}
			if !tc.bucket.Allow("other", now) {
				t.Fatal("independent key rejected")
			}
			for range tc.burst {
				if !tc.bucket.Allow("boundary", now) {
					t.Fatal("boundary key burst")
				}
			}
			if tc.bucket.Allow("boundary", now.Add(time.Duration(float64(time.Second)/tc.rate)-time.Nanosecond)) {
				t.Fatal("early refill")
			}
			if !tc.bucket.Allow("one", now.Add(time.Duration(float64(time.Second)/tc.rate))) {
				t.Fatal("one-token refill rejected")
			}
		})
	}
}
