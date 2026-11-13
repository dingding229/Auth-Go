// Copied ONLY into the temporary test-image build, never into the shipped SDK.
// Real HTTP and a real stopped Auth Go container; only the SDK's existing test
// clock is advanced so the signed 72-hour window need not take three days.
package sdk

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

var dockerClockConfig string // pinned using -ldflags at test-image build time

func TestDockerClockAgent(t *testing.T) {
	var advance atomic.Bool
	g, err := StartGuard(context.Background(), GuardOptions{Config: dockerClockConfig, Version: "1.0.0", SDKOptions: []Option{func(c *Client) {
		c.now = func() time.Time {
			now := time.Now()
			if advance.Load() {
				return now.Add(72*time.Hour + time.Second)
			}
			return now
		}
	}}, OnChange: func(r *Result, e error) {
		if e != nil {
			fmt.Println("clock agent:", e)
			return
		}
		fmt.Println("clock agent:", r.Availability)
		if r.Availability == "grace" {
			advance.Store(true)
		}
	}})
	if err != nil {
		fmt.Println("clock startup:", err)
		os.Exit(77)
	}
	defer g.Close(context.Background())
	fmt.Println("clock ready")
	<-g.Done()
	fmt.Println("clock stopped:", g.Err())
	os.Exit(77)
}
