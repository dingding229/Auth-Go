package sdk

import (
	"context"
	"time"
)

// StartAutoCheck blocks until cancellation or a failed check. Run it in a caller-
// owned goroutine for background use. Callbacks execute outside the Client lock.
// Network outages inside grace return Offline results and keep checking; explicit
// authenticated refusals stop the loop; unauthenticated responses and temporary
// server errors use exactly the same fallback policy as Verify/Heartbeat.
func (c *Client) StartAutoCheck(ctx context.Context, onChange func(*Result, error)) error {
	c.mu.Lock()
	if c.autoRunning {
		c.mu.Unlock()
		return failure(AutoCheckRunning, "此 Client 已有自动校验循环", nil)
	}
	c.autoRunning = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.autoRunning = false; c.mu.Unlock() }()
	notify := func(result *Result, err error) {
		if onChange != nil && ctx.Err() == nil {
			onChange(result, err)
		}
	}
	result, err := c.Verify(ctx)
	notify(result, err)
	if err != nil {
		return err
	}
	nextVerify := c.clock().Add(time.Duration(result.NextCheckIn) * time.Second)
	nextHeartbeat := c.clock().Add(time.Duration(result.HeartbeatInterval) * time.Second)
	for {
		next := nextVerify
		if result.floating() && nextHeartbeat.Before(next) {
			next = nextHeartbeat
		}
		ends := []*time.Time{result.ExpiresAt}
		if result.Availability == "grace" {
			ends = append(ends, &result.usableUntil)
		} else {
			ends = append(ends, result.LeaseExpiresAt)
		}
		for _, end := range ends {
			if end != nil && end.Before(next) {
				next = *end
			}
		}
		delay := next.Sub(c.clock())
		if delay < 0 {
			delay = 0
		}
		wait := c.wait
		if wait == nil {
			wait = waitContext
		}
		if err := wait(ctx, delay); err != nil {
			return err
		}
		now := c.clock()
		didCheck := false
		if !now.Before(nextVerify) || !now.Before(next) && now.Before(nextVerify) && (!result.floating() || now.Before(nextHeartbeat)) {
			result, err = c.Verify(ctx)
			notify(result, err)
			if err != nil {
				return err
			}
			nextVerify = c.clock().Add(time.Duration(result.NextCheckIn) * time.Second)
			didCheck = true
		}
		if result.floating() && !c.clock().Before(nextHeartbeat) {
			result, err = c.Heartbeat(ctx)
			notify(result, err)
			if err != nil {
				return err
			}
			nextHeartbeat = c.clock().Add(time.Duration(result.HeartbeatInterval) * time.Second)
			didCheck = true
		}
		if !didCheck && ctx.Err() != nil {
			return ctx.Err()
		}
	}
}
func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
