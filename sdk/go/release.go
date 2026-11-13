package sdk

import (
	"context"
	"errors"
)

// ReleaseSeat releases floating capacity, never a binding or local authorization
// proof. Transport/temporary errors preserve it; authenticated authorization
// refusals retain the normal fail-closed policy (except INSTANCE_REPLACED).
func (c *Client) ReleaseSeat(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.online(""); e != nil {
		return e
	}
	if e := c.restore(); e != nil {
		return e
	}
	if c.state.Proof == nil {
		return nil
	}
	r, e := c.cachedResult()
	if e != nil {
		return e
	}
	if !r.floating() {
		return nil
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	_, _, _, e = c.exchange(ctx, "release-seat")
	if isInstanceReplaced(e) {
		c.rememberReplacement(c.state.Key)
		return e
	}
	if explicitRefusal(e) {
		return errors.Join(e, c.invalidate())
	}
	return e
}
