package sdk

import (
	"context"
	"errors"
)

// fallback uses only the last authenticated grant and its original grace deadline.
func (c *Client) fallback(ctx context.Context, network error) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := c.cachedResult()
	if err != nil {
		return nil, network
	}
	if result.IsTrial {
		return nil, failure(GraceExpired, "试用需要在线校验", network)
	}
	now := c.clock()
	if now.Unix()+300 < c.state.ObservedAt {
		return nil, failure(ClockRollback, "检测到本地时钟回退", nil)
	}
	c.state.ObservedAt = max64(c.state.ObservedAt, now.Unix())
	if err := c.persist(); err != nil {
		return nil, err
	}
	if err := result.validPeriodAt(now); err != nil {
		return nil, err
	}
	grant, err := c.validateTicket(result.ticket, true)
	if err != nil {
		return nil, network
	}
	until := grant.GraceUntil
	if grant.ExpiresAt != nil && until.After(*grant.ExpiresAt) {
		until = *grant.ExpiresAt
	}
	if !now.Before(until) {
		return nil, failure(GraceExpired, "断连宽限期已结束", network)
	}
	result.Offline = true
	result.Source = "cache"
	result.Reason = network.Error()
	result.Availability = "grace"
	result.Status = "grace"
	result.RemainingSeconds = int64(until.Sub(now).Seconds())
	result.usableUntil = until
	result.clock = c.clock
	c.offlineTicket = result.ticket
	c.offlineUntil = until
	result.CacheWarning = errors.Join(c.cacheWarning, c.persist())
	return result, nil
}
