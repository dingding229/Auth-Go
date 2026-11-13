package sdk

import (
	"authgo/sdk/wire"
	"time"
)

// Ticket is an immutable signed proof. Copying it does not grant a different device access.
type Ticket string

func (r *Result) Ticket() Ticket {
	if r == nil {
		return ""
	}
	return Ticket(r.ticket)
}
func (c *Client) validateTicket(ticket string, cached bool) (wire.Grant, error) {
	g, e := wire.DecodeTicket(ticket, c.PublicKey)
	if e != nil || g.V != 2 || g.AppKey != c.AppKey || g.Status != "active" || g.LicenseID == 0 || g.DeviceHash != sha([]byte(c.fingerprint)) || g.NextCheckIn < 1 || g.NextCheckIn > 86400 {
		return g, failure(ResponseSignatureInvalid, "验证票据无效", nil)
	}
	ch, e := decodeURL(g.Challenge)
	if e != nil || len(ch) != 32 || g.IssuedAt.IsZero() || g.GraceUntil.Before(g.IssuedAt) || !cached && g.IssuedAt.After(c.clock().Add(5*time.Minute)) || !cached && g.IssuedAt.Before(c.clock().Add(-5*time.Minute)) {
		return g, failure(ResponseTimestampInvalid, "验证票据时间或挑战无效", nil)
	}
	return g, nil
}

// Validate checks signature, app/device binding and the original signed validity
// window locally. No alternate status source can extend its deadline.
// It never downloads a list or contacts the primary server.
func (c *Client) Validate(ticket Ticket) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.replacedKey != "" && c.replacedKey == c.state.Key {
		return failure(InstanceReplaced, "此进程已被接管", nil)
	}
	if _, e := c.identity(""); e != nil {
		return e
	}
	if c.endpoint != "" {
		if e := c.restore(); e != nil {
			return e
		}
	}
	if c.processReplaced(c.state.Key) {
		return failure(InstanceReplaced, "此进程已被接管", nil)
	}
	if c.state.Refused {
		return failure(NotActivated, "此实例已收到明确拒绝，请重新联网验证", nil)
	}
	g, e := c.validateTicket(string(ticket), true)
	if e != nil {
		return e
	}
	now := c.clock()
	if now.Unix()+300 < c.state.ObservedAt {
		return failure(ClockRollback, "检测到本地时钟回退", nil)
	}
	if g.StartsAt != nil && now.Before(*g.StartsAt) {
		return failure(LicenseNotStarted, "授权尚未生效", nil)
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		return failure(LicenseExpired, "授权已到期", nil)
	}
	if g.Floating && (g.LeaseExpiresAt == nil || !now.Before(*g.LeaseExpiresAt)) {
		if string(ticket) != c.offlineTicket || !now.Before(c.offlineUntil) {
			return failure(LeaseExpired, "席位租约已到期", nil)
		}
	}
	if !now.Before(g.GraceUntil) {
		if string(ticket) == c.onlineTicket && now.Before(c.onlineUntil) {
			return nil
		}
		return failure(GraceExpired, "票据可用期已结束", nil)
	}
	return nil
}
