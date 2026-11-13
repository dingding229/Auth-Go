package middleware

import (
	"authgo/internal/netpolicy"
	"github.com/gin-gonic/gin"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// TrustedPeer checks the actual socket peer, never a forwarded client address.
func TrustedPeer(proxies []string) func(string) bool {
	return func(remote string) bool {
		host, _, err := net.SplitHostPort(remote)
		if err != nil {
			host = remote
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return false
		}
		ip = ip.WithZone("").Unmap()
		if len(proxies) == 0 {
			return netpolicy.InternalPeer(ip)
		}
		for _, raw := range proxies {
			if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Contains(ip) {
				return true
			}
			if addr, err := netip.ParseAddr(raw); err == nil && addr.Unmap() == ip {
				return true
			}
		}
		return false
	}
}

// ForwardedHeaders sanitizes all forwarding metadata before cookies, URLs, logs or limiters use it.
func ForwardedHeaders(trusted func(string) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		request := c.Request.Clone(c.Request.Context())
		c.Request = request
		if !trusted(request.RemoteAddr) {
			for _, name := range []string{"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-Host", "Forwarded"} {
				request.Header.Del(name)
			}
		} else {
			proto := request.Header.Get("X-Forwarded-Proto")
			if proto == "http" || proto == "https" {
				request.URL.Scheme = proto
			} else {
				request.Header.Del("X-Forwarded-Proto")
			}
			host := request.Header.Get("X-Forwarded-Host")
			u, err := url.Parse("//" + host)
			if err == nil && host != "" && u.Host == host && u.User == nil && !strings.ContainsAny(host, " ,\\\t\r\n") {
				request.Host = host
			} else {
				request.Header.Del("X-Forwarded-Host")
			}
		}
		c.Next()
	}
}

// ClientAddress runs once, after forwarding headers have been sanitized. Gin
// subsequently sees only the resolved address and never re-parses an XFF chain.
func ClientAddress(trusted func(string) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := netpolicy.ResolveClientIP(c.Request.RemoteAddr, c.GetHeader("X-Forwarded-For"), c.GetHeader("X-Real-IP"), func(ip netip.Addr) bool { return trusted(net.JoinHostPort(ip.String(), "0")) })
		c.Request.RemoteAddr = net.JoinHostPort(ip, "0")
		c.Next()
	}
}
