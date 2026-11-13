package middleware

import (
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
		ip = ip.Unmap()
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
