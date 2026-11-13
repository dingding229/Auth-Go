package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestForwardedHeaders(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		r := gin.New()
		var proxies []string
		if trusted {
			proxies = []string{"10.0.0.0/8"}
		}
		r.Use(ForwardedHeaders(TrustedPeer(proxies)))
		r.GET("/probe", func(c *gin.Context) {
			if trusted {
				if c.Request.Host != "public.example:8443" || c.Request.URL.Scheme != "https" || c.GetHeader("X-Forwarded-For") != "203.0.113.9" {
					t.Fatal(c.Request)
				}
			} else {
				if c.Request.Host != "actual.example" || c.Request.URL.Scheme == "https" {
					t.Fatal(c.Request)
				}
				for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
					if c.GetHeader(h) != "" {
						t.Fatal(h)
					}
				}
			}
			// Same expression as the download Cookie: untrusted proto cannot mark it Secure.
			secure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
			c.SetCookie("probe", "value", 1, "/", "", secure, true)
			c.Status(204)
		})
		q := httptest.NewRequest("GET", "http://actual.example/probe", nil)
		q.RemoteAddr = "10.0.0.2:1234"
		for h, v := range map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "203.0.113.9", "X-Forwarded-Host": "public.example:8443", "X-Forwarded-Proto": "https", "Forwarded": "for=203.0.113.9;proto=https"} {
			q.Header.Set(h, v)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		if cookies := w.Result().Cookies(); len(cookies) != 1 || cookies[0].Secure != trusted {
			t.Fatal(w.Header())
		}
	}
}
