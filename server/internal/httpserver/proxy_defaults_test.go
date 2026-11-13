package httpserver

import (
	"authgo/internal/automation"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRuntimeProxyDefaultAndExplicitAllowlist(t *testing.T) {
	f, s := automationFixture(t)
	f.r.GET("/forward-probe", func(c *gin.Context) {
		c.JSON(200, gin.H{"ip": c.ClientIP(), "host": c.Request.Host, "proto": c.Request.URL.Scheme})
	})
	for _, tc := range []struct {
		name, peer, xff, real, want string
		proxies                     []string
	}{
		{"private default", "172.19.0.2:80", "203.0.113.9,10.0.0.2", "", "203.0.113.9", nil},
		{"public direct", "198.51.100.2:80", "203.0.113.9", "203.0.113.10", "198.51.100.2", nil},
		{"private realip", "172.19.0.2:80", "", "203.0.113.10", "203.0.113.10", nil},
		{"explicit excludes private", "172.19.0.2:80", "203.0.113.9", "", "172.19.0.2", []string{"10.1.0.0/16"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := tc.proxies
			if list == nil {
				list = []string{}
			}
			if _, e := s.UpdateSettings(t.Context(), automation.SettingsInput{TrustedProxies: &list}); e != nil {
				t.Fatal(e)
			}
			req := httptest.NewRequest("GET", "http://actual.example/forward-probe", nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("X-Forwarded-For", tc.xff)
			req.Header.Set("X-Real-IP", tc.real)
			req.Header.Set("X-Forwarded-Host", "external.example")
			req.Header.Set("X-Forwarded-Proto", "https")
			w := httptest.NewRecorder()
			f.r.ServeHTTP(w, req)
			expectedHost, expectedProto := "actual.example", "http"
			if tc.name == "private default" || tc.name == "private realip" {
				expectedHost, expectedProto = "external.example", "https"
			}
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"ip":"`+tc.want+`"`) || !strings.Contains(w.Body.String(), `"host":"`+expectedHost+`"`) || !strings.Contains(w.Body.String(), `"proto":"`+expectedProto+`"`) {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
