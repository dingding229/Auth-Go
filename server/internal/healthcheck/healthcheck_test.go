package healthcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestURL(t *testing.T) {
	for _, tt := range []struct{ addr, want string }{
		{"", "http://127.0.0.1:8080/healthz"}, {":8080", "http://127.0.0.1:8080/healthz"},
		{"0.0.0.0:9000", "http://127.0.0.1:9000/healthz"}, {"[::]:8080", "http://[::1]:8080/healthz"},
		{"127.0.0.1:9001", "http://127.0.0.1:9001/healthz"}, {"[::1]:9001", "http://[::1]:9001/healthz"},
	} {
		got, err := URL(tt.addr)
		if err != nil || got != tt.want {
			t.Fatalf("URL(%q)=%q %v", tt.addr, got, err)
		}
	}
	for _, addr := range []string{"bad", ":", ":0"} {
		if _, err := URL(addr); err == nil {
			t.Fatalf("accepted %q", addr)
		}
	}
}

func TestCheck(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	for _, status := range []int{200, 503, 302} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				t.Errorf("path=%s", r.URL.Path)
			}
			w.Header().Set("Location", "/healthz")
			w.WriteHeader(status)
		}))
		err := Check(context.Background(), strings.TrimPrefix(s.URL, "http://"))
		s.Close()
		if (err == nil) != (status == 200) {
			t.Fatalf("status=%d err=%v", status, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Check(ctx, ":8080"); err == nil {
		t.Fatal("cancelled probe passed")
	}
}
