package httpserver

import (
	"authgo/internal/auth"
	"authgo/internal/config"
	"authgo/internal/ipinfo"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

type uploadSpaces struct{}

func (uploadSpaces) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

type uploadZeros struct{}

func (uploadZeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// A real TCP HTTP server, real bearer authentication and the real MMDB parser.
// Large padding is streamed, not allocated or written to the database file.
func TestRealHTTPUploadKnownAndChunkedBoundaries(t *testing.T) {
	f := newAdminFixture(t)
	token := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	ips, err := ipinfo.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ips.Close()
	identity, err := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := f.db.DB()
	r, err := NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext, WithAdmin(identity, f.db), WithIPInfo(ips))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(r)
	defer server.Close()
	client := server.Client()
	call := func(method, path, contentType string, body io.Reader, length int64, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), method, server.URL+"/api/v1/admin"+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = length
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", contentType)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("%s %s length=%d: %d %s", method, path, length, res.StatusCode, raw)
		}
		if !strings.Contains(res.Header.Get("Content-Type"), "application/json") {
			t.Fatal("not JSON", res.Header)
		}
	}
	for _, kind := range []string{"city", "asn"} {
		valid, err := os.ReadFile("../ipinfo/testdata/" + kind + ".mmdb")
		if err != nil {
			t.Fatal(err)
		}
		prefix := "--authgo-boundary\r\nContent-Disposition: form-data; name=\"padding\"\r\n\r\n"
		suffix := "\r\n--authgo-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"db.mmdb\"\r\nContent-Type: application/octet-stream\r\n\r\n"
		footer := "\r\n--authgo-boundary--\r\n"
		for _, chunked := range []bool{false, true} {
			for _, delta := range []int64{-1, 0, 1} {
				t.Run(fmt.Sprintf("%s/chunked=%v/delta=%d", kind, chunked, delta), func(t *testing.T) {
					size := int64(513<<20) + delta
					padding := size - int64(len(prefix)+len(suffix)+len(valid)+len(footer))
					body := io.MultiReader(strings.NewReader(prefix), io.LimitReader(uploadZeros{}, padding), strings.NewReader(suffix), bytes.NewReader(valid), strings.NewReader(footer))
					length, want := size, 200
					if chunked {
						length = -1
					}
					if delta > 0 {
						want = 413
					}
					before := ips.Status()
					call("POST", "/system/ip-info/"+kind, "multipart/form-data; boundary=authgo-boundary", body, length, want)
					after := ips.Status()
					if want == 413 && (!reflect.DeepEqual(before.City, after.City) || !reflect.DeepEqual(before.ASN, after.ASN)) {
						t.Fatal("rejected upload replaced live DB")
					}
				})
			}
			// Raw files have the stricter 512 MiB business ceiling in both encodings.
			length := ipinfo.MaxDatabaseBytes + 1
			if chunked {
				length = -1
			}
			call("POST", "/system/ip-info/"+kind, "application/octet-stream", io.LimitReader(uploadZeros{}, ipinfo.MaxDatabaseBytes+1), length, 413)
			// Even a valid file followed by an oversized epilogue is rejected
			// before it can replace the old database (the old early-return bug).
			first := "--authgo-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"db.mmdb\"\r\n\r\n"
			tailSize := int64(513<<20) + 1
			tailBody := io.MultiReader(strings.NewReader(first), bytes.NewReader(valid), strings.NewReader(footer), io.LimitReader(uploadZeros{}, tailSize-int64(len(first)+len(valid)+len(footer))))
			tailLength := tailSize
			if chunked {
				tailLength = -1
			}
			before := ips.Status()
			call("POST", "/system/ip-info/"+kind, "multipart/form-data; boundary=authgo-boundary", tailBody, tailLength, 413)
			after := ips.Status()
			if !reflect.DeepEqual(before.City, after.City) || !reflect.DeepEqual(before.ASN, after.ASN) {
				t.Fatal("oversized epilogue replaced live DB")
			}

		}
	}
	// No other method or IP-management path receives the enlarged HTTP ceiling.
	for _, tc := range []struct{ method, path string }{{"PUT", "/system/ip-info/city"}, {"POST", "/system/ip-info/update"}, {"POST", "/system/ip-info/enable"}, {"POST", "/system/ip-info/other"}, {"POST", "/system/ip-info/city/"}} {
		call(tc.method, tc.path, "application/octet-stream", io.LimitReader(uploadZeros{}, 32<<20+1), 32<<20+1, 413)
	}
	// JSON endpoints reject at their stricter 64 KiB parser ceiling, including
	// chunked bodies. A parser may reject before the outer 32 MiB is reached.
	for _, chunked := range []bool{false, true} {
		for _, delta := range []int64{-1, 0, 1} {
			n := int64(32<<20) + delta
			length, want := n, 400
			if chunked {
				length = -1
			} else if delta > 0 {
				want = 413
			}
			call("POST", "/auth/password", "application/json", io.MultiReader(io.LimitReader(uploadSpaces{}, n-2), strings.NewReader(`{}`)), length, want)
		}
	}
}
