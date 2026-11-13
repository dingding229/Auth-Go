package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type zeroBody struct{ remaining int64 }

func (b *zeroBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > b.remaining {
		n = int(b.remaining)
	}
	clear(p[:n])
	b.remaining -= int64(n)
	return n, nil
}
func (*zeroBody) Close() error { return nil }

func TestBodyLimit(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(BodyLimit())
	r.NoRoute(func(c *gin.Context) {
		_, err := io.Copy(io.Discard, c.Request.Body)
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			c.Status(413)
			return
		}
		if err != nil {
			t.Error(err)
		}
		c.Status(204)
	})
	for _, tc := range []struct {
		method, path string
		limit        int64
	}{
		{"POST", "/api/v1/admin/system/ip-info/city", 513 << 20},
		{"POST", "/api/v1/admin/system/ip-info/asn", 513 << 20},
		{"PUT", "/api/v1/admin/system/ip-info/city", 32 << 20},
		{"POST", "/api/v1/admin/system/ip-info/update", 32 << 20},
		{"POST", "/api/v1/admin/system/ip-info/city/", 32 << 20},
		{"POST", "/api/v1/admin/other", 32 << 20},
	} {
		for _, streamed := range []bool{false, true} {
			for _, delta := range []int64{0, 1} {
				req := httptest.NewRequest(tc.method, tc.path, nil)
				req.Body = &zeroBody{tc.limit + delta}
				req.ContentLength = tc.limit + delta
				if streamed {
					req.ContentLength = -1
				}
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				want := 204
				if delta > 0 {
					want = 413
				}
				if w.Code != want {
					t.Fatalf("%s %s streamed=%v delta=%d: %d", tc.method, tc.path, streamed, delta, w.Code)
				}
			}
		}
	}
}
