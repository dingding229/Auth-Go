package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBearerParsing(t *testing.T) {
	for _, test := range []struct {
		header string
		ok     bool
	}{{"Bearer abc", true}, {"bearer abc", true}, {"Basic abc", false}, {"Bearer", false}, {"Bearer a b", false}, {"", false}, {"Bearer " + strings.Repeat("x", 8200), false}} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Request.Header.Set("Authorization", test.header)
		_, ok := Bearer(c)
		if ok != test.ok {
			t.Fatalf("header parse ok=%v want=%v", ok, test.ok)
		}
	}
}
