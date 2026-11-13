package response

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestPagination(t *testing.T) {
	for _, test := range []struct {
		query string
		valid bool
	}{{"", true}, {"page=2&page_size=50", true}, {"page=0", false}, {"page=-1", false}, {"page_size=101", false}, {"page_size=", false}, {"page=9999999999999999999999", false}, {"page=1000001", false}, {"page_size=no", false}} {
		v, _ := url.ParseQuery(test.query)
		p, err := ParsePage(v)
		if (err == nil) != test.valid {
			t.Fatalf("query %q error %v", test.query, err)
		}
		if test.query == "page=2&page_size=50" && p.Offset() != 50 {
			t.Fatal("offset")
		}
	}
}
func TestStrictJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, raw := range []string{`{"name":"ok"}`, `{"name":"ok","extra":1}`, `{} {}`, `{`, strings.Repeat(" ", 65537) + `{}`} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/", strings.NewReader(raw))
		var in struct {
			Name string `json:"name"`
		}
		err := BindJSON(c, &in)
		if (err == nil) != (raw == `{"name":"ok"}`) {
			t.Fatalf("strict decode %v", err)
		}
	}
}
