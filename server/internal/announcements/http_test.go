package announcements

import (
	"authgo/internal/db"
	"authgo/internal/model"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicAnnouncementsFiltersBoundsNonEnumerationAndRateLimit(t *testing.T) {
	d, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	app := model.Application{Name: "news", AppKey: "public-key", Status: "active"}
	if e = d.Create(&app).Error; e != nil {
		t.Fatal(e)
	}
	empty := model.Application{Name: "empty", AppKey: "empty-key", Status: "active"}
	if e = d.Create(&empty).Error; e != nil {
		t.Fatal(e)
	}
	s := New(d)
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	for _, v := range []model.Announcement{{AppID: app.ID, Title: "published", Content: "plain <script>text</script>", Level: "warning", PublishedAt: &past, ExpiresAt: &future}, {AppID: app.ID, Title: "draft", Level: "info"}, {AppID: app.ID, Title: "future", Level: "info", PublishedAt: &future}, {AppID: app.ID, Title: "expired", Level: "info", PublishedAt: &past, ExpiresAt: &now}} {
		if e = d.Create(&v).Error; e != nil {
			t.Fatal(e)
		}
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	s.Register(r)
	call := func(key, ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/public/announcements?app_key="+key, nil)
		req.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	got := call("public-key", "198.51.100.1")
	if got.Code != 200 || got.Header().Get("Cache-Control") != "public, max-age=60" || got.Header().Get("Access-Control-Allow-Origin") != "*" || got.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal(got)
	}
	var body struct {
		Signature any `json:"signature"`
		Data      struct {
			Items []Item `json:"items"`
		} `json:"data"`
	}
	if e = json.Unmarshal(got.Body.Bytes(), &body); e != nil || len(body.Data.Items) != 1 || body.Data.Items[0].Title != "published" || body.Data.Items[0].Level != "warning" || body.Signature != nil {
		t.Fatal(got.Body.String(), e)
	}
	absent := call("unknown-key", "198.51.100.2")
	noNews := call("empty-key", "198.51.100.2")
	if absent.Code != noNews.Code || absent.Body.String() != noNews.Body.String() || absent.Header().Get("Cache-Control") != noNews.Header().Get("Cache-Control") {
		t.Fatal("software enumeration")
	}
	for i := 0; i < MaxItems+5; i++ {
		if e = d.Create(&model.Announcement{AppID: app.ID, Title: "large", Content: strings.Repeat("\x01", 32768), Level: "info", PublishedAt: &past}).Error; e != nil {
			t.Fatal(e)
		}
	}
	got = call("public-key", "198.51.100.3")
	if got.Code != 200 || got.Body.Len() > MaxResponseBytes {
		t.Fatal("unbounded public payload", got.Body.Len())
	}
	json.Unmarshal(got.Body.Bytes(), &body)
	if len(body.Data.Items) == 0 || len(body.Data.Items) > MaxItems {
		t.Fatal("missing or unbounded list")
	}
	for i := 0; i < 30; i++ {
		if got = call("unknown-key", "198.51.100.4"); got.Code != 200 {
			t.Fatal(i, got.Code)
		}
	}
	if got = call("public-key", "198.51.100.4"); got.Code != 429 || got.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("rate limit", got.Code)
	}
}
