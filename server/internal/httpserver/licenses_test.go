package httpserver

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"authgo/internal/auth"
	"authgo/internal/catalog"
	"authgo/internal/config"
	"authgo/internal/licensing"

	"github.com/gin-gonic/gin"
)

func newLicensingFixture(t *testing.T) *adminFixture {
	t.Helper()
	f := newAdminFixture(t)
	pool, _ := f.db.DB()
	identity, err := auth.NewServiceWithClock(f.db, make([]byte, 32), f.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	catalogService, err := catalog.NewService(f.db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.r, err = NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext, WithAdmin(identity, f.db), WithCatalog(catalogService), WithLicensing(licensing.NewServiceWithClock(f.db, f.clock.now)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func csvRequest(t *testing.T, f *adminFixture, path, token string, raw []byte, multi bool) map[string]any {
	t.Helper()
	reader := raw
	content := "text/csv"
	if multi {
		var b bytes.Buffer
		writer := multipart.NewWriter(&b)
		part, err := writer.CreateFormFile("file", "licenses.csv")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write(raw)
		_ = writer.Close()
		reader = b.Bytes()
		content = writer.FormDataContentType()
	}
	req := httptest.NewRequest("POST", "/api/v1/admin"+path, bytes.NewReader(reader))
	req.Header.Set("Content-Type", content)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "license-CSV-integration")
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("CSV status %d: %s", w.Code, w.Body)
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func exportRequest(t *testing.T, f *adminFixture, path, token string) [][]string {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/admin"+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("CSV export %d: %s", w.Code, w.Body)
	}
	rows, err := csv.NewReader(w.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestLicenseHTTPValidationAndRelativeDates(t *testing.T) {
	f := newLicensingFixture(t)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	user := data(f.request(t, "POST", "/users", owner, gin.H{"name": "用户"}, 200))
	app := data(f.request(t, "POST", "/applications", owner, gin.H{"name": "应用"}, 200))
	for _, input := range []gin.H{{"app_id": app["id"], "key": "chosen"}, {"app_id": app["id"], "status": "active"}, {"app_id": app["id"], "verify_methods": []string{"KEY", "USER"}}} {
		input["user_id"] = user["id"]
		f.request(t, "POST", "/licenses", owner, input, 400)
	}
	l := data(f.request(t, "POST", "/licenses", owner, gin.H{"user_id": user["id"], "app_id": app["id"], "validity_rule": "fixed_days", "duration_days": 30}, 200))
	lp := idPath("/licenses", l["id"])
	f.request(t, "POST", lp+"/renew", owner, gin.H{}, 400)
	f.request(t, "POST", lp+"/renew", owner, gin.H{"days": 2, "expires_at": f.clock.now().AddDate(0, 0, 90)}, 400)
	f.request(t, "POST", lp+"/renew", owner, gin.H{"expires_at": f.clock.now().AddDate(0, 0, 60)}, 200)
	for _, query := range []string{"status=bad", "type=bad", "app_id=0", "expires_from=bad", "expires_from=2026-11-04T00:00:00Z&expires_to=2026-11-03T00:00:00Z", "sort_by=portal_password_hash"} {
		f.request(t, "GET", "/licenses?"+query, owner, nil, 400)
	}
	f.request(t, "GET", "/activations?license_id=bad", owner, nil, 400)
	f.request(t, "POST", "/licenses/import", owner, gin.H{}, 415)
}

func TestLicenseExpiryFilterTimezones(t *testing.T) {
	f := newLicensingFixture(t)
	owner := f.login(t, "owner", "initial-password", "")["access_token"].(string)
	user := data(f.request(t, "POST", "/users", owner, gin.H{"name": "用户"}, 200))
	app := data(f.request(t, "POST", "/applications", owner, gin.H{"name": "时区应用"}, 200))
	f.request(t, "POST", "/licenses", owner, gin.H{"user_id": user["id"], "app_id": app["id"], "expires_at": f.clock.now().Add(24 * time.Hour)}, 200)
	list := data(f.request(t, "GET", "/licenses?expires_from=2026-11-04T15:00:00%2B08:00&expires_to=2026-11-04T17:00:00%2B08:00", owner, nil, 200))
	if list["total"] != float64(1) {
		t.Fatal("expiry filters did not normalize timezone")
	}
}
