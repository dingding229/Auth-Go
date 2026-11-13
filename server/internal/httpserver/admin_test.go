package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"authgo/internal/adminpath"
	"authgo/internal/auth"
	"authgo/internal/bootstrap"
	"authgo/internal/config"
	"authgo/internal/db"
	"authgo/internal/model"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type httpClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *httpClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *httpClock) add(d time.Duration) { c.mu.Lock(); c.at = c.at.Add(d); c.mu.Unlock() }

type adminFixture struct {
	r      *adminpath.Router
	db     *gorm.DB
	clock  *httpClock
	writes int
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	database, err := db.Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := database.DB()
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.EnsureAdmin(database, "owner", "initial-password"); err != nil {
		t.Fatal(err)
	}
	clock := &httpClock{at: time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)}
	service, err := auth.NewServiceWithClock(database, make([]byte, 32), clock.now)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRouter(config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), pool.PingContext, WithAdmin(service, database))
	if err != nil {
		t.Fatal(err)
	}
	return &adminFixture{r: r, db: database, clock: clock}
}
func (f *adminFixture) request(t *testing.T, method, path, token string, body any, want int) map[string]any {
	t.Helper()
	var reader io.Reader
	if raw, ok := body.(string); ok {
		reader = strings.NewReader(raw)
	} else if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "/api/v1/admin"+path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "auth-integration-test")
	req.RemoteAddr = "198.51.100.7:4567"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, req)
	if method != "GET" && method != "HEAD" && method != "OPTIONS" {
		f.writes++
	}
	if w.Code != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, w.Code, want, w.Body)
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code == 404 && result["message"] == "接口不存在" {
		// A nonexistent endpoint carries no credentials and must not reveal
		// a management namespace via a special cache header.
		if w.Header().Get("Cache-Control") != "" {
			t.Fatal("unknown endpoint has identifying cache marker")
		}
	} else if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential response is cacheable")
	}
	for _, field := range []string{"code", "message", "data", "signature"} {
		if _, ok := result[field]; !ok {
			t.Fatalf("missing %s", field)
		}
	}
	if result["signature"] != nil {
		t.Fatal("management response unexpectedly signed")
	}
	return result
}
func data(r map[string]any) map[string]any { return r["data"].(map[string]any) }
func (f *adminFixture) login(t *testing.T, user, password, code string) map[string]any {
	return data(f.request(t, "POST", "/auth/login", "", gin.H{"username": user, "password": password, "totp_code": code}, 200))
}
func idPath(prefix string, id any) string {
	return prefix + "/" + strconv.FormatUint(uint64(id.(float64)), 10)
}

func TestTOTPHTTPWorkflow(t *testing.T) {
	f := newAdminFixture(t)
	pair := f.login(t, "owner", "initial-password", "")
	access := pair["access_token"].(string)
	f.request(t, "POST", "/auth/totp/setup", access, gin.H{"password": "wrong"}, 401)
	setup := data(f.request(t, "POST", "/auth/totp/setup", access, gin.H{"password": "initial-password"}, 200))
	secret := setup["secret"].(string)
	uri, err := url.Parse(setup["otpauth_uri"].(string))
	if err != nil || uri.Query().Get("secret") != secret {
		t.Fatal("URI invalid")
	}
	f.request(t, "POST", "/auth/totp/enable", access, gin.H{"totp_code": "wrong"}, 400)
	code, _ := totp.GenerateCode(secret, f.clock.now())
	f.request(t, "POST", "/auth/totp/enable", access, gin.H{"totp_code": code}, 200)
	f.request(t, "GET", "/auth/me", access, nil, 401)
	f.request(t, "POST", "/auth/login", "", gin.H{"username": "owner", "password": "initial-password"}, 401)
	f.clock.add(30 * time.Second)
	code, _ = totp.GenerateCode(secret, f.clock.now())
	pair = f.login(t, "owner", "initial-password", code)
	access = pair["access_token"].(string)
	f.request(t, "POST", "/auth/totp/disable", access, gin.H{"password": "initial-password", "totp_code": code}, 400)
	f.clock.add(30 * time.Second)
	code, _ = totp.GenerateCode(secret, f.clock.now())
	f.request(t, "POST", "/auth/totp/disable", access, gin.H{"password": "wrong", "totp_code": code}, 401)
	f.request(t, "POST", "/auth/totp/disable", access, gin.H{"password": "initial-password", "totp_code": code}, 200)
	f.login(t, "owner", "initial-password", "")
	var logs []model.AuditLog
	f.db.Find(&logs)
	encoded, _ := json.Marshal(logs)
	if bytes.Contains(encoded, []byte(secret)) {
		t.Fatal("TOTP secret leaked in audit")
	}
}

func TestHTTPExpiryLockoutAndUnifiedFailures(t *testing.T) {
	f := newAdminFixture(t)
	pair := f.login(t, "owner", "initial-password", "")
	access := pair["access_token"].(string)
	f.clock.add(15 * time.Minute)
	f.request(t, "GET", "/auth/me", access, nil, 401)
	f.request(t, "POST", "/auth/refresh", "", gin.H{"refresh_token": pair["refresh_token"]}, 200)
	for i := 0; i < 5; i++ {
		want := http.StatusUnauthorized
		if i == 4 {
			want = 429
		}
		f.request(t, "POST", "/auth/login", "", gin.H{"username": "owner", "password": "bad-password"}, want)
	}
	f.request(t, "POST", "/auth/login", "", gin.H{"username": "owner", "password": "initial-password"}, 429)
	f.clock.add(15 * time.Minute)
	pair = f.login(t, "owner", "initial-password", "")
	access = pair["access_token"].(string)
	pool, _ := f.db.DB()
	_ = pool.Close()
	errResponse := f.request(t, "GET", "/auth/me", access, nil, 500)
	if errResponse["message"] != "服务器内部错误" {
		t.Fatal("internal error exposed")
	}
	blocked := f.request(t, "POST", "/auth/login", "", gin.H{"username": "owner", "password": "initial-password"}, 500)
	if blocked["code"] != "INTERNAL_ERROR" {
		t.Fatal("anonymous login DB failure exposed details")
	}
}

// Ensure the production clock/constructor is also usable after persistence.
func TestProductionAuthConstructor(t *testing.T) {
	f := newAdminFixture(t)
	service, err := auth.NewService(f.db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(context.Background(), "owner", "initial-password", "", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}

func TestSingleAdministratorSessionAndAudit(t *testing.T) {
	f := newAdminFixture(t)
	pair := f.login(t, "owner", "initial-password", "")
	access := pair["access_token"].(string)
	me := data(f.request(t, "GET", "/auth/me", access, nil, 200))
	if me["username"] != "owner" {
		t.Fatal(me)
	}
	f.request(t, "POST", "/auth/password", access, gin.H{"old_password": "wrong", "new_password": "replacement-password"}, 401)
	f.request(t, "POST", "/auth/password", access, gin.H{"old_password": "initial-password", "new_password": "replacement-password"}, 200)
	f.request(t, "GET", "/auth/me", access, nil, 401)
	f.request(t, "POST", "/auth/refresh", "", gin.H{"refresh_token": pair["refresh_token"]}, 401)
	next := f.login(t, "owner", "replacement-password", "")["access_token"].(string)
	f.request(t, "POST", "/auth/logout", next, nil, 200)
	f.request(t, "GET", "/auth/me", next, nil, 401)
	var logs []model.AuditLog
	f.db.Where("action=?", "auth.password").Order("id").Find(&logs)
	if len(logs) != 2 || logs[0].StatusCode != 401 || logs[1].StatusCode != 200 || logs[1].Operator != "owner" {
		t.Fatal(logs)
	}
}
