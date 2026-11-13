package client

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"authgo/internal/code"
	"authgo/internal/db"
	"authgo/internal/model"
	"authgo/sdk/wire"
	"encoding/json"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	database, e := db.Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := database.DB()
	t.Cleanup(func() { _ = pool.Close() })
	if e := db.Migrate(database); e != nil {
		t.Fatal(e)
	}
	return database
}
func TestNonceCacheAtomicAndTTL(t *testing.T) {
	c := nonceCache{entries: map[string]time.Time{}, limit: 2}
	now := time.Unix(1000, 0)
	var good atomic.Int64
	var wg sync.WaitGroup
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replay, full := c.checkAndAdd("app:nonce", now)
			if !replay && !full {
				good.Add(1)
			}
		}()
	}
	wg.Wait()
	if good.Load() != 1 {
		t.Fatal(good.Load())
	}
	if replay, full := c.checkAndAdd("other:nonce", now); replay || full {
		t.Fatal("app scope collision")
	}
	if _, full := c.checkAndAdd("third:nonce", now); !full {
		t.Fatal("unbounded cache")
	}
	if replay, full := c.checkAndAdd("app:nonce", now.Add(10*time.Minute)); replay || full {
		t.Fatal("TTL boundary")
	}
}
func TestTokenBucket(t *testing.T) {
	l := newLimiter(2, 2, 2)
	now := time.Unix(1000, 0)
	if !l.allow("one", now) || !l.allow("one", now) || l.allow("one", now) {
		t.Fatal("burst")
	}
	if l.allow("one", now.Add(499*time.Millisecond)) || !l.allow("one", now.Add(500*time.Millisecond)) {
		t.Fatal("fractional refill")
	}
	if !l.allow("two", now) || l.allow("three", now) {
		t.Fatal("key isolation or capacity")
	}
	if !l.allow("three", now.Add(2*time.Hour)) {
		t.Fatal("idle entries not evicted")
	}
}
func TestMalformedLicenseNeverQueriesDB(t *testing.T) {
	database := testDB(t)
	s, e := NewService(database, make([]byte, 32), slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.Close(context.Background()); e != nil {
			t.Error(e)
		}
	})
	var queries atomic.Int64
	if e := database.Callback().Query().Before("gorm:query").Register("test:no-query", func(tx *gorm.DB) { queries.Add(1) }); e != nil {
		t.Fatal(e)
	}
	defer database.Callback().Query().Remove("test:no-query")
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	s.Register(r)
	for _, key := range []string{"bad-key", "AUTH-AAAAA-AAAAA-AAAAA-AAAAA"} {
		inner := wire.Inner{Op: "activate", Body: json.RawMessage(`{"license_key":"` + key + `","challenge":"` + wire.B64.EncodeToString(make([]byte, 32)) + `"}`)}
		raw, _ := json.Marshal(inner)
		k, _ := s.channel.Current(context.Background())
		pub, _ := wire.B64.DecodeString(k.PublicKey)
		outer, session, _ := wire.Encrypt(pub, raw)
		raw, _ = json.Marshal(outer)
		queries.Store(0)
		req := httptest.NewRequest("POST", "/api/v1/client/gateway", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var encrypted wire.Response
		json.Unmarshal(w.Body.Bytes(), &encrypted)
		plain, _ := session.DecryptResponse(encrypted)
		if w.Code != 200 || !strings.Contains(string(plain), code.InvalidLicenseKey) {
			t.Fatal(w.Code, w.Body)
		}
	}
	if queries.Load() != 1 {
		t.Fatalf("malformed key made %d queries", queries.Load())
	}
}
func TestLogReservationDrainAndBestEffortFailure(t *testing.T) {
	database := testDB(t)
	w := newLogWriter(database, slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	submit, ok := w.reserve()
	if !ok {
		t.Fatal("reserve")
	}
	if _, ok := w.reserve(); ok {
		t.Fatal("unbounded queue")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if e := w.close(ctx); e == nil {
		t.Fatal("must wait for in-flight requests")
	}
	submit(model.VerifyLog{Code: code.InvalidLicenseKey, CreatedAt: time.Now()})
	if e := w.close(context.Background()); e != nil {
		t.Fatal(e)
	}
	var n int64
	database.Model(&model.VerifyLog{}).Count(&n)
	if n != 1 {
		t.Fatal(n)
	}
	if _, ok := w.reserve(); ok {
		t.Fatal("reserve after close")
	}
	// A failed batch is counted and discarded; auxiliary failures do not fail shutdown.
	if e := database.Migrator().DropTable(&model.VerifyLog{}); e != nil {
		t.Fatal(e)
	}
	failed := newLogWriter(database, slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	send, _ := failed.reserve()
	send(model.VerifyLog{Code: code.OK})
	if e := failed.close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if failed.dropped.Load() != 1 {
		t.Fatal("lost batch not counted")
	}

}
func TestLogMissingRelationAndUnsignedEarlyFailure(t *testing.T) {
	database := testDB(t)
	w := newLogWriter(database, slog.New(slog.NewTextHandler(io.Discard, nil)), 2)
	id := uint64(123456)
	send, _ := w.reserve()
	send(model.VerifyLog{AppID: &id, LicenseID: &id, ActivationID: &id, Code: code.OK})
	if e := w.close(context.Background()); e != nil {
		t.Fatal(e)
	}
	var row model.VerifyLog
	if e := database.First(&row).Error; e != nil {
		t.Fatal(e)
	}
	if row.AppID != nil || row.LicenseID != nil || row.ActivationID != nil {
		t.Fatal("dangling FK")
	}
}
func TestTimestampAndNonceSyntax(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, tt := range []struct {
		v  string
		ok bool
	}{{"700", true}, {"1300", true}, {"699", false}, {"1301", false}, {"+1000", false}, {"01000", false}, {"1000.0", false}, {"9223372036854775808", false}} {
		if validTimestamp(tt.v, now) != tt.ok {
			t.Fatal(tt)
		}
	}
	for _, tt := range []struct {
		v  string
		ok bool
	}{{strings.Repeat("a", 16), true}, {strings.Repeat("z", 128), true}, {strings.Repeat("a", 129), false}, {"", false}, {"a b-no-valid-nonce", false}} {
		if validNonce(tt.v) != tt.ok {
			t.Fatal(tt)
		}
	}
	if !bytes.Equal(SigningInput("verify", "1000", "nonce", []byte("{}")), []byte("verify1000nonce44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")) {
		t.Fatal("signing input changed")
	}
}
