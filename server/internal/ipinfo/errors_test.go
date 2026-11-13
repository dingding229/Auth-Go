package ipinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestOperationReturnsSpecificSafeErrorsAndStoresOnlySafeText(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		want   string
		status int
	}{
		{"invalid mmdb", errInvalidMMDB, string(errInvalidMMDB), 400},
		{"wrong type", errTypeMismatch, string(errTypeMismatch), 400},
		{"invalid metadata", errInvalidMetadata, string(errInvalidMetadata), 400},
		{"invalid content", errInvalidContent, string(errInvalidContent), 400},
		{"database limit", errDatabaseTooLarge, string(errDatabaseTooLarge), 413},
		{"compressed limit", errCompressedTooLarge, string(errCompressedTooLarge), 400},
		{"gzip", errInvalidGzip, string(errInvalidGzip), 400},
		{"disabled", errDisabled, string(errDisabled), 400},
		{"not published", errNotPublished, string(errNotPublished), 400},
		{"wrapped validation", fmt.Errorf("private details: %w", errInvalidMMDB), string(errInvalidMMDB), 400},
		{"body limit", &http.MaxBytesError{Limit: MaxDatabaseBytes + (1 << 20)}, string(errUploadTooLarge), 413},
		{"network", &url.Error{Op: "Get", URL: "https://192.0.2.1:443/private", Err: errors.New("internal network address")}, genericError, 400},
		{"filesystem", &os.PathError{Op: "open", Path: "/private/server/state.json", Err: os.ErrPermission}, genericError, 400},
		{"untrusted message", errors.New("无效的 MMDB 文件 /private/server/path"), genericError, 400},
		{"canceled", context.Canceled, canceledError, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testService(t)
			r := gin.New()
			r.POST("/test", s.operation(func(*gin.Context) error { s.recordError(tc.err); return tc.err }))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("POST", "/test", nil))
			var body struct {
				Message string `json:"message"`
			}
			if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
				t.Fatal(e)
			}
			if w.Code != tc.status || body.Message != tc.want || s.Status().LastError != tc.want {
				t.Fatalf("status=%d want_status=%d message=%s last_error=%s want=%s", w.Code, tc.status, body.Message, s.Status().LastError, tc.want)
			}
			raw, e := os.ReadFile(filepath.Join(s.dir, "state.json"))
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(raw, []byte("/private/")) || bytes.Contains(raw, []byte("192.0.2.1")) || bytes.Contains(w.Body.Bytes(), []byte("private details")) {
				t.Fatalf("internal details leaked: %s", raw)
			}
		})
	}
}

func TestStartupDamageIsLoggedAndPreserved(t *testing.T) {
	previous := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "ipdb")
	if e := os.MkdirAll(dbDir, 0700); e != nil {
		t.Fatal(e)
	}
	statePath := filepath.Join(dbDir, "state.json")
	if e := os.WriteFile(statePath, []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if !strings.Contains(logs.String(), "IP 库已降级停用，不影响授权服务") || !strings.Contains(logs.String(), string(errInvalidState)) {
		t.Fatal("missing degradation log", logs.String())
	}
	if s.Status().Enabled || s.Lookup("8.8.8.8") != nil {
		t.Fatal("not disabled")
	}
	raw, e := os.ReadFile(statePath)
	if e != nil || string(raw) != "broken" {
		t.Fatal("damaged state was overwritten", e)
	}
}

func TestActualOperationsReturnValidationAndBusinessMessages(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation func(*Service) error
		want      userError
	}{
		{"invalid MMDB", func(s *Service) error { return s.Upload(context.Background(), "city", strings.NewReader("broken")) }, errInvalidMMDB},
		{"wrong type", func(s *Service) error {
			return s.Upload(context.Background(), "city", bytes.NewReader(fixture(t, "asn")))
		}, errTypeMismatch},
		{"invalid kind", func(s *Service) error { return s.Upload(context.Background(), "bad", strings.NewReader("broken")) }, errInvalidKind},
		{"disabled", func(s *Service) error { return s.Update(context.Background()) }, errDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testService(t)
			r := gin.New()
			r.POST("/test", s.operation(func(*gin.Context) error { return tc.operation(s) }))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("POST", "/test", nil))
			var body struct {
				Message string `json:"message"`
			}
			if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
				t.Fatal(e)
			}
			if w.Code != 400 || body.Message != string(tc.want) {
				t.Fatalf("unexpected operation error: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
