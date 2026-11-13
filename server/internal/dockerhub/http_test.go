package dockerhub

import (
	"authgo/internal/auth"
	"authgo/internal/bootstrap"
	"authgo/internal/middleware"
	"authgo/internal/model"
	"bytes"
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestManagementAuthenticationAuditAndFirstPageOnly(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { responsePage(w, []map[string]any{good("1.0.0")}, nil) })
	bootstrap.EnsureAdmin(f.dbService.db, "owner", "initial-password")
	identity, err := auth.NewService(f.dbService.db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := identity.Login(context.Background(), "owner", "initial-password", "", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AdminRequests(identity), middleware.Audit(f.dbService.db, slog.New(slog.NewTextHandler(io.Discard, nil))))
	f.dbService.Register(r, identity)
	base := "/api/v1/admin/applications/" + strconv.FormatUint(f.app.ID, 10) + "/dockerhub"
	call := func(method, path, key string, want int) {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewBufferString("{}"))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatal(w.Code, want)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{base, base + "/test", base + "/sync"} {
		method := "POST"
		if p == base {
			method = "GET"
		}
		call(method, p, "", 401)
	}
	call("POST", base+"/test", token.AccessToken, 200)
	var n int64
	f.dbService.db.Model(&State{}).Count(&n)
	if n != 1 {
		t.Fatal("connection test created/deleted state")
	}
	call("GET", base, token.AccessToken, 200)
	call("POST", base+"/sync", token.AccessToken, 200)
	waitBackground(t, f)
	f.dbService.db.Model(&model.AuditLog{}).Where("action IN ?", []string{"dockerhub.test", "dockerhub.sync"}).Count(&n)
	if n != 2 {
		t.Fatal("missing audits", n)
	}
}

func TestManualSyncHTTPReturnsBeforeSlowHubCompletes(t *testing.T) {
	release := make(chan struct{})
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		responsePage(w, []map[string]any{good("1.0.0")}, nil)
	})
	// Register this defer after fixture cleanup, so even a failing synchronous
	// implementation is released rather than leaving httptest.Close hanging.
	releaseHub := sync.OnceFunc(func() { close(release) })

	if _, err := bootstrap.EnsureAdmin(f.dbService.db, "owner", "initial-password"); err != nil {
		t.Fatal(err)
	}
	identity, err := auth.NewService(f.dbService.db, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := identity.Login(t.Context(), "owner", "initial-password", "", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(middleware.AdminRequests(identity))
	f.dbService.Register(router, identity)
	server := httptest.NewUnstartedServer(router)
	server.Config.WriteTimeout = 20 * time.Millisecond
	server.Start()
	defer server.Close()
	defer releaseHub()
	client := server.Client()
	client.Timeout = 100 * time.Millisecond
	req, _ := http.NewRequest("POST", server.URL+"/api/v1/admin/applications/"+strconv.FormatUint(f.app.ID, 10)+"/dockerhub/sync", bytes.NewBufferString("{}"))
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal("manual sync blocked on Hub", err)
	}
	defer res.Body.Close()
	var out struct {
		Data State `json:"data"`
	}
	if err = json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != 200 || !out.Data.Running {
		t.Fatal(out, res.StatusCode, err)
	}
	// Release and join the background task before fixture DB teardown.
	releaseHub()
	waitBackground(t, f)
}
