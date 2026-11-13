package publishing

import (
	"authgo/internal/auth"
	"authgo/internal/bootstrap"
	"authgo/internal/catalog"
	"authgo/internal/db"
	"authgo/internal/keycheck"
	"authgo/internal/middleware"
	"authgo/internal/model"
	"authgo/internal/payloadkey"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	s      *Service
	id     uint64
	token  string
	router *gin.Engine
	logs   bytes.Buffer
}

func ptr[T any](v T) *T { return &v }
func newFixture(t *testing.T, handler http.Handler) *fixture {
	t.Helper()
	database, err := db.Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := database.DB()
	t.Cleanup(func() { _ = pool.Close() })
	if err = db.Migrate(database); err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{7}, 32)
	cat, err := catalog.NewService(database, master)
	if err != nil {
		t.Fatal(err)
	}
	app, err := cat.CreateApplication(context.Background(), catalog.ApplicationInput{Name: ptr("发布测试"), DockerImage: ptr("example/test")})
	if err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]string{"login": "example"})
		case "/v2/users/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "mock-session"})
		default:
			handler.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(remote.Close)
	service, err := newService(database, master, cat, remote.Client(), remote.URL)
	if err != nil {
		t.Fatal(err)
	}
	service.dockerBase = remote.URL
	f := &fixture{s: service, id: app.ID}
	previousLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&f.logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLog) })
	if _, err = bootstrap.EnsureAdmin(database, "owner", "initial-password"); err != nil {
		t.Fatal(err)
	}
	identity, err := auth.NewService(database, master)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := identity.Login(context.Background(), "owner", "initial-password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	f.token = pair.AccessToken
	gin.SetMode(gin.TestMode)
	f.router = gin.New()
	f.router.Use(middleware.AdminRequests(identity), middleware.Audit(database, slog.New(slog.NewTextHandler(&f.logs, nil))))
	service.Register(f.router, identity, func() string { return "https://license.example" })
	return f
}
func (f *fixture) request(t *testing.T, method, path string, body any, token string, want int) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, "/api/v1/admin"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	if w.Code != want {
		t.Fatalf("%s %s status %d want %d: %s", method, path, w.Code, want, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"github-secret-value", "docker-secret-value"} {
		if strings.Contains(w.Body.String(), secret) || strings.Contains(f.logs.String(), secret) {
			t.Fatal("令牌进入响应或日志")
		}
	}
	return result
}
func (f *fixture) setup(t *testing.T) string {
	t.Helper()
	f.request(t, "PATCH", "/system/publishing", map[string]any{"github_token": "github-secret-value", "docker_token": "docker-secret-value", "docker_username": "example"}, f.token, 200)
	path := "/applications/" + strconv.FormatUint(f.id, 10) + "/publishing"
	f.request(t, "PATCH", path, map[string]any{"repository": "owner/repo", "branch": "main", "language": "Go", "mode": "cli", "encrypted": false}, f.token, 200)
	return path
}

func TestGitHubPublishHTTPRoundTrip(t *testing.T) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	workflow := ""
	variable := ""
	dispatched := false
	secrets := map[string]string{}
	writes := []string{}
	remote := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer github-secret-value" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Error("GitHub 认证头错误")
		}
		path := strings.TrimPrefix(r.URL.Path, "/repos/owner/repo")
		reply := func(v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
		if r.Method == "GET" {
			switch path {
			case "", "/branches/main":
				reply(map[string]any{})
				return
			case "/contents/examples/docker/Dockerfile":
				if r.URL.Query().Get("ref") != "main" {
					t.Error("missing branch")
				}
				reply(map[string]string{"type": "file"})
				return
			case "/contents/" + WorkflowPath:
				if workflow == "" {
					w.WriteHeader(404)
				} else {
					reply(map[string]string{"sha": "current-sha", "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(workflow))})
				}
				return
			case "/actions/secrets/public-key":
				reply(map[string]string{"key_id": "public-key-id", "key": base64.StdEncoding.EncodeToString(pub[:])})
				return
			case "/actions/variables/AUTHGO_CONFIG":
				if variable == "" {
					w.WriteHeader(404)
				} else {
					reply(map[string]string{"value": variable})
				}
				return
			case "/actions/workflows/authgo-publish.yml/runs":
				if r.URL.Query().Get("branch") != "main" || r.URL.Query().Get("per_page") != "5" {
					t.Error("unbounded runs")
				}
				reply(map[string]any{"workflow_runs": []any{map[string]any{"id": 99, "status": "completed", "conclusion": "success", "created_at": "2026-11-15T00:00:00Z", "html_url": "https://evil.example/github-secret-value"}}})
				return
			}
		}
		writes = append(writes, r.Method+" "+path)
		var body map[string]string
		if path == "/actions/workflows/authgo-publish.yml/dispatches" {
			var in struct {
				Ref    string            `json:"ref"`
				Inputs map[string]string `json:"inputs"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Ref != "main" || in.Inputs["version"] != "1.2.3" {
				t.Error("dispatch input mismatch")
			}
			dispatched = true
			w.WriteHeader(204)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		switch {
		case r.Method == "PUT" && path == "/contents/"+WorkflowPath:
			if workflow != "" && body["sha"] != "current-sha" {
				t.Error("update missing SHA")
			}
			if body["branch"] != "main" {
				t.Error("workflow wrong branch")
			}
			data, e := base64.StdEncoding.DecodeString(body["content"])
			if e != nil {
				t.Error(e)
			}
			workflow = string(data)
		case r.Method == "PUT" && strings.HasPrefix(path, "/actions/secrets/"):
			encrypted, e := base64.StdEncoding.DecodeString(body["encrypted_value"])
			if e != nil {
				t.Error(e)
			}
			plain, ok := box.OpenAnonymous(nil, encrypted, pub, priv)
			if !ok || body["key_id"] != "public-key-id" {
				t.Error("not sealed with repository key")
			}
			secrets[strings.TrimPrefix(path, "/actions/secrets/")] = string(plain)
		case (r.Method == "POST" && path == "/actions/variables") || (r.Method == "PATCH" && path == "/actions/variables/AUTHGO_CONFIG"):
			if body["name"] != "AUTHGO_CONFIG" {
				t.Error("unexpected variable")
			}
			variable = body["value"]
		default:
			t.Errorf("unexpected remote operation: %s %s", r.Method, path)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(201)
	})
	f := newFixture(t, remote)
	path := f.setup(t)
	f.request(t, "POST", path+"/dispatch", DispatchInput{"1.2.3"}, f.token, 409)
	f.request(t, "POST", path+"/test", map[string]any{}, f.token, 200)
	f.request(t, "POST", path+"/sync", map[string]any{}, f.token, 200)
	f.request(t, "POST", path+"/dispatch", DispatchInput{"1.2.3"}, f.token, 200)
	if !dispatched || secrets["DOCKERHUB_USERNAME"] != "example" || secrets["DOCKERHUB_TOKEN"] != "docker-secret-value" || !strings.HasPrefix(variable, "authgo2.") {
		t.Fatal("发布配置不完整")
	}
	expected, e := f.s.Preview(context.Background(), f.id)
	if e != nil || workflow != expected {
		t.Fatal("提交内容与预览不一致", e)
	}
	// Idempotent sync updates the existing variable, without another workflow commit.
	f.request(t, "POST", path+"/sync", map[string]any{}, f.token, 200)
	if strings.Count(strings.Join(writes, "\n"), "PUT /contents/") != 1 || !strings.Contains(strings.Join(writes, "\n"), "PATCH /actions/variables/AUTHGO_CONFIG") {
		t.Fatal(writes)
	}
	// A user-modified workflow is replaced using its actual SHA.
	mu.Lock()
	workflow += "\n# changed\n"
	mu.Unlock()
	f.request(t, "POST", path+"/sync", map[string]any{}, f.token, 200)
	runs := f.request(t, "GET", path+"/runs", nil, f.token, 200)
	data, _ := json.Marshal(runs)
	if !strings.Contains(string(data), "https://github.com/owner/repo/actions/runs/99") || strings.Contains(string(data), "evil.example") {
		t.Fatal("unsafe run link")
	}
	f.request(t, "PATCH", "/system/publishing", map[string]string{"docker_username": "changed"}, f.token, 200)
	f.request(t, "POST", path+"/dispatch", DispatchInput{"1.2.3"}, f.token, 409)
	f.request(t, "PATCH", "/system/publishing", map[string]string{"docker_username": "example"}, f.token, 200)
	var stored Credentials
	if err = f.s.db.First(&stored, 1).Error; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.GitHubEncrypted, "github-secret-value") || strings.Contains(stored.DockerEncrypted, "docker-secret-value") {
		t.Fatal("plaintext at rest")
	}
	if err = keycheck.Validate(context.Background(), f.s.db, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	if err = f.s.db.Model(&Credentials{}).Where("id=1").Update("github_encrypted", stored.DockerEncrypted).Error; err != nil {
		t.Fatal(err)
	}
	if err = keycheck.Validate(context.Background(), f.s.db, bytes.Repeat([]byte{7}, 32)); err == nil {
		t.Fatal("publishing ciphertext AAD mismatch accepted")
	}
	if err = f.s.db.Model(&Credentials{}).Where("id=1").Update("github_encrypted", stored.GitHubEncrypted).Error; err != nil {
		t.Fatal(err)
	}
	if err = keycheck.Validate(context.Background(), f.s.db, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("incorrect master accepted")
	}
	var audits []model.AuditLog
	if err = f.s.db.Find(&audits).Error; err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(audits)
	for _, secret := range []string{"github-secret-value", "docker-secret-value", variable} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("审计含敏感值")
		}
	}
	if !strings.Contains(string(raw), "github:owner/repo") || !strings.Contains(string(raw), "publishing.workflow.dispatch") {
		t.Fatal("missing repository audit")
	}
	publicSet := f.request(t, "GET", "/system/publishing", nil, f.token, 200)["data"].(map[string]any)
	if publicSet["has_github_token"] != true || publicSet["has_docker_token"] != true {
		t.Fatal("missing set flags")
	}
	f.request(t, "PATCH", "/system/publishing", map[string]string{"github_token": ""}, f.token, 200)
	remaining := f.request(t, "GET", "/system/publishing", nil, f.token, 200)["data"].(map[string]any)
	if remaining["has_github_token"] != false || remaining["has_docker_token"] != true {
		t.Fatal("clear changed other token")
	}
	f.request(t, "PATCH", "/system/publishing", map[string]string{"github_token": "", "docker_token": ""}, f.token, 200)
	public := f.request(t, "GET", "/system/publishing", nil, f.token, 200)["data"].(map[string]any)
	if public["has_github_token"] != false || public["has_docker_token"] != false || public["github_token"] != nil || public["github_encrypted"] != nil {
		t.Fatal(public)
	}
	f.request(t, "POST", path+"/sync", map[string]any{}, f.token, 400)
}

func TestPublishPermissionsValidationAndConcurrentOperations(t *testing.T) {
	requests := 0
	f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(404) }))
	path := f.setup(t)
	for _, action := range []struct {
		method, path string
		body         any
	}{{"GET", "/system/publishing", nil}, {"PATCH", "/system/publishing", map[string]any{}}, {"POST", "/system/publishing/verify", map[string]any{}}, {"GET", path, nil}, {"PATCH", path, map[string]any{}}, {"GET", path + "/workflow", nil}, {"POST", path + "/test", map[string]any{}}, {"POST", path + "/sync", map[string]any{}}, {"POST", path + "/dispatch", DispatchInput{"1.0.0"}}, {"GET", path + "/runs", nil}} {
		f.request(t, action.method, action.path, action.body, "", 401)
	}
	if requests != 0 {
		t.Fatal("unauthenticated GitHub access")
	}
	for _, repo := range []string{"https://github.com/owner/repo", "owner/repo/other", "owner/..", "owner/repo?x=1", "owner/repo\nX", "owner@host/repo"} {
		f.request(t, "PATCH", path, Config{Repository: repo, Branch: "main", Language: "Go", Mode: "cli"}, f.token, 400)
	}
	for _, branch := range []string{"../main", "feature//x", "x.lock", "a/b.lock", "x?ref=y", "feature/.hidden"} {
		f.request(t, "PATCH", path, Config{Repository: "owner/repo", Branch: branch, Language: "Go", Mode: "cli"}, f.token, 400)
	}
	for _, version := range []string{"v1.0.0", "1.0", "1.0.0+meta", "1.0.0\nrun: injected", "1.0.0-01"} {
		f.request(t, "POST", path+"/dispatch", DispatchInput{version}, f.token, 400)
	}
	unlock, err := f.s.lock(f.id)
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "POST", path+"/sync", map[string]any{}, f.token, 409)
	f.request(t, "POST", path+"/dispatch", DispatchInput{"1.0.0"}, f.token, 409)
	f.request(t, "PATCH", path, Config{Repository: "owner/repo", Branch: "main", Language: "Go", Mode: "cli"}, f.token, 409)
	unlock()
	f.request(t, "POST", path+"/test", map[string]any{}, f.token, 400)
	if requests != 1 {
		t.Fatal("missing Dockerfile must stop before writes")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestGitHubBoundedSafeTransport(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{{"auth", 403, `{"message":"github-secret-value"}`}, {"redirect", 302, "github-secret-value"}, {"oversize", 200, strings.Repeat("a", maxResponse+1)}, {"invalidJSON", 200, "github-secret-value"}} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "api.github.com" || r.URL.Scheme != "https" {
					t.Fatal("host configurable in production")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Location": []string{"https://evil.example"}}, Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			})}
			g := newGitHub(client, githubURL)
			var out map[string]any
			_, err := g.request(context.Background(), "github-secret-value", "GET", "/repos/owner/repo", nil, &out, false)
			if err == nil || strings.Contains(err.Error(), "github-secret-value") {
				t.Fatal("unbounded or unsanitized response", err)
			}
			if g.client.Timeout != 12*time.Second {
				t.Fatal("missing timeout")
			}
		})
	}
	hits := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(200) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer redirect.Close()
	g := newGitHub(nil, redirect.URL)
	if _, err := g.request(context.Background(), "secret", "GET", "/", nil, nil, false); err == nil || hits != 0 {
		t.Fatal("redirect followed or accepted")
	}
}

func TestWorkflowLanguageEncryptionAndSharedSources(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		file := "docker-templates.json"
		if encrypted {
			file = "protected-templates.json"
		}
		raw, err := os.ReadFile(filepath.Join("../../../web/src/lib", file))
		if err != nil {
			t.Fatal(err)
		}
		var templates map[string]struct {
			Directory string `json:"directory"`
		}
		if err = json.Unmarshal(raw, &templates); err != nil {
			t.Fatal(err)
		}
		languages := map[string]string{"go": "Go", "python": "Python", "node": "Node.js", "rust": "Rust", "java": "Java", "csharp": "C#", "php": "PHP", "php-fpm": "PHP", "php-apache": "PHP"}
		for name, language := range languages {
			mode := "cli"
			if name == "php-fpm" {
				mode = "fpm"
			}
			if name == "php-apache" {
				mode = "apache"
			}
			cfg := Config{Language: language, Mode: mode, Encrypted: encrypted}
			dir, err := directory(cfg)
			if err != nil || dir != templates[name].Directory {
				t.Fatalf("wrong template %s: %s", name, dir)
			}
			workflow, err := renderWorkflow(cfg, model.Application{DockerImage: "docker.io/example/app", AppKey: "app_test"}, payloadkey.Key{KeyID: "key_test", PublicKey: strings.Repeat("a", 43)})
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range []string{"workflow_dispatch:", "inputs.version", "platforms: linux/amd64,linux/arm64", dir + "/Dockerfile", "example/app:${{ steps.release.outputs.version }}", "example/app:latest"} {
				if !strings.Contains(workflow, part) {
					t.Fatal("missing workflow content", part)
				}
			}
			if name == "php-fpm" && encrypted {
				expected, err := os.ReadFile("testdata/php-fpm-workflow.yml")
				if err != nil || workflow != string(expected) {
					t.Fatal("workflow differs from shared manual/sync contract", err)
				}
			}
			if strings.Contains(workflow, "AUTHGO_TOOLS_IMAGE") || strings.Contains(workflow, "@DIRECTORY@") || strings.Contains(workflow, "PAYLOAD_PUBLIC_KEY=") != encrypted {
				t.Fatal("workflow mismatch")
			}
		}
	}
}

func TestMissingTemplateAndPartialSyncCannotDispatch(t *testing.T) {
	for _, tc := range []struct {
		name, missing, message string
	}{
		{"repository", "/repos/owner/repo", "无法访问仓库：确认仓库名正确，且令牌已授权该仓库"},
		{"branch", "/repos/owner/repo/branches/main", "分支不存在"},
		{"dockerfile", "/repos/owner/repo/contents/examples/docker/Dockerfile", "仓库中缺少 examples/docker/Dockerfile，请先按向导放入模板文件"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("must not write when repository, branch or template is missing")
				}
				if r.URL.Path == tc.missing {
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`{"message":"github-secret-value docker-secret-value"}`))
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"type": "file"})
			}))
			path := f.setup(t)
			for _, operation := range []string{"test", "sync"} {
				result := f.request(t, "POST", path+"/"+operation, map[string]any{}, f.token, 400)
				if result["message"] != tc.message || result["code"] != "INVALID_REQUEST" {
					t.Fatalf("%s missing resource response: %v", operation, result)
				}
			}
			f.request(t, "POST", path+"/dispatch", DispatchInput{"1.0.0"}, f.token, 409)
		})
	}
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/contents/"+WorkflowPath) && r.Method == "GET":
			w.WriteHeader(404)
		case strings.HasSuffix(r.URL.Path, "/actions/secrets/public-key"):
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "key", "key": base64.StdEncoding.EncodeToString(pub[:])})
		case strings.Contains(r.URL.Path, "/actions/secrets/"):
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"message":"docker-secret-value github-secret-value"}`))
		default:
			_ = json.NewEncoder(w).Encode(map[string]string{"type": "file"})
		}
	}))
	path := f.setup(t)
	f.request(t, "POST", path+"/sync", map[string]any{}, f.token, 400)
	f.request(t, "POST", path+"/dispatch", DispatchInput{"1.0.0"}, f.token, 409)
}

func TestInFlightSyncBlocksDispatchAndUnlocksAfterFailure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(404) }))
	f.setup(t)
	done := make(chan error, 1)
	go func() { done <- f.s.Sync(context.Background(), f.id, "https://license.example") }()
	<-entered
	if err := f.s.Dispatch(context.Background(), f.id, "https://license.example", "1.0.0"); err == nil || !strings.Contains(err.Error(), "已有发布操作") {
		t.Fatal("concurrent dispatch not blocked", err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("missing repository accepted")
	}
	unlock, err := f.s.lock(f.id)
	if err != nil {
		t.Fatal("failed operation kept lock", err)
	}
	unlock()
}

func TestEncryptedWorkflowUsesCurrentSoftwareKey(t *testing.T) {
	f := newFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("preview must not call GitHub") }))
	ctx := context.Background()
	cfg := Config{Repository: "owner/repo", Branch: "main", Language: "PHP", Mode: "fpm", Encrypted: true}
	if _, err := f.s.SaveConfig(ctx, f.id, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Preview(ctx, f.id); err == nil {
		t.Fatal("encrypted workflow without packaging key")
	}
	keys := payloadkey.New(f.s.db, f.s.cipher)
	first, err := keys.Rotate(ctx, f.id)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := f.s.Preview(ctx, f.id)
	if err != nil {
		t.Fatal(err)
	}
	var app model.Application
	if err = f.s.db.First(&app, f.id).Error; err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"PAYLOAD_PUBLIC_KEY=" + first.PublicKey, "PAYLOAD_KEY_ID=" + first.KeyID, "PAYLOAD_APP_KEY=" + app.AppKey, "examples/docker-protected/php-fpm/Dockerfile.nginx", "example/test-nginx:${{ steps.release.outputs.version }}"} {
		if !strings.Contains(workflow, part) {
			t.Fatal("missing current encryption input", part)
		}
	}
	next, err := keys.Rotate(ctx, f.id)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err = f.s.Preview(ctx, f.id)
	if err != nil || !strings.Contains(workflow, next.PublicKey) || strings.Contains(workflow, first.PublicKey) {
		t.Fatal("workflow did not follow current key", err)
	}
}
