package publishing

import (
	"authgo/internal/model"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCredentialVerificationBeforeSave(t *testing.T) {
	for _, tc := range []struct {
		name, scopes               string
		githubStatus, dockerStatus int
		want                       string
	}{
		{"fine-grained", "", 200, 200, ""},
		{"classic", "repo, workflow", 200, 200, ""},
		{"github401", "", 401, 200, "GitHub 令牌无效或已过期"},
		{"docker401", "", 200, 401, "Docker Hub 用户名或访问令牌无效"},
		{"missingScope", "repo", 200, 200, "GitHub 令牌缺少 repo / workflow 权限"},
		{"emptyScopes", "empty", 200, 200, "GitHub 令牌缺少 repo / workflow 权限"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, http.NotFoundHandler())
			var checks atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				checks.Add(1)
				if r.URL.Path == "/user" {
					if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer github-secret-value" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
						t.Error("GitHub verification request invalid")
					}
					if tc.scopes != "" {
						value := tc.scopes
						if value == "empty" {
							value = ""
						}
						w.Header().Set("X-OAuth-Scopes", value)
					}
					w.WriteHeader(tc.githubStatus)
					_ = json.NewEncoder(w).Encode(map[string]string{"login": "owner", "message": "github-secret-value"})
				} else if r.URL.Path == "/v2/users/login" {
					var body map[string]string
					if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || (body["username"] != "example" && body["username"] != "changed") || body["password"] != "docker-secret-value" {
						t.Error("Docker Hub verification request invalid")
					}
					if body["username"] == "changed" {
						w.WriteHeader(401)
						return
					}
					w.WriteHeader(tc.dockerStatus)
					_ = json.NewEncoder(w).Encode(map[string]string{"token": "docker-secret-value"})
				} else {
					t.Error("unexpected path", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer upstream.Close()
			f.s.github = newGitHub(upstream.Client(), upstream.URL)
			f.s.dockerBase = upstream.URL
			input := CredentialsInput{GitHubToken: ptr("github-secret-value"), DockerToken: ptr("docker-secret-value"), DockerUsername: ptr("example")}
			_, err := f.s.SaveCredentials(context.Background(), input)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret-value") {
					t.Fatal("wrong safe validation error", err)
				}
				saved, _ := f.s.credentials(context.Background())
				if saved.GitHubEncrypted != "" || saved.DockerEncrypted != "" || saved.DockerUsername != "" {
					t.Fatal("failed verification persisted partial credentials")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if checks.Load() != 2 {
				t.Fatal("new tokens not both checked", checks.Load())
			}
			verified := f.request(t, "POST", "/system/publishing/verify", map[string]any{}, f.token, 200)["data"].(map[string]any)
			if verified["github"].(map[string]any)["login"] != "owner" || verified["docker_hub"].(map[string]any)["username"] != "example" {
				t.Fatal(verified)
			}
			var audits []model.AuditLog
			if err := f.s.db.Where("action = ?", "publishing.credentials.verify").Find(&audits).Error; err != nil || len(audits) != 1 || audits[0].StatusCode != 200 {
				t.Fatal("verification not audited", err, len(audits))
			}
			auditText, _ := json.Marshal(audits)
			if strings.Contains(string(auditText), "secret-value") || strings.Contains(f.logs.String(), "secret-value") {
				t.Fatal("credential appeared in audit or logs")
			}
			_, err = f.s.SaveCredentials(context.Background(), CredentialsInput{DockerUsername: ptr("changed")})
			if err == nil {
				t.Fatal("changed username with retained token not revalidated")
			}
			saved, _ := f.s.credentials(context.Background())
			if saved.DockerUsername != "example" {
				t.Fatal("invalid username change persisted")
			}
		})
	}
}

func TestCredentialVerificationTimeoutAndRedirect(t *testing.T) {
	f := newFixture(t, http.NotFoundHandler())
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer upstream.Close()
	f.s.github = newGitHub(upstream.Client(), upstream.URL)
	f.s.dockerBase = upstream.URL
	for _, github := range []bool{true, false} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := f.s.verifyToken(ctx, github, "example", "secret-value")
		cancel()
		if err == nil || !strings.Contains(err.Error(), "验证令牌，请稍后重试") || strings.Contains(err.Error(), "secret-value") {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("timeout did not reach local mock")
	}
	// A redirect must never send credentials to another host (or even follow a same-host redirect).
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed with credentials") }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer redirect.Close()
	f.s.github = newGitHub(redirect.Client(), redirect.URL)
	f.s.dockerBase = redirect.URL
	for _, github := range []bool{true, false} {
		if _, err := f.s.verifyToken(context.Background(), github, "example", "secret-value"); err == nil {
			t.Fatal("redirect accepted")
		}
	}
}

func TestVerificationUsesFixedHTTPSHostsAndTenSecondDeadline(t *testing.T) {
	s := &Service{dockerBase: dockerHubURL}
	s.github = newGitHub(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || (r.URL.Host != "api.github.com" && r.URL.Host != "hub.docker.com") {
			t.Fatal("unexpected verification host", r.URL)
		}
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 10*time.Second || time.Until(deadline) <= 0 {
			t.Fatal("verification deadline missing")
		}
		body := `{"login":"owner"}`
		if r.URL.Host == "hub.docker.com" {
			body = `{"token":"mock-session"}`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}, githubURL)
	for _, github := range []bool{true, false} {
		if _, err := s.verifyToken(context.Background(), github, "example", "secret-value"); err != nil {
			t.Fatal(err)
		}
	}
}
