package publishing

import (
	"authgo/internal/apperror"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const dockerHubURL = "https://hub.docker.com"

var githubLogin = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)

type VerificationResult struct {
	Valid    bool   `json:"valid"`
	Login    string `json:"login,omitempty"`
	Username string `json:"username,omitempty"`
	Error    string `json:"error,omitempty"`
}
type CredentialsVerification struct {
	GitHub    VerificationResult `json:"github"`
	DockerHub VerificationResult `json:"docker_hub"`
}

// Production URLs are fixed; package tests can replace the two upstream bases.
// Reuse the publishing client, which does not follow redirects or log responses.
func (s *Service) verifyToken(ctx context.Context, github bool, username, token string) (string, error) {
	name, method, address := "Docker Hub", http.MethodPost, s.dockerBase+"/v2/users/login"
	var body []byte
	if github {
		name, method, address = "GitHub", http.MethodGet, s.github.base+"/user"
	} else {
		if username == "" {
			return "", apperror.Invalid("请填写 Docker Hub 用户名")
		}
		body, _ = json.Marshal(map[string]string{"username": username, "password": token})
	}
	unavailable := func() error { return apperror.Invalid("无法连接 " + name + " 验证令牌，请稍后重试") }
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return "", unavailable()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AuthGo")
	if github {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	client := *s.github.client
	client.Timeout = 10 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return "", unavailable()
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		if github {
			return "", apperror.Invalid("GitHub 令牌无效或已过期")
		}
		return "", apperror.Invalid("Docker Hub 用户名或访问令牌无效")
	}
	if resp.StatusCode != http.StatusOK {
		return "", unavailable()
	}
	if github {
		// Header presence (including an empty value) identifies a classic token.
		if scopes, present := resp.Header["X-Oauth-Scopes"]; present {
			granted := map[string]bool{}
			for _, scope := range strings.Split(strings.Join(scopes, ","), ",") {
				granted[strings.TrimSpace(scope)] = true
			}
			if !granted["repo"] || !granted["workflow"] {
				return "", apperror.Invalid("GitHub 令牌缺少 repo / workflow 权限")
			}
		}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return "", unavailable()
	}
	if !github {
		var result struct {
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}
		if json.Unmarshal(raw, &result) != nil || (result.Token == "" && result.RefreshToken == "") {
			return "", unavailable()
		}
		return username, nil
	}
	var result struct {
		Login string `json:"login"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Login) > 39 || !githubLogin.MatchString(result.Login) {
		return "", unavailable()
	}
	return result.Login, nil
}

func (s *Service) verifyEncrypted(ctx context.Context, github bool, v Credentials) (string, error) {
	encrypted, aad := v.DockerEncrypted, dockerAAD
	if github {
		encrypted, aad = v.GitHubEncrypted, githubAAD
	}
	if encrypted == "" {
		return "", apperror.Invalid("尚未设置访问令牌")
	}
	plain, err := s.cipher.Decrypt(encrypted, []byte(aad))
	if err != nil {
		return "", apperror.Invalid("发布凭据无法解密，请重新保存")
	}
	defer clear(plain)
	return s.verifyToken(ctx, github, v.DockerUsername, string(plain))
}
func (s *Service) VerifyCredentials(ctx context.Context) (CredentialsVerification, error) {
	s.credentialsMu.Lock()
	defer s.credentialsMu.Unlock()
	v, err := s.credentials(ctx)
	if err != nil {
		return CredentialsVerification{}, err
	}
	out := CredentialsVerification{}
	for _, target := range []struct {
		github bool
		result *VerificationResult
	}{{true, &out.GitHub}, {false, &out.DockerHub}} {
		login, err := s.verifyEncrypted(ctx, target.github, v)
		if err != nil {
			if safe, ok := err.(*apperror.Error); ok {
				target.result.Error = safe.Message
			} else {
				target.result.Error = "发布凭据验证失败"
			}
			continue
		}
		target.result.Valid = true
		if target.github {
			target.result.Login = login
		} else {
			target.result.Username = login
		}
	}
	return out, nil
}
