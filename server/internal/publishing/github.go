package publishing

import (
	"authgo/internal/apperror"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const githubURL = "https://api.github.com"
const maxResponse = 2 << 20

type githubClient struct {
	client *http.Client
	base   string
}

func newGitHub(client *http.Client, base string) *githubClient {
	if client == nil {
		client = &http.Client{}
	}
	copy := *client
	copy.Timeout = 12 * time.Second
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &githubClient{&copy, strings.TrimRight(base, "/")}
}

// Only package tests supply a different base. Production always uses githubURL.
func (g *githubClient) request(ctx context.Context, token, method, path string, body, out any, missingOK bool) (bool, error) {
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return false, remoteError()
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, g.base+path, bytes.NewReader(raw))
	if err != nil {
		return false, remoteError()
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "AuthGo")
	res, err := g.client.Do(req)
	if err != nil {
		return false, remoteError()
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return false, remoteError()
	}
	if res.StatusCode == 404 && missingOK {
		return false, nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		switch res.StatusCode {
		case 401, 403:
			return false, apperror.Invalid("GitHub 拒绝访问，请检查令牌权限、有效期、仓库保护规则或请求额度")
		case 404:
			return false, missingResource(path)
		case 409, 422:
			return false, apperror.Conflict("GitHub 配置冲突，请检查分支保护、版本及工作流是否已在默认分支，然后重新同步")
		default:
			return false, remoteError()
		}
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return false, remoteError()
	}
	return true, nil
}

// Resource hints come only from the requested API path, never the remote body.
func missingResource(path string) error {
	resource, _, _ := strings.Cut(path, "?")
	parts := strings.Split(strings.TrimPrefix(resource, "/"), "/")
	if len(parts) >= 3 && parts[0] == "repos" {
		if len(parts) == 3 {
			return apperror.Invalid("无法访问仓库：确认仓库名正确，且令牌已授权该仓库")
		}
		if len(parts) >= 5 && parts[3] == "branches" {
			return apperror.Invalid("分支不存在")
		}
		if len(parts) >= 5 && parts[3] == "contents" {
			file := parts[len(parts)-1]
			if file == "Dockerfile" || file == "Dockerfile.nginx" {
				return apperror.Invalid("仓库中缺少 " + strings.Join(parts[4:], "/") + "，请先按向导放入模板文件")
			}
		}
	}
	return apperror.Invalid("GitHub 请求的资源不存在，或令牌无权访问")
}

func remoteError() error {
	return apperror.New(502, "INTERNAL_ERROR", "GitHub 请求未完成，请查看仓库状态后重试；操作可能已被接收")
}
