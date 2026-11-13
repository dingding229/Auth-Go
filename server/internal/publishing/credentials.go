package publishing

import (
	"authgo/internal/apperror"
	"context"
	"errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"regexp"
	"strings"
)

type Credentials struct {
	ID              uint64 `json:"-" gorm:"primaryKey"`
	GitHubEncrypted string `json:"-" gorm:"column:github_encrypted"`
	DockerEncrypted string `json:"-"`
	DockerUsername  string `json:"docker_username"`
	HasGitHubToken  bool   `json:"has_github_token" gorm:"-"`
	HasDockerToken  bool   `json:"has_docker_token" gorm:"-"`
}

func (Credentials) TableName() string { return "publishing_credentials" }

type CredentialsInput struct {
	GitHubToken    *string `json:"github_token"`
	DockerToken    *string `json:"docker_token"`
	DockerUsername *string `json:"docker_username"`
}

const githubAAD = "authgo/system/publishing/github-token/v1"
const dockerAAD = "authgo/system/publishing/docker-token/v1"

func (s *Service) credentials(ctx context.Context) (Credentials, error) {
	v := Credentials{ID: 1}
	err := s.db.WithContext(ctx).First(&v, 1).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = nil
	}
	return v, err
}
func (s *Service) Credentials(ctx context.Context) (Credentials, error) {
	v, err := s.credentials(ctx)
	v.HasGitHubToken = v.GitHubEncrypted != ""
	v.HasDockerToken = v.DockerEncrypted != ""
	v.GitHubEncrypted = ""
	v.DockerEncrypted = ""
	return v, err
}
func (s *Service) SaveCredentials(ctx context.Context, in CredentialsInput) (Credentials, error) {
	s.credentialsMu.Lock()
	defer s.credentialsMu.Unlock()
	v, err := s.credentials(ctx)
	if err != nil {
		return Credentials{}, err
	}
	previousUsername := v.DockerUsername
	if in.DockerUsername != nil {
		v.DockerUsername = strings.TrimSpace(*in.DockerUsername)
		if v.DockerUsername != "" && !regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`).MatchString(v.DockerUsername) {
			return Credentials{}, apperror.Invalid("Docker Hub 用户名格式无效")
		}
	}
	for _, f := range []struct {
		input  *string
		target *string
		aad    string
	}{{in.GitHubToken, &v.GitHubEncrypted, githubAAD}, {in.DockerToken, &v.DockerEncrypted, dockerAAD}} {
		if f.input == nil {
			continue
		}
		token := *f.input
		if len(token) > 4096 || strings.IndexFunc(token, func(r rune) bool { return r <= 0x20 || r >= 0x7f }) >= 0 {
			return Credentials{}, apperror.Invalid("令牌格式无效")
		}
		*f.target = ""
		if token != "" {
			*f.target, err = s.cipher.Encrypt([]byte(token), []byte(f.aad))
			if err != nil {
				return Credentials{}, remoteError()
			}
		}
	}
	if in.GitHubToken != nil && *in.GitHubToken != "" {
		if _, err = s.verifyEncrypted(ctx, true, v); err != nil {
			return Credentials{}, err
		}
	}
	if (in.DockerToken != nil && *in.DockerToken != "") || (v.DockerUsername != previousUsername && v.DockerEncrypted != "") {
		if _, err = s.verifyEncrypted(ctx, false, v); err != nil {
			return Credentials{}, err
		}
	}
	if err = s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&v).Error; err != nil {
		return Credentials{}, err
	}
	return s.Credentials(ctx)
}

type secrets struct{ github, docker, username string }

func (s *Service) secrets(ctx context.Context, docker bool) (secrets, error) {
	v, err := s.credentials(ctx)
	if err != nil {
		return secrets{}, err
	}
	out := secrets{username: v.DockerUsername}
	if v.GitHubEncrypted == "" || (docker && (v.DockerEncrypted == "" || out.username == "")) {
		return out, apperror.Invalid("请先在系统设置中保存 GitHub 与 Docker Hub 发布凭据")
	}
	plain, err := s.cipher.Decrypt(v.GitHubEncrypted, []byte(githubAAD))
	if err != nil {
		return out, apperror.Invalid("发布凭据无法解密，请重新保存")
	}
	out.github = string(plain)
	clear(plain)
	if docker {
		plain, err = s.cipher.Decrypt(v.DockerEncrypted, []byte(dockerAAD))
		if err != nil {
			return out, apperror.Invalid("发布凭据无法解密，请重新保存")
		}
		out.docker = string(plain)
		clear(plain)
	}
	return out, nil
}
