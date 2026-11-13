package publishing

import (
	"authgo/internal/apperror"
	"authgo/internal/catalog"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/model"
	"authgo/internal/payloadkey"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/Masterminds/semver/v3"
	"golang.org/x/crypto/nacl/box"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	AppID        uint64 `json:"-" gorm:"primaryKey"`
	Repository   string `json:"repository"`
	Branch       string `json:"branch"`
	Language     string `json:"language"`
	Mode         string `json:"mode"`
	Encrypted    bool   `json:"encrypted"`
	SyncedDigest string `json:"-"`
}

func (Config) TableName() string { return "application_publishing" }

type Service struct {
	db            *gorm.DB
	cipher        *cryptoutil.Cipher
	catalog       *catalog.Service
	github        *githubClient
	dockerBase    string
	credentialsMu sync.Mutex
	mu            sync.Mutex
	busy          map[uint64]bool
}

func New(db *gorm.DB, master []byte, cat *catalog.Service) (*Service, error) {
	return newService(db, master, cat, nil, githubURL)
}
func newService(db *gorm.DB, master []byte, cat *catalog.Service, client *http.Client, base string) (*Service, error) {
	cipher, err := cryptoutil.NewCipher(master)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, cipher: cipher, catalog: cat, github: newGitHub(client, base), dockerBase: dockerHubURL, busy: map[uint64]bool{}}, nil
}
func (s *Service) lock(id uint64) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy[id] {
		return nil, apperror.Conflict("此软件已有发布操作进行中，请稍后再试")
	}
	s.busy[id] = true
	return func() { s.mu.Lock(); delete(s.busy, id); s.mu.Unlock() }, nil
}
func validConfig(v Config) error {
	if len(v.Repository) > 140 || !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$`).MatchString(v.Repository) {
		return apperror.Invalid("GitHub 仓库须为 owner/repo，不含网址或凭据")
	}
	parts := strings.Split(v.Repository, "/")
	if strings.Contains(parts[0], "--") {
		return apperror.Invalid("GitHub 仓库所有者格式无效")
	}
	repo := parts[1]
	if repo == "." || repo == ".." {
		return apperror.Invalid("GitHub 仓库格式无效")
	}
	if len(v.Branch) == 0 || len(v.Branch) > 200 || !regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*$`).MatchString(v.Branch) || strings.Contains(v.Branch, "..") || strings.Contains(v.Branch, "//") || strings.HasSuffix(v.Branch, "/") || strings.HasSuffix(v.Branch, ".") {
		return apperror.Invalid("分支名格式无效")
	}
	for _, part := range strings.Split(v.Branch, "/") {
		if strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return apperror.Invalid("分支名格式无效")
		}
	}
	_, err := directory(v)
	return err
}
func (s *Service) Config(ctx context.Context, id uint64) (Config, error) {
	var app model.Application
	if err := s.db.WithContext(ctx).First(&app, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Config{}, apperror.NotFound()
		}
		return Config{}, err
	}
	v := Config{AppID: id, Branch: "main", Language: "Go", Mode: "cli"}
	err := s.db.WithContext(ctx).First(&v, "app_id=?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = nil
	}
	return v, err
}
func (s *Service) SaveConfig(ctx context.Context, id uint64, v Config) (Config, error) {
	unlock, err := s.lock(id)
	if err != nil {
		return Config{}, err
	}
	defer unlock()
	if _, err = s.Config(ctx, id); err != nil {
		return Config{}, err
	}
	v.AppID = id
	v.SyncedDigest = ""
	v.Repository = strings.TrimSpace(v.Repository)
	v.Branch = strings.TrimSpace(v.Branch)
	if v.Branch == "" {
		v.Branch = "main"
	}
	if err = validConfig(v); err != nil {
		return Config{}, err
	}
	err = s.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&v).Error
	return v, err
}
func (s *Service) workflow(ctx context.Context, v Config) (string, error) {
	var app model.Application
	if err := s.db.WithContext(ctx).First(&app, v.AppID).Error; err != nil {
		return "", apperror.NotFound()
	}
	var key payloadkey.Key
	if v.Encrypted {
		if err := s.db.WithContext(ctx).Where("app_id=? AND is_current=?", v.AppID, true).First(&key).Error; err != nil {
			return "", apperror.Invalid("请先生成当前打包公钥")
		}
	}
	return renderWorkflow(v, app, key)
}
func (s *Service) Preview(ctx context.Context, id uint64) (string, error) {
	v, err := s.Config(ctx, id)
	if err != nil {
		return "", err
	}
	return s.workflow(ctx, v)
}
func (s *Service) check(ctx context.Context, v Config, token string) error {
	base := "/repos/" + v.Repository
	if _, err := s.github.request(ctx, token, "GET", base, nil, nil, false); err != nil {
		return err
	}
	if _, err := s.github.request(ctx, token, "GET", base+"/branches/"+url.PathEscape(v.Branch), nil, nil, false); err != nil {
		return err
	}
	dir, err := directory(v)
	if err != nil {
		return err
	}
	paths := []string{dir + "/Dockerfile"}
	if v.Language == "PHP" && v.Mode == "fpm" {
		paths = append(paths, dir+"/Dockerfile.nginx")
	}
	for _, path := range paths {
		var info struct {
			Type string `json:"type"`
		}
		if _, err = s.github.request(ctx, token, "GET", base+"/contents/"+path+"?ref="+url.QueryEscape(v.Branch), nil, &info, false); err != nil {
			return err
		}
		if info.Type != "file" {
			return apperror.Invalid("目标分支缺少模板 Dockerfile，请先按向导上传模板文件")
		}
	}
	return nil
}
func (s *Service) Test(ctx context.Context, id uint64) error {
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	v, err := s.Config(ctx, id)
	if err != nil {
		return err
	}
	if err = validConfig(v); err != nil {
		return err
	}
	keys, err := s.secrets(ctx, false)
	if err != nil {
		return err
	}
	return s.check(ctx, v, keys.github)
}
func digest(v Config, workflow, config string, keys secrets) string {
	raw := strings.Join([]string{v.Repository, v.Branch, workflow, config, keys.github, keys.docker, keys.username}, "\x00")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
func (s *Service) desired(ctx context.Context, v Config, publicURL string) (string, string, secrets, error) {
	keys, err := s.secrets(ctx, true)
	if err != nil {
		return "", "", keys, err
	}
	workflow, err := s.workflow(ctx, v)
	if err != nil {
		return "", "", keys, err
	}
	if !strings.HasPrefix(publicURL, "https://") {
		return "", "", keys, apperror.Invalid("请先在系统设置中保存 HTTPS 对外服务地址")
	}
	config, err := s.catalog.ConnectionConfig(ctx, v.AppID, publicURL)
	return workflow, config, keys, err
}
func (s *Service) Sync(ctx context.Context, id uint64, publicURL string) error {
	unlock, err := s.lock(id)
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	v, err := s.Config(ctx, id)
	if err != nil {
		return err
	}
	if err = validConfig(v); err != nil {
		return err
	}
	workflow, config, keys, err := s.desired(ctx, v, publicURL)
	if err != nil {
		return err
	}
	if err = s.check(ctx, v, keys.github); err != nil {
		return err
	}
	base := "/repos/" + v.Repository
	var content struct {
		SHA      string `json:"sha"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	found, err := s.github.request(ctx, keys.github, "GET", base+"/contents/"+WorkflowPath+"?ref="+url.QueryEscape(v.Branch), nil, &content, true)
	if err != nil {
		return err
	}
	previous, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(content.Content, "\n", ""))
	if !found || string(previous) != workflow {
		body := map[string]any{"message": "配置 AuthGo 镜像发布", "content": base64.StdEncoding.EncodeToString([]byte(workflow)), "branch": v.Branch}
		if found {
			body["sha"] = content.SHA
		}
		if _, err = s.github.request(ctx, keys.github, "PUT", base+"/contents/"+WorkflowPath, body, nil, false); err != nil {
			return err
		}
	}
	var pk struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if _, err = s.github.request(ctx, keys.github, "GET", base+"/actions/secrets/public-key", nil, &pk, false); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(pk.Key)
	if err != nil || len(decoded) != 32 || pk.KeyID == "" {
		return remoteError()
	}
	var pub [32]byte
	copy(pub[:], decoded)
	for _, secret := range []struct{ name, value string }{{"DOCKERHUB_USERNAME", keys.username}, {"DOCKERHUB_TOKEN", keys.docker}} {
		sealed, e := box.SealAnonymous(nil, []byte(secret.value), &pub, rand.Reader)
		if e != nil {
			return remoteError()
		}
		body := map[string]string{"key_id": pk.KeyID, "encrypted_value": base64.StdEncoding.EncodeToString(sealed)}
		if _, err = s.github.request(ctx, keys.github, "PUT", base+"/actions/secrets/"+secret.name, body, nil, false); err != nil {
			return err
		}
	}
	found, err = s.github.request(ctx, keys.github, "GET", base+"/actions/variables/AUTHGO_CONFIG", nil, nil, true)
	if err != nil {
		return err
	}
	method, path := "POST", base+"/actions/variables"
	if found {
		method, path = "PATCH", path+"/AUTHGO_CONFIG"
	}
	if _, err = s.github.request(ctx, keys.github, method, path, map[string]string{"name": "AUTHGO_CONFIG", "value": config}, nil, false); err != nil {
		return err
	}
	return s.db.WithContext(ctx).Model(&Config{}).Where("app_id=?", id).Update("synced_digest", digest(v, workflow, config, keys)).Error
}
func (s *Service) Dispatch(ctx context.Context, id uint64, publicURL, version string) error {
	// SemVer build metadata cannot be represented in Docker tags.
	if len(version) > 128 || strings.ContainsAny(version, "+ \r\n") {
		return apperror.Invalid("版本须为 Docker 标签可用的语义版本，例如 1.0.0 或 1.1.0-rc.1")
	}
	if _, err := semver.StrictNewVersion(version); err != nil {
		return apperror.Invalid("版本号无效")
	}
	unlock, err := s.lock(id)
	if err != nil {
		return err
	}
	defer unlock()
	v, err := s.Config(ctx, id)
	if err != nil {
		return err
	}
	if err = validConfig(v); err != nil {
		return err
	}
	workflow, config, keys, err := s.desired(ctx, v, publicURL)
	if err != nil {
		return err
	}
	if v.SyncedDigest == "" || v.SyncedDigest != digest(v, workflow, config, keys) {
		return apperror.Conflict("发布配置已变更或尚未同步，请先同步配置到仓库")
	}
	_, err = s.github.request(ctx, keys.github, "POST", "/repos/"+v.Repository+"/actions/workflows/authgo-publish.yml/dispatches", map[string]any{"ref": v.Branch, "inputs": map[string]string{"version": version}}, nil, false)
	return err
}

type Run struct {
	ID         uint64    `json:"id"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	CreatedAt  time.Time `json:"created_at"`
	URL        string    `json:"url"`
}

func (s *Service) Runs(ctx context.Context, id uint64) ([]Run, error) {
	out := []Run{}
	v, err := s.Config(ctx, id)
	if err != nil {
		return nil, err
	}
	if v.Repository == "" {
		return out, nil
	}
	if err = validConfig(v); err != nil {
		return nil, err
	}
	keys, err := s.secrets(ctx, false)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Runs []struct {
			ID         uint64    `json:"id"`
			Status     string    `json:"status"`
			Conclusion string    `json:"conclusion"`
			CreatedAt  time.Time `json:"created_at"`
		} `json:"workflow_runs"`
	}
	_, err = s.github.request(ctx, keys.github, "GET", "/repos/"+v.Repository+"/actions/workflows/authgo-publish.yml/runs?per_page=5&branch="+url.QueryEscape(v.Branch), nil, &payload, true)
	if err != nil {
		return nil, err
	}
	for i, r := range payload.Runs {
		if i == 5 {
			break
		}
		switch r.Status {
		case "queued", "in_progress", "completed", "waiting", "pending", "requested":
		default:
			return nil, remoteError()
		}
		switch r.Conclusion {
		case "", "success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral", "stale", "startup_failure":
		default:
			return nil, remoteError()
		}
		out = append(out, Run{r.ID, r.Status, r.Conclusion, r.CreatedAt, "https://github.com/" + v.Repository + "/actions/runs/" + strconv.FormatUint(r.ID, 10)})
	}
	return out, nil
}
