// Package dockerhub owns public Docker Hub version synchronization and its APIs.
package dockerhub

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"authgo/internal/updater"
	"context"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type State struct {
	Running    bool       `json:"running" gorm:"-"`
	ID         uint64     `json:"-"`
	AppID      uint64     `json:"app_id"`
	Image      string     `json:"image"`
	Configured bool       `json:"configured" gorm:"-"`
	LastSyncAt *time.Time `json:"last_sync_at"`
	LastResult string     `json:"last_result"`
	LastError  string     `json:"last_error"`
	NextSyncAt time.Time  `json:"next_sync_at"`
	RetryAt    *time.Time `json:"retry_at"`
	Collected  int        `json:"collected"`
	Ignored    int        `json:"ignored"`
	Failures   int        `json:"-"`
	TagsJSON   string     `json:"-"`
}

func (State) TableName() string { return "docker_hub_sync_states" }

type Service struct {
	db         *gorm.DB
	updates    *updater.Service
	now        func() time.Time
	api        string
	http       *http.Client
	mu         sync.Mutex
	active     map[uint64]bool
	testLimits map[uint64]struct {
		image   string
		stateID uint64
		until   time.Time
	}
	tickMu sync.Mutex
	slots  chan struct{}
}

func New(database *gorm.DB, updates *updater.Service, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: database, updates: updates, now: now, api: "https://hub.docker.com", http: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, active: map[uint64]bool{}, testLimits: map[uint64]struct {
		image   string
		stateID uint64
		until   time.Time
	}{}, slots: make(chan struct{}, 2)}
}

var imagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*/[a-z0-9]+([._-]+[a-z0-9]+)*$`)

func Image(raw string) (string, error) {
	image := strings.TrimPrefix(raw, "docker.io/")
	if len(image) > 255 || !imagePattern.MatchString(image) {
		return "", apperror.Invalid("请先填写有效的Docker Hub镜像名（命名空间/镜像名）")
	}
	return image, nil
}
func (s *Service) application(ctx context.Context, id uint64) (model.Application, error) {
	var a model.Application
	err := s.db.WithContext(ctx).First(&a, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = apperror.NotFound()
	}
	return a, err
}
func (s *Service) state(ctx context.Context, a model.Application) (State, error) {
	out := State{AppID: a.ID, Image: a.DockerImage, NextSyncAt: s.now().UTC(), LastResult: "等待同步", TagsJSON: "{}"}
	if a.DockerImage == "" {
		out.LastResult = "未配置镜像"
		return out, nil
	}
	if _, err := Image(a.DockerImage); err != nil {
		return out, err
	}
	// A row is created only for the currently configured image; the DB trigger
	// removes it on any image change. No network I/O occurs while in a transaction.
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current model.Application
		if err := tx.First(&current, a.ID).Error; err != nil {
			return err
		}
		if current.DockerImage != a.DockerImage {
			return apperror.Conflict("镜像名已更改，请重试")
		}
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "app_id"}}, DoNothing: true}).Create(&out).Error; err != nil {
			return err
		}
		return tx.Where("app_id=?", a.ID).First(&out).Error
	})
	out.Configured = true
	if out.NextSyncAt.Before(time.Unix(1, 0)) {
		out.NextSyncAt = s.now().UTC()
	}
	return out, err
}
func (s *Service) Status(ctx context.Context, id uint64) (State, error) {
	a, err := s.application(ctx, id)
	if err != nil {
		return State{}, err
	}
	st, err := s.state(ctx, a)
	s.mu.Lock()
	limit := s.testLimits[id]
	st.Running = s.active[id]
	s.mu.Unlock()
	if limit.image == a.DockerImage && limit.stateID == st.ID && limit.until.After(s.now()) {
		at := limit.until
		if st.RetryAt == nil || st.RetryAt.Before(at) {
			st.RetryAt = &at
		}
		if st.NextSyncAt.Before(at) {
			st.NextSyncAt = at
		}
	}
	return st, err
}
func (s *Service) claim(id uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[id] {
		return false
	}
	s.active[id] = true
	return true
}
func (s *Service) unclaim(id uint64) { s.mu.Lock(); delete(s.active, id); s.mu.Unlock() }
func (s *Service) limited(id uint64, image string, st State) bool {
	now := s.now()
	if st.RetryAt != nil && now.Before(*st.RetryAt) {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.testLimits[id]
	return v.image == image && v.stateID == st.ID && now.Before(v.until)
}
func limitedError() error {
	return apperror.New(429, "RATE_LIMITED", "Docker Hub请求过于频繁，请等待重试时间后再同步")
}
func (s *Service) Tick(ctx context.Context) error {
	if !s.tickMu.TryLock() {
		return nil
	}
	defer s.tickMu.Unlock()
	var apps []model.Application
	if err := s.db.WithContext(ctx).Model(&model.Application{}).Select("applications.*").Joins("LEFT JOIN docker_hub_sync_states ds ON ds.app_id=applications.id").Where("applications.docker_image<>'' AND (ds.app_id IS NULL OR ds.next_sync_at<=?)", s.now().UTC()).Order("applications.id").Limit(8).Find(&apps).Error; err != nil {
		return err
	}
	var wg sync.WaitGroup
	for _, a := range apps {
		wg.Add(1)
		go func(id uint64) { defer wg.Done(); _ = s.Sync(ctx, id) }(a.ID)
	}
	wg.Wait()
	return nil
}
func (s *Service) poll() time.Duration {
	if s.updates != nil {
		if v, err := s.updates.CurrentSettings(); err == nil {
			return time.Duration(v.PollMinutes) * time.Minute
		}
	}
	return 10 * time.Minute
}
func (s *Service) recordFailure(ctx context.Context, st State, f *hubFailure) error {
	next := s.now().UTC().Add(time.Minute * time.Duration(1<<min(st.Failures, 6)))
	values := map[string]any{"last_error": f.message, "next_sync_at": next, "failures": st.Failures + 1}
	if f.status == 429 {
		values["retry_at"] = f.retry
		if f.retry.After(next) {
			values["next_sync_at"] = f.retry
		}
	}
	result := s.db.WithContext(ctx).Model(&State{}).Where("id=?", st.ID).Updates(values)
	if result.Error != nil {
		return apperror.New(500, "INTERNAL_ERROR", "无法记录Docker Hub同步状态")
	}
	if result.RowsAffected == 0 {
		return apperror.Conflict("镜像名已更改，本次同步结果已丢弃")
	}
	return f.public()
}
func tagsOf(st State) map[string]string {
	v := map[string]string{}
	_ = json.Unmarshal([]byte(st.TagsJSON), &v)
	if v == nil {
		v = map[string]string{}
	}
	return v
}
