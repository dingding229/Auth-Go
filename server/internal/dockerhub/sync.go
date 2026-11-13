package dockerhub

import (
	"authgo/internal/apperror"
	"authgo/internal/model"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"time"
)

const fullSyncTimeout = 90 * time.Second

type ConnectionResult struct {
	TotalTags    int64 `json:"total_tags"`
	AcceptedTags int   `json:"accepted_tags"`
	IgnoredTags  int   `json:"ignored_tags"`
}

// TestConnection reads exactly the first page and never persists anything.
func (s *Service) TestConnection(ctx context.Context, id uint64) (ConnectionResult, error) {
	if !s.claim(id) {
		return ConnectionResult{}, apperror.Conflict("该软件正在同步，请稍后再试")
	}
	defer s.unclaim(id)
	a, err := s.application(ctx, id)
	if err != nil {
		return ConnectionResult{}, err
	}
	image, err := Image(a.DockerImage)
	if err != nil {
		return ConnectionResult{}, err
	}
	var st State
	err = s.db.WithContext(ctx).Where("app_id=?", id).First(&st).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return ConnectionResult{}, err
	}
	if s.limited(id, a.DockerImage, st) {
		return ConnectionResult{}, limitedError()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, fail := s.read(ctx, image, true)
	if fail != nil {
		if fail.status == 429 {
			s.mu.Lock()
			s.testLimits[id] = struct {
				image   string
				stateID uint64
				until   time.Time
			}{a.DockerImage, st.ID, fail.retry}
			s.mu.Unlock()
		}
		return ConnectionResult{}, fail.public()
	}
	return ConnectionResult{out.total, out.accepted, out.ignored}, nil
}
func (s *Service) Sync(ctx context.Context, id uint64) error {
	if !s.claim(id) {
		return apperror.Conflict("该软件正在同步，请稍后再试")
	}
	defer s.unclaim(id)
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return apperror.Conflict("同步任务较多，请稍后再试")
	}
	return s.sync(ctx, id)
}
func (s *Service) sync(ctx context.Context, id uint64) error {
	a, err := s.application(ctx, id)
	if err != nil {
		return err
	}
	image, err := Image(a.DockerImage)
	if err != nil {
		return err
	}
	st, err := s.state(ctx, a)
	if err != nil {
		return err
	}
	if s.limited(id, a.DockerImage, st) {
		return limitedError()
	}
	ioCtx, cancel := context.WithTimeout(ctx, fullSyncTimeout)
	snap, fail := s.read(ioCtx, image, false)
	cancel()
	if fail != nil {
		return s.recordFailure(ctx, st, fail)
	}
	poll := s.poll()
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current State
		if err := tx.Where("id=? AND image=?", st.ID, a.DockerImage).First(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return apperror.Conflict("镜像名已更改，本次同步结果已丢弃")
			}
			return err
		}
		tags := map[string]string{}
		if !snap.complete {
			tags = tagsOf(current)
		}
		// Only a complete snapshot may retract Docker-owned rows. Other sources and
		// all assets remain untouched, including matching manual/GitHub releases.
		if snap.complete {
			q := tx.Model(&model.AppVersion{}).Where("app_id=? AND source='docker'", id)
			present := make([]string, 0, len(snap.present))
			for name := range snap.present {
				present = append(present, name)
			}
			if len(present) > 0 {
				q = q.Where("version NOT IN ?", present)
			}
			if err := q.Update("withdrawn", true).Error; err != nil {
				return err
			}
			// A tag with missing timestamps cannot create/update a release, but
			// its continued presence is not evidence of deletion.
			for name := range tagsOf(current) {
				if raw, exists := snap.present[name]; exists {
					tags[name] = raw
				}
			}
		}
		for version, r := range snap.versions {
			tags[version] = r.Tag
			var old model.AppVersion
			err := tx.Where("app_id=? AND version=?", id, version).First(&old).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if old.ID == 0 {
				v := model.AppVersion{AppID: id, Version: version, Source: "docker", PublishedAt: &r.Published}
				if err := tx.Create(&v).Error; err != nil {
					return err
				}
			} else {
				values := map[string]any{}
				if old.PublishedAt == nil {
					values["published_at"] = r.Published
				}
				if old.Source == "docker" {
					values["withdrawn"] = false
				}
				if len(values) > 0 {
					if err := tx.Model(&old).Updates(values).Error; err != nil {
						return err
					}
				}
			}
		}
		raw, _ := json.Marshal(tags)
		result := "同步成功"
		if !snap.complete {
			result = snap.partialResult
			if result == "" {
				result = fmt.Sprintf("已读取%d页，达到分页上限，未撤回旧版本", maxPages)
			}
		}
		return tx.Model(&current).Updates(map[string]any{"last_sync_at": s.now().UTC(), "last_result": result, "last_error": "", "next_sync_at": s.now().UTC().Add(poll), "retry_at": nil, "collected": len(snap.versions), "ignored": snap.ignored, "failures": 0, "tags_json": string(raw)}).Error
	})
	if err != nil {
		var safe *apperror.Error
		if errors.As(err, &safe) && safe.Status == 409 {
			return err
		}
		return s.recordFailure(ctx, st, &hubFailure{message: "Docker Hub版本保存失败，请稍后重试"})
	}
	return nil
}

// StartSync reserves capacity before acknowledging. It never waits for Hub I/O.
// Completion is observable through Status even after the initiating request ends.
func (s *Service) StartSync(ctx context.Context, id uint64) (State, error) {
	if !s.claim(id) {
		return State{}, apperror.Conflict("该软件正在同步，请稍后再试")
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.unclaim(id)
		return State{}, apperror.Conflict("同步任务较多，请稍后再试")
	}
	st, err := s.Status(ctx, id)
	if err == nil {
		_, err = Image(st.Image)
	}
	if err == nil && s.limited(id, st.Image, st) {
		err = limitedError()
	}
	if err != nil {
		<-s.slots
		s.unclaim(id)
		return State{}, err
	}
	go func() {
		defer s.unclaim(id)
		defer func() { <-s.slots }()
		background, cancel := context.WithTimeout(context.WithoutCancel(ctx), fullSyncTimeout+5*time.Second)
		defer cancel()
		_ = s.sync(background, id)
	}()
	return st, nil
}
