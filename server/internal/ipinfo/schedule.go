package ipinfo

import (
	"authgo/internal/apperror"
	"context"
	"github.com/robfig/cron/v3"
	"strings"
	"time"
)

type SyncPlan struct {
	Enabled bool   `json:"enabled"`
	Cron    string `json:"cron" example:"0 3 1 * *"`
}
type SyncSchedule struct {
	Running bool `json:"running"`
	SyncPlan
	LastSyncAt *time.Time `json:"last_sync_at"`
	LastResult string     `json:"last_result"`
	NextRunAt  *time.Time `json:"next_run_at"`
	Failures   int        `json:"failures"`
}

func defaultSchedule() SyncSchedule {
	return SyncSchedule{SyncPlan: SyncPlan{Cron: "0 3 1 * *"}}
}
func validatePlan(v SyncPlan) error {
	invalid := func() error {
		return apperror.Invalid("cron 表达式无效，应为 5 段：分 时 日 月 周（UTC）")
	}
	if len(strings.Fields(v.Cron)) != 5 || strings.Contains(v.Cron, "@") {
		return invalid()
	}
	schedule, err := cron.ParseStandard(v.Cron)
	if err != nil {
		return invalid()
	}
	// Starting immediately before a UTC year ensures the first pair includes
	// every selected minute of the earliest matching hour, including leap days.
	first := schedule.Next(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Second))
	second := schedule.Next(first)
	if first.IsZero() || second.IsZero() {
		return invalid()
	}
	if second.Sub(first) < time.Hour {
		return apperror.Invalid("定时同步的两次执行间隔不能小于 1 小时")
	}
	return nil
}
func nextScheduled(now time.Time, p SyncPlan) time.Time {
	schedule, _ := cron.ParseStandard(p.Cron) // Plans are validated before persistence and after loading.
	return schedule.Next(now.UTC())
}
func retryAt(now time.Time, failures int) time.Time {
	if failures > 8 {
		failures = 8
	}
	if failures < 1 {
		failures = 1
	}
	delay := 5 * time.Minute * time.Duration(1<<uint(failures-1))
	if delay > 6*time.Hour {
		delay = 6 * time.Hour
	}
	return now.Add(delay)
}
func (s *Service) SaveSchedule(ctx context.Context, p SyncPlan) error {
	if e := validatePlan(p); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if !s.op.TryLock() {
		return apperror.Conflict("IP 库正在操作，请稍后保存")
	}
	defer s.op.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	state.Schedule.SyncPlan = p
	state.Schedule.Failures = 0
	state.Schedule.NextRunAt = nil
	if p.Enabled {
		at := nextScheduled(s.now(), p)
		state.Schedule.NextRunAt = &at
	}
	if e := s.save(state); e != nil {
		return e
	}
	s.state = state
	return nil
}
func (s *Service) autoDue() bool {
	state := s.snapshot()
	v := state.Schedule
	return v.Enabled && v.NextRunAt != nil && !v.NextRunAt.After(s.now())
}
func (s *Service) tick(ctx context.Context) {
	if !s.op.TryLock() {
		return
	}
	defer s.op.Unlock()
	if !s.autoDue() {
		return
	}
	_ = s.updateLocked(ctx, true)
}

// Run is a single scheduler per process; the manifest retains due/retry times on restart.
func (s *Service) Run(ctx context.Context) {
	if !s.schedulerRunning.CompareAndSwap(false, true) {
		return
	}
	defer s.schedulerRunning.Store(false)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		s.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Service) recordSyncError(e error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	now := s.now().UTC()
	state.Schedule.LastSyncAt = &now
	state.Schedule.LastResult = "失败"
	state.LastError = safeMessage(e)
	state.Schedule.Failures++
	if state.Schedule.Enabled {
		at := retryAt(now, state.Schedule.Failures)
		state.Schedule.NextRunAt = &at
	}
	_ = s.save(state)
	s.state = state
}
