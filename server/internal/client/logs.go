package client

import (
	"authgo/internal/model"
	"context"
	"gorm.io/gorm"
	"log/slog"
	"math/bits"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type logWriter struct {
	db       *gorm.DB
	log      *slog.Logger
	queue    chan model.VerifyLog
	slots    chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	closed   bool
	inflight sync.WaitGroup
	dropped  atomic.Uint64
}

func newLogWriter(db *gorm.DB, log *slog.Logger, size int) *logWriter {
	w := &logWriter{db: db, log: log, queue: make(chan model.VerifyLog, size), slots: make(chan struct{}, size), done: make(chan struct{})}
	for range size {
		w.slots <- struct{}{}
	}
	go w.run()
	return w
}

// reserve bounds logging memory only. A failed reservation must never gate business work.
func (w *logWriter) reserve() (func(model.VerifyLog), bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, false
	}
	select {
	case <-w.slots:
	default:
		return nil, false
	}
	w.inflight.Add(1)
	var once sync.Once
	return func(row model.VerifyLog) { once.Do(func() { w.queue <- row; w.inflight.Done() }) }, true
}

// trySubmit never blocks on database IO and never affects the response.
func (w *logWriter) trySubmit(row model.VerifyLog) {
	submit, ok := w.reserve()
	if !ok {
		w.discard(1, "queue_full_or_closed", nil)
		return
	}
	submit(row)
}
func (w *logWriter) discard(count uint64, reason string, err error) {
	n := w.dropped.Add(count)
	previous := n - count
	// Report the first loss and each crossed power-of-two total. This also
	// works for batched losses (whose totals need not be exact powers of two).
	if previous == 0 || bits.Len64(n) != bits.Len64(previous) {
		attrs := []any{"dropped_logs", n, "count", count, "reason", reason}
		if err != nil {
			attrs = append(attrs, "error", err)
		}
		w.log.Warn("验证日志已丢弃，请求结果不受影响", attrs...)
	}
}
func (s *Service) recordVerifyLog(row model.VerifyLog, sample bool) {
	key := ipLimitKey(row.IP)
	if row.Reason == "版本未收录或缺少发布时间，维护期检查已放行" && row.LicenseID != nil {
		key = "maintenance:" + strconv.FormatUint(*row.LicenseID, 10) + ":" + row.ClientVersion
	}
	if sample && !s.logSamples.allow(key, s.now().UTC()) {
		s.sampledLogs.Add(1)
		return
	}
	s.logs.trySubmit(row)
}
func (w *logWriter) close(ctx context.Context) error {
	w.mu.Lock()
	first := !w.closed
	w.closed = true
	w.mu.Unlock()
	if first {
		go func() { w.inflight.Wait(); close(w.queue) }()
	}
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (w *logWriter) run() {
	defer close(w.done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]model.VerifyLog, 0, 64)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				// A management deletion may race an enqueued request. Keep the log but
				// detach absent relations instead of losing the entire batch to an FK.
				for i := range batch {
					for _, ref := range []struct {
						entity any
						id     **uint64
					}{{&model.Application{}, &batch[i].AppID}, {&model.License{}, &batch[i].LicenseID}, {&model.Activation{}, &batch[i].ActivationID}} {
						if *ref.id == nil {
							continue
						}
						var n int64
						if e := tx.Model(ref.entity).Where("id = ?", **ref.id).Count(&n).Error; e != nil {
							return e
						}
						if n == 0 {
							*ref.id = nil
						}
					}
				}
				return tx.Omit("Application", "License", "Activation").Create(&batch).Error
			})
			cancel()
			if err == nil {
				break
			}
			time.Sleep(time.Duration(attempt+1) * 20 * time.Millisecond)
		}
		if err != nil {
			// Exhausted retries discard this batch only. Future batches still get
			// a chance to persist; neither requests nor shutdown fail for lost logs.
			w.discard(uint64(len(batch)), "persistence_failed", err)
		}
		for range batch {
			w.slots <- struct{}{}
		}
		batch = make([]model.VerifyLog, 0, 64)
	}
	for {
		select {
		case row, ok := <-w.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, row)
			if len(batch) == 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
