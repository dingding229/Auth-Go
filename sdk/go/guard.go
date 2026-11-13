package sdk

import (
	"context"
	"os"
	"sync"
	"time"
)

const ExitLicense = 77

type GuardOptions struct {
	Config     string
	License    string
	Version    string
	OnChange   func(*Result, error)
	SDKOptions []Option
}

type Guard struct {
	client    *Client
	mu        sync.RWMutex
	result    *Result
	err       error
	done      chan struct{}
	stopped   chan struct{}
	cancel    context.CancelFunc
	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
}

// StartGuard never reads configuration from the environment or a file. The
// caller must compile its trust roots into the program; only the license varies.
func StartGuard(ctx context.Context, opts GuardOptions) (*Guard, error) {
	touchWatermarkSlots()
	hardenProtected()
	if opts.Config == "" {
		return nil, failure(InvalidConfig, "接入配置必须编译进程序", nil)
	}
	options := append([]Option(nil), opts.SDKOptions...)
	options = append(options, WithClientVersion(opts.Version))
	c, err := New(opts.Config, options...)
	if err != nil {
		return nil, err
	}
	key := opts.License
	if key == "" {
		key = os.Getenv("AUTHGO_LICENSE")
	}
	result, err := c.guardCheck(ctx, key)
	if err != nil {
		return nil, err
	}
	loopCtx, cancel := context.WithCancel(ctx)
	g := &Guard{client: c, result: cloneResult(result), done: make(chan struct{}), stopped: make(chan struct{}), cancel: cancel, closed: make(chan struct{})}
	go func() {
		defer close(g.stopped)
		// Callbacks run outside SDK locks and must return promptly.
		err := c.StartAutoCheck(loopCtx, func(r *Result, err error) {
			g.mu.Lock()
			if r != nil {
				g.result = cloneResult(r)
			}
			if err != nil && loopCtx.Err() == nil {
				g.failLocked(err)
			}
			g.mu.Unlock()
			if opts.OnChange != nil {
				opts.OnChange(cloneResult(r), err)
			}
		})
		if err != nil && loopCtx.Err() == nil {
			g.mu.Lock()
			g.failLocked(err)
			g.mu.Unlock()
		}
	}()
	return g, nil
}

func (g *Guard) failLocked(err error) {
	if g.err == nil {
		g.err = err
		close(g.done)
	}
}
func (g *Guard) Result() *Result       { g.mu.RLock(); defer g.mu.RUnlock(); return cloneResult(g.result) }
func (g *Guard) Done() <-chan struct{} { return g.done }
func (g *Guard) Err() error            { g.mu.RLock(); defer g.mu.RUnlock(); return g.err }
func (g *Guard) Require(feature string) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.err != nil {
		return g.err
	}
	select {
	case <-g.closed:
		return failure(NotActivated, "授权守卫已关闭", nil)
	default:
	}
	if g.result == nil {
		return failure(NotActivated, "尚未验证授权", nil)
	}
	if err := g.client.Validate(g.result.Ticket()); err != nil {
		return err
	}
	if feature != "" && g.result.Features[feature] != true {
		return failure(InvalidPolicy, "当前授权未开放此功能", nil)
	}
	return nil
}

// Close bounds loop cancellation and release together to five seconds. It never
// unbinds or removes the proof, so a graceful restart can still use outage grace.
func (g *Guard) Close(ctx context.Context) error {
	g.closeOnce.Do(func() {
		defer close(g.closed)
		g.cancel()
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		released := make(chan error, 1)
		go func() {
			select {
			case <-g.stopped:
				released <- g.client.ReleaseSeat(bounded)
			case <-bounded.Done():
				released <- bounded.Err()
			}
		}()
		select {
		case g.closeErr = <-released:
		case <-bounded.Done():
			g.closeErr = bounded.Err()
		}
	})
	<-g.closed
	return g.closeErr
}

func cloneResult(r *Result) *Result {
	if r == nil {
		return nil
	}
	copy := *r
	copy.Features = cloneFeatures(r.Features)
	copy.SatisfiedMethods = append([]string(nil), r.SatisfiedMethods...)
	copy.unlockSeed = append([]byte(nil), r.unlockSeed...)
	for _, pair := range []struct {
		src *time.Time
		dst **time.Time
	}{{r.StartsAt, &copy.StartsAt}, {r.ExpiresAt, &copy.ExpiresAt}, {r.LeaseExpiresAt, &copy.LeaseExpiresAt}, {r.MaintenanceUntil, &copy.MaintenanceUntil}} {
		if pair.src != nil {
			value := *pair.src
			*pair.dst = &value
		}
	}
	return &copy
}
func cloneFeatures(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = cloneFeature(v)
	}
	return dst
}
func cloneFeature(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneFeatures(x)
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = cloneFeature(v)
		}
		return out
	default:
		return v
	}
}
