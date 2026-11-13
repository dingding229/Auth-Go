// Package automation owns settings, expiry email, backups and single-instance jobs.
package automation

import (
	"authgo/internal/config"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/dockerhub"
	"authgo/internal/mailer"
	"authgo/internal/updater"
	"context"
	"gorm.io/gorm"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type Options struct {
	Now      func() time.Time
	DataDir  string
	Defaults config.Config
	SendMail func(context.Context, mailer.Config, mailer.Message) error
}
type Service struct {
	sharing                                          func(context.Context) error
	hub                                              *dockerhub.Service
	deploymentProxies                                []netip.Prefix
	updates                                          *updater.Service
	db                                               *gorm.DB
	masterKey                                        []byte
	cipher                                           *cryptoutil.Cipher
	now                                              func() time.Time
	log                                              *slog.Logger
	dataDir                                          string
	sendMail                                         func(context.Context, mailer.Config, mailer.Message) error
	settings                                         atomic.Pointer[Settings]
	apply                                            func(Settings)
	settingsMu, dispatchMu, jobsMu, backupMu, lifeMu sync.Mutex
	cancel                                           context.CancelFunc
	done                                             chan struct{}
}

func New(database *gorm.DB, master []byte, log *slog.Logger, opts Options) (*Service, error) {
	box, err := cryptoutil.NewCipher(master)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.SendMail == nil {
		opts.SendMail = mailer.Send
	}
	s := &Service{db: database, masterKey: append([]byte(nil), master...), cipher: box, now: opts.Now, log: log, dataDir: opts.DataDir, sendMail: opts.SendMail}
	s.updates, err = updater.New(database, master, opts.Now)
	if err != nil {
		return nil, err
	}
	s.hub = dockerhub.New(database, s.updates, opts.Now)
	if err = s.loadSettings(opts.Defaults); err != nil {
		return nil, err
	}
	for _, raw := range opts.Defaults.TrustedProxies {
		if ip, e := netip.ParseAddr(raw); e == nil {
			ip = ip.Unmap()
			s.deploymentProxies = append(s.deploymentProxies, netip.PrefixFrom(ip, ip.BitLen()))
		} else if p, e := netip.ParsePrefix(raw); e == nil {
			s.deploymentProxies = append(s.deploymentProxies, p)
		}
	}
	return s, nil
}
func (s *Service) SetApply(fn func(Settings)) {
	s.apply = fn
	if fn != nil {
		fn(s.Current())
	}
}
func (s *Service) Start(parent context.Context) {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if s.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.done = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(4)
	run := func(interval time.Duration, fn func(context.Context) error) {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := fn(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("定时任务失败", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
	go run(time.Second, s.ProcessDue)
	go run(time.Second, s.hub.Tick)
	go run(time.Minute, s.Tick)
	go run(time.Hour, func(ctx context.Context) error {
		if s.sharing != nil {
			return s.sharing(ctx)
		}
		return nil
	})
	go func() { wg.Wait(); close(s.done) }()
}
func (s *Service) ProcessDue(ctx context.Context) error {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	return s.processMail(ctx)
}
func (s *Service) Close(ctx context.Context) error {
	s.lifeMu.Lock()
	cancel, done := s.cancel, s.done
	s.lifeMu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) Updates() *updater.Service { return s.updates }

func (s *Service) DockerHub() *dockerhub.Service { return s.hub }

// SetSharing registers the startup/hourly scan before Start.
func (s *Service) SetSharing(fn func(context.Context) error) { s.sharing = fn }
