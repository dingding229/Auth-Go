package main

import (
	"authgo/internal/auth"
	"authgo/internal/automation"
	"authgo/internal/bootstrap"
	"authgo/internal/buildinfo"
	"authgo/internal/catalog"
	"authgo/internal/client"
	"authgo/internal/config"
	"authgo/internal/db"
	"authgo/internal/httpserver"
	"authgo/internal/ipinfo"
	"authgo/internal/keycheck"
	"authgo/internal/licensing"
	"authgo/internal/portal"
	"authgo/internal/service"
	"authgo/internal/sharing"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if handled, err := command(os.Args[1:], os.Stdout); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("服务启动或运行失败", "error", err)
		os.Exit(1)
	}
}

func run() (runErr error) {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	database, err := db.Open(cfg.DataDir, cfg.BusyTimeout)
	if err != nil {
		return err
	}
	pool, err := database.DB()
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.CheckSchema(database); err != nil {
		return err
	}
	if err := keycheck.Validate(ctx, database, cfg.MasterKey); err != nil {
		return err
	}
	if err := db.Migrate(database); err != nil {
		return err
	}
	admin, err := bootstrap.EnsureAdmin(database, cfg.AdminUser, cfg.AdminPassword)
	if err != nil {
		return err
	}
	if admin.Created {
		log.Info("已创建初始管理员", "username", cfg.AdminUser)
	}
	setup, setupToken, err := bootstrap.NewSetup(database)
	if err != nil {
		return err
	}
	authService, err := auth.NewService(database, cfg.MasterKey)
	if err != nil {
		return err
	}
	catalogService, err := catalog.NewService(database, cfg.MasterKey)
	if err != nil {
		return err
	}
	clientService, err := client.NewService(database, cfg.MasterKey, log, client.Options{IPRate: float64(cfg.ClientIPRate), IPBurst: cfg.ClientIPBurst, LicenseRate: float64(cfg.ClientLicenseRate), LicenseBurst: cfg.ClientLicenseBurst, LogCapacity: cfg.ClientLogCapacity})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		runErr = errors.Join(runErr, clientService.Close(ctx))
	}()

	entitlements, err := service.New(database, cfg.MasterKey, log, service.Options{})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		runErr = errors.Join(runErr, entitlements.Close(ctx))
	}()

	notifications, err := automation.New(database, cfg.MasterKey, log, automation.Options{DataDir: cfg.DataDir, Defaults: cfg})
	if err != nil {
		return err
	}
	clientService.SetDockerHub(notifications.DockerHub())
	notifications.SetApply(func(v automation.Settings) {
		clientService.ConfigureRateLimits(v.IPQueryRate, v.IPBurst, v.LicenseRate, v.LicenseBurst)
	})
	ips, err := ipinfo.New(cfg.DataDir)
	if err != nil {
		return err
	}
	ipDone := make(chan struct{})
	ipCtx, ipCancel := context.WithCancel(ctx)
	go func() { defer close(ipDone); ips.Run(ipCtx) }()
	defer func() { ipCancel(); <-ipDone; runErr = errors.Join(runErr, ips.Close()) }()
	sharingService := sharing.New(database, ips, nil)
	notifications.SetSharing(sharingService.Tick)
	notifications.Start(ctx)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		runErr = errors.Join(runErr, notifications.Close(ctx))
	}()
	licensingService := licensing.NewService(database)
	portalService, err := portal.New(database, cfg.MasterKey, notifications, entitlements, portal.Options{})
	if err != nil {
		return err
	}
	router, err := httpserver.NewRouter(cfg, log, pool.PingContext, httpserver.WithAdmin(authService, database), httpserver.WithSetup(setup), httpserver.WithCatalog(catalogService), httpserver.WithLicensing(licensingService), httpserver.WithClient(clientService), httpserver.WithAutomation(notifications), httpserver.WithPortal(portalService), httpserver.WithIPInfo(ips), httpserver.WithSharing(sharingService))
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: cfg.Addr, Handler: router,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("监听地址: %w", err)
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	if setupToken != "" {
		log.Log(ctx, max(cfg.LogLevel, slog.LevelWarn), "首次使用：请用前端初始化页面设置管理员账号（令牌仅本次有效）", "setup_token", setupToken, "public_url", notifications.Current().PublicURL)
		setupToken = ""
	}
	log.Info("服务已启动", "addr", listener.Addr().String(), "version", buildinfo.Version, "commit", buildinfo.Commit, "built_at", buildinfo.BuiltAt)
	select {
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("正在优雅关闭服务")
		stop() // A second interrupt can force the process to exit.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("优雅关闭超时或失败: %w", err)
		}
		if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	log.Info("服务已停止")
	return nil
}
