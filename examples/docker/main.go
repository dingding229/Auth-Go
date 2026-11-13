// A business program owns signals and process exit; the SDK does neither.
package main

import (
	sdk "authgo/sdk"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	version    = "1.0.0"
	authConfig = ""
)

func main() { os.Exit(run()) }
func run() int {
	// The HTTP listener is business configuration, not an SDK/trust-root option.
	addr := flag.String("listen", ":8080", "HTTP监听地址")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	guard, err := sdk.StartGuard(ctx, sdk.GuardOptions{Config: authConfig, Version: version, OnChange: func(r *sdk.Result, err error) {
		if err != nil {
			log.Printf("授权检查: %v", err)
			return
		}
		log.Printf("授权状态: %s", r.Availability)
		if r.CacheWarning != nil {
			log.Printf("缓存提示: %v", r.CacheWarning)
		}
	}})
	if err != nil {
		log.Printf("授权验证失败: %v", err)
		return sdk.ExitLicense
	}
	defer func() {
		if err := guard.Close(context.Background()); err != nil {
			log.Printf("释放席位: %v", err)
		}
	}()
	if guard.Result().IsTrial {
		log.Print("当前为试用")
	}
	if r := guard.Result(); r.CacheWarning != nil {
		log.Printf("缓存提示: %v", r.CacheWarning)
	}
	appCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runServer(appCtx, guard, *addr) }()
	select {
	case <-ctx.Done():
		cancel()
		<-done
		return 0
	case <-guard.Done():
		log.Printf("授权已失效: %v", guard.Err())
		cancel()
		<-done
		return sdk.ExitLicense
	case err := <-done:
		if err != nil {
			log.Print(err)
			return 1
		}
		return 0
	}
}
func runServer(ctx context.Context, guard *sdk.Guard, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		// Check locally at a business entry, not just once during startup.
		if err := guard.Require(""); err != nil {
			http.Error(w, "授权暂不可用", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"features": guard.Result().Features})
	})
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("HTTP已启动 version=%s address=%s", version, listener.Addr())
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			deadline, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = server.Shutdown(deadline)
		case <-stopped:
		}
	}()
	err = server.Serve(listener)
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
