// Package healthcheck probes a running server without opening SQLite or loading secrets.
package healthcheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// URL translates a wildcard listen address to a loopback HTTP endpoint.
func URL(addr string) (string, error) {
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" || port == "0" {
		return "", fmt.Errorf("健康检查监听地址无效: %q", addr)
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	} else if host == "::" {
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func Check(ctx context.Context, addr string) error {
	url, err := URL(addr)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// Never send a local readiness probe through HTTP_PROXY, nor follow redirects.
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("健康检查失败: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("健康检查失败: HTTP %d", resp.StatusCode)
	}
	return nil
}
