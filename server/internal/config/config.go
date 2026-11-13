// Package config loads the server's AUTHGO_ environment variables.
package config

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Config struct {
	SwaggerEnabled     bool
	Addr               string
	DataDir            string
	MasterKey          []byte `json:"-"`
	AdminUser          string
	AdminPassword      string `json:"-"`
	PublicURL          string
	TrustedProxies     []string
	LogLevel           slog.Level
	BusyTimeout        time.Duration
	ShutdownTimeout    time.Duration
	ClientIPRate       int
	ClientIPBurst      int
	ClientLicenseRate  int
	ClientLicenseBurst int
	ClientLogCapacity  int
}

// Load deliberately does not read .env files: the process environment is authoritative.
func Load() (Config, error) {
	cfg, err := load(os.Getenv)
	if err != nil {
		return Config{}, err
	}
	if err = ResolveMasterKey(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr: value(getenv, "ADDR", ":8080"), DataDir: value(getenv, "DATA_DIR", "./data"),
		AdminUser: value(getenv, "ADMIN_USER", "admin"), AdminPassword: getenv("AUTHGO_ADMIN_PASSWORD"),
	}
	var err error
	cfg.SwaggerEnabled, err = strconv.ParseBool(value(getenv, "SWAGGER_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("AUTHGO_SWAGGER_ENABLED 必须为布尔值: %w", err)
	}
	key := getenv("AUTHGO_MASTER_KEY")

	decoded, err := base64.StdEncoding.DecodeString(key)
	if key != "" && (err != nil || len(decoded) != 32) {
		return Config{}, fmt.Errorf("AUTHGO_MASTER_KEY 必须是 Base64 编码的 32 字节密钥")
	}
	cfg.MasterKey = decoded
	if _, _, err := net.SplitHostPort(cfg.Addr); err != nil {
		return Config{}, fmt.Errorf("AUTHGO_ADDR 格式无效: %w", err)
	}
	if strings.TrimSpace(cfg.AdminUser) == "" || len(cfg.AdminUser) > 128 || strings.IndexFunc(cfg.AdminUser, unicode.IsControl) >= 0 {
		return Config{}, fmt.Errorf("AUTHGO_ADMIN_USER 不能为空白、包含控制字符或超过 128 字节")
	}
	// bcrypt rejects passwords longer than 72 bytes; do not silently truncate.
	if len(cfg.AdminPassword) > 72 {
		return Config{}, fmt.Errorf("AUTHGO_ADMIN_PASSWORD 不能超过 72 字节")
	}
	if err := cfg.LogLevel.UnmarshalText([]byte(value(getenv, "LOG_LEVEL", "info"))); err != nil {
		return Config{}, fmt.Errorf("AUTHGO_LOG_LEVEL 无效: %w", err)
	}
	if proxies := strings.TrimSpace(getenv("AUTHGO_TRUSTED_PROXIES")); proxies != "" {
		for _, proxy := range strings.Split(proxies, ",") {
			proxy = strings.TrimSpace(proxy)
			if net.ParseIP(proxy) == nil {
				if _, _, err := net.ParseCIDR(proxy); err != nil {
					return Config{}, fmt.Errorf("AUTHGO_TRUSTED_PROXIES 包含无效 IP/CIDR: %q", proxy)
				}
			}
			cfg.TrustedProxies = append(cfg.TrustedProxies, proxy)
		}
	}
	cfg.PublicURL = strings.TrimSpace(getenv("AUTHGO_PUBLIC_URL"))
	if cfg.PublicURL != "" {
		u, e := url.Parse(cfg.PublicURL)
		if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return Config{}, fmt.Errorf("AUTHGO_PUBLIC_URL 必须为外部 HTTP/HTTPS 来源")
		}
	}
	ms, err := strconv.Atoi(value(getenv, "DB_BUSY_TIMEOUT_MS", "5000"))
	if err != nil || ms < 1 || ms > 60000 {
		return Config{}, fmt.Errorf("AUTHGO_DB_BUSY_TIMEOUT_MS 必须在 1 到 60000 之间")
	}
	cfg.BusyTimeout = time.Duration(ms) * time.Millisecond
	cfg.ShutdownTimeout, err = time.ParseDuration(value(getenv, "SHUTDOWN_TIMEOUT", "10s"))
	if err != nil || cfg.ShutdownTimeout <= 0 || cfg.ShutdownTimeout > 5*time.Minute {
		return Config{}, fmt.Errorf("AUTHGO_SHUTDOWN_TIMEOUT 必须大于 0 且不超过 5m，例如 10s")
	}

	for _, item := range []struct {
		name, def string
		max       int
		dst       *int
	}{
		{"CLIENT_IP_RATE", "10", 100000, &cfg.ClientIPRate}, {"CLIENT_IP_BURST", "60", 100000, &cfg.ClientIPBurst},
		{"CLIENT_LICENSE_RATE", "5", 100000, &cfg.ClientLicenseRate}, {"CLIENT_LICENSE_BURST", "30", 100000, &cfg.ClientLicenseBurst},
		{"CLIENT_LOG_CAPACITY", "4096", 100000, &cfg.ClientLogCapacity},
	} {
		n, e := strconv.Atoi(value(getenv, item.name, item.def))
		if e != nil || n < 1 || n > item.max {
			return Config{}, fmt.Errorf("AUTHGO_%s 必须为 1 至 %d", item.name, item.max)
		}
		*item.dst = n
	}
	return cfg, nil
}

func value(getenv func(string) string, name, fallback string) string {
	if v := getenv("AUTHGO_" + name); v != "" {
		return v
	}
	return fallback
}
