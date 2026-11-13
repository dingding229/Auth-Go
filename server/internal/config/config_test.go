package config

import (
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{"defaults", nil, false},
		{"invalid swagger", map[string]string{"SWAGGER_ENABLED": "bad"}, true},
		{"invalid client rate", map[string]string{"CLIENT_IP_RATE": "0"}, true},
		{"invalid license burst", map[string]string{"CLIENT_LICENSE_BURST": "bad"}, true},
		{"excessive log queue", map[string]string{"CLIENT_LOG_CAPACITY": "100001"}, true},
		{"missing key", map[string]string{"MASTER_KEY": ""}, false},
		{"invalid base64", map[string]string{"MASTER_KEY": "???"}, true},
		{"short key", map[string]string{"MASTER_KEY": "c2hvcnQ="}, true},
		{"invalid addr", map[string]string{"ADDR": "invalid"}, true},
		{"blank user", map[string]string{"ADMIN_USER": "  "}, true},
		{"long user", map[string]string{"ADMIN_USER": strings.Repeat("a", 129)}, true},
		{"control user", map[string]string{"ADMIN_USER": "owner\n"}, true},
		{"long password", map[string]string{"ADMIN_PASSWORD": strings.Repeat("a", 73)}, true},
		{"invalid log level", map[string]string{"LOG_LEVEL": "trace"}, true},
		{"invalid proxy", map[string]string{"TRUSTED_PROXIES": "example.com"}, true},
		{"empty proxy entry", map[string]string{"TRUSTED_PROXIES": "127.0.0.1,"}, true},
		{"bad timeout", map[string]string{"DB_BUSY_TIMEOUT_MS": "abc"}, true},
		{"zero timeout", map[string]string{"DB_BUSY_TIMEOUT_MS": "0"}, true},
		{"huge timeout", map[string]string{"DB_BUSY_TIMEOUT_MS": "60001"}, true},
		{"invalid shutdown", map[string]string{"SHUTDOWN_TIMEOUT": "bad"}, true},
		{"negative shutdown", map[string]string{"SHUTDOWN_TIMEOUT": "-1s"}, true},
		{"huge shutdown", map[string]string{"SHUTDOWN_TIMEOUT": "10m"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{"AUTHGO_MASTER_KEY": key}
			for k, v := range tt.env {
				env["AUTHGO_"+k] = v
			}
			cfg, err := load(func(k string) string { return env[k] })
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.name == "defaults" {
				if cfg.SwaggerEnabled || cfg.Addr != ":8080" || cfg.DataDir != "./data" || cfg.AdminUser != "admin" ||
					len(cfg.MasterKey) != 32 || cfg.TrustedProxies != nil || cfg.LogLevel != slog.LevelInfo ||
					cfg.BusyTimeout != 5*time.Second || cfg.ShutdownTimeout != 10*time.Second || cfg.ClientIPRate != 10 || cfg.ClientIPBurst != 60 || cfg.ClientLicenseRate != 5 || cfg.ClientLicenseBurst != 30 || cfg.ClientLogCapacity != 4096 {
					t.Fatal("unexpected defaults")
				}
			}
		})
	}
}

func TestLoadOverrides(t *testing.T) {
	env := map[string]string{
		"AUTHGO_SWAGGER_ENABLED": "true",
		"AUTHGO_MASTER_KEY":      base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"AUTHGO_ADDR":            "127.0.0.1:9000", "AUTHGO_DATA_DIR": "/tmp/test",
		"AUTHGO_ADMIN_USER": "owner", "AUTHGO_ADMIN_PASSWORD": "test-password",
		"AUTHGO_TRUSTED_PROXIES": "127.0.0.1, 10.0.0.0/8, ::1, 2001:db8::/32",
		"AUTHGO_LOG_LEVEL":       "debug", "AUTHGO_DB_BUSY_TIMEOUT_MS": "1234", "AUTHGO_SHUTDOWN_TIMEOUT": "3s",
	}
	cfg, err := load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SwaggerEnabled || cfg.Addr != "127.0.0.1:9000" || cfg.DataDir != "/tmp/test" || cfg.AdminUser != "owner" ||
		cfg.AdminPassword != "test-password" || len(cfg.TrustedProxies) != 4 || cfg.LogLevel != slog.LevelDebug ||
		cfg.BusyTimeout != 1234*time.Millisecond || cfg.ShutdownTimeout != 3*time.Second {
		t.Fatal("overrides not loaded")
	}
}
