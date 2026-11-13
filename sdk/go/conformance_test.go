package sdk

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConformanceRunner(t *testing.T) {
	if os.Getenv("AUTHGO_SDK_RUNNER") != "1" {
		t.Skip("opt-in runner")
	}
	var c *Client
	var result *Result
	now := time.Now()
	scan := bufio.NewScanner(os.Stdin)
	for scan.Scan() {
		var p struct {
			Op, Config, Key, Version, Fingerprint, CacheDir, Content string
			Automatic, Unversioned                                   bool
			Time, Seconds                                            int64
			CachePath                                                string `json:"cache_dir"`
		}
		_ = json.Unmarshal(scan.Bytes(), &p)
		out := map[string]any{"code": "OK"}
		var e error
		switch p.Op {
		case "init":
			now = time.Unix(p.Time, 0)
			dir := p.CachePath
			if dir == "" {
				dir, _ = os.MkdirTemp("", "authgo-go-")
			}
			fp := p.Fingerprint
			if fp == "" {
				fp = strings.Repeat("a", 64)
			}
			v := p.Version
			if v == "" {
				v = "1.0.0"
			}
			if p.Unversioned {
				v = ""
			}
			opts := []Option{WithCacheDir(dir), WithClientVersion(v)}
			if !p.Automatic {
				opts = append(opts, WithFingerprint(func() (string, error) { return fp, nil }))
			}
			c, e = New(p.Config, opts...)
			if e == nil {
				c.now = func() time.Time { return now }
				out["status"] = "ready"
			}
		case "clock":
			now = now.Add(time.Duration(p.Seconds) * time.Second)
		case "guard_check":
			result, e = c.guardCheck(context.Background(), p.Key)
		case "trial_info":
			out["is_trial"] = result.IsTrial
		case "check":
			result, e = c.Check(context.Background(), p.Key)
		case "activate":
			result, e = c.Activate(context.Background(), p.Key, ActivateOptions{ClientVersion: "1.0.0"})
		case "verify":
			result, e = c.Verify(context.Background())
		case "heartbeat":
			result, e = c.Heartbeat(context.Background())
		case "release_seat":
			e = c.ReleaseSeat(context.Background())
		case "entitlement":
			out["maintenance_until"] = result.MaintenanceUntil
			out["latest_entitled_version"] = result.LatestEntitledVersion
		case "validate":
			e = c.Validate(result.Ticket())
		case "identity":
			var fp string
			fp, e = c.identity("")
			out["fingerprint"] = fp
		case "cache_warning":
			out["cache_warning"] = result.CacheWarning != nil
		case "deactivate":
			e = c.Deactivate(context.Background())
		case "announcements":
			var items []Announcement
			items, e = c.Announcements(context.Background())
			out["count"] = len(items)
		case "check_update":
			v := p.Version
			if v == "" {
				v = "1.0.0"
			}
			candidate, problem := c.CheckUpdate(context.Background(), v)
			e = problem
			if e == nil {
				update := candidate
				out["available"] = update.Available
				out["version"] = update.Version
				out["docker_image"] = update.DockerImage
				out["docker_pull"] = update.DockerPull
			}

		}
		if e != nil {
			var ae *Error
			if errors.As(e, &ae) {
				out = map[string]any{"code": ae.Code}
				if ae.Code == MaintenanceExpired {
					out["latest_entitled_version"] = ae.LatestEntitledVersion
				}
				if ae.LatestVersion != "" {
					out["latest_version"] = ae.LatestVersion
				}
			} else {
				out = map[string]any{"code": "RUNNER_ERROR"}
			}
		} else if result != nil && (p.Op == "guard_check" || p.Op == "check" || p.Op == "activate" || p.Op == "verify" || p.Op == "heartbeat") {
			status := result.Availability
			out["status"] = status
		}
		raw, _ := json.Marshal(out)
		fmt.Println(string(raw))
	}
}
