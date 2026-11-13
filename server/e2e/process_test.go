package e2e

import (
	"authgo/sdk"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A real built server process (not an injected transport failure): stop/restart
// with the same SQLite volume and refuse from the separately hosted signed list.
func TestRealProcessOutageAndAuthenticatedRefusal(t *testing.T) {
	if testing.Short() {
		t.Skip("真实进程测试需构建服务端")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "authgo")
	build := exec.Command("go", "build", "-o", binary, "../cmd/authgo")
	if raw, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, raw)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := listener.Addr().String()
	listener.Close()
	base := "http://" + addr
	env := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "AUTHGO_") {
			env = append(env, v)
		}
	}
	env = append(env, "AUTHGO_ADDR="+addr, "AUTHGO_DATA_DIR="+filepath.Join(dir, "data"), "AUTHGO_ADMIN_USER=process-owner", "AUTHGO_ADMIN_PASSWORD=process-password", "AUTHGO_LOG_LEVEL=error")
	var process *exec.Cmd
	var output *os.File
	stop := func() {
		if process != nil {
			process.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- process.Wait() }()
			select {
			case e := <-done:
				if e != nil {
					t.Errorf("server shutdown: %v", e)
				}
			case <-time.After(10 * time.Second):
				process.Process.Kill()
				<-done
				t.Error("server shutdown timeout")
			}
			output.Close()
			process = nil
		}
	}
	defer stop()
	start := func() {
		var e error
		output, e = os.OpenFile(filepath.Join(dir, "process.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		process = exec.Command(binary)
		process.Env = env
		process.Stdout = output
		process.Stderr = output
		if e := process.Start(); e != nil {
			t.Fatal(e)
		}
		until := time.Now().Add(15 * time.Second)
		for {
			client := &http.Client{Timeout: time.Second}
			res, e := client.Get(base + "/healthz")
			if e == nil {
				res.Body.Close()
				if res.StatusCode == 200 {
					return
				}
			}
			if time.Now().After(until) {
				t.Fatal("real server did not become healthy")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	var jwt string
	call := func(method, path string, in any) map[string]any {
		var body io.Reader
		if in != nil {
			raw, _ := json.Marshal(in)
			body = bytes.NewReader(raw)
		}
		req, _ := http.NewRequest(method, base+path, body)
		req.Header.Set("Content-Type", "application/json")
		if jwt != "" {
			req.Header.Set("Authorization", "Bearer "+jwt)
		}
		res, e := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 {
			t.Fatalf("%s %s %d %s", method, path, res.StatusCode, raw)
		}
		var out map[string]any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if e := d.Decode(&out); e != nil {
			t.Fatal(e)
		}
		if data, ok := out["data"].(map[string]any); ok {
			return data
		}
		return out
	}
	login := func() {
		jwt = call("POST", "/api/v1/admin/auth/login", map[string]any{"username": "process-owner", "password": "process-password"})["access_token"].(string)
	}
	start()
	login()
	app := call("POST", "/api/v1/admin/applications", map[string]any{"name": "真实服务故障测试", "grace_hours": 0, "next_check_in": 1})
	appID := app["id"].(json.Number).String()
	user := call("POST", "/api/v1/admin/users", map[string]any{"name": "真实进程用户"})
	lic := call("POST", "/api/v1/admin/licenses", map[string]any{"app_id": app["id"], "user_id": user["id"], "validity_rule": "perpetual", "verify_methods": []string{"KEY", "FLOATING"}})
	key := lic["key"].(string)
	config := call("POST", "/api/v1/admin/applications/"+appID+"/connection", map[string]any{"url": base})["config"].(string)
	c, e := sdk.New(config, sdk.WithCacheDir(filepath.Join(dir, "cache")), sdk.WithFingerprint(func() (string, error) { return strings.Repeat("b", 64), nil }))
	if e != nil {
		t.Fatal(e)
	}
	online, e := c.Check(context.Background(), key)
	if e != nil {
		t.Fatal(e)
	}
	if e := c.Validate(online.Ticket()); e != nil {
		t.Fatal("zero-grace online ticket", e)
	}

	// Keep a reverse proxy reachable while the real primary process is stopped.
	target, _ := url.Parse(base)
	reverse := httputil.NewSingleHostReverseProxy(target)
	reverse.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	proxy := httptest.NewServer(reverse)
	defer proxy.Close()
	call("PATCH", "/api/v1/admin/applications/"+appID, map[string]any{"grace_hours": 72})
	proxyLicense := call("POST", "/api/v1/admin/licenses", map[string]any{"app_id": app["id"], "user_id": user["id"], "verify_methods": []string{"KEY", "FLOATING"}})
	proxyKey := proxyLicense["key"].(string)
	proxyConfig := call("POST", "/api/v1/admin/applications/"+appID+"/connection", map[string]any{"url": proxy.URL})["config"].(string)
	viaProxy, e := sdk.New(proxyConfig, sdk.WithCacheDir(filepath.Join(dir, "proxy-cache")), sdk.WithFingerprint(func() (string, error) { return strings.Repeat("c", 64), nil }))
	if e != nil {
		t.Fatal(e)
	}
	if r, e := viaProxy.Check(context.Background(), proxyKey); e != nil || r.Status != "online" {
		t.Fatal("proxy online", e)
	}
	stop()
	if r, e := viaProxy.Check(context.Background(), proxyKey); e != nil || r.Status != "grace" || r.Reason == "" {
		t.Fatal("live proxy502 lost grace", e)
	}
	restored, e := sdk.New(proxyConfig, sdk.WithCacheDir(filepath.Join(dir, "proxy-cache")), sdk.WithFingerprint(func() (string, error) { return strings.Repeat("c", 64), nil }))
	if e != nil {
		t.Fatal(e)
	}
	if r, e := restored.Check(context.Background(), proxyKey); e != nil || r.Status != "grace" {
		t.Fatal("proxy502 destroyed persistent cache", e)
	}
	if _, e := c.Check(context.Background(), key); !errors.Is(e, sdk.ErrGraceExpired) {
		t.Fatal("zero grace was extended", e)
	}
	if e := c.Validate(online.Ticket()); e == nil {
		t.Fatal("old online ticket used after known zero-grace outage")
	}
	start()
	login()
	call("POST", "/api/v1/admin/licenses/"+lic["id"].(json.Number).String()+"/revoke", map[string]any{})
	if _, e := c.Check(context.Background(), key); !errors.Is(e, sdk.ErrActivationInvalid) {
		t.Fatal("authenticated refusal lost", e)
	}
	stop()
	if r, e := c.Check(context.Background(), key); r != nil || e == nil {
		t.Fatal("authenticated refusal fell back to cache", r, e)
	}
}
