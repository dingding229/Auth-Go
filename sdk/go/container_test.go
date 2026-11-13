package sdk

import (
	"context"
	"encoding/json"

	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestContainerDetection(t *testing.T) {
	for _, path := range []string{"/.dockerenv", "/run/.containerenv", "docker", "containerd", "kubepods", "libpod", "none"} {
		for _, force := range []string{"", "0", "1"} {
			read := func(p string) ([]byte, error) {
				if p == path {
					return nil, nil
				}
				if p == "/proc/1/cgroup" {
					return []byte("0::/" + path), nil
				}
				return nil, os.ErrNotExist
			}
			got := detectContainer(read, func(string) string { return force })
			want := force == "1" || force != "0" && path != "none"
			if got != want {
				t.Fatal(path, force, got)
			}
		}
	}
}
func TestContainerIdentityAtomicAndMemory(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	results := make(chan string, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, e := containerIdentity(dir)
			if e != nil {
				t.Error(e)
			}
			results <- id
		}()
	}
	wg.Wait()
	close(results)
	id := ""
	for got := range results {
		if id != "" && got != id {
			t.Fatal("different concurrent IDs")
		}
		id = got
	}
	info, e := os.Stat(filepath.Join(dir, "instance-id"))
	if e != nil || info.Mode().Perm() != 0600 || len(id) != 64 {
		t.Fatal(info, e, id)
	}
	if instanceFingerprint(id) != sha([]byte("authgo/instance/v1\x00"+id)) {
		t.Fatal("wrong hash")
	}
	if e := os.Remove(filepath.Join(dir, "instance-id")); e != nil {
		t.Fatal(e)
	}
	next, e := containerIdentity(dir)
	if e != nil || next == id {
		t.Fatal("removed identity reused", e)
	}
	bad := filepath.Join(t.TempDir(), "file")
	if e := os.WriteFile(bad, []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	a, e := containerIdentity(bad)
	b, f := containerIdentity(bad)
	if e == nil || f == nil || a != b || len(a) != 64 {
		t.Fatal("memory fallback", e, f)
	}
}
func TestContainerConfigurationPriority(t *testing.T) {
	s := newSignedServer(t)
	t.Setenv("AUTHGO_CONTAINER", "1")
	t.Setenv("AUTHGO_CACHE_DIR", t.TempDir())
	t.Setenv("AUTHGO_INSTANCE_ID", "customer-instance")
	c, e := New(configFor(s))
	if e != nil {
		t.Fatal(e)
	}
	if c.CacheDir != os.Getenv("AUTHGO_CACHE_DIR") {
		t.Fatal(c.CacheDir)
	}
	if fp, e := c.identity(""); e != nil || fp != instanceFingerprint("customer-instance") {
		t.Fatal(fp, e)
	}
	override := strings.Repeat("b", 64)
	c, e = New(configFor(s), WithFingerprint(func() (string, error) { return override, nil }), WithCacheDir(""))
	if e != nil {
		t.Fatal(e)
	}
	if fp, e := c.identity(""); e != nil || fp != override || c.CacheDir != "" {
		t.Fatal(fp, e, c.CacheDir)
	}
	t.Setenv("AUTHGO_INSTANCE_ID", "")
	t.Setenv("AUTHGO_CACHE_DIR", "")
	c, e = New(configFor(s))
	if e != nil || c.CacheDir != "/var/lib/authgo" {
		t.Fatal(e, c)
	}
	c, e = New(configFor(s), WithCacheDir(""))
	if e != nil {
		t.Fatal(e)
	}
	c.now = s.clock.now
	r, e := c.Check(context.Background(), testKey)
	if e != nil || r.CacheWarning == nil || !strings.Contains(r.CacheWarning.Error(), "此实例重启后是新实例，没有断连宽限") {
		t.Fatal(r, e)
	}
}

func TestContainerVectors(t *testing.T) {
	var vectors struct {
		Detection []struct {
			Name     string
			Env      map[string]string
			Files    map[string]string
			Expected bool
		}
		Fingerprints []struct{ ID, Expected string }
	}
	raw, e := os.ReadFile("../vectors/container-identity.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors.Detection {
		got := detectContainer(func(p string) ([]byte, error) {
			if data, ok := v.Files[p]; ok {
				return []byte(data), nil
			}
			return nil, os.ErrNotExist
		}, func(k string) string { return v.Env[k] })
		if got != v.Expected {
			t.Fatal(v.Name, got)
		}
	}
	for _, v := range vectors.Fingerprints {
		if instanceFingerprint(v.ID) != v.Expected {
			t.Fatal(v.ID)
		}
	}
}
