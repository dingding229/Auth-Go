package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMasterKeySources(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	t.Run("environment", func(t *testing.T) {
		c := Config{DataDir: t.TempDir(), MasterKey: key}
		os.WriteFile(filepath.Join(c.DataDir, "master.key"), []byte("invalid"), 0600)
		if e := ResolveMasterKey(&c); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(c.MasterKey, key) {
			t.Fatal("environment precedence")
		}
	})
	t.Run("file", func(t *testing.T) {
		c := Config{DataDir: t.TempDir()}
		p := filepath.Join(c.DataDir, "master.key")
		os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(key)), 0644)
		os.WriteFile(filepath.Join(c.DataDir, "authgo.db"), nil, 0600)
		if e := ResolveMasterKey(&c); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(c.MasterKey, key) {
			t.Fatal("key mismatch")
		}
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0600 {
			t.Fatal(st.Mode())
		}
	})
	t.Run("new database", func(t *testing.T) {
		c := Config{DataDir: t.TempDir()}
		if e := ResolveMasterKey(&c); e != nil {
			t.Fatal(e)
		}
		first := append([]byte(nil), c.MasterKey...)
		c.MasterKey = nil
		if e := ResolveMasterKey(&c); e != nil {
			t.Fatal(e)
		}
		if len(first) != 32 || !bytes.Equal(c.MasterKey, first) {
			t.Fatal("overwritten")
		}
	})
	t.Run("existing database", func(t *testing.T) {
		c := Config{DataDir: t.TempDir()}
		os.WriteFile(filepath.Join(c.DataDir, "authgo.db"), nil, 0600)
		if e := ResolveMasterKey(&c); e == nil || !strings.Contains(e.Error(), "禁止自动生成") {
			t.Fatal(e)
		}
		if _, e := os.Stat(filepath.Join(c.DataDir, "master.key")); !os.IsNotExist(e) {
			t.Fatal("generated replacement")
		}
	})
	t.Run("invalid file", func(t *testing.T) {
		c := Config{DataDir: t.TempDir()}
		p := filepath.Join(c.DataDir, "master.key")
		os.WriteFile(p, []byte("invalid"), 0600)
		if e := ResolveMasterKey(&c); e == nil {
			t.Fatal("accepted invalid file")
		}
		b, _ := os.ReadFile(p)
		if string(b) != "invalid" {
			t.Fatal("overwritten")
		}
	})
}

func TestLoadEnvironmentMasterKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUTHGO_DATA_DIR", dir)
	key := bytes.Repeat([]byte{9}, 32)
	t.Setenv("AUTHGO_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	cfg, e := Load()
	if e != nil || !bytes.Equal(cfg.MasterKey, key) {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(e) {
		t.Fatal("ENV must not write key file")
	}
	t.Setenv("AUTHGO_MASTER_KEY", "bad")
	if _, e = Load(); e == nil {
		t.Fatal("bad environment fell back")
	}
}

func TestConcurrentMasterKeyPublication(t *testing.T) {
	dir := t.TempDir()
	results := make(chan Config, 8)
	errors := make(chan error, 8)
	for range 8 {
		go func() { c := Config{DataDir: dir}; e := ResolveMasterKey(&c); results <- c; errors <- e }()
	}
	var first []byte
	for range 8 {
		c := <-results
		if e := <-errors; e != nil {
			t.Fatal(e)
		}
		if first == nil {
			first = c.MasterKey
		}
		if !bytes.Equal(first, c.MasterKey) {
			t.Fatal("concurrent starts selected different keys")
		}
	}
}
