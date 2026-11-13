package main

import (
	"authgo/internal/adminpath"
	"authgo/internal/db"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCommand(t *testing.T) {
	t.Setenv("AUTHGO_MASTER_KEY", "") // utility commands must not load configuration
	for _, cmd := range []string{"version", "--version", "help", "--help", "-h"} {
		var out bytes.Buffer
		if handled, err := command([]string{cmd}, &out); !handled || err != nil || out.Len() == 0 {
			t.Fatalf("%s handled=%v err=%v out=%s", cmd, handled, err, out.String())
		}
	}
	if handled, err := command(nil, &bytes.Buffer{}); handled || err != nil {
		t.Fatal("default must start service")
	}
	for _, args := range [][]string{{"bad"}, {"version", "bad"}} {
		if handled, err := command(args, &bytes.Buffer{}); !handled || err == nil {
			t.Fatal("invalid command accepted")
		}
	}
	t.Setenv("AUTHGO_ADDR", "bad")
	if handled, err := command([]string{"healthcheck"}, &bytes.Buffer{}); !handled || err == nil || !strings.Contains(err.Error(), "地址无效") {
		t.Fatal("bad probe passed")
	}
}

func TestAdminPathCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUTHGO_DATA_DIR", dir)
	d, err := db.Open(dir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if err = db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	paths, err := adminpath.New(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = paths.Change(context.Background(), "/test-console", adminpath.Actor{Operator: "test"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if handled, err := command([]string{"admin-path"}, &out); !handled || err != nil || out.String() != "/test-console\n" {
		t.Fatal(handled, err, out.String())
	}
	out.Reset()
	if handled, err := command([]string{"admin-path", "reset"}, &out); !handled || err != nil || out.String() != "/admin\n" {
		t.Fatal(handled, err, out.String())
	}
	if current, err := paths.Current(context.Background()); err != nil || current != "/admin" {
		t.Fatal(current, err)
	}
	for _, args := range [][]string{{"admin-path", "bad"}, {"admin-path", "reset", "extra"}} {
		if handled, err := command(args, &out); !handled || err == nil {
			t.Fatal("invalid recovery command accepted")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(err) {
		t.Fatal("utility unexpectedly loaded/created master key", err)
	}
}
