package main

import (
	"authgo/internal/adminpath"
	"authgo/internal/backupfile"
	"authgo/internal/db"
	"bytes"
	"context"
	"fmt"
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

func TestBackupUnlockCommandAcceptsEnvironmentAndStandardInput(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "snapshot")
	original := filepath.Join(dir, "original.zip")
	if err := os.WriteFile(database, []byte("snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := backupfile.Write(database, original, bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	password := "private backup password"
	if err := backupfile.Encrypt(&encrypted, bytes.NewReader(raw), password); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "bundle.enc")
	if err := os.WriteFile(source, encrypted.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	for i, environment := range []string{password, ""} {
		t.Setenv("AUTHGO_BACKUP_PASSWORD", environment)
		var out bytes.Buffer
		destination := filepath.Join(dir, fmt.Sprintf("restored-%d.zip", i))
		if err := unlockBackup([]string{"backup-unlock", source, destination}, strings.NewReader(password+"\n"), &out); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), password) {
			t.Fatal("password leaked")
		}
	}
	t.Setenv("AUTHGO_BACKUP_PASSWORD", "")
	if err := unlockBackup([]string{"backup-unlock", original, filepath.Join(dir, "legacy.zip")}, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatal("legacy ZIP no longer supported", err)
	}
}
