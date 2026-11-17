package main

import (
	"authgo/internal/catalog"
	"authgo/internal/db"
	"authgo/internal/keycheck"
	"authgo/internal/model"
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestWrongMasterKeyStopsBeforeWriteOrListen(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "current"
		if legacy {
			name = "baseline"
		}
		t.Run(name, func(t *testing.T) { wrongMasterKeyStopsBeforeWriteOrListen(t, legacy) })
	}
}

func wrongMasterKeyStopsBeforeWriteOrListen(t *testing.T, legacy bool) {
	t.Helper()
	dir := t.TempDir()
	master := bytes.Repeat([]byte{3}, 32)
	d, e := db.Open(dir, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(d); e != nil {
		t.Fatal(e)
	}
	if legacy {
		if e = d.Exec("DROP INDEX idx_licenses_template_id; ALTER TABLE licenses DROP COLUMN template_id").Error; e != nil {
			t.Fatal(e)
		}
		if e = d.Exec("ALTER TABLE app_versions DROP COLUMN build_verified").Error; e != nil {
			t.Fatal(e)
		}
		if e = d.Exec("DELETE FROM schema_migrations WHERE version>1").Error; e != nil {
			t.Fatal(e)
		}
	}
	var before []model.SchemaMigration
	if e = d.Order("version ASC").Find(&before).Error; e != nil {
		t.Fatal(e)
	}
	want := 3
	if legacy {
		want = 1
	}
	if len(before) != want {
		t.Fatal("unexpected initial migration history", before)
	}
	// Production gateway service creates actual persisted ciphertext.
	if _, e = catalog.NewService(d, master); e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	pool.Close()
	original := []byte(base64.StdEncoding.EncodeToString(master) + "\n")
	if e = os.WriteFile(filepath.Join(dir, "master.key"), original, 0600); e != nil {
		t.Fatal(e)
	}
	backupDir := filepath.Join(dir, "backups")
	os.MkdirAll(backupDir, 0700)
	if e = os.WriteFile(filepath.Join(backupDir, "sentinel"), []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("AUTHGO_DATA_DIR", dir)
	t.Setenv("AUTHGO_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)))
	occupied, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	t.Setenv("AUTHGO_ADDR", occupied.Addr().String())
	t.Setenv("AUTHGO_ADMIN_PASSWORD", "")
	if e := run(); !errors.Is(e, keycheck.ErrMismatch) {
		t.Fatal("startup did not reject wrong master", e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "master.key"))
	if e != nil || !bytes.Equal(raw, original) {
		t.Fatal("master.key changed", e)
	}
	entries, e := os.ReadDir(backupDir)
	if e != nil || len(entries) != 1 || entries[0].Name() != "sentinel" {
		t.Fatal("backups rotated/generated", entries, e)
	}
	d, e = db.Open(dir, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ = d.DB()
	defer pool.Close()
	var after []model.SchemaMigration
	if e = d.Order("version ASC").Find(&after).Error; e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, after) || d.Migrator().HasColumn(&model.AppVersion{}, "build_verified") == legacy || d.Migrator().HasColumn(&model.License{}, "template_id") == legacy {
		t.Fatal("database migrated during failed key validation", before, after)
	}
}
