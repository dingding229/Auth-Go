package db

import (
	"authgo/internal/model"
	"strings"
	"testing"
	"time"
)

func TestBaselineIsAtomicAndIdempotent(t *testing.T) {
	d, e := Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if e = Migrate(d); e != nil {
		t.Fatal(e)
	}
	if e = Migrate(d); e != nil {
		t.Fatal(e)
	}
	var versions []model.SchemaMigration
	if e = d.Find(&versions).Error; e != nil || len(versions) != 1 || versions[0].Version != 1 || versions[0].Name != BaselineName {
		t.Fatal(versions, e)
	}
	for _, table := range []string{"admins", "end_users", "licenses", "activations", "gateway_keys", "payload_keys", "docker_hub_sync_states", "feature_templates", "license_sharing", "trial_claims", "activation_instance_sessions"} {
		if !d.Migrator().HasTable(table) {
			t.Fatal("missing", table)
		}
	}
	var enabled int
	if e = d.Raw("PRAGMA foreign_keys").Scan(&enabled).Error; e != nil || enabled != 1 {
		t.Fatal("foreign keys disabled", e)
	}
	if e = d.Exec("INSERT INTO payload_keys(app_id,key_id,public_key,private_key_encrypted,created_at) VALUES(999,'key','pub','private',CURRENT_TIMESTAMP)").Error; e == nil {
		t.Fatal("foreign key accepted")
	}
	a := model.Admin{Username: "first", PasswordHash: "hash"}
	if e = d.Create(&a).Error; e != nil {
		t.Fatal(e)
	}
	if e = d.Create(&model.Admin{Username: "second", PasswordHash: "hash"}).Error; e == nil {
		t.Fatal("singleton admin not enforced")
	}
}

func TestUnsupportedSchemaIsNotModified(t *testing.T) {
	d, e := Open(t.TempDir(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	pool, _ := d.DB()
	defer pool.Close()
	if e = d.Exec("CREATE TABLE marker(value text NOT NULL);INSERT INTO marker VALUES ('unchanged')").Error; e != nil {
		t.Fatal(e)
	}
	if e = Migrate(d); e == nil || !strings.Contains(e.Error(), "本版本不支持从旧版本升级") {
		t.Fatal(e)
	}
	var value string
	if e = d.Raw("SELECT value FROM marker").Scan(&value).Error; e != nil || value != "unchanged" {
		t.Fatal(value, e)
	}
	if d.Migrator().HasTable("schema_migrations") {
		t.Fatal("unsupported database modified")
	}
}
