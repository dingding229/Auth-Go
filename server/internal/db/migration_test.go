package db

import (
	"archive/zip"
	"authgo/internal/backupfile"
	cryptoutil "authgo/internal/crypto"
	"authgo/internal/keycheck"
	"authgo/internal/model"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func migrationDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	d, err := Open(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := d.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	return d
}

func baselineDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	d := migrationDatabase(t)
	column := "  build_verified integer NOT NULL DEFAULT 0 CHECK(build_verified IN (0,1)),\n"
	if strings.Count(initialSchema, column) != 1 {
		t.Fatal("cannot derive the released baseline schema")
	}
	if err := d.Exec(strings.NewReplacer(column, "", "  template_id integer REFERENCES feature_templates(id) ON DELETE SET NULL,\n", "", "CREATE INDEX idx_licenses_template_id ON licenses(template_id);\n", "").Replace(initialSchema)).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Create(&model.SchemaMigration{Version: 1, Name: BaselineName, AppliedAt: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)}).Error; err != nil {
		t.Fatal(err)
	}
	if d.Migrator().HasColumn(&model.AppVersion{}, "build_verified") || d.Migrator().HasColumn(&model.License{}, "template_id") {
		t.Fatal("baseline already contains a new column")
	}
	return d
}

func migrationRecords(t *testing.T, d *gorm.DB) []model.SchemaMigration {
	t.Helper()
	var rows []model.SchemaMigration
	if err := d.Order("version ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func seedLegacyVersion(t *testing.T, d *gorm.DB) {
	t.Helper()
	if err := d.Exec("INSERT INTO applications (id,name,app_key,app_secret_encrypted,private_key_encrypted,public_key) VALUES (7,'kept','app_kept','','','')").Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Exec("INSERT INTO app_versions (id,app_id,version,changelog,encrypted,built_at) VALUES (9,7,'1.2.3','keep this release',1,?)", time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Exec(`INSERT INTO licenses(id,app_id,key,features) VALUES (11,7,'retained-license','{"export":true}')`).Error; err != nil {
		t.Fatal(err)
	}

}

func assertLegacyVersion(t *testing.T, d *gorm.DB) {
	t.Helper()
	var row model.AppVersion
	if err := d.First(&row, 9).Error; err != nil {
		t.Fatal(err)
	}
	built := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	if row.AppID != 7 || row.Version != "1.2.3" || row.Changelog != "keep this release" || !row.Encrypted || row.BuiltAt == nil || !row.BuiltAt.Equal(built) || row.BuildVerified {
		t.Fatalf("migration lost data or confirmed a manual build: %+v", row)
	}
	var license model.License
	if err := d.First(&license, 11).Error; err != nil {
		t.Fatal(err)
	}
	if license.Key != "retained-license" || license.TemplateID != nil || license.Features["export"] != true {
		t.Fatal("migration changed legacy license", license)
	}

}

func TestBaselineUpgradePreservesDataAndIsIdempotent(t *testing.T) {
	d := baselineDatabase(t)
	seedLegacyVersion(t, d)
	before := migrationRecords(t, d)
	if err := CheckSchema(d); err != nil {
		t.Fatal(err)
	}
	if d.Migrator().HasColumn(&model.AppVersion{}, "build_verified") || !reflect.DeepEqual(before, migrationRecords(t, d)) {
		t.Fatal("CheckSchema modified the baseline")
	}
	if err := Migrate(d); err != nil {
		t.Fatal(err)
	}
	after := migrationRecords(t, d)
	if len(after) != 3 || after[0] != before[0] || after[1].Version != 2 || after[1].Name != "authgo_1_0_3_build_verified" || after[2].Version != 3 || after[2].Name != "authgo_1_0_3_license_template" {
		t.Fatal("incorrect upgrade history", after)
	}
	if !d.Migrator().HasColumn(&model.AppVersion{}, "build_verified") || !d.Migrator().HasColumn(&model.License{}, "template_id") {
		t.Fatal("upgrade did not add build_verified")
	}
	assertLegacyVersion(t, d)
	if err := d.Exec("UPDATE app_versions SET build_verified=2 WHERE id=9").Error; err == nil {
		t.Fatal("build_verified check constraint was not installed")
	}
	if err := CheckSchema(d); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(d); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, migrationRecords(t, d)) {
		t.Fatal("repeated migration changed history")
	}
	assertLegacyVersion(t, d)
}

func TestFreshAndUpgradedVersionColumnsMatch(t *testing.T) {
	fresh, upgraded := migrationDatabase(t), baselineDatabase(t)
	for _, d := range []*gorm.DB{fresh, upgraded} {
		if err := Migrate(d); err != nil {
			t.Fatal(err)
		}
	}
	type column struct {
		CID          int `gorm:"column:cid"`
		NotNull      int `gorm:"column:not_null"`
		PK           int `gorm:"column:pk"`
		Name, Type   string
		DefaultValue *string `gorm:"column:dflt_value"`
	}
	columns := func(d *gorm.DB, table string) []column {
		var out []column
		if err := d.Raw(`SELECT cid,name,type,"notnull" AS not_null,dflt_value,pk FROM pragma_table_info(?) ORDER BY cid`, table).Scan(&out).Error; err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, table := range []string{"app_versions", "licenses"} {
		left, right := columns(fresh, table), columns(upgraded, table)
		if len(left) == 0 || !reflect.DeepEqual(left, right) {
			t.Fatal("fresh and upgraded columns differ", table, left, right)
		}
	}
	type foreignKey struct{ Table, From, To, OnDelete string }
	keys := func(d *gorm.DB) []foreignKey {
		var out []foreignKey
		if err := d.Raw(`SELECT "table","from","to",on_delete FROM pragma_foreign_key_list('licenses') WHERE "from"='template_id'`).Scan(&out).Error; err != nil {
			t.Fatal(err)
		}
		return out
	}
	if left, right := keys(fresh), keys(upgraded); len(left) != 1 || !reflect.DeepEqual(left, right) || left[0].OnDelete != "SET NULL" {
		t.Fatal("fresh and upgraded template foreign keys differ", left, right)
	}
	for _, d := range []*gorm.DB{fresh, upgraded} {
		if !d.Migrator().HasIndex(&model.License{}, "idx_licenses_template_id") {
			t.Fatal("missing template source index")
		}
	}
}

func TestInvalidMigrationHistoryIsRejectedWithoutWrites(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{
		{"empty-history", "DELETE FROM schema_migrations"},
		{"missing-baseline", "UPDATE schema_migrations SET version=2,name='authgo_1_0_3_build_verified'"},
		{"wrong-baseline-name", "UPDATE schema_migrations SET name='other'"},
		{"unknown-version", "INSERT INTO schema_migrations VALUES (4,'unknown',CURRENT_TIMESTAMP)"},
		{"wrong-migration-name", "INSERT INTO schema_migrations VALUES (2,'other',CURRENT_TIMESTAMP)"},
		{"wrong-third-name", "INSERT INTO schema_migrations VALUES (2,'authgo_1_0_3_build_verified',CURRENT_TIMESTAMP),(3,'other',CURRENT_TIMESTAMP)"},
		{"missing-second", "INSERT INTO schema_migrations VALUES (3,'authgo_1_0_3_license_template',CURRENT_TIMESTAMP)"},
		{"unknown-after-current", "INSERT INTO schema_migrations VALUES (2,'authgo_1_0_3_build_verified',CURRENT_TIMESTAMP),(3,'authgo_1_0_3_license_template',CURRENT_TIMESTAMP),(4,'unknown',CURRENT_TIMESTAMP)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := baselineDatabase(t)
			seedLegacyVersion(t, d)
			if err := d.Exec(tc.sql).Error; err != nil {
				t.Fatal(err)
			}
			before := migrationRecords(t, d)
			for _, check := range []func(*gorm.DB) error{CheckSchema, Migrate} {
				if err := check(d); err == nil || !strings.Contains(err.Error(), "数据库结构不受支持") {
					t.Fatal("invalid history accepted", err)
				}
				if !reflect.DeepEqual(before, migrationRecords(t, d)) || d.Migrator().HasColumn(&model.AppVersion{}, "build_verified") {
					t.Fatal("rejected database was modified")
				}
				var changelog string
				if err := d.Raw("SELECT changelog FROM app_versions WHERE id=9").Scan(&changelog).Error; err != nil || changelog != "keep this release" {
					t.Fatal("rejected migration changed data", changelog, err)
				}
			}
		})
	}
}

func TestMigrationRecordFailureRollsBackAlter(t *testing.T) {
	d := baselineDatabase(t)
	seedLegacyVersion(t, d)
	before := migrationRecords(t, d)
	if err := d.Exec("CREATE TRIGGER reject_migration BEFORE INSERT ON schema_migrations WHEN NEW.version=2 BEGIN SELECT RAISE(ABORT,'record unavailable'); END").Error; err != nil {
		t.Fatal(err)
	}
	if err := Migrate(d); err == nil {
		t.Fatal("migration succeeded without its record")
	}
	if d.Migrator().HasColumn(&model.AppVersion{}, "build_verified") || !reflect.DeepEqual(before, migrationRecords(t, d)) {
		t.Fatal("failed migration was partially committed")
	}
	if err := d.Exec("DROP TRIGGER reject_migration").Error; err != nil {
		t.Fatal(err)
	}
	if err := Migrate(d); err != nil {
		t.Fatal(err)
	}
	assertLegacyVersion(t, d)
}

func TestLegacyZIPRestoreAcceptsBaselineAndUpgrades(t *testing.T) {
	d := baselineDatabase(t)
	seedLegacyVersion(t, d)
	master := bytes.Repeat([]byte{3}, 32)
	box, err := cryptoutil.NewCipher(master)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := box.Encrypt([]byte("retained secret"), []byte("application:app_kept:app_secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Exec("UPDATE applications SET app_secret_encrypted=? WHERE id=7", secret).Error; err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	snapshot, bundle, unlocked := filepath.Join(dir, "snapshot.db"), filepath.Join(dir, "old.zip"), filepath.Join(dir, "unlocked.zip")
	if err := d.Exec("VACUUM INTO ?", snapshot).Error; err != nil {
		t.Fatal(err)
	}
	if err := backupfile.Write(snapshot, bundle, master); err != nil {
		t.Fatal(err)
	}
	if err := backupfile.Unlock(bundle, unlocked, ""); err != nil {
		t.Fatal("legacy ZIP rejected", err)
	}
	archive, err := zip.OpenReader(unlocked)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	restored := t.TempDir()
	for _, entry := range archive.File {
		reader, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(filepath.Join(restored, entry.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			reader.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(file, reader)
		closeErr, readErr := file.Close(), reader.Close()
		if copyErr != nil || closeErr != nil || readErr != nil {
			t.Fatal(copyErr, closeErr, readErr)
		}
	}
	raw, err := os.ReadFile(filepath.Join(restored, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || !bytes.Equal(key, master) {
		t.Fatal("restored key changed", err)
	}
	loaded, err := Open(restored, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := loaded.DB()
	defer pool.Close()
	// Match startup ordering: schema and key checks precede any migration.
	if err := CheckSchema(loaded); err != nil {
		t.Fatal(err)
	}
	if err := keycheck.Validate(context.Background(), loaded, key); err != nil {
		t.Fatal(err)
	}
	if len(migrationRecords(t, loaded)) != 1 || loaded.Migrator().HasColumn(&model.AppVersion{}, "build_verified") {
		t.Fatal("validation changed the restored baseline")
	}
	if err := Migrate(loaded); err != nil {
		t.Fatal(err)
	}
	if len(migrationRecords(t, loaded)) != 3 {
		t.Fatal("restored backup not upgraded")
	}
	assertLegacyVersion(t, loaded)
	if err := keycheck.Validate(context.Background(), loaded, key); err != nil {
		t.Fatal("migration damaged restored ciphertext", err)
	}
}

func TestSecondMigrationUpgradesToLicenseTemplate(t *testing.T) {
	d := baselineDatabase(t)
	seedLegacyVersion(t, d)
	if err := d.Exec(migrations[1].sql).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Create(&model.SchemaMigration{Version: 2, Name: migrations[1].name, AppliedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(d); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(d); err != nil {
		t.Fatal(err)
	}
	if len(migrationRecords(t, d)) != 3 {
		t.Fatal("third migration not recorded")
	}
	assertLegacyVersion(t, d)
	source := model.FeatureTemplate{AppID: 7, Name: "source", Features: model.JSONMap{}}
	if err := d.Create(&source).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Model(&model.License{}).Where("id=11").Update("template_id", source.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(&source).Error; err != nil {
		t.Fatal(err)
	}
	assertLegacyVersion(t, d)
}
