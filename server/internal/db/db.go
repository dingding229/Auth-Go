// Package db opens the pure-Go SQLite database and applies ordered schema migrations.
package db

import (
	"authgo/internal/model"
	_ "embed"
	"fmt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func Open(dataDir string, busyTimeout time.Duration) (*gorm.DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录: %w", err)
	}
	path, err := filepath.Abs(filepath.Join(dataDir, "authgo.db"))
	if err != nil {
		return nil, err
	}
	// Create the DB with private permissions before handing it to SQLite.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("创建 SQLite 文件: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	// URI PRAGMAs apply to every new connection, not only the first pooled connection.
	params := url.Values{}
	params.Add("_pragma", "journal_mode(WAL)")
	params.Add("_pragma", "foreign_keys(1)")
	params.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeout.Milliseconds()))
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: params.Encode()}).String()
	// glebarez/sqlite uses glebarez/go-sqlite with modernc.org/sqlite/lib (no CGO).
	database, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // No SQL/password/token values in logs.
	})
	if err != nil {
		return nil, fmt.Errorf("连接 SQLite: %w", err)
	}
	pool, err := database.DB()
	if err != nil {
		return nil, err
	}
	// Serialize writes; SQLite only supports one writer at a time.
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	if err := pool.Ping(); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("检查 SQLite 连接: %w", err)
	}
	return database, nil
}

//go:embed schema.sql
var initialSchema string

const BaselineName = "authgo_1_0_0"

// schema.sql contains the latest schema; new databases record all migrations
// without replaying ALTER statements already reflected in that snapshot.
var migrations = []struct{ name, sql string }{
	{BaselineName, initialSchema},
	{"authgo_1_0_3_build_verified", "ALTER TABLE app_versions ADD COLUMN build_verified integer NOT NULL DEFAULT 0 CHECK(build_verified IN (0,1))"},
	{"authgo_1_0_3_license_template", "ALTER TABLE licenses ADD COLUMN template_id integer REFERENCES feature_templates(id) ON DELETE SET NULL; CREATE INDEX idx_licenses_template_id ON licenses(template_id)"},
	{"authgo_1_0_6_version_architectures", "ALTER TABLE app_versions ADD COLUMN architectures text NOT NULL DEFAULT ''"},
}

// CheckSchema accepts an empty database or an ordered prefix of known migrations.
// It performs no writes, including on unsupported or damaged databases.
func CheckSchema(database *gorm.DB) error {
	var tables int64
	if err := database.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables).Error; err != nil {
		return err
	}
	if tables == 0 {
		return nil
	}
	unsupported := fmt.Errorf("数据库结构不受支持：必须包含 Auth Go 1.0.0 基线及按顺序匹配的已知迁移")
	if !database.Migrator().HasTable("schema_migrations") {
		return unsupported
	}
	var versions []model.SchemaMigration
	if err := database.Order("version ASC").Find(&versions).Error; err != nil {
		return unsupported
	}
	if len(versions) == 0 || len(versions) > len(migrations) {
		return unsupported
	}
	for i, v := range versions {
		if v.Version != i+1 || v.Name != migrations[i].name {
			return unsupported
		}
	}
	return nil
}

// Migrate creates the current schema or applies missing migrations atomically.
func Migrate(database *gorm.DB) error {
	return database.Transaction(func(tx *gorm.DB) error {
		if err := CheckSchema(tx); err != nil {
			return err
		}
		fresh := !tx.Migrator().HasTable("schema_migrations")
		var applied int64
		if fresh {
			if err := tx.Exec(migrations[0].sql).Error; err != nil {
				return fmt.Errorf("创建初始数据库: %w", err)
			}
		} else if err := tx.Model(&model.SchemaMigration{}).Count(&applied).Error; err != nil {
			return err
		}
		for i := int(applied); i < len(migrations); i++ {
			migration := migrations[i]
			if !fresh {
				if err := tx.Exec(migration.sql).Error; err != nil {
					return fmt.Errorf("执行数据库迁移 %d: %w", i+1, err)
				}
			}
			if err := tx.Create(&model.SchemaMigration{Version: i + 1, Name: migration.name, AppliedAt: time.Now().UTC()}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
