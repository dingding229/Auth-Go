// Package db opens the pure-Go SQLite database and creates its initial schema.
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

// CheckSchema accepts only an empty database or this product's exact baseline.
// It performs no writes, including on unsupported or damaged databases.
func CheckSchema(database *gorm.DB) error {
	var tables int64
	if err := database.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables).Error; err != nil {
		return err
	}
	if tables == 0 {
		return nil
	}
	unsupported := fmt.Errorf("本版本不支持从旧版本升级：数据库必须使用 Auth Go 1.0.0 初始结构")
	if !database.Migrator().HasTable("schema_migrations") {
		return unsupported
	}
	var versions []model.SchemaMigration
	if err := database.Find(&versions).Error; err != nil {
		return unsupported
	}
	if len(versions) != 1 || versions[0].Version != 1 || versions[0].Name != BaselineName {
		return unsupported
	}
	return nil
}

// Migrate creates the single baseline atomically; existing schemas are never converted.
func Migrate(database *gorm.DB) error {
	return database.Transaction(func(tx *gorm.DB) error {
		if err := CheckSchema(tx); err != nil {
			return err
		}
		if tx.Migrator().HasTable("schema_migrations") {
			return nil
		}
		if err := tx.Exec(initialSchema).Error; err != nil {
			return fmt.Errorf("创建初始数据库: %w", err)
		}
		return tx.Create(&model.SchemaMigration{Version: 1, Name: BaselineName, AppliedAt: time.Now().UTC()}).Error
	})
}
