package adminpath

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"authgo/internal/db"
)

// Command never starts a listener, migrations, a second scheduler, or a key loader.
// It opens the existing SQLite file used by the running nonroot process.
func Command(ctx context.Context, dataDir string, reset bool) (string, error) {
	info, err := os.Lstat(filepath.Join(dataDir, "authgo.db"))
	if err != nil {
		return "", fmt.Errorf("读取现有数据库: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("数据库必须是普通文件")
	}
	database, err := db.Open(dataDir, 5*time.Second)
	if err != nil {
		return "", err
	}
	pool, err := database.DB()
	if err != nil {
		return "", err
	}
	defer pool.Close()
	if err = db.CheckSchema(database); err != nil {
		return "", err
	}
	s, err := New(database)
	if err != nil {
		return "", err
	}
	if reset {
		return s.Reset(ctx, Actor{Operator: "local-cli"})
	}
	return s.Current(ctx)
}
