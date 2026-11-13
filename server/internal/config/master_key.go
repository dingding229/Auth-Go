package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveMasterKey never invents a replacement key for an existing database.
// A hard-link publishes the fully written temporary inode atomically without
// overwriting an existing key, including one won by a concurrent first start.
func ResolveMasterKey(cfg *Config) error {
	if len(cfg.MasterKey) == 32 {
		return nil
	} // Explicit environment key is authoritative.
	path := filepath.Join(cfg.DataDir, "master.key")
	read := func() error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 256 {
			return fmt.Errorf("master.key 必须是包含32字节Base64密钥的普通文件")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("无法读取 master.key")
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != 32 {
			return fmt.Errorf("master.key 格式无效，请恢复原主密钥，不要重新生成")
		}
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("无法将 master.key 权限设为0600")
		}
		cfg.MasterKey = key
		return nil
	}
	if err := read(); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	checkDatabase := func() error {
		if _, err := os.Lstat(filepath.Join(cfg.DataDir, "authgo.db")); err == nil {
			return fmt.Errorf("数据库已存在，但没有可用主密钥：请恢复原 DATA_DIR/master.key 或设置原 AUTHGO_MASTER_KEY；为保护已有加密数据，禁止自动生成新密钥")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("无法确认数据库是否存在，拒绝生成主密钥")
		}
		return nil
	}
	if err := checkDatabase(); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("无法创建数据目录: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("无法生成主密钥")
	}
	file, err := os.CreateTemp(cfg.DataDir, ".master-key-*")
	if err != nil {
		return fmt.Errorf("无法创建主密钥文件")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	fail := func() error { return fmt.Errorf("无法安全保存 master.key，请检查数据目录权限") }
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return fail()
	}
	if _, err = file.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		file.Close()
		return fail()
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return fail()
	}
	if err = file.Close(); err != nil {
		return fail()
	}
	if err := checkDatabase(); err != nil {
		return err
	}
	if err = os.Link(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return read()
		}
		return fail()
	}
	directory, err := os.Open(cfg.DataDir)
	if err != nil {
		return fail()
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		return fail()
	}
	cfg.MasterKey = key
	return nil
}
