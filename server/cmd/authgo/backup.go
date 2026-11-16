package main

import (
	"authgo/internal/backupfile"
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func unlockBackup(args []string, input io.Reader, out io.Writer) error {
	if len(args) != 3 {
		return fmt.Errorf("用法: authgo backup-unlock <备份文件> <输出.zip>；密码使用 AUTHGO_BACKUP_PASSWORD 或标准输入")
	}
	file, err := os.Open(args[1])
	if err != nil {
		return err
	}
	encrypted, err := backupfile.IsEncrypted(file)
	file.Close()
	if err != nil {
		return err
	}
	password := ""
	if encrypted {
		password = os.Getenv("AUTHGO_BACKUP_PASSWORD")
		if password == "" {
			if file, ok := input.(*os.File); ok {
				info, statErr := file.Stat()
				if statErr != nil {
					return fmt.Errorf("无法读取备份密码")
				}
				if info.Mode()&os.ModeCharDevice != 0 {
					return fmt.Errorf("请通过 AUTHGO_BACKUP_PASSWORD 或管道标准输入提供备份密码，避免终端回显")
				}
			}
			fmt.Fprintln(os.Stderr, "请输入备份密码（标准输入）：")
			line, readErr := bufio.NewReader(io.LimitReader(input, 4098)).ReadString('\n')
			if readErr != nil && readErr != io.EOF {
				return fmt.Errorf("无法读取备份密码")
			}
			password = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		}
		if password == "" {
			return backupfile.ErrPasswordRequired
		}
		if err = backupfile.ValidatePassword(password); err != nil {
			return err
		}
	}
	if err = backupfile.Unlock(args[1], args[2], password); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "备份包已校验并解封，尚未恢复数据库；请按离线恢复步骤校验快照后替换数据。")
	return err
}
