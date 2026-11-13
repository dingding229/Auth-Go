package main

import (
	"authgo/internal/adminpath"
	"authgo/internal/buildinfo"
	"authgo/internal/healthcheck"
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// command handles utility subcommands before config, migrations and background jobs.
func command(args []string, out io.Writer) (handled bool, err error) {
	if len(args) == 0 {
		return false, nil
	}
	if args[0] == "admin-path" {
		if len(args) > 2 || (len(args) == 2 && args[1] != "reset") {
			return true, fmt.Errorf("用法: authgo admin-path [reset]")
		}
		dir := os.Getenv("AUTHGO_DATA_DIR")
		if dir == "" {
			dir = "./data"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, e := adminpath.Command(ctx, dir, len(args) == 2)
		if e != nil {
			return true, e
		}
		_, e = fmt.Fprintln(out, path)
		return true, e
	}
	if len(args) != 1 {
		return true, fmt.Errorf("用法: authgo [version|healthcheck|admin-path [reset]|help]")
	}
	switch args[0] {
	case "version", "--version":
		_, err = fmt.Fprintf(out, "Auth Go %s (commit=%s, built_at=%s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.BuiltAt)
	case "healthcheck":
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err = healthcheck.Check(ctx, os.Getenv("AUTHGO_ADDR"))
		if err == nil {
			_, err = fmt.Fprintln(out, "健康检查通过")
		}
	case "help", "--help", "-h":
		_, err = fmt.Fprintln(out, "用法: authgo [version|healthcheck|admin-path [reset]|help]\n不带参数启动服务；配置使用 AUTHGO_ 环境变量。")
	default:
		err = fmt.Errorf("未知命令 %q；用法: authgo [version|healthcheck|admin-path [reset]|help]", args[0])
	}
	return true, err
}
