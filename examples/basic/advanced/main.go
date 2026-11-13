package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"authgo/sdk"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "操作失败：", err)
		os.Exit(1)
	}
}
func run() error {
	command := flag.String("command", "verify", "activate / verify / heartbeat / deactivate / auto / fingerprint")
	key := flag.String("key", os.Getenv("AUTHGO_LICENSE"), "授权码")
	cache := flag.String("cache", "./data/sdk-cache", "本地加密缓存目录")
	fingerprint := flag.String("fingerprint", "", "显式覆盖实例指纹（64位SHA256十六进制）")
	version := flag.String("version", "1.0.0", "客户端版本")
	flag.Parse()
	const config = "authgo2.请在构建时替换为后台接入配置"
	client, err := sdk.New(config, sdk.WithCacheDir(*cache))
	if err != nil {
		return err
	}
	if *fingerprint != "" {
		client.FingerprintFunc = func() (string, error) { return *fingerprint, nil }
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	show := func(r *sdk.Result, err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, "校验失败：", err)
			return
		}
		raw, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(raw))
		if r.CacheWarning != nil {
			fmt.Fprintln(os.Stderr, "缓存警告：", r.CacheWarning)
		}
	}
	switch *command {
	case "fingerprint":
		var fp string
		var err error
		if client.FingerprintFunc != nil {
			fp, err = client.FingerprintFunc()
		} else {
			fp, err = sdk.Fingerprint()
		}
		if err != nil {
			return err
		}
		fmt.Println(fp)
	case "activate":
		deadline, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		r, err := client.Activate(deadline, *key, sdk.ActivateOptions{ClientVersion: *version})
		if err != nil {
			return err
		}
		show(r, nil)
	case "verify":
		r, err := client.Verify(ctx)
		if err != nil {
			return err
		}
		show(r, nil)
	case "heartbeat":
		r, err := client.Heartbeat(ctx)
		if err != nil {
			return err
		}
		show(r, nil)
	case "deactivate":
		if err := client.Deactivate(ctx); err != nil {
			return err
		}
		fmt.Println("已停用当前激活，本地宽限缓存已失效")
	case "auto":
		err := client.StartAutoCheck(ctx, show)
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	default:
		return fmt.Errorf("不支持的命令 %q", *command)
	}
	return nil
}
