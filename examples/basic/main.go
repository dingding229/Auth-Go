package main

import (
	"context"
	"log"
	"os"

	sdk "authgo/sdk"
)

// 由开发者在构建时写入；不得从环境变量或文件读取配置。
const authConfig = "authgo2.请在构建时替换为后台接入配置"

func main() {
	client, err := sdk.New(authConfig)
	if err != nil {
		log.Fatal(err)
	}
	result, err := client.Check(context.Background(), os.Getenv("AUTHGO_LICENSE"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("授权状态：%s，离线：%t", result.Status, result.Offline)
}
