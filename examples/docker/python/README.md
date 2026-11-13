# Python容器接入示例

在仓库根运行（本仓库SDK，不发布包）：

```sh
AUTHGO_CONFIG='后台复制的配置' docker compose -f examples/docker/python/docker-compose.yml build
AUTHGO_LICENSE='客户授权码' docker compose -f examples/docker/python/docker-compose.yml up -d --no-build
```

配置只在构建时写入程序，不向SDK提供运行时配置源，不把AUTHGO_CONFIG放进容器环境。客户只填AUTHGO_LICENSE。Python构建生成_authgo_build.py。

程序拥有SIGTERM/SIGINT处理器和退出逻辑，SDK不处理信号。正常停止释放席位并退出0；明确拒绝、宽限耗尽等最终失败退出77；宽限/降级只记录变化继续运行。HTTP入口调用不联网的require。关闭最多5秒，释放失败只记录错误。

UID65532、只读根、cap_drop=ALL、no-new-privileges，缓存使用命名卷。保留卷重建仍是同一实例；删除卷是新实例；共卷进程互相替换。没有卷或缓存不可写时显示警告，不保证重启后的断连宽限。docker stop的10秒内退出由真实容器测试断言。正式构建不含测试时钟fixture。

服务地址保持HTTPS；测试仅使用回环HTTP，不放宽TLS。业务监听参数-listen默认为8080，可在测试中使用127.0.0.1:0，不改变授权配置。

首次验证尚未返回时，业务程序也响应停止信号，不等待网络超时；已获得守卫时仍调用有界close。Python、Rust的HTTP请求不占住主信号循环，避免请求正在等待本地校验时拖延停机。测试会暂时使授权服务不可达，断言启动中的容器在10秒内停止且退出码不是137。
