# C#安全容器示例

在仓库根构建（不发布包）：

```sh
AUTHGO_CONFIG='后台复制的配置' VERSION=1.0.0 docker compose -f examples/docker/csharp/docker-compose.yml build
AUTHGO_LICENSE='客户授权码' docker compose -f examples/docker/csharp/docker-compose.yml up -d --no-build
```

配置由开发者在构建时固化，不向运行容器传AUTHGO_CONFIG；客户只填AUTHGO_LICENSE。Java配置打入jar资源，由主程序读取传给SDK；C#生成Build常量类；PHP生成只读程序常量文件。配置不接受运行时替换。SDK不处理信号或退出，由业务程序负责。

只读根、非root、cap_drop=ALL、no-new-privileges、命名缓存卷。仅绑定127.0.0.1；服务地址使用HTTPS，测试仅允许回环HTTP。保留卷重建保持身份，删除卷成为新实例。不要记录授权码、配置或密钥。测试时钟仅在scripts/fixtures/单独镜像中构建，正式示例没有测试入口。

业务程序自己处理SIGTERM/SIGINT，停止时有界close释放席位，正常退出0，最终授权失败退出77。首次验证失败不启动业务服务；宽限和降级继续运行。每个关键HTTP入口执行不联网require。HTTP监听参数-listen默认8080，测试用127.0.0.1:0避免端口冲突。
