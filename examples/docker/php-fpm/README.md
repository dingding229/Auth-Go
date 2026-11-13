# PHP-FPM安全容器示例

在仓库根构建（不发布包）：

```sh
AUTHGO_CONFIG='后台复制的配置' VERSION=1.0.0 docker compose -f examples/docker/php-fpm/docker-compose.yml build
AUTHGO_LICENSE='客户授权码' docker compose -f examples/docker/php-fpm/docker-compose.yml up -d --no-build
```

配置由开发者在构建时固化，不向运行容器传AUTHGO_CONFIG；客户只填AUTHGO_LICENSE。Java配置打入jar资源，由主程序读取传给SDK；C#生成Build常量类；PHP生成只读程序常量文件。配置不接受运行时替换。SDK不处理信号或退出，由业务程序负责。

只读根、非root、cap_drop=ALL、no-new-privileges、命名缓存卷。仅绑定127.0.0.1；服务地址使用HTTPS，测试仅允许回环HTTP。保留卷重建保持身份，删除卷成为新实例。不要记录授权码、配置或密钥。测试时钟仅在scripts/fixtures/单独镜像中构建，正式示例没有测试入口。

FPM与nginx两个容器，PHP4个worker，nginx无特权镜像。请求驱动验证/心跳，SDK用缓存文件锁合并并发；不发送instance_session，因此共卷多副本无法检测冲突。空闲租约到期回收，下一次请求重新竞争。拒绝返回503和错误码，不退出worker；不在请求末close，停止依靠租约回收。详细限制见sdk/php/README.md。
