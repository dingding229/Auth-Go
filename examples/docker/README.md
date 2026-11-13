# Go容器接入示例

在仓库根构建，配置作为构建参数编译进程序，客户部署只填授权码：

```sh
AUTHGO_CONFIG='后台复制的配置' VERSION=1.0.0 docker compose -f examples/docker/docker-compose.yml build
AUTHGO_LICENSE='客户授权码' docker compose -f examples/docker/docker-compose.yml up -d --no-build
```

AUTHGO_CONFIG只在构建时必填；它不会传入运行容器，也不能覆盖已编译的配置。完整程序负责SIGTERM/SIGINT、正常退出和释放席位，使用`run()`确保defer执行。`/`处理器还会调用本地`Require`。授权失效退出77，正常停止退出0。HTTP业务监听参数`-listen`默认`:8080`；真实容器测试用`127.0.0.1:0`避免共享主机端口冲突，与SDK配置无关。

根文件系统只读，UID65532，cap_drop=ALL；缓存卷保留`instance-id`与加密票据。保留卷重建仍是原实例，删除卷会成为新实例。缓存卷不可写时仅内存运行、无重启宽限，并显示明确警告。

生产服务地址应为HTTPS；真实容器测试使用host网络连接回环HTTP，不放宽TLS。不要把AUTHGO_CONFIG放到客户环境或外部配置文件，也不要输出配置或授权码。容器共享同一卷会相互接管，不能同时稳定使用一个席位。

Python、Node.js、Rust的同等安全示例位于python/、node/、rust/。真实容器测试支持`sh scripts/test-docker-license.sh go,python,node,rust`（串行，每语言完整19项），也可传单语言或all；仅清理本次运行创建的命名资源。

Java、C#、PHP常驻CLI与请求式（FPM、Apache等）示例位于java/、csharp/、php/、php-fpm/、php-apache/。只有PHP_SAPI=cli发送进程instance_session；其他SAPI统一使用请求式缓存锁及租约回收，拒绝由业务返回503而不结束进程。请求式多副本共卷不能检测进程冲突。测试支持`go,python,node,rust,java,csharp,php,php-fpm`，依次运行：各语言测试覆盖授权生命周期；php-fpm 测试组还覆盖真实 mod_php 多进程并发与吊销。Apache基于php:8.1-apache，非root、根只读、cap_drop ALL、no-new-privileges，运行目录在/tmp的tmpfs，使用命名缓存卷；SDK和构建配置不在DocumentRoot内。

构建和启动请求式示例：在仓库根使用`docker compose -f examples/docker/php-apache/docker-compose.yml build`（构建时提供AUTHGO_CONFIG），再设置AUTHGO_LICENSE运行`docker compose -f examples/docker/php-apache/docker-compose.yml up -d --no-build`；FPM将路径换成php-fpm。两个示例均只绑定127.0.0.1:8090，不能同时占用该端口。
