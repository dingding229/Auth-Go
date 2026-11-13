# Protected php-apache Docker 示例

这是可导出的完整语言目录；Docker build context 为仓库根目录，并使用仓库中的 SDK。
业务核心只从认证密文加载。正式授权和试用使用同一镜像，客户仅填写 `AUTHGO_LICENSE`。

## 构建

先构建/加载与目标架构匹配的工具镜像，例如：

```sh
make tools-image TOOLS_IMAGE=authgo-payload-tools TOOLS_VERSION=test \
  TOOLS_PLATFORMS=linux/amd64 TOOLS_OUTPUT=type=docker
```

以下六项是 **build args**，不是容器运行环境变量：
`AUTHGO_TOOLS_IMAGE=authgo-payload-tools:test`、`PAYLOAD_PUBLIC_KEY`、`PAYLOAD_KEY_ID`、
`PAYLOAD_APP_KEY`、`AUTHGO_CONFIG`、`VERSION`（默认 `1.0.0`）。
公钥与编号来自同一软件；`PAYLOAD_APP_KEY` 必须匹配固化配置内的软件标识。
示例默认工具名 `authgo-tools:dev` 是无账号占位；必须在系统设置中替换为实际工具镜像名/版本，
并在构建时显式传入合法且可访问的 `AUTHGO_TOOLS_IMAGE=image:tag`。

```sh
docker buildx build --platform linux/amd64 --load \
  -f examples/docker-protected/php-apache/Dockerfile \
  --build-arg AUTHGO_TOOLS_IMAGE=authgo-payload-tools:test \
  --build-arg PAYLOAD_PUBLIC_KEY="$PAYLOAD_PUBLIC_KEY" \
  --build-arg PAYLOAD_KEY_ID="$PAYLOAD_KEY_ID" \
  --build-arg PAYLOAD_APP_KEY="$PAYLOAD_APP_KEY" \
  --build-arg AUTHGO_CONFIG="$AUTHGO_CONFIG" \
  --build-arg VERSION=1.0.0 -t authgo-protected-php-apache-example:local .
```

多架构 CI 使用 `--platform linux/amd64,linux/arm64`，为工具 `image:tag` 提供两架构清单。
`FROM ${AUTHGO_TOOLS_IMAGE} AS tools` 不指定 BUILDPLATFORM，和应用 build 阶段一样跟随目标架构；
因此每目标架构各自编译、打包，不会执行异架构 pack。工具本身还嵌入两套静态 ELF stub。
工具与业务源码只出现在 build 阶段；最终镜像只 COPY 公开启动器/SDK/运行库和密文。
**不会先 COPY 明文核心再删除**，最后一条 Dockerfile 指令 COPY 密文（Go/Rust 为自带密文的替换 ELF）。
公开 SDK、运行库和解释器启动胶水不是保密核心；PHP 常量固定在公开入口程序内，不读取运行时配置文件。

## 运行与矩阵接口

入口：`/app/entrypoint.sh apache2 -f /app/apache.conf -DFOREGROUND`。
本模式使用真实 mod_php/prefork，不接受 `-listen`；固定监听 HTTP `8080`。
就绪 stdout 为 `HTTP已启动 php-apache :8080`；须再 GET `/` 确认授权及核心实际可用。

七语言 CLI 就绪日志包含 `HTTP已启动`；成功 HTTP `/` 响应包含固定业务标记与语言字段。
精确标记见核心源码；不要把核心源码、未加密编译产物、build helper COPY 到最终镜像。
拒绝后 CLI 返回 `77`，正常 SIGTERM/SIGINT 关闭 Guard、释放实例并返回 `0`。
请求式 PHP 拒绝返回 `503`，不会杀 worker；这不是 CLI 退出码断言的对象。

```sh
# 在本目录使用 Compose；上面六项只在构建时读取。
docker compose up --build -d
# GET http://127.0.0.1:8090/ 验证业务核心，而不只检查进程存活。
docker compose down
```

Compose 保留 nonroot、只读根、cap_drop ALL、no-new-privileges、默认 seccomp（不覆盖）、
512 MiB 应用内存限制、命名缓存卷及 noexec tmpfs；未增加 runtime trust root 或测试开关。
保留命名缓存卷才能使用已签名宽限；不要用 `down -v` 测试保留缓存的重启。
试用不持久化内容密钥缓存，断网后不能靠镜像重新解锁。
高级缓存目录/实例标识行为沿用 SDK，不能拿这些运行环境变量替换接入信任配置。

测试：`scripts/test-docker-license.sh protected`。

停止时 PID 1 shell 先向 SAPI 发 graceful stop，等待所有 worker 退出，再运行短时 CLI Guard，
以同一缓存卷中的稳定实例重新校验/接管并 `close()`；不复用已停止 PID 的 instance_session。
此步骤不解密核心、不启用常驻 sidecar、不会并行占第二个实例；全步骤最多 8 秒，Compose 预留 20 秒。
服务器不可达时只能记录释放未完成，保留缓存，服务端按既有租约回收。
FPM/Apache 空闲 worker 不后台心跳；吊销和心跳测试需持续 HTTP 请求，与 SDK 现有请求式语义一致。

## 最终 PHP 运行库

独立 `runtime` 阶段只来自官方 PHP 镜像，从未 COPY 业务源码、配置或打包输出；
移除其公开的 `/usr/src` 构建/测试语料后，才复制合并后的运行文件系统到 `scratch` 最终阶段。
原官方镜像中的损坏归档回归夹具不会进入最终镜像任何层，严格全层扫描不用对白名单放行。
这不是先把业务明文 COPY 到最终镜像再删除；业务核心一直留在独立 `build` 阶段，仅密文进入最终镜像。
最终镜像保留原系统 CA、动态库、命令及 PHP ini 目录；仍非 root、只读根、drop ALL、默认 seccomp。
