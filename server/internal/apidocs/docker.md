# Docker 接入

## 1. 准备授权服务器

按 [README 安装](https://github.com/dingding229/Auth-Go#安装docker-compose)，在“系统设置”填写客户可访问的 HTTPS 对外服务地址，再按[快速开始](?tab=quickstart#1-准备软件和授权)创建软件、用户与授权。

软件镜像名填写 Docker Hub 公开仓库，如 `your-org/your-app`，不带标签。首次激活必须联网；客户只填授权码。

反向代理配置、Cloudflare 填入步骤及网段维护要求，
统一见 [HTTPS 反向代理与受信代理](https://github.com/dingding229/Auth-Go#https-反向代理与受信代理)。
客户运行部署另见[给客户的运行说明](?tab=customer)。

## 2. 接入 SDK 与授权

1. 打开软件“接入程序”，选择语言和 PHP 运行模式。
2. 从 [SDK 示例](?tab=sdk)安装对应 SDK，复制接入代码，把接入配置编译进程序。
3. 复制向导模板文件到仓库，保持向导中的目录结构，换入业务逻辑。
4. 使用高层守卫执行激活、心跳、本地票据检查和退出释放；常驻程序最终失败退出 77。

| 语言 | 源码安装 | 参考入口 |
| --- | --- | --- |
| Go | `go.mod` 用 replace 指向 [sdk/go](https://github.com/dingding229/Auth-Go/tree/main/sdk/go) | [main.go](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/main.go) |
| Python | `python -m pip install ./sdk/python` | [main.py](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/python/main.py) |
| Node.js | `npm install ./sdk/node`，ES modules | [main.mjs](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/node/main.mjs) |
| Java | 编译 [SDK 源码](https://github.com/dingding229/Auth-Go/tree/main/sdk/java/src/main/java/io/authgo)，JDK 17+ | [Main.java](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/java/Main.java) |
| C# | 项目引用 [AuthGo.csproj](https://github.com/dingding229/Auth-Go/blob/main/sdk/csharp/AuthGo/AuthGo.csproj)，.NET 8 | [Program.cs](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/csharp/Program.cs) |
| PHP | require [Client.php](https://github.com/dingding229/Auth-Go/blob/main/sdk/php/src/Client.php)，PHP 8.1+、sodium、openssl | [CLI](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/php/main.php)、[FPM](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/php-fpm/index.php)、[Apache](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/php-apache/index.php) |
| Rust | Cargo 路径依赖 [sdk/rust](https://github.com/dingding229/Auth-Go/tree/main/sdk/rust) | [main.rs](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/rust/src/main.rs) |

SDK 尚未发布到公共包仓库。复制源码时保留上述相对目录，或同步调整依赖与 Dockerfile COPY 路径。

### 2.1 试用、功能与维护期

- 试用：软件仅有开关，参数在系统设置统一配置；客户留空授权码申领。[全局参数、限制与转正规则](?tab=protocol#64-免授权码试用)。
- 功能模板：软件详情中建立，发放正式授权时填表使用；保存最终值，不关联模板，修改模板不影响已发授权。
- 维护期：授权可设维护天数或截止时间，留空不限；续期不自动延长维护期，0 天或空时间清除限制。
- 当前版本禁用返回 `VERSION_DISABLED`；版本超出维护期返回 `MAINTENANCE_EXPIRED`，已签名宽限不因此延长。[版本规则](?tab=protocol#63-docker-hub-更新与维护期)。

### 2.2 运行模式与构建常量

常驻程序处理 SIGTERM、关闭守卫；PHP CLI 在事件循环中调用 `tick()`。PHP FPM/Apache 按请求检查，拒绝返回 503，不退出服务进程；空闲时不心跳。开发者须先选模式，不能只替换启动命令。

接入配置、版本均在构建时固定；变更软件、服务域名或信任根需重新构建。不要让客户设置 `AUTHGO_CONFIG`，不要把令牌放进构建参数。

## 3. 构建与 GitHub Actions 发布

### 3.1 本地构建

按向导复制完整构建命令和 Dockerfile，在项目根目录执行。使用向导给出的镜像名和版本，并将示例中的接入配置替换为实际值，例如：

```sh
docker build --build-arg AUTHGO_CONFIG='authgo2.…' --build-arg VERSION=1.2.3 -t your-org/your-app:1.2.3 -f examples/docker/Dockerfile .
docker push your-org/your-app:1.2.3
```

### 3.2 后台自动发布

1. 在“系统设置 → GitHub 与 Docker Hub 发布”填写 GitHub PAT、Docker Hub 用户名及 Read & Write 令牌。新令牌保存时联网验证，失败不保存；“验证”可复查已保存凭据。
2. PAT 仅授权目标仓库，Contents、Secrets、Variables、Actions、Workflows 读写，Metadata 只读；经典令牌须有 `repo`、`workflow`。令牌只写加密保存，可分别清除。
3. 向导“自动发布”填写 `owner/repo` 和分支（默认 `main`），先把模板文件放入该分支，点击“测试连接”。
4. 点击“同步配置到仓库”：只写 `.github/workflows/authgo-publish.yml`、Secrets `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` 与 Variable `AUTHGO_CONFIG`，不代提交业务代码或 Dockerfile。
5. 工作流须在默认分支存在；输入版本号点“发布新版本”，在状态区打开 GitHub 运行链接。

构建在 GitHub Actions 执行，Auth Go 不构建镜像、不挂载 Docker 套接字。推送 `<版本>` 和 `latest`，支持 amd64/arm64。PHP-FPM 另有 nginx 配套镜像；Apache 为单镜像。

手动方式复制同一工作流，设置上述 Secrets/Variable，打 `v1.2.3` 标签或手动输入 `1.2.3`。凭据创建见 [README](https://github.com/dingding229/Auth-Go#8-自动构建并发布到-docker-hub)。

### 3.3 Docker Hub 版本同步

“接入程序”可查看状态、测试连接、立即同步；默认轮询 10 分钟，系统设置最短 5 分钟。只读公开仓库，不下载或代理镜像；手动同步最长约 90 秒，页面每 5 秒刷新。

- 仅收录完整正式版本 `1.2.3`/`v1.2.3`；忽略 latest、短版本、架构后缀和预发布。
- 推送时间优先，回退更新时间；无有效时间忽略。同名已记录时间及说明保留，不因重新推送改变。
- 最多 10 页、1000 标签；未读完整、后续页 403 或失败不撤回旧版本。完整读取后才撤回消失的 Docker 来源版本，再出现会恢复。
- 首页面 403 失败；限流按 Retry-After、X-Retry-After、X-RateLimit-Reset 最晚时间重试，等待期间不能手动绕过。
- 测试连接只读第一页不保存。清空镜像名停止同步，旧版本保留。撤回不等于禁用；拉取命令保留真实 `v` 标签。

## 4. 代码加密（可选）

authgo-pack 已内置在 `docker.io/dingding229/authgo` 镜像中，代码加密构建会自动使用，无需配置。生成模板和工作流使用当前服务的正式版本标签（去掉前缀 v），开发构建回退 latest 并注明。需要更强保证时，用 `docker buildx imagetools inspect docker.io/dingding229/authgo:1.0.2` 查看 Digest，将 Dockerfile 和工作流中镜像的 `:标签` 都替换为 `@sha256:摘要`；镜像自己的摘要在构建完成后才产生，无法写回同一次构建的二进制，不进行运行时仓库查询。

1. 软件详情“打包密钥”创建密钥，复制 key_id 和打包公钥。
2. 向导开启代码加密，填入构建信息，复制受保护模板和构建命令。
3. 在中间构建阶段打包，最终镜像只 COPY 密文、公开 SDK 和启动胶水；不要先复制明文再删除，否则旧层仍有源码。
4. 构建目录应静止，`--out` 必须尚不存在；构建失败保留原文件。版本展示的加密状态与 built_at 从产物登记，不是授权信任源。

| 语言 | 运行方式与限制 |
| --- | --- |
| Go、Rust | `--protect` 就地替换 Linux amd64/arm64 ELF；启动桩解密后 exec 消失，真正业务仍调用 Guard 并释放席位；动态运行库由镜像提供 |
| Python | `install_sealed('core')` 后 import；CPython 主次版本匹配，不含核心包原生扩展和资源 |
| Node.js | `requireSealed('core')`；预先打包为单文件 CommonJS，不支持 ESM/原生 .node |
| Java | `Bootstrap.run` 内存 ClassLoader，复用同一 Guard；不支持依赖落地文件的原生加载 |
| C# | `Bootstrap.RunAsync`，.NET 8 IL-only 内存加载；不支持 native/mixed-mode、AOT、裁剪、单文件发布 |
| PHP | `installSealed`，仅 .php、64 位、每包 256 MiB；受保护请求关闭 opcache，无法确认关闭则失败；[加载边界](https://github.com/dingding229/Auth-Go/blob/main/sdk/php/README.md) |

Go/Rust 内存执行优先 memfd，受限时只回退可执行 tmpfs；两者不可用则退出 77，不放宽容器策略。PID 不变；依赖 `/proc/self/exe` 路径、重执行自身或相对自身找资源的程序需调整。保留非 root、只读根、`cap_drop: ALL` 和默认 seccomp。

试用与正式授权使用同一镜像；试用或零宽限不写内容密钥缓存。正式授权须同时有合法票据和对应密钥缓存才能在原签名宽限内重启；空卷不能离线启动。[格式及完整边界](?tab=protocol#8-代码加密载荷格式)。

代码加密主要阻止无运行授权者直接读取镜像核心；强度为 Go/Rust > Java/C# > Python/Node.js > PHP，无法防止已授权主机导出内存、密钥或明文。PHP 已加载的函数、类及引擎副本不能撤回。

## 5. 水印追查

1. 软件详情“打包密钥”下打开“水印追查”，选择实际执行代码的导出文件。
2. 浏览器本地扫描，只将候选水印提交查询；文件、文件名和片段不上传。
3. 完整且唯一最高频候选才自动查询；平票、部分扫描、取消需人工处理，不能据此认定授权来源。
4. 保留历史打包密钥，追查会使用软件全部新旧标记；删除密钥可能失去历史归属查询能力。

离线扫描（替换命令中的软件标记和导出文件名）：

```sh
docker run --rm --entrypoint /authgo-pack -v "$PWD:/work:ro" docker.io/dingding229/authgo:1.0.2 trace --tag '替换为软件标记' '/work/替换为导出文件'
```

ZIP/JAR 会扫描解压条目及嵌套 JAR；其他压缩格式按普通字节扫描。零槽不是授权值。槽位、限额和结果定义见[水印规范](?tab=protocol#9-水印)。水印仅事后辅助追查，不是授权证据，也不保证无法抹除。

## 6. 交付客户

向导最后一步生成客户 Compose；确认镜像已发布后交付，客户只填授权码，版本可由 latest 改为固定标签。缓存卷、席位、PHP 请求式、断网和反向代理说明统一见[给客户的运行说明](?tab=customer)。
