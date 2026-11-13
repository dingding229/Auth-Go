# Docker接入与部署

## 部署 Auth Go 授权服务器

正式镜像为 `docker.io/dingding229/authgo:1.0.0`，也可用 `docker.io/dingding229/authgo:latest` 跟随稳定发布；当前正式部署只保留 `1.0.0` 和 `latest` 两个标签。部署参数见 [部署指南](https://github.com/dingding229/Auth-Go/blob/main/README.md#安装docker-compose)。

授权服务器只需下载根 Compose 文件，按 [README 安装步骤](https://github.com/dingding229/Auth-Go/blob/main/README.md#安装docker-compose)拉取并启动，不需要源码。

以下内容说明开发者自己的受授权程序，其镜像仓库和标签由开发者管理。

## 给开发者：五步接入

### 1. 创建软件和授权

在管理端创建软件，打开“接入程序”向导，填写Docker Hub镜像名，例如`your-org/your-app`（不含标签）。发放授权默认KEY+FLOATING，同时运行实例数为1；可显式选择KEY-only。

授权服务器地址应提前确定，例如`https://auth.example.com`。接入配置包含固定地址、软件标识及公钥等信任根，可以公开，但必须在构建时写入程序；不能让客户通过运行时环境变量或外部配置文件替换。`app_secret`不是调用方身份凭据。其他密钥、私有配置和Docker Hub令牌不要放进镜像，不要输出接入配置或授权码。

### 免授权码试用

开发者可在软件的“免授权码试用”中开启，设置1至365天（默认14天）。客户首次部署时留空AUTHGO_LICENSE即可启动试用；软件未开放试用时需填写正式授权码。程序使用同一镜像，不需要试用专用版本。启动只显示“当前为试用”，不会输出授权码；SDK只在现有加密缓存中保存申领结果。

试用同时运行1个实例，有效期从申领时开始。同一实例重启不重新发放；即使未保留卷，同一网络在30天内仍取回原试用。**同一NAT后的多台机器共用一个试用**，同时启动第二个实例会受实例数限制。关闭试用不影响已发放试用，软件停用仍按正常授权规则拒绝运行。

**试用没有断网宽限，需要稳定联网**；网络中断时常驻实例退出，建议compose使用`restart: unless-stopped`，请求式PHP返回503，连接恢复后再试。到期后常驻实例退出77，请联系提供方。管理员可在授权详情“转为正式授权”分配用户并设置有效期，实例下一次校验恢复正式授权规则，无需重启；客户也可以填写正式AUTHGO_LICENSE后重启，原试用的席位会在正式激活成功时释放。过期试用不会因重建而延期。

开发者说明：试用票据包含“签发时间加校验间隔再加30秒”的刷新重叠，且始终受授权到期时间封顶。它只供在线刷新时本地校验旧票据；SDK仍按原校验间隔联网，网络失败立即拒绝，不会把刷新重叠当作断网宽限。

局限：删除卷并更换IP可以重复试用。试用用于方便客户评估，并非防护手段；每个软件的同IP规则按IPv4地址或IPv6 /64归并，全部软件每天最多新建100个试用，复用不占新建额度。试用可在软件设置中选择功能模板，仅复制模板的功能项；未选择时功能项为空对象。实例数始终固定为1，有效期始终取试用天数，模板其他默认值不用于试用。已发放试用不受模板修改影响。

### 更新维护期

发放授权时可在“更多选项”填写更新维护天数，0表示不限；批量发放同样支持。授权详情的“修改维护期”可单独调整，续期时默认保持原维护期，只有勾选“同时修改更新维护期”才会改变。维护期和授权到期时间相互独立：维护期结束后仍能运行维护期内发布的版本，新版本可能需要续期。用户中心显示维护期、可用最高版本和续期提示，只给出有权使用的Docker Hub版本拉取命令。

版本发布时间等于维护期到期时间时仍可用，晚于它才拒绝。尚未收录或没有发布时间的版本不会因同步延迟被拒绝；重新推送旧标签不会改变已记录的发布时间。断网时依旧使用已有缓存和宽限，不在客户端按本地时间判断维护期；联网后发现超出维护期才拒绝。修改维护期后下一次联网检查即可恢复，无需重新激活。

局限：不加密时版本号写在二进制里，能修改二进制的客户可以通过修改上报版本绕过维护期限制。加密方案使用信封里的构建时间加强这一边界。

### 自动同步Docker Hub版本

在软件“接入程序”的镜像名附近，可查看Docker Hub同步状态、最近错误、收录版本数和已忽略标签数，也可以“测试连接”或“立即同步”。只支持Docker Hub公开仓库，无需令牌；不下载镜像、不代理拉取。镜像名支持`namespace/repository`和可选的`docker.io/`前缀。手动同步在后台执行，最长约90秒，页面每5秒查询 running、last_result 和 last_error；系统设置“版本同步”中的轮询间隔用于Docker Hub，默认10分钟，最短5分钟。

只接受`1.2.3`或`v1.2.3`这样的完整正式版本标签；`latest`、`1.2`、`1.2.3-amd64`和预发布标签都会忽略。发布时间优先取标签推送时间，没有时取更新时间；缺少有效时间的标签忽略。同名版本一旦记录发布时间，重新推送不会改变它。已存在的同名版本保留原有来源和说明，仅在发布时间为空时补齐。

Docker Hub匿名接口只能读取最新1000个标签（每页100个，最多10页）。第10页仍有下一页时，只保存已读到的版本，不撤回旧版本；后续页返回403时也保留已读内容，不撤回旧版本。第一页被拒绝访问则同步失败，请确认仓库是公开仓库。只有成功读取完整标签列表且未达到10页上限，才撤回消失的Docker Hub版本。失败、仓库不可用、限流或达到上限都不会撤回旧版本。重新出现的标签会恢复；Docker Hub只撤回Docker来源的版本。撤回不等于禁用：撤回只影响版本列表状态和更新提示，不阻止已运行版本；明确“禁用版本”才会在联网校验时拒绝。

限流期间会显示重试时间，取Retry-After、X-Retry-After和X-RateLimit-Reset中最晚的时间，到期前手动同步也不能发起请求。测试连接只读取第一页，不保存版本。修改镜像名后重新同步；清空时停止同步，已有版本保留。Docker Hub版本在后台显示来源“Docker Hub”，可以像其他版本一样禁用。

该软件的授权用户在用户中心可复制`docker pull namespace/repository:标签`。显示版本会去掉开头的v，拉取命令保留仓库真实标签，避免只有v标签时拉取不存在的地址。Docker版本只提供镜像版本信息，没有文件下载地址；没有配置镜像的软件不提供更新拉取命令；不托管安装包或代理下载。

### 2. 获取SDK和接入代码

七种SDK尚未发布到公共包仓库。从本仓库复制所需的[sdk/](https://github.com/dingding229/Auth-Go/tree/main/sdk/)与[examples/docker/](https://github.com/dingding229/Auth-Go/tree/main/examples/docker/)子目录并保留原路径，再把业务入口替换成自己的处理器；也可以放到`third_party`并相应修改项目引用和Dockerfile的COPY路径。

| 语言 | 源码位置与本地安装 | 容器参考入口 |
| --- | --- | --- |
| Go | [sdk/go](https://github.com/dingding229/Auth-Go/tree/main/sdk/go)，go.mod使用replace指向本地SDK | [examples/docker/main.go](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/main.go) |
| Python | `python -m pip install ./sdk/python` | [examples/docker/python/main.py](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/python/main.py) |
| Node.js | `npm install ./sdk/node`，ES modules | [examples/docker/node/main.mjs](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/node/main.mjs) |
| Java | 编译[sdk/java/src/main/java/io/authgo/*.java](https://github.com/dingding229/Auth-Go/tree/main/sdk/java/src/main/java/io/authgo)，JDK17+ | [examples/docker/java/Main.java](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/java/Main.java) |
| C# | 项目引用[sdk/csharp/AuthGo/AuthGo.csproj](https://github.com/dingding229/Auth-Go/blob/main/sdk/csharp/AuthGo/AuthGo.csproj)，.NET8 | [examples/docker/csharp/Program.cs](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/csharp/Program.cs) |
| PHP常驻CLI | require [sdk/php/src/Client.php](https://github.com/dingding229/Auth-Go/blob/main/sdk/php/src/Client.php)，PHP8.1+、sodium和openssl | [examples/docker/php/main.php](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/php/main.php) |
| PHP请求式 | 同一PHP SDK，不同业务入口 | [examples/docker/php-fpm/index.php](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/php-fpm/index.php)或[examples/docker/php-apache/index.php](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/php-apache/index.php) |
| Rust | Cargo.toml路径依赖[sdk/rust](https://github.com/dingding229/Auth-Go/tree/main/sdk/rust) | [examples/docker/rust/src/main.rs](https://github.com/dingding229/Auth-Go/blob/main/examples/docker/rust/src/main.rs) |

使用高层Guard接口，配置是必填参数。授权码缺省读取`AUTHGO_LICENSE`。首次验证成功后才开始业务。常驻程序由业务处理SIGTERM、停止业务和调用close释放席位；SDK不接管信号或启动子进程。关键业务入口调用Require/require作本地校验，不联网。宽限只通知变化，宽限结束必须停止，最终失败通过完成信号通知业务，常驻程序退出77。不要只调用一次check后永远不处理后续结果。向导中的代码是嵌入业务的核心片段；上述目录包含完整启动、信号和关闭示例。

### PHP运行方式选择

只有PHP_SAPI=cli算常驻模式；FPM、Apache、CGI、LiteSpeed、cli-server等其他SAPI都按请求式运行。请求式示例每个请求调用start_guard，未到截止时间只本地校验；缓存文件锁合并多个worker的联网检查。请求结束不调用close。请求式业务应捕获授权错误并返回HTTP503和明确原因，不调用exit(77)结束worker。需要严格按实例计数时选择常驻CLI；请求式不发送进程级instance_session，无法检测多副本共用同一缓存卷的冲突。

### 3. 构建时写入配置和版本

向导提供可直接使用的Dockerfile示例。构建参数`AUTHGO_CONFIG`只用于构建：Go通过链接参数写入常量变量，Python生成`_authgo_build.py`，Node.js生成`authgo-build.json`，Java打包资源，C#生成常量类，PHP生成只读程序内的常量文件，Rust使用`env!`。这些内容是构建产物，不是客户挂载的配置文件；SDK不读取环境变量或文件来选择信任根。运行容器不设置`AUTHGO_CONFIG`。

Go、Python、Node.js、Java、C#、PHP的版本由构建参数VERSION写入，发布标签去掉开头的v；Rust使用Cargo.toml的package.version（`env!("CARGO_PKG_VERSION")`），发布前须与标签对应。客户端需要上报版本，管理员可以禁用指定版本；被禁用的常驻程序下次联网会停止，请求式返回503。

修改接入地址、公钥、AppSecret或网关配置后必须重新构建并发布。重新生成AppSecret会立即使旧HMAC配置失效；网关轮换仅在指定过渡期接受旧配置，过期后旧程序不能在线验证，已有可信缓存只能使用原签名宽限。换授权服务器域名同样需要重新发版。

### 4. GitHub Actions发版

向导提供打标签构建并推送的Actions文件。在仓库Actions Variables中设置`AUTHGO_CONFIG`（使用后台生成的配置）；只设置两个Secrets：`DOCKERHUB_USERNAME`和`DOCKERHUB_TOKEN`。配置不是机密，不需要第三个secret。不要把令牌写进构建参数或镜像。

打`v1.2.3`标签后，流水线构建该版本镜像并推送`v1.2.3`和`latest`。PHP-FPM还构建并推送无特权nginx配套镜像；Apache使用单个真实mod_php镜像。明文程序在客户手中无法做到绝对防破解：有能力的客户可以修改程序绕过校验，Python、Node.js源码尤其容易直接读取和修改，Require只能提高修改成本；如需提高还原成本，可启用下述代码加密功能；其边界见 下方代码加密边界说明。

### 5. 发给客户的compose

客户使用向导最后一步的compose，只需填授权码，无需配置授权服务器或安装SDK。默认镜像标签为latest，可改为已发布的固定版本。先验证发布镜像存在，再交付compose。PHP运行模式必须由开发者在向导中选择，不能只改容器命令来混用两种模型。

## 代码加密（可选）

代码加密是可选的，未启用时沿用上面的 SDK Guard 接入流程。启用后公开镜像只发布核心代码的密文，
运行时须先完成授权，服务端认证 `payload.json` 信封后才下发内容密钥。**不加密数据文件**。

### 发布流程

1. 管理员先在系统设置填写已构建的 **authgo-pack 工具镜像名和版本**；没有硬编码的仓库账号。
   `make tools-image TOOLS_IMAGE=<仓库/工具镜像> TOOLS_VERSION=<版本>` 默认构建 amd64/arm64 的 OCI 归档；
   单架构本地测试可设置 `TOOLS_PLATFORMS=linux/amd64 TOOLS_OUTPUT=type=docker`。
   默认文件在 `bin/authgo-tools-<版本>.oci.tar`，是有 manifest/config/压缩层的真正双架构镜像归档，**不是** `type=local` 导出的两个裸二进制。
   使用支持多架构镜像存储的 Docker（例如 containerd image store）时可运行 `docker load -i <归档>`，
   再以构建时指定的 `TOOLS_IMAGE:TOOLS_VERSION` 作 `COPY --from` 来源；经典单架构存储请使用上述单架构 `type=docker` 构建。
   `scripts/test-tools-image.py` 运行默认 make 参数、核验两架构 blob/diffID/ELF、导入镜像，
   并用导入标签执行真实 `COPY --from`、原生打包和结构校验。ARM64 的 ELF/平台检查不冒充 ARM64 原生运行。
   该目标不推送。工具镜像只有静态 `/authgo-pack`，含两架构的启动桩，可用 `COPY --from=tools` 取用。
2. 软件工作台接入向导先保存客户镜像名，再选择“代码加密：启用”。同一向导复用现有“打包密钥”组件生成、
   查看和轮换公钥，显示真实 `key_id` 与公钥；私钥始终由授权服务器保存。轮换不影响已发布旧镜像。
3. 按语言复制入口、`Dockerfile` 和构建所需参考文件，路径为 [examples/docker-protected/](https://github.com/dingding229/Auth-Go/tree/main/examples/docker-protected/) 下对应目录。
   `AUTHGO_CONFIG` 只作为公开**构建参数**，以字面量、编译常量或链接常量固化进启动代码，
   不能改为运行时从客户环境变量或配置文件加载信任根。`AUTHGO_PAYLOAD_DIR` 只定位公开密文，不选择服务地址或公钥。
4. 构建参数包括 `AUTHGO_TOOLS_IMAGE=<镜像名>:<版本>`、`PAYLOAD_PUBLIC_KEY`、`PAYLOAD_KEY_ID`、
   `PAYLOAD_APP_KEY`、`AUTHGO_CONFIG`、`VERSION`。不需要任何打包私钥，不要把授权码放进构建参数。
   生成的 GitHub Actions 使用 buildx 的 `linux/amd64,linux/arm64`；每个目标架构分别编译、运行打包工具并生成新信封，
   不能在 amd64 上打包一次后把同一 ELF 密文复制到 arm64。
5. 在版本创建/编辑或“软件版本详情”中登记“代码加密”和打包产物 `payload.json` 的 `built_at`。
   手动版本与同步版本均可登记，后续 Docker Hub 同步保留这些字段；未填写的构建记录显示未登记加密。
   **这些字段只供展示，绝不是授权信任源**。维护期判断始终使用已认证信封的 `built_at`，不会信任管理员填的展示时间。

工具镜像尚未发布时不要给客户不可访问的引用；本仓库示例和测试不推送任何仓库。
客户仍只填 `AUTHGO_LICENSE`；每个实例使用自己的持久缓存卷，保留非 root、只读根文件系统、`cap_drop: ALL` 和默认 seccomp。

### 七语言写法与限制

| 语言 | 核心加载方式 | 示例目录与边界 |
|---|---|---|
| Go | `authgo-pack --protect /app`，启动桩解密后 exec；业务 `StartGuard` | `go/`；PID 1 是真正业务程序，Linux ELF amd64/arm64；示例含 100 MiB 数据用于验证大程序 |
| Rust | 同一 Go 启动桩保护 ELF，业务 `Guard::start` | `rust/`；同样 100 MiB；libc/原生运行库不属于核心密文 |
| Python | `guard.install_sealed('core')` 后 `import core` | `python/`；CPython bytecode 主次版本必须与打包时一致，不支持核心包中的原生扩展或资源文件 |
| Node.js | `await guard.requireSealed('core')` | `node/`；单文件 CommonJS，先打包依赖，不支持 ESM/原生 `.node`，公开启动胶水和 SDK 不是核心密文 |
| Java | `Bootstrap.run(options, 'app', args)` | `java/`；JAR 内存 ClassLoader，复用 `Guards.current()` 的同一 Guard，不支持依赖落地文件的原生加载 |
| C# | `Bootstrap.RunAsync(options, args)` | `csharp/`；net8.0，IL-only、内存 AssemblyLoadContext；不支持 native/mixed-mode、AOT、裁剪和单文件发布 |
| PHP | `guard->installSealed('core')` 后 `require 'authgo-sealed://core/bootstrap.php'` | `php/`、`php-fpm/`、`php-apache/`；严格只读 USTAR，仅 `.php`，64 位、256 MiB/包，FPM 控制器拒绝返回 503 不杀 worker |

Go/Rust 的 Guard 仍位于业务进程，启动桩 exec 后消失，不是常驻授权 sidecar。
Java/C# 受保护业务复用 Bootstrap 的 Guard，不再单独启动第二个 Guard，避免抢占同一席位。
所有常驻应用负责正常停止并关闭 Guard；PHP 常驻 CLI 必须在事件循环中定时 `tick()`。
FPM/Apache 每请求重新校验及加载，空闲时不后台心跳；停止脚本先排空业务 worker，再一次性完成同实例的席位释放，
授权服务器不可达时不能保证立即释放，仍受签名租约约束。

PHP 是保护最弱的语言，扩展可读取解密后的源码。实测 opcache 会缓存裸相对 include，因此安装前关闭**当前受保护请求**的 opcache，
无法确认关闭（如管理员禁用 `ini_set`）时不解锁、失败关闭。CLI 的关闭持续到进程退出。此取舍增加请求编译开销。
拒绝后撤销加载器挂载及预读缓冲，但不能撤回已经运行的代码、已定义类/函数、引擎副本或应用通过 fread 取得的明文。
新 Guard 重装不是 PHP 代码热更新。详细路径、相对加载、自动加载与缓存边界见 [sdk/php/README.md](https://github.com/dingding229/Auth-Go/blob/main/sdk/php/README.md)。

### 镜像层、离线与安全边界

- 使用多阶段构建：源码与打包仅在中间阶段，最终阶段从未 COPY 明文核心；不能先 COPY 明文后在另一层删除。
  将密文的 COPY 尽量放在 Dockerfile 最后一层，以减少代码变化导致的运行库层缓存失效。
- 加密文件、公开 SDK、启动胶水、基础镜像、数据文件和公钥都可公开。不要把其他密钥或敏感数据混入基础镜像和数据层。
- 强度排序：**Go/Rust > Java/C# > Python/Node.js > PHP**。解释型及字节码代码解密后更容易从进程内存还原，
  加密不等于无法破解；有效授权客户可从内存导出代码和内容密钥，这一点无法杜绝。
- **试用与正式授权共用同一镜像**；试用也可在线取得内容密钥，功能差异必须靠功能项控制。
  试用不写内容密钥缓存，停服后重启失败。拥有试用运行权限的人同样可能从内存导出核心。
- 正式授权只在原签名票据窗口内复用加密内容密钥缓存；空卷断网不能启动，换实例标识后复制的卷不可用。
  已认证明确拒绝清缓存；未认证网络故障不能被用来撤销合法离线缓存。
- 离线缓存不是硬件保险箱：**能读取缓存卷和实例 ID 的人可推导缓存保护材料并解开离线缓存**。
  镜像加密主要阻止没有运行授权的人直接从公开镜像取得核心代码，不防御完全控制已授权主机的攻击者。

## 功能模板

在软件详情的“功能模板”中新建模板，填写名称、功能项JSON对象，以及可选的默认实例数、有效天数、维护天数。名称在同一软件内唯一，维护天数0表示不限。

发放单个或批量授权时，选择软件后可选择功能模板。模板仅用于填表，填入后仍可修改，保存的是最终表单值，不保存模板关联。以后修改或删除模板不会改变已发放授权。没有模板的软件不显示模板选择。

软件的“试用功能模板”可以留空，表示功能项为空。被试用设置引用的模板不能删除，请先更换或清空选择。模板只决定新申领试用的功能项，不改变试用天数和固定的1个实例额度，也不改变已经申领的试用。


## Go、Rust 的整体加密（可选）

程序仍按各语言示例调用高层守卫，退出时由程序处理SIGTERM并释放席位。软件详情“打包密钥”生成公钥后，在构建服务器运行`make build-pack`取得含linux amd64/arm64启动桩的`bin/authgo-pack`。构建程序后，在**中间构建阶段**增加一行：

```dockerfile
RUN authgo-pack --protect /out/app --public-key '<打包公钥>' --key-id '<密钥编号>' --app-key '<软件App Key>' --version '<版本号>' --config '<构建时接入配置>' --out /out/payload
```

Rust把`/out/app`替换成编译所得ELF路径。接入配置仍编译进业务程序，并通过工具参数写入启动桩尾部；不从运行时环境变量或文件读配置。运行镜像从保护阶段**只复制替换后的程序**及必要的动态库，不复制原始程序、构建树或保护前镜像层。`ENTRYPOINT`不变，客户只填`AUTHGO_LICENSE`；留空按已开启的试用规则处理。正式程序需挂载原有命名缓存卷。

启动桩一次校验和解锁后，流式解密到memfd并exec替换自身，不常驻，不转发信号。PID保持不变，PID 1即真正程序，正常退出码由程序决定；启动桩失败退出77。`docker stop`直接发给程序，由程序的守卫在5秒内尝试释放席位。`/proc/self/exe`指向memfd（或已unlink的tmpfs文件），不再指向原镜像路径：依赖此路径找资源、自更新或重新执行自己的程序必须改用明确资源路径。

默认seccomp、非root、只读根、cap_drop ALL、no-new-privileges无需放宽。memfd被内核策略禁止执行时，只使用可执行tmpfs（例如显式挂载`/tmp`为tmpfs且允许exec），执行前unlink；默认`/dev/shm`可能为noexec。两种方式都不可用则明确失败，绝不写明文到持久盘。动态ELF需要镜像提供相同架构的解释器和库。

Go、Rust受保护守卫每次在线成功更新同一语言中立签名证据。断网重启必须同时有未过期证据和内容密钥缓存；已认证拒绝会删除二者。试用及零宽限不写这两种文件，试用每次启动必须联网。缓存不能跨实例标识复制使用。程序会尽力禁用同uid转储，但阻挡不了宿主机root，也阻挡不了已授权客户从内存提取程序。加密不等于防止逆向。


## 水印追查

软件详情的“打包密钥”区域新增“水印追查”。文件在浏览器Worker中分块扫描，不上传文件、文件名或片段；
只有完整且唯一的非零候选值才自动提交。更多选项可手贴水印值、查看全部历史key_id的软件标记。
CLI可用 `authgo-pack trace --tag '<软件标记>' '<本地文件>'`，多次`--tag`同时检查轮换前后的标记。
ZIP/JAR和嵌套JAR逐条目解压并检查CRC与长度；超过固定解压/深度/条目限额会显示部分结果和“未扫描完”，不自动查授权。
无水印、全0、未知授权和最高频平票分别提示；未知授权也可能是授权已被删除。

**当前实现范围：**追查工具、软件标记/授权来源管理接口及服务端已认证解锁响应中的水印值。

水印仅用于事后追踪，不阻止导出，不能作为授权证据。有能力的人可以抹除水印，对比两个授权的导出内容更容易找到它。
拿到内容密钥后直接解密公开密文，会得到构建时的全0槽位，这种副本不能追查；未启用代码加密的程序也没有水印。
Java/C#反编译后重新编译、重新混淆或重写元数据可能丢印。C#正式打印链路要求保留源码注入的8个u8槽位，

### v2打印链路实现说明

新打包入口已默认准备8槽以上的真实代码常量及独立加密索引，旧公开manifest仍公开且认证；槽位索引本身是普通GCM密文条目，不是公开位置表。
Go/Rust使用SDK实际引用的8个不同96字节占位符；Java只追加Utf8常量并保留旧CP编号，不动字节码/StackMap/属性，已签名JAR拒绝。
Python仅处理匹配3.8–3.14的预编译pyc（SDK最低3.9），在模块/真实函数/嵌套函数/闭包的每个CodeType.co_consts末尾追加8个不同字符串；全局marshal引用会安全重编号，原co_code、原常量索引前缀及普通字段/容器共享引用保持，co_consts与普通元组alias分域，不能让names/locals扩容。原co_consts为空时先放None文档哨兵再加8槽（空表总增9），非空表仅末尾加8；不让新函数__doc__变成水印。SDK虚拟文件名使用图memo保留共享code；可以直接marshal已执行业务函数.__code__追查，不只保证模块根。不可安全拆分的递归常量表/不可变code循环和非法格式失败关闭。不是在pyc尾部追加数据。
Node在保留Directive Prologue后加入无标识符访问的 `void [字符串…]` 表达式，不改变公开exports或全局业务对象；SDK仅在 `_compile` 成功后于Guard私有状态保留实际执行的同一份核心源码（约一份字符串的额外内存，V8副本不保证），关闭/拒绝释放引用，不能擦除V8或撤回已编译代码；PHP使用幂等、按水印区分名称的根常量，以及真实函数内立即调用的私有闭包常量；不向业务函数get_defined_vars加入static局部、不因$function/成员调用/namespace误向类体插属性；Python使用原模块 co_consts。每个安全常量容器内用独立随机长度的前缀打散槽位字节偏移（不是任意插入业务语句或改写原常量编号）。PHP根常量元数据及源码本身仍可被反射或调试观察，不应把水印当成不可检测的措施。PHP主导出证据读取实际已调用闭包的Reflection opened_path对应的Guard有效内存源文件，含完整业务代码并做PHP语法验证；静态变量序列化仅为辅助，不冒称完整opcode文件。
C#业务项目由向导提供AuthGo.Watermark.cs的一行Compile包含，标准PublishTrimmed/PublishAot/PublishSingleFile时不包含槽位，打包拒绝缺槽；这不是对任意二次修改PE文件的不可绕过编译开关证明。
当前载荷必须取得非零水印并使用64字节绑定材料缓存。



## 给客户：运行与排查（可单独转发）

### 部署

保存开发者提供的`docker-compose.yml`，在同目录的`.env`写入自己的授权码：

```sh
AUTHGO_LICENSE=请替换为自己的授权码
```

```sh
docker compose pull
docker compose up -d
docker compose logs --tail=50
```

compose采用非root、只读根文件系统、cap_drop ALL、no-new-privileges和命名缓存卷。示例HTTP端口只绑定`127.0.0.1:8090`，对外访问通过自己的反向代理。不要把配置、授权码和日志中的敏感内容转发到公开渠道。

### 缓存卷、扩容与席位

每个实例保留自己的命名缓存卷。保留卷重建仍是原实例；删除卷会失去实例身份和已签名缓存，必须重新联网。缓存不可写只能在内存运行，无法提供重启后的宽限，应检查日志中的明确警告。

默认按同时运行实例数限制。常驻程序docker stop正常退出时释放席位；崩溃不重启时在两个心跳间隔后回收，立即保留卷重启可以接管自己的席位。滚动更新新旧容器重叠运行需要额外一个席位。

**“多副本共用一个卷会互相替换”只适用于常驻运行程序**。每个副本应有独立卷，不能用同一身份稳定共占一个席位。管理端“释放席位”删除实例记录并保留审计，不改变会话凭据；仍在运行的程序下次心跳可能重新占位，需要阻止运行应暂停或吊销授权。

### PHP请求式：FPM、Apache等

与常驻CLI的行为差异如下：

- 拒绝时**不使用退出码77**，由业务返回HTTP503和明确原因，FPM/Apache容器不退出。
- docker stop不能立即释放席位，要等租约到期回收。
- 空闲超过租约时席位被回收；下次请求重新竞争，有空位成功，满额拒绝。
- 请求式**检测不到多副本共用一个卷**。需要严格按实例计数时使用常驻CLI，每个副本使用独立卷。
- 同一个实例处理多个并发请求仍只占一个席位；吊销或禁用版本在下一次需要联网校验时才被发现。已有缓存可在停服及重启后继续服务，宽限耗尽或空卷停服返回503。


### 授权失败与断网

常驻程序最终失败退出77，使用`docker compose logs --tail=50`查看稳定错误原因；例如席位已满、授权吊销、当前版本禁用、宽限耗尽。不要把所有失败都当成断网。PHP请求式按上一节返回503，容器继续运行。

首次激活必须联网。只有已经在线成功且有合法缓存的程序能在授权服务器不可达时继续运行/重启；默认断网继续运行72小时，0表示不提供宽限。授权到期始终优先拒绝。已完整认证的明确拒绝不走宽限；代理502、HTML、解密或验签失败只能使在线检查退回宽限，不能伪造在线成功。

KEY-only和FLOATING均只使用原已签名宽限，到期必须停止，不走备用镜像延长或降级。更新检查无论成功或失败都不改变授权缓存；只返回Docker镜像信息，不下载或替换运行中的程序。

断网宽限期间服务端无法清点真实运行席位，宽限越长越宽松。缓存加密不防本机所有者：能读取卷和实例标识的人可以解开缓存，但不能伪造签名，最多利用原已签名的grace_until，仍受授权到期限制。

### 反向代理与真实IP

Auth Go 官方 Compose 使用一个 authgo 镜像/容器，Go 同时提供前端和 API，默认发布 `8080:8080` 且不设置任何受信代理。直接访问时服务端不采信转发头；使用 HTTPS 反向代理时，在管理端“系统设置 → 受信代理”填写实际代理 IP/CIDR，并在“对外服务地址”填写 HTTPS 地址。反代必须覆盖 X-Forwarded-For/Proto/Host；不要信任全网或允许不可信容器加入受信网络。数据库只接受 v1.0.0 基线。备份必须包含数据库和 master.key，不执行历史数据转换，不得执行 down -v 删除持久数据。详见 [README 代理说明](https://github.com/dingding229/Auth-Go/blob/main/README.md#https-反向代理与受信代理)。


