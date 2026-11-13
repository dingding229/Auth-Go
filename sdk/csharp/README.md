# Auth Go C# SDK

.NET 8。依赖：BouncyCastle.Cryptography 2.6.2（X25519/Ed25519），其他算法为 .NET 内置。尚未发布到公共包仓库；从本仓库安装，不要使用不存在的公共包坐标。

## 本仓库安装与最简示例

在仓库根目录，先把后台配置写入示例的源码常量并构建，只设置`AUTHGO_LICENSE`后执行：

```sh
dotnet run --project sdk/csharp/Example/Example.csproj
```


## 当前授权契约

接入配置继续使用 `authgo2.<无填充 Base64URL JSON>`，信任字段为 `url`、`app_key`、`app_secret`、`public_key`、`gateway_key`。**配置可以公开，但必须编译进程序，不能从环境变量或文件读取**；客户只配置 `AUTHGO_LICENSE`。不要记录配置、授权码、令牌或密钥。HTTPS 和签名验证不能关闭。未知配置字段与重复字段按统一严格规则拒绝。

仅支持 KEY / FLOATING 授权。物理机及容器实例指纹继续用于签名票据、缓存和席位身份。首次激活必须联网；已成功验证的正式授权在原始签名宽限内可断连运行和重启。状态只有 `online`、`grace` 或明确失败；默认宽限 72 小时，到期必须停止。试用必须在线。

连接故障、代理 502、HTML、解密/验签/nonce/时间错误不撤销可信缓存，但不能产生新的授权证据。仅已有有效签名票据可进入 grace。完整认证的临时错误使用既有允许名单；其余已认证非 OK 错误（包括未知错误）默认拒绝。`INSTANCE_REPLACED` 停止旧进程但不清除接管者共享缓存。时钟回退超过 300 秒禁止缓存放行；全新在线签名校验可恢复。

加密代码通过 `payload.unlock` 获得签名绑定的内部解封材料、密文缓存及水印。敏感业务入口使用守卫 Require 或票据 Validate。

## Docker Hub 更新检查

公开更新功能**仅**调用 `update.check`：返回 `available`、`docker_image`、`docker_pull`、`version`、`changelog`、`mandatory`、`published_at`，以及维护期、最新有权版本和续期提示。调用方显示镜像信息，由客户自行拉取和重建容器。没有 GitHub Releases/asset 下载、下载 URL、assets 列表、update.download 或二进制替换接口。更新检查无论成功或失败均不修改授权票据、缓存或 Refused；授权动作仍按原签名拒绝分类处理。保留版本禁用与维护期限制。

### Linux 物理指纹归一化

Linux CPU 身份按 `/proc/cpuinfo` 文件行顺序选取第一个非空的 `model name`、`Hardware` 或 `cpu model`，保持既有指纹不变。都没有时取第一组 `CPU implementer` 和 `CPU part`，值去除空白并转小写后组成 `arm:<implementer>:<part>`；仍不可用时取第一个非空 `uarch`。原始输入不出本机；最后才与机器 ID、主网卡 MAC 一起规范化并哈希。没有任何可用身份时返回 `SDK_FINGERPRINT_UNAVAILABLE`，需显式覆盖指纹。

授权码在 Check 和 Activate 入口先做与 Go 相同的分组、字符及校验位验证（区分大小写）。格式错误返回 `INVALID_LICENSE_KEY`，不访问网络、不改变已有缓存。尝试另一个合法授权码但激活失败时，只返回该错误，不复用旧授权的结果，也不撤销原授权的缓存；同一授权的已认证明确拒绝仍立即清理缓存。



## 容器身份与浮动授权

接入配置必须编译进程序，绝不从运行时AUTHGO_CONFIG或外部文件读取。这里只新增容器身份相关行为，不提供新的信任配置来源，也不放宽HTTPS。

身份优先级：显式fingerprint覆盖 > 非空AUTHGO_INSTANCE_ID > 容器身份 > 原物理机采集。AUTHGO_CONTAINER=0强制关闭容器检测，=1强制开启；默认检测/.dockerenv、/run/.containerenv和/proc/1/cgroup中的docker、containerd、kubepods、libpod。原物理机算法及向量不变。容器不采集MAC、machine-id、CPU。

缓存目录优先级：显式缓存目录 > 非空AUTHGO_CACHE_DIR > 容器默认/var/lib/authgo > 原用户缓存目录。显式空目录禁用磁盘缓存。对应本语言参数：ClientOptions.CacheDir / ClientOptions.Fingerprint。

容器在缓存目录原子创建0600的instance-id文件，内容为32随机字节的小写十六进制（不附换行）。指纹是SHA256("authgo/instance/v1\0"+标识文本)的小写十六进制；AUTHGO_INSTANCE_ID也按原值使用同一算法，不做去空白或大小写转换。持久卷重建保持身份，删除卷成为新实例。目录不可用时使用进程内随机身份并继续在线运行，result.CacheWarning给出“此实例重启后是新实例，没有断连宽限”。

每个进程还产生独立的16随机字节Base64URL instance_session，不写缓存。共享缓存的新进程可以接管实例；服务端保留每个激活最近32个session历史。已收到完整认证INSTANCE_REPLACED的旧进程立即失败，不能进入宽限、不能重新创建Client忘记拒绝，也不能清除新进程缓存。它不是普通授权拒绝清缓存规则的放宽；其他已认证明确拒绝仍立即清除授权证据。

浮动授权只有连接故障或已认证临时错误才使用原签名grace_until，即使旧lease已过期也保留功能与解锁值。到期和时钟回拨仍优先拒绝；grace_hours=0不提供离线宽限。窗口结束返回SDK_GRACE_EXPIRED，不降级、不用镜像延长。恢复后心跳重新竞争席位；满额的明确拒绝绝不回退。只有实际观察过故障并成功回退的当前Client，才能在原宽限内通过本地validate及unlock继续使用过期lease票据。

正常退出时可调用：

```csharp
client.ReleaseSeat();
```

它只释放浮动容量，不解绑、不扣解绑次数、不撤销激活token、不删除有效缓存；非浮动授权为本地无操作。连接故障/临时错误保留缓存；明确拒绝沿用授权分类，INSTANCE_REPLACED只停止旧进程。SDK不注册信号或退出程序，信号处理由业务程序负责。高层接口见下文。

VERSION_DISABLED为已认证拒绝，可从error.LatestVersion读取最新允许且未禁用的版本；未上报版本不受禁用标记影响。禁用旧版本不妨碍更新检查与客户自行拉取允许的新镜像版本，更新请求仍然不改变授权缓存。

边界：若已有持久缓存可读，但目录后来变为只读，故障回退必须先持久化最晚时间水位；写入失败与Go一样返回SDK_CACHE_UNAVAILABLE，不跳过时钟回拨保护。这不同于新实例一开始无法写目录时的纯内存运行。

## 容器高层接口

```csharp
await using var guard = await AuthGo.Guard.StartAsync(new AuthGo.GuardOptions {
    Config = Build.Config, // 构建生成的常量类，非运行时环境或配置文件
    Version = Build.Version
}, cancellationToken);
guard.Require("export"); // 本地校验，可用于多个关键业务入口
var result = guard.Result; // 并发安全的深拷贝
await guard.Done; // 最终失败，从guard.Error.Code读取原因
```

配置必填，SDK不读AUTHGO_CONFIG或文件获取配置；只有License为空时读取AUTHGO_LICENSE。首次失败返回异常，不启动循环。后台自动验证/浮动心跳，宽限只调用OnChange；明确拒绝、宽限耗尽等最终失败完成Done，Require此后失败。取消令牌只停止循环，不伪造授权拒绝；调用者应DisposeAsync释放席位。异步关闭并发安全、幂等，整体最多5秒，失败只返回异常，不退出程序。SDK不处理信号、不新增子进程、不写缓存以外的文件。回调应及时返回、不抛异常。ExitLicense=77，目标net8.0，无新增依赖。

examples/docker/csharp/提供构建常量、安全容器与程序自己的SIGTERM处理。心跳间隔由已验签响应提供并保存在加密缓存，不假设票据有该字段；旧缓存按签名双心跳租约保守调度，不改变宽限和拒绝规则。

### 更新维护期

Result公开`MaintenanceUntil`、`LatestEntitledVersion`，错误公开最高可用版本。可选字段缺失时表示不限/空值。维护期按服务端记录的版本发布时间判断，不是授权到期；SDK不使用本地时间拒绝。断网沿用已有缓存与宽限，联网收到`MAINTENANCE_EXPIRED`后按明确拒绝处理；高层守卫语义与`VERSION_DISABLED`相同。更新动作失败仍不清授权缓存。

### 免授权码试用

仅高层守卫在配置已由调用方传入、授权码和AUTHGO_LICENSE均为空时申请试用；低层check仍要求有效格式授权码。Result的`IsTrial`表示当前是否试用。试用只保存在已有加密缓存，不打印授权码；重启复用。试用无断网宽限，网络故障最终失败，常驻程序退出77，请求式PHP返回503。管理员转正后下一次校验恢复正式授权宽限。TRIAL_DISABLED提示配置AUTHGO_LICENSE，TRIAL_IP_LIMIT及TRIAL_QUOTA_EXCEEDED为已认证明确拒绝。

## 运行时内容密钥解锁

```csharp
var client = new Client(CONFIG); // CONFIG 在构建时固化，不从环境或文件读取
client.Check(licenseKey);
var payload = Payload.ParsePayload(payloadJson); // 完整原始 payload.json，含 config
byte[] contentKey = client.UnlockPayload(payload);
try
{
    // 在内存使用 32 字节内容密钥；不要把明文或密钥写入磁盘。
}
finally
{
    System.Security.Cryptography.CryptographicOperations.ZeroMemory(contentKey);
}
```

`UnlockPayload` 不隐式激活，必须先成功完成 `Check`、`Activate` 或 `Verify`。
载荷内公开 `config` 只参与绑定，不会改变 Client 的连接目标。
解锁、授权及 `SavePayloadKey` / `LoadPayloadKey` / `ClearPayloadKeys` 共用既有同步锁。
请求复用既有 v2 AEAD、Nonce、Ed25519 签名与挑战校验；重新封装还绑定当前载荷及临时公钥。
新票据上下文错误或解封失败直接报错，不用旧缓存掩盖；`PAYLOAD_INVALID` 属于临时错误。

内容密钥缓存使用跨语言 `AUTHGO-PAYLOAD-CACHE-v2`，派生、AAD、文件名与 Go/Python/Node/Java 一致。
缓存密钥来自已验证票据的 `unlock_hash` 字节及二进制 label，不把 label 转为字符串，也不新增种子。
文件仅含密文、0600 权限，临时文件强制落盘后原子改名。Unix 读取使用 NOFOLLOW，
比较路径与打开句柄的设备号/inode，并核验普通文件、权限及大小；Linux 还避免 FIFO 替换阻塞。
句柄身份使用 .NET 8 自带 System.Native 的规范化文件信息，不解析架构相关的 libc stat 布局。
不能保证 Unix 权限/句柄检查（例如 Windows 或相关运行时接口不可用）时，不落盘密钥，在线解锁仍可用。
这是内容密钥缓存的安全条件，不影响既有授权缓存。不可写存储也不影响在线解锁成功。

内容密钥缓存只在原签名票据宽限内有效，不用镜像延长；试用、零宽限、内存缓存模式不缓存。
已成功进入离线宽限的同一票据直接读缓存，不重复等待网络超时。复制到另一实例无法解开。
已认证明确拒绝立即清理内容密钥缓存；`INSTANCE_REPLACED` 禁止旧进程再解锁，但保留授权票据。
网络故障、通道认证失败和 `PAYLOAD_INVALID` 不清缓存。正常释放席位仍保留有效缓存，
释放时收到明确拒绝才按分类清理，与普通授权流程一致。
不生成、读取或删除 `payload_proof` 证据文件。低层解锁本身不加载程序集；下述 Bootstrap 提供独立的内存加载层，不包含启动桩。

测试入口 `Tests` 包含三个载荷向量及 payload 测试；可用 `dotnet build -warnaserror` 后运行。
使用现有 BouncyCastle 依赖及 .NET 8 运行库，未新增 NuGet 包。

## 加密程序集：内存启动入口（.NET 8）

公开入口只有几行，业务程序集不再放在启动器的 ProjectReference/发布文件中：

```csharp
using AuthGo;
const string Config = "authgo2.构建时固定的接入配置";
return await Bootstrap.RunAsync(new GuardOptions { Config = Config }, args);
```

见 `ProtectedExample/`。Config 是编译进公开启动器的常量，不从环境变量、配置文件或
payload.config 读取。客户只填 `AUTHGO_LICENSE`；空时沿用已有试用流程。
Bootstrap 默认从 `/opt/authgo/payload.json` 选名为 `app` 的 .NET 主归档；任务约定的
`AUTHGO_PAYLOAD_DIR` 可以更换**公开密文**目录。payload.config 只参与原信封绑定，绝不
替换 Client 的连接目标。上报版本取自同一份载荷的 version，成功认证信封后才执行程序集，
后续 Guard 校验也使用该版本，而不使用调用方的 options.Version。

构建时先发布业务程序集（net8.0，纯 IL），再加密最后一层：

```sh
authgo-pack --dotnet app=/staging/MyApp.dll \
  --dotnet private_dep=/staging/SecretLib.dll \
  --public-key <公钥> --key-id <编号> --app-key <软件标识> \
  --version 1.0.0 --config <固定接入配置> --out /opt/authgo
```

每个 pack .NET 条目包含输入程序集及可选同名 `.deps.json`。私有依赖也要作为 `--dotnet`
条目打包，放入同一个载荷（共享一次内容密钥解锁）。Bootstrap 在内存解密所有 .NET 条目，
按程序集名称、版本、culture、公钥 token 解析依赖，通过 `AssemblyLoadContext.LoadFromStream`
加载；同名不同文件也拒绝，不静默覆盖。公开依赖由**公开启动器的** ProjectReference/发布
依赖提供，不使用密文归档里的 `.deps.json` 路径从文件系统探测依赖。SDK 和运行库共享宿主
程序集，不能在业务归档里覆盖它们，因此业务和启动器使用同一份 AuthGo SDK。

业务代码用 `Bootstrap.Current` 取得同一个 Guard，继续使用 `Require(feature)`、Result、Done
等既有接口。不创建第二个 Guard、进程或席位。入口参数原样按值传递，支持 void/int/Task/
Task<int> 入口，原业务异常保持其类型和堆栈；正常入口返回值交给公开入口作为退出码。
同步 Main 启动前台工作线程后返回时，Guard 仍保留到 ProcessExit，退出时关闭载荷并释放实例。
异步程序仍应等待自己的后台任务；线程池任务不会阻止 .NET 进程退出。
启动/授权失败返回 77，运行中 Guard 结束时退出 77，不把业务异常伪装成授权拒绝。

### 安全与运行边界

- 只接受带 CLR 头、BSJB 元数据签名的 IL-only PE；拒绝混合模式、原生入口点、ReadyToRun
  原生头、P/Invoke 及依赖清单里的原生资产。不支持 NativeAOT、自包含原生发布、原生插件或
  单文件 bundle。使用常规 net8.0 托管程序集，不能用本加载器做 .NET/原生混合部署。
- 加载前、每次 Load/Resolving/私有依赖加载及入口调用前检查 Guard；明确拒绝或关闭后
  不再加载新程序集。CLR 已加载对象和绑定缓存不能撤销，应用仍须按 Guard 状态退出。
- tar 只接受安全且唯一的普通文件路径，不接受符号链接、硬链接、设备或路径穿越。归档只含
  托管程序集及 `.deps.json`；数据文件应放在加密包之外。
- `Assembly.Location` 为空；依赖真实 DLL 路径、`AssemblyDependencyResolver` 物理目录、
  自行读盘或提取本机库的框架需要调整。嵌入式资源仍由 CLR 在内存程序集里提供。
- 分块格式与 Go 一致：每块最大 1 MiB，独立 AES-256-GCM，认证后才写出。
  `PayloadFiles.PayloadCipherSize` 精确校验长度，空文件也有一个标签。迭代/解密失败时
  必须丢弃此前部分输出。只有分块缓冲有界；完整归档、私有依赖及 CLR 对象会占用随代码
  大小增长的内存，MemoryStream/byte[] 的平台上限仍适用。
- 内容密钥、中间明文以及退役的扩容缓冲用 `CryptographicOperations.ZeroMemory` 清理。
  加载后的源字节和 context 关闭时的未加载字节也清理；CLR 内部 IL、JIT 和资源副本不能
  保证擦除，collectible context 的 Unload 也不是立即从内存清除。它不是安全沙箱，不能
  防止有效授权客户从进程内存还原内容。

既有 UnlockPayload、内容密钥缓存、试用/离线/拒绝分类语义不变，不生成启动桩证据文件。
Tests 入口增加 `payload-envelope` 分块向量及 sealed 测试，Fixtures 为纯编译测试素材，不随 SDK
发布；ProtectedExample 是公开启动器示例。全部项目在 .NET 8 下用 `dotnet build -warnaserror`
验证，包括新增示例和测试素材项目，未新增 NuGet 依赖。

## Payload v2 与运行时水印

SDK 只接受 payload v2。公开 manifest 必须且只能含一个 `__authgo_watermark` 条目（`kind: "watermark"`、`encoding: "raw"`）；私有槽位索引作为独立 AES-GCM 密文保存。先认证私有索引全部分块，再认证目标代码并验证槽位，最后写入签名响应中的水印。

公开解锁接口返回 K32；内部加载材料及内容缓存为 K32||WM32。WM 必须是非零 32 字节值，并由响应签名认证。缓存使用 `AUTHGO-PAYLOAD-CACHE-v2.` 和 `authgo-payload-v2-`，绑定原始载荷、授权、实例及签名宽限窗口。试用和零宽限不缓存。未知或未认证响应不能产生新证据，完整认证的明确拒绝按授权动作规则处理。

当前算法仍使用 `authgo/payload/v1/wrap`、`authgo/payload/v1/rewrap`、`authgo-payload-chunk-v1` 等密码学域，它们不是旧载荷格式入口。Go/Rust 启动桩证据使用独立的 `AUTHGO-PAYLOAD-PROOF-v1.` 当前格式。

水印用于事后追踪，不防宿主调试器或内存导出，不能保证反编译、重编译或修改后保留。运行中代码无法安全撤回，高层守卫与敏感入口必须继续校验授权。协议以 [完整协议](../../server/internal/apidocs/protocol.md) 为唯一来源。
