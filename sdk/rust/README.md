# Auth Go Rust SDK

Rust stable。依赖：RustCrypto + dalek；同步 ureq/rustls，不需要系统 OpenSSL 或 tokio。尚未发布到公共包仓库；从本仓库安装，不要使用不存在的公共包坐标。

## 本仓库安装与最简示例

在仓库根目录，先把后台配置写入示例的源码常量并构建，只设置`AUTHGO_LICENSE`后执行：

```sh
cargo run --manifest-path sdk/rust/Cargo.toml --example basic
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

`offline_request(&key)` 返回 `Result<String, authgo::Error>`，请用 `?` 处理格式错误。



## 容器身份与浮动授权

接入配置必须编译进程序，绝不从运行时AUTHGO_CONFIG或外部文件读取。这里只新增容器身份相关行为，不提供新的信任配置来源，也不放宽HTTPS。

身份优先级：显式fingerprint覆盖 > 非空AUTHGO_INSTANCE_ID > 容器身份 > 原物理机采集。AUTHGO_CONTAINER=0强制关闭容器检测，=1强制开启；默认检测/.dockerenv、/run/.containerenv和/proc/1/cgroup中的docker、containerd、kubepods、libpod。原物理机算法及向量不变。容器不采集MAC、machine-id、CPU。

缓存目录优先级：显式缓存目录 > 非空AUTHGO_CACHE_DIR > 容器默认/var/lib/authgo > 原用户缓存目录。显式空目录禁用磁盘缓存。对应本语言参数：Options.cache_dir / Options.fingerprint。

容器在缓存目录原子创建0600的instance-id文件，内容为32随机字节的小写十六进制（不附换行）。指纹是SHA256("authgo/instance/v1\0"+标识文本)的小写十六进制；AUTHGO_INSTANCE_ID也按原值使用同一算法，不做去空白或大小写转换。持久卷重建保持身份，删除卷成为新实例。目录不可用时使用进程内随机身份并继续在线运行，result.cache_warning给出“此实例重启后是新实例，没有断连宽限”。

每个进程还产生独立的16随机字节Base64URL instance_session，不写缓存。共享缓存的新进程可以接管实例；服务端保留每个激活最近32个session历史。已收到完整认证INSTANCE_REPLACED的旧进程立即失败，不能进入宽限、不能重新创建Client忘记拒绝，也不能清除新进程缓存。它不是普通授权拒绝清缓存规则的放宽；其他已认证明确拒绝仍立即清除授权证据。

浮动授权只有连接故障或已认证临时错误才使用原签名grace_until，即使旧lease已过期也保留功能与解锁值。到期和时钟回拨仍优先拒绝；grace_hours=0不提供离线宽限。窗口结束返回SDK_GRACE_EXPIRED，不降级、不用镜像延长。恢复后心跳重新竞争席位；满额的明确拒绝绝不回退。只有实际观察过故障并成功回退的当前Client，才能在原宽限内通过本地validate及unlock继续使用过期lease票据。

正常退出时可调用：

```rust
client.release_seat()?;
```

它只释放浮动容量，不解绑、不扣解绑次数、不撤销激活token、不删除有效缓存；非浮动授权为本地无操作。连接故障/临时错误保留缓存；明确拒绝沿用授权分类，INSTANCE_REPLACED只停止旧进程。SDK不注册信号或退出程序，信号处理由业务程序负责。高层守卫接口见下文。

VERSION_DISABLED为已认证拒绝，可从error.latest_version读取最新允许且未禁用的版本；未上报版本不受禁用标记影响。禁用旧版本不妨碍更新检查与客户自行拉取允许的新镜像版本，更新请求仍然不改变授权缓存。

边界：若已有持久缓存可读，但目录后来变为只读，故障回退必须先持久化最晚时间水位；写入失败与Go一样返回SDK_CACHE_UNAVAILABLE，不跳过时钟回拨保护。这不同于新实例一开始无法写目录时的纯内存运行。

## 容器高层接口

```rust
use authgo::{Guard, GuardOptions, EXIT_LICENSE};
let guard = Guard::start(GuardOptions {
    config: env!("AUTHGO_CONFIG").into(),       // 仅编译时
    version: env!("CARGO_PKG_VERSION").into(),
    ..Default::default()
})?;
guard.require("export")?;                    // 不联网
let result = guard.result();                 // 独立快照
// 业务程序自己处理SIGTERM/SIGINT；guard.is_done()后以EXIT_LICENSE退出。
guard.close()?;                              // 包含停止循环和释放，整体最多5秒
```

配置必填，SDK不读取环境变量或文件获取配置；仅授权码为空时读取AUTHGO_LICENSE。首次check失败返回Result::Err，不启动线程。后台使用标准库线程，不需要tokio；Guard可跨线程使用，内部Mutex与Condvar保护状态。`on_change`接收`Option<ResultData>`和`Option<Error>`，锁外调用，应及时返回、不panic。宽限不触发完成信号；明确拒绝、宽限耗尽等最终失败触发`done()`返回的Completion句柄（`wait()`/`is_done()`），`guard.error()`保留原因。require在完成后必定失败。close并发安全且幂等，失败只返回错误；Drop也进行有界关闭。EXIT_LICENSE为77。SDK仅在受保护Linux进程的prctl加固调用处使用隔离的FFI unsafe，不注册信号、不启动子进程，除缓存外不写文件。

完整示例见`examples/docker/rust/`。仅Linux容器业务示例为SIGTERM/SIGINT使用一处隔离的POSIX FFI unsafe（标准库不提供信号API，避免新增依赖）；处理器仅修改静态AtomicBool。此代码不在SDK内。程序自行停止HTTP、close并选择退出码，不替换正在运行的程序。

心跳间隔来自已验签响应的`data.heartbeat_interval`（它不在票据载荷里），保存于本机加密缓存并由守卫调度。旧缓存没有这项元数据时，浮动授权从签名票据剩余的双心跳租约保守推导更早的重试间隔；第一次联网成功后使用服务器返回的准确间隔。不修改票据，不放宽租约、宽限、到期或拒绝判断。

### 更新维护期

Result公开`maintenance_until`、`latest_entitled_version`，错误公开最高可用版本。可选字段缺失时表示不限/空值。维护期按服务端记录的版本发布时间判断，不是授权到期；SDK不使用本地时间拒绝。断网沿用已有缓存与宽限，联网收到`MAINTENANCE_EXPIRED`后按明确拒绝处理；高层守卫语义与`VERSION_DISABLED`相同。更新动作失败仍不清授权缓存。

### 免授权码试用

仅高层守卫在配置已由调用方传入、授权码和AUTHGO_LICENSE均为空时申请试用；低层check仍要求有效格式授权码。Result的`is_trial`表示当前是否试用。试用只保存在已有加密缓存，不打印授权码；重启复用。试用无断网宽限，网络故障最终失败，常驻程序退出77，请求式PHP返回503。管理员转正后下一次校验恢复正式授权宽限。TRIAL_DISABLED提示配置AUTHGO_LICENSE，TRIAL_IP_LIMIT及TRIAL_QUOTA_EXCEEDED为已认证明确拒绝。

### 整体保护

编译后的Rust ELF可用`authgo-pack --protect`整体加密，运行时由内嵌Go启动桩解锁并exec，不需要常驻Go进程。应用仍使用本SDK的Guard，AUTHGO_PROTECTED=1时尽力关闭Linux进程转储，并在每次在线成功后原子更新语言中立的原始签名票据证据；明确拒绝删除证据和内容密钥缓存，网络错误及PAYLOAD_INVALID不删。试用、零宽限不写共享证据。与Go启动桩不互读私有授权缓存，不新增解锁种子。信任根仍编译进应用，不能由运行时配置替换。宿主机root仍能读取内存。构建用法与`/proc/self/exe`限制见[Docker 接入说明](../../server/internal/apidocs/docker.md)。

## Payload v2 与运行时水印

SDK 只接受 payload v2。公开 manifest 必须且只能含一个 `__authgo_watermark` 条目（`kind: "watermark"`、`encoding: "raw"`）；私有槽位索引作为独立 AES-GCM 密文保存。先认证私有索引全部分块，再认证目标代码并验证槽位，最后写入签名响应中的水印。

公开解锁接口返回 K32；内部加载材料及内容缓存为 K32||WM32。WM 必须是非零 32 字节值，并由响应签名认证。缓存使用 `AUTHGO-PAYLOAD-CACHE-v2.` 和 `authgo-payload-v2-`，绑定原始载荷、授权、实例及签名宽限窗口。试用和零宽限不缓存。未知或未认证响应不能产生新证据，完整认证的明确拒绝按授权动作规则处理。

当前算法仍使用 `authgo/payload/v1/wrap`、`authgo/payload/v1/rewrap`、`authgo-payload-chunk-v1` 等密码学域，它们不是旧载荷格式入口。Go/Rust 启动桩证据使用独立的 `AUTHGO-PAYLOAD-PROOF-v1.` 当前格式。

水印用于事后追踪，不防宿主调试器或内存导出，不能保证反编译、重编译或修改后保留。运行中代码无法安全撤回，高层守卫与敏感入口必须继续校验授权。协议以 [完整协议](../../server/internal/apidocs/protocol.md) 为唯一来源。
