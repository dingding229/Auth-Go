# Auth Go Go SDK

## 两行接入

```go
const authConfig = "authgo2.请在构建时替换为后台接入配置"
client, err := sdk.New(authConfig)
result, err := client.Check(ctx, os.Getenv("AUTHGO_LICENSE"))
```

完整可运行程序见 [examples/basic](../../examples/basic/main.go)；本仓库模块名`authgo/sdk`，本地开发用replace指向sdk/go，公开分发时改为自己的模块地址。后台：添加软件 → 添加用户 → 发放授权 → 软件“接入程序”复制配置。用户中心入口`/portal`，可查看自己的授权并释放FLOATING实例席位（不轮换凭据，没有次数/冷却额度）。

接入配置使用编译固定的 authgo2 信任根，通信经过加密信道并验证签名、挑战与时间。

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

## 实例与退出

进程启动时自动生成仅内存的instance_session；重启可接管同一缓存实例，被替换的旧进程收到INSTANCE_REPLACED后必须退出。此错误不清票据、不写Refused，但旧进程不能再走宽限。不要自动重新Activate来抢回。

浮动授权在连接故障或已认证临时错误时也使用现有GraceUntil（默认72小时），保留功能项；授权到期优先。原窗口结束返回SDK_GRACE_EXPIRED，不降级、不靠清单延长。恢复联网后Heartbeat重新竞争席位，满了明确失败。Verify发现缓存lease过期会发Heartbeat，在线响应仍校验lease。

正常退出调用`client.ReleaseSeat(ctx)`只释放浮动容量，不清缓存、不解绑、不消耗解绑次数。非浮动为本地无操作。网络失败返回原错误且不改变本地状态；Deactivate停用当前激活并清除本地缓存；正常退出应使用ReleaseSeat。

禁用已上报版本返回VERSION_DISABLED，`errors.As(err, &sdkError)`后可读取`LatestVersion`。更新检查仍可用于升级禁用旧版本，不改变授权缓存。

## 容器与高层守卫（Go）

默认容器判定：`/.dockerenv`、`/run/.containerenv`存在，或`/proc/1/cgroup`含docker/containerd/kubepods/libpod；`AUTHGO_CONTAINER=1`强制启用，`0`强制关闭。指纹优先级：WithFingerprint > AUTHGO_INSTANCE_ID > 容器实例 > 原物理机算法（物理机结果不变）。容器不采集MAC、machine-id或CPU。实例文件`<缓存目录>/instance-id`为32随机字节的小写十六进制，权限0600，临时文件+link原子发布；指纹是`SHA256("authgo/instance/v1\x00"+标识)`。AUTHGO_INSTANCE_ID使用相同哈希算法，不做规范化。

缓存目录优先级：WithCacheDir（空字符串禁用磁盘）> AUTHGO_CACHE_DIR > 容器`/var/lib/authgo` > 原用户缓存目录。挂持久卷才能保留实例身份和断连宽限；正常停止只释放席位，不解绑、不删除票据。目录不可写时使用进程内实例ID，Result.CacheWarning提示“此实例重启后是新实例，没有断连宽限”。共享卷的并发进程会接管，旧进程INSTANCE_REPLACED后必须退出，不可清掉新进程的缓存。

配置是信任根，必须编译进程序，StartGuard不读取AUTHGO_CONFIG或配置文件，只允许License为空时读取AUTHGO_LICENSE。Version由构建参数编译。完整可运行HTTP程序、多阶段非root镜像和只读根Compose见[examples/docker](../../examples/docker/)。标准接入方式：

```go
var (
    version = "dev" // -ldflags "-X main.version=1.2.3"
    authConfig = "" // -ldflags "-X main.authConfig=$AUTHGO_CONFIG"
)
func main() { os.Exit(run()) }
func run() int {
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
    defer stop()
    guard, err := sdk.StartGuard(ctx, sdk.GuardOptions{Config: authConfig, Version: version})
    if err != nil { log.Printf("授权验证失败: %v", err); return sdk.ExitLicense }
    defer guard.Close(context.Background())
    appCtx, cancel := context.WithCancel(ctx)
    defer cancel()
    done := make(chan error, 1)
    go func() { done <- runServer(appCtx, guard.Result().Features) }()
    select {
    case <-ctx.Done(): cancel(); <-done; return 0
    case <-guard.Done():
        log.Printf("授权已失效: %v", guard.Err())
        cancel(); <-done; return sdk.ExitLicense
    case err := <-done:
        if err != nil { log.Print(err); return 1 }; return 0
    }
}
```

StartGuard先Check，首次失败不启动后台循环；成功后StartAutoCheck。Result返回深拷贝，OnChange在SDK锁外通知，宽限不关闭Done；校验最终失败（含宽限耗尽）关闭Done，Err保留原因。Close取消循环并释放席位，整体最多5秒，失败仅返回错误；不清有效缓存。方法并发安全；回调应及时返回，不要在回调里同步等待Close。

在核心业务入口反复调用`guard.Require("feature_name")`（空字符串只验票据）。它不联网，检查Done、票据签名与时间、功能项必须为true。也可用 `guard.Result().Ticket()` 做分散票据校验；不能承诺绝对防破解。宽限耗尽必须停止。SDK不注册信号、不创建子进程、不调用os.Exit，只写缓存。

### 更新维护期

Result公开`MaintenanceUntil`、`LatestEntitledVersion`，错误公开最高可用版本。可选字段缺失时表示不限/空值。维护期按服务端记录的版本发布时间判断，不是授权到期；SDK不使用本地时间拒绝。断网沿用已有缓存与宽限，联网收到`MAINTENANCE_EXPIRED`后按明确拒绝处理；高层守卫语义与`VERSION_DISABLED`相同。更新动作失败仍不清授权缓存。

### 免授权码试用

仅高层守卫在配置已由调用方传入、授权码和AUTHGO_LICENSE均为空时申请试用；低层check仍要求有效格式授权码。Result的`IsTrial`表示当前是否试用。试用只保存在已有加密缓存，不打印授权码；重启复用。试用无断网宽限，网络故障最终失败，常驻程序退出77，请求式PHP返回503。管理员转正后下一次校验恢复正式授权宽限。TRIAL_DISABLED提示配置AUTHGO_LICENSE，TRIAL_IP_LIMIT及TRIAL_QUOTA_EXCEEDED为已认证明确拒绝。

### 加密载荷及整体保护

已有成功Check/Activate/Verify的Client可调用`UnlockPayload(ctx, payload)`，用完对返回的32字节密钥调用`clear(key)`。响应经过原有v2认证及本次临时X25519重封装验证，SDK不隐式激活。仅合法签名票据宽限内允许读取密钥密文缓存；试用、零宽限不缓存，明确拒绝清除，PAYLOAD_INVALID和网络错误不清。

Go、Rust整体保护由`make build-pack`构建的工具提供：`--protect`就地替换已编译ELF。启动桩exec后消失，应用仍调用自己的高层守卫。受保护守卫维护语言中立的原始签名证据；启动桩离线时只读取该证据，不读取另一语言SDK私有缓存。格式和公开测试向量见[完整协议第12节](../../server/internal/apidocs/protocol.md#12-语言无关加密载荷与整体保护-v2)。Linux高层守卫在AUTHGO_PROTECTED=1时尽力禁用转储；这挡不住宿主机root。运行方式、PID及路径限制见[Docker 接入说明](../../server/internal/apidocs/docker.md)。

## Payload v2 与运行时水印

SDK 只接受 payload v2。公开 manifest 必须且只能含一个 `__authgo_watermark` 条目（`kind: "watermark"`、`encoding: "raw"`）；私有槽位索引作为独立 AES-GCM 密文保存。先认证私有索引全部分块，再认证目标代码并验证槽位，最后写入签名响应中的水印。

公开解锁接口返回 K32；内部加载材料及内容缓存为 K32||WM32。WM 必须是非零 32 字节值，并由响应签名认证。缓存使用 `AUTHGO-PAYLOAD-CACHE-v2.` 和 `authgo-payload-v2-`，绑定原始载荷、授权、实例及签名宽限窗口。试用和零宽限不缓存。未知或未认证响应不能产生新证据，完整认证的明确拒绝按授权动作规则处理。

当前算法仍使用 `authgo/payload/v1/wrap`、`authgo/payload/v1/rewrap`、`authgo-payload-chunk-v1` 等密码学域，它们不是旧载荷格式入口。Go/Rust 启动桩证据使用独立的 `AUTHGO-PAYLOAD-PROOF-v1.` 当前格式。

水印用于事后追踪，不防宿主调试器或内存导出，不能保证反编译、重编译或修改后保留。运行中代码无法安全撤回，高层守卫与敏感入口必须继续校验授权。协议以 [完整协议](../../server/internal/apidocs/protocol.md) 为唯一来源。
