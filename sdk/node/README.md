# Auth Go Node.js SDK

Node.js 22+。依赖：内置 crypto/http/https，零 npm 依赖。尚未发布到公共包仓库；从本仓库安装，不要使用不存在的公共包坐标。

## 本仓库安装与最简示例

在仓库根目录，先把后台配置写入示例的源码常量并构建，只设置`AUTHGO_LICENSE`后执行：

```sh
node sdk/node/example.mjs
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

缓存目录优先级：显式缓存目录 > 非空AUTHGO_CACHE_DIR > 容器默认/var/lib/authgo > 原用户缓存目录。显式空目录禁用磁盘缓存。对应本语言参数：cacheDir / fingerprint。

容器在缓存目录原子创建0600的instance-id文件，内容为32随机字节的小写十六进制（不附换行）。指纹是SHA256("authgo/instance/v1\0"+标识文本)的小写十六进制；AUTHGO_INSTANCE_ID也按原值使用同一算法，不做去空白或大小写转换。持久卷重建保持身份，删除卷成为新实例。目录不可用时使用进程内随机身份并继续在线运行，result.cacheWarning给出“此实例重启后是新实例，没有断连宽限”。

每个进程还产生独立的16随机字节Base64URL instance_session，不写缓存。共享缓存的新进程可以接管实例；服务端保留每个激活最近32个session历史。已收到完整认证INSTANCE_REPLACED的旧进程立即失败，不能进入宽限、不能重新创建Client忘记拒绝，也不能清除新进程缓存。它不是普通授权拒绝清缓存规则的放宽；其他已认证明确拒绝仍立即清除授权证据。

浮动授权只有连接故障或已认证临时错误才使用原签名grace_until，即使旧lease已过期也保留功能与解锁值。到期和时钟回拨仍优先拒绝；grace_hours=0不提供离线宽限。窗口结束返回SDK_GRACE_EXPIRED，不降级、不用镜像延长。恢复后心跳重新竞争席位；满额的明确拒绝绝不回退。只有实际观察过故障并成功回退的当前Client，才能在原宽限内通过本地validate及unlock继续使用过期lease票据。

正常退出时可调用：

```js
await client.releaseSeat()
```

它只释放浮动容量，不解绑、不扣解绑次数、不撤销激活token、不删除有效缓存；非浮动授权为本地无操作。连接故障/临时错误保留缓存；明确拒绝沿用授权分类，INSTANCE_REPLACED只停止旧进程。SDK不注册信号或退出程序，信号处理由业务程序负责。高层守卫接口见下文。

VERSION_DISABLED为已认证拒绝，可从error.latestVersion读取最新允许且未禁用的版本；未上报版本不受禁用标记影响。禁用旧版本不妨碍更新检查与客户自行拉取允许的新镜像版本，更新请求仍然不改变授权缓存。

边界：若已有持久缓存可读，但目录后来变为只读，故障回退必须先持久化最晚时间水位；写入失败与Go一样返回SDK_CACHE_UNAVAILABLE，不跳过时钟回拨保护。这不同于新实例一开始无法写目录时的纯内存运行。

## 容器高层接口

```js
import { startGuard, EXIT_LICENSE } from "authgo";
import build from "./authgo-build.json" with { type: "json" }; // 构建生成
const guard = await startGuard({ config: build.config, version: build.version });
guard.require("export");                  // 仅本地验签与功能检查
const result = guard.result();             // 独立快照，包含完整ticket/unlock能力
// 业务程序自己处理SIGTERM/SIGINT；guard.done完成后以EXIT_LICENSE退出。
await guard.close();                       // 整体最多5秒，释放席位
```

配置必填，SDK不读取AUTHGO_CONFIG或配置文件；仅授权码默认读取AUTHGO_LICENSE。`authgo-build.json`在构建中固化，不能挂载客户提供的替代文件。首次check失败抛AuthGoError，不启动定时器。自动验证和浮动心跳使用unref定时器，不阻止进程退出；运行HTTP等业务服务由程序自己负责。`onChange(result,error)`在SDK锁外调用，应及时返回、不抛异常。宽限只通知变化，不完成`done`；明确拒绝、宽限耗尽等最终失败resolve `done`，从`guard.error`读取原因。`require`不联网，完成后必定失败。`close`幂等，停止后不再调度或通知；失败reject但不退出进程。SDK不注册信号、不启动子进程，除缓存外不写文件。EXIT_LICENSE为77。

完整示例见`examples/docker/node/`。配置、版本构建固定；部署只填授权码。关闭时由业务程序停止HTTP并调用close，不替换运行中的程序。

心跳间隔来自已验签响应的`data.heartbeat_interval`（它不在票据载荷里），保存于本机加密缓存并由守卫调度。旧缓存没有这项元数据时，浮动授权从签名票据剩余的双心跳租约保守推导更早的重试间隔；第一次联网成功后使用服务器返回的准确间隔。不修改票据，不放宽租约、宽限、到期或拒绝判断。

### 更新维护期

Result公开`maintenanceUntil`、`latestEntitledVersion`，错误公开最高可用版本。可选字段缺失时表示不限/空值。维护期按服务端记录的版本发布时间判断，不是授权到期；SDK不使用本地时间拒绝。断网沿用已有缓存与宽限，联网收到`MAINTENANCE_EXPIRED`后按明确拒绝处理；高层守卫语义与`VERSION_DISABLED`相同。更新动作失败仍不清授权缓存。

### 免授权码试用

仅高层守卫在配置已由调用方传入、授权码和AUTHGO_LICENSE均为空时申请试用；低层check仍要求有效格式授权码。Result的`isTrial`表示当前是否试用。试用只保存在已有加密缓存，不打印授权码；重启复用。试用无断网宽限，网络故障最终失败，常驻程序退出77，请求式PHP返回503。管理员转正后下一次校验恢复正式授权宽限。TRIAL_DISABLED提示配置AUTHGO_LICENSE，TRIAL_IP_LIMIT及TRIAL_QUOTA_EXCEEDED为已认证明确拒绝。

## 运行时内容密钥解锁

配置仍由源码／构建时传入；载荷内的公开配置仅参与绑定，不改变连接目标。

```js
import { Client, parsePayload } from "./index.js";
const client = new Client(CONFIG); // CONFIG 是构建时固化的接入配置
await client.check(licenseKey);
const payload = parsePayload(payloadJSON); // 完整原始 payload.json，含 config
const contentKey = await client.unlockPayload(payload);
try {
  // 使用 32 字节内容密钥在内存解密；不把明文或密钥写入磁盘。
} finally {
  contentKey.fill(0);
}
```

`unlockPayload` 不自动激活。必须先成功完成 `check`、`activate` 或 `verify`。
解锁与授权请求共用串行锁；认证的明确拒绝清理此实例的全部内容密钥缓存，
`INSTANCE_REPLACED` 同时禁止旧进程再次解锁，但保留授权票据。
`PAYLOAD_INVALID`、网络和通道认证失败不会清缓存；新票据上下文错误或重新封装认证失败
直接报错，不以缓存掩盖错误。

内容密钥缓存采用 `AUTHGO-PAYLOAD-CACHE-v2`，与 Go／Python 的派生、AAD、文件名逐位一致。
文件是 0600 的 AES-GCM 密文，临时文件写入后原子替换；不可写时不影响在线成功。
只在原签名票据的宽限内可用，不使用镜像延长；试用、零宽限和内存缓存模式
不缓存内容密钥。缓存绑定实例指纹、软件、服务端公钥、授权及载荷，复制到另一实例无法解开。
已成功进入离线宽限的同一票据直接读取缓存，不重复等待网络超时。
不生成或读取启动桩的 `payload_proof` 证据文件；低层解锁本身不加载模块；使用下述 Guard.requireSealed 安装内存核心包。

测试：`npm test`；静态检查：外部安装 ESLint 9+ 后运行 `eslint . --max-warnings 0`。


## 加密 CommonJS 核心包：内存加载

```js
import { startGuard } from "authgo";
import { CONFIG, VERSION } from "./authgo-build.js"; // 固定在程序中的配置
const guard = await startGuard({ config: CONFIG, version: VERSION });
const core = await guard.requireSealed("core");
```

ESM 主程序可直接使用上面的写法。CommonJS 主程序在自己的异步入口使用
`const { startGuard } = await import("authgo")`，随后使用相同接口；这不要求把主程序改为 ESM。
`requireSealed` 读取 `/opt/authgo/payload.json` 中名为 `core` 的 Node 单文件和相邻编号 `.agc`。
任务约定的 `AUTHGO_PAYLOAD_DIR` 可更换公开密文目录；payload.config 仅参与信封绑定，
从不替换已创建 Client 的连接配置。构建时先将核心及其私有依赖打包为单个 CommonJS 文件，
再执行 `authgo-pack --node core=/staging/core.cjs ... --out /opt/authgo`。

Node 22 实验确认 `Module._compile(source, filename)` 的双参数调用可用；由它提供标准的
`exports`、`module.exports`（含函数、原始值）、异常传播和 require 语义。
核心的 filename 是密文目录内**不存在于磁盘**的 `.authgo-sealed-core.cjs`，不是可执行明文文件。
内存模块不注册全局 `require.cache`，不能通过普通 require 绕过入口门控。
`require('./helper.cjs')` 相对密文目录解析，第三方公开依赖从该目录的 `node_modules`
及 Node 的父目录搜索路径解析；这些依赖是公开文件，不受本核心的代码加密保护。
建议将需要保密的依赖一并打包，数据文件单独公开发布；不要依赖核心的真实文件路径。

仅支持 CommonJS 单文件，不支持 ESM 密封包、动态 import 或原生 `.node` 插件。
加载前用保守的词法检查拒绝 import/export、.node、dlopen，再验证 CommonJS 语法；
注释/字符串中的同名内容也可能被拒绝。运行时 require 还会拒绝解析为 `.node`/`.mjs` 的文件。
这不是 JavaScript 沙箱，不能防止已获授权、能修改进程的客户从内存还原代码。

同一 Guard/名称/载荷重复调用返回相同 exports，并发调用共享一次解锁及求值。
同名但载荷绑定、文件索引或目录改变时拒绝，不能混用旧 exports；升级需重启程序。
失败不保留部分 exports，可重新尝试。已有同名虚拟文件或全局 require 缓存冲突也会拒绝。
调用入口及每次求值前、核心发起 require 时检查 Guard；明确拒绝、到期或关闭后不能再加载。
已经返回的对象/函数不能撤销，应用仍需按 Guard.done/error 规则退出。

`decryptPayloadFile(payload, key, index, ciphertext)` 是同步迭代器，支持 Buffer/Uint8Array，
每块（最大 1 MiB）GCM 认证成功后才返回。`payloadCipherSize(size)` 返回 bigint 精确总长，
空文件也有认证标签。消费方必须完整迭代，任一失败都丢弃部分结果。
加载器不写明文、不创建临时文件；分块缓冲有界，但完整源字符串及执行对象需要随核心包大小
增长的内存。内容密钥和中间明文 Buffer 用后清零，JavaScript 字符串/V8 内部副本无法保证擦除。
既有 unlockPayload、试用、离线缓存和明确拒绝规则不变，不生成启动桩证据文件。

## Payload v2 与运行时水印

SDK 只接受 payload v2。公开 manifest 必须且只能含一个 `__authgo_watermark` 条目（`kind: "watermark"`、`encoding: "raw"`）；私有槽位索引作为独立 AES-GCM 密文保存。先认证私有索引全部分块，再认证目标代码并验证槽位，最后写入签名响应中的水印。

公开解锁接口返回 K32；内部加载材料及内容缓存为 K32||WM32。WM 必须是非零 32 字节值，并由响应签名认证。缓存使用 `AUTHGO-PAYLOAD-CACHE-v2.` 和 `authgo-payload-v2-`，绑定原始载荷、授权、实例及签名宽限窗口。试用和零宽限不缓存。未知或未认证响应不能产生新证据，完整认证的明确拒绝按授权动作规则处理。

当前算法仍使用 `authgo/payload/v1/wrap`、`authgo/payload/v1/rewrap`、`authgo-payload-chunk-v1` 等密码学域，它们不是旧载荷格式入口。Go/Rust 启动桩证据使用独立的 `AUTHGO-PAYLOAD-PROOF-v1.` 当前格式。

水印用于事后追踪，不防宿主调试器或内存导出，不能保证反编译、重编译或修改后保留。运行中代码无法安全撤回，高层守卫与敏感入口必须继续校验授权。协议以 [完整协议](../../server/internal/apidocs/protocol.md) 为唯一来源。
