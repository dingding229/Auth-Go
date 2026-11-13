# Auth Go Python SDK

Python 3.9+。依赖：cryptography（X25519、Ed25519、HKDF、AES-GCM）。尚未发布到公共包仓库；从本仓库安装，不要使用不存在的公共包坐标。

## 本仓库安装与最简示例

在仓库根目录，先把后台配置写入示例的源码常量并构建，只设置`AUTHGO_LICENSE`后执行：

```sh
python -m pip install ./sdk/python
python sdk/python/example.py
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

缓存目录优先级：显式缓存目录 > 非空AUTHGO_CACHE_DIR > 容器默认/var/lib/authgo > 原用户缓存目录。显式空目录禁用磁盘缓存。对应本语言参数：cache_dir / fingerprint。

容器在缓存目录原子创建0600的instance-id文件，内容为32随机字节的小写十六进制（不附换行）。指纹是SHA256("authgo/instance/v1\0"+标识文本)的小写十六进制；AUTHGO_INSTANCE_ID也按原值使用同一算法，不做去空白或大小写转换。持久卷重建保持身份，删除卷成为新实例。目录不可用时使用进程内随机身份并继续在线运行，result.cache_warning给出“此实例重启后是新实例，没有断连宽限”。

每个进程还产生独立的16随机字节Base64URL instance_session，不写缓存。共享缓存的新进程可以接管实例；服务端保留每个激活最近32个session历史。已收到完整认证INSTANCE_REPLACED的旧进程立即失败，不能进入宽限、不能重新创建Client忘记拒绝，也不能清除新进程缓存。它不是普通授权拒绝清缓存规则的放宽；其他已认证明确拒绝仍立即清除授权证据。

浮动授权只有连接故障或已认证临时错误才使用原签名grace_until，即使旧lease已过期也保留功能与解锁值。到期和时钟回拨仍优先拒绝；grace_hours=0不提供离线宽限。窗口结束返回SDK_GRACE_EXPIRED，不降级、不用镜像延长。恢复后心跳重新竞争席位；满额的明确拒绝绝不回退。只有实际观察过故障并成功回退的当前Client，才能在原宽限内通过本地validate及unlock继续使用过期lease票据。

正常退出时可调用：

```python
client.release_seat()
```

它只释放浮动容量，不解绑、不扣解绑次数、不撤销激活token、不删除有效缓存；非浮动授权为本地无操作。连接故障/临时错误保留缓存；明确拒绝沿用授权分类，INSTANCE_REPLACED只停止旧进程。SDK不注册信号或退出程序，信号处理由业务程序负责。高层守卫接口见下文。

VERSION_DISABLED为已认证拒绝，可从error.latest_version读取最新允许且未禁用的版本；未上报版本不受禁用标记影响。禁用旧版本不妨碍更新检查与客户自行拉取允许的新镜像版本，更新请求仍然不改变授权缓存。

边界：若已有持久缓存可读，但目录后来变为只读，故障回退必须先持久化最晚时间水位；写入失败与Go一样返回SDK_CACHE_UNAVAILABLE，不跳过时钟回拨保护。这不同于新实例一开始无法写目录时的纯内存运行。

## 容器高层接口

```python
import authgo
from _authgo_build import CONFIG, VERSION  # 构建生成，不加载客户提供的配置

guard = authgo.start_guard(config=CONFIG, version=VERSION)
guard.require("export")                  # 仅本地验签与功能检查
result = guard.result                     # 并发安全的深拷贝
# 业务程序自己处理SIGTERM/SIGINT；等待guard.done后以authgo.EXIT_LICENSE退出。
guard.close()                             # 停止校验并释放席位，整体最多5秒
```

配置必填，SDK不读取AUTHGO_CONFIG或配置文件；仅授权码默认读取AUTHGO_LICENSE。构建生成的`_authgo_build.py`是程序的一部分，不挂载为可替换配置。首次check失败直接抛出Error，不启动循环。后台守护线程自动验证和浮动心跳；`on_change(result, error)`在SDK锁外调用，应及时返回、不抛异常。宽限只通知变化，不触发`done`；明确拒绝、宽限耗尽等最终失败设置`threading.Event`类型的`done`，`error`保留原因。`require`不联网，完成信号触发后必定失败。`close`幂等，失败抛Error；也支持`with authgo.start_guard(...) as guard:`。SDK不退出进程、不处理信号、不启动子进程，除缓存外不写文件。EXIT_LICENSE为77。

完整HTTP程序、构建与只读根/非root/缓存卷配置见`examples/docker/python/`。多线程可安全读取`result`，返回值的features等嵌套数据不会修改守卫状态。不会替换运行中的程序。

心跳间隔来自已验签响应的`data.heartbeat_interval`（它不在票据载荷里），保存于本机加密缓存并由守卫调度。旧缓存没有这项元数据时，浮动授权从签名票据剩余的双心跳租约保守推导更早的重试间隔；第一次联网成功后使用服务器返回的准确间隔。不修改票据，不放宽租约、宽限、到期或拒绝判断。

### 更新维护期

Result公开`maintenance_until`、`latest_entitled_version`，错误公开最高可用版本。可选字段缺失时表示不限/空值。维护期按服务端记录的版本发布时间判断，不是授权到期；SDK不使用本地时间拒绝。断网沿用已有缓存与宽限，联网收到`MAINTENANCE_EXPIRED`后按明确拒绝处理；高层守卫语义与`VERSION_DISABLED`相同。更新动作失败仍不清授权缓存。

### 免授权码试用

仅高层守卫在配置已由调用方传入、授权码和AUTHGO_LICENSE均为空时申请试用；低层check仍要求有效格式授权码。Result的`is_trial`表示当前是否试用。试用只保存在已有加密缓存，不打印授权码；重启复用。试用无断网宽限，网络故障最终失败，常驻程序退出77，请求式PHP返回503。管理员转正后下一次校验恢复正式授权宽限。TRIAL_DISABLED提示配置AUTHGO_LICENSE，TRIAL_IP_LIMIT及TRIAL_QUOTA_EXCEEDED为已认证明确拒绝。

### 运行时内容密钥解锁

```python
payload = authgo.parse_payload(payload_json_bytes)  # 完整原始 payload.json，最多64KiB
client.check(license_key)                          # 必须先成功校验，不隐式激活
content_key = client.unlock_payload(payload)       # 32字节，仅供当前进程使用
```

`Payload`/`PayloadEnvelope`为不可变数据类；`payload.payload_binding()`与Go的当前载荷绑定完全一致。配置仍由调用方固定在程序中；payload中的公开config只参与原信封绑定，不决定请求目标。

解锁复用现有v2加密通道和响应认证，再验证签名票据的challenge、授权编号、时间及解锁哈希，用本次临时X25519密钥解开重新封装。只在最近一次已验证票据的原始`grace_until`内允许读取内容密钥缓存，不能扩大此期限；原授权的到期和未开始检查仍生效。低层解锁本身不注册导入钩子；使用下述 Guard.install_sealed 安装内存包。

内容密钥缓存与 Go 使用相同的协议字节编码：由签名票据的`unlock_hash`、实例指纹和载荷标签派生AES-GCM密钥，文件名不含授权码，0600权限，同目录临时文件写入、fsync后原子替换。不可写只放弃缓存，不影响成功在线解锁。试用、零宽限不缓存；已认证明确拒绝立即删除该上下文全部内容密钥缓存，`PAYLOAD_INVALID`和网络/验签失败不清缓存。已有离线校验成功时直接读缓存，不重复网络等待。

Python不生成或使用`AUTHGO-PAYLOAD-PROOF-v1`启动桩证据文件，也不读取Go/Rust私有授权缓存。内容密钥返回为Python bytes，使用后及时解除引用；Python及底层密码库的内存副本无法保证完全清零。不打印内容密钥或授权码。缓存不防可读取实例身份、有效票据和缓存卷的本机所有者。

跨语言向量由现有`tests/vectors.py`入口执行；Python单元测试可用`python -m pytest sdk/python/tests/test_payload.py sdk/python/tests/guard.py`运行（在具备 Python 依赖的环境中）。复用现有payload向量，不修改已发布向量或增加运行时依赖。


## 加密 Python 包：内存加载

```python
import authgo
from _authgo_build import CONFIG, VERSION  # 固定在程序中的接入配置

guard = authgo.start_guard(config=CONFIG, version=VERSION)
guard.install_sealed("core")
import core
```

`install_sealed` 从 `/opt/authgo/payload.json` 读取完整载荷，按清单名字选择 Python 包。
可用任务约定的 `AUTHGO_PAYLOAD_DIR` 更换**公开密文**目录；该路径和 payload 中的公开 config
都不能替换 Client 的连接配置。目录内同时放置编号的 `00000000.agc` 等密文文件。
安装应在首次 import 之前执行；已安装、同名已导入、清单缺失或认证失败都会明确拒绝，
不会回退加载磁盘上的同名明文模块。

构建时用与运行镜像**主次版本相同**的 CPython，先在独立发布暂存目录编译 `.pyc`，
移除暂存目录的 `.py`，再交给 `authgo-pack --python core=/staging/core ... --out /opt/authgo`。
不要对开发源码目录执行删除。接受 CPython 3.8–3.14 的正式版 magic，但本 SDK 最低版本仍为
Python 3.9；只加载与当前解释器 magic 完全相同的字节码。支持平铺 `.pyc` 及标准
`__pycache__/模块.cpython-XY[.opt-1/.opt-2].pyc` 布局；不要同时打包同一模块的多个变体。
支持子包、相对导入及纯 Python 隐式命名空间包；不支持 `.so` / `.pyd` 原生扩展。

解密遵循原分块协议：`decrypt_payload_file(payload, key, index, ciphertext)` 返回迭代器，
每块 AES-GCM 认证后才产出（最多 1 MiB），总长由 `payload_cipher_size(size)` 校验，空文件也有
一个认证标签。输入可为 bytes / memoryview。调用方必须完整消费迭代器，任何块认证失败都要
丢弃已取得的部分内容。加载器流式解析内存 tar，全部认证、检查完成后才注册 MetaPathFinder；
不解压到磁盘、不创建临时目录、不生成 `.pyc` 缓存文件。密文、模块字节码及执行对象需要进程
内存，因此总驻留内存随核心包大小增长；只有分块解密缓冲是约 1 MiB，不宣称整个包常量内存。
内容密钥用后尽力清零；Python/加密库可能保留不可变对象副本，不能承诺所有副本已擦除。

`__file__`、包路径及代码对象的文件名使用 `authgo-sealed://` 虚拟路径。
不支持 `importlib.resources` 或依赖真实文件路径的操作，数据文件应放在加密包之外。
每次发现、执行新模块前重新检查 Guard，关闭、过期或明确拒绝后不能继续加载新模块。
Python 的 `sys.modules` 会保留已经导入的模块，加载器不能撤销已执行代码；应用仍须按 Guard
的 done/error 退出规则处理吊销。既有解锁、试用及密钥缓存规则保持不变，不生成启动桩证据文件。

测试：`python -m pytest sdk/python/tests`（包括原解锁/缓存回归和新的分块/加载测试）。
原七语言 conformance 的 Python 入口也验证 `payload-envelope` 分块向量。

## Payload v2 与运行时水印

SDK 只接受 payload v2。公开 manifest 必须且只能含一个 `__authgo_watermark` 条目（`kind: "watermark"`、`encoding: "raw"`）；私有槽位索引作为独立 AES-GCM 密文保存。先认证私有索引全部分块，再认证目标代码并验证槽位，最后写入签名响应中的水印。

公开解锁接口返回 K32；内部加载材料及内容缓存为 K32||WM32。WM 必须是非零 32 字节值，并由响应签名认证。缓存使用 `AUTHGO-PAYLOAD-CACHE-v2.` 和 `authgo-payload-v2-`，绑定原始载荷、授权、实例及签名宽限窗口。试用和零宽限不缓存。未知或未认证响应不能产生新证据，完整认证的明确拒绝按授权动作规则处理。

当前算法仍使用 `authgo/payload/v1/wrap`、`authgo/payload/v1/rewrap`、`authgo-payload-chunk-v1` 等密码学域，它们不是旧载荷格式入口。Go/Rust 启动桩证据使用独立的 `AUTHGO-PAYLOAD-PROOF-v1.` 当前格式。

水印用于事后追踪，不防宿主调试器或内存导出，不能保证反编译、重编译或修改后保留。运行中代码无法安全撤回，高层守卫与敏感入口必须继续校验授权。协议以 [完整协议](../../server/internal/apidocs/protocol.md) 为唯一来源。
