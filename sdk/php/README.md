# Auth Go PHP SDK

PHP 8.1+。依赖：sodium、openssl 扩展，零 Composer 依赖。尚未发布到公共包仓库；从本仓库安装，不要使用不存在的公共包坐标。

## 本仓库安装与最简示例

在仓库根目录，先把后台配置写入示例的源码常量并构建，只设置`AUTHGO_LICENSE`后执行：

```sh
php sdk/php/example.php
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

容器在缓存目录原子创建0600的instance-id文件，内容为32随机字节的小写十六进制（不附换行）。指纹是SHA256("authgo/instance/v1\0"+标识文本)的小写十六进制；AUTHGO_INSTANCE_ID也按原值使用同一算法，不做去空白或大小写转换。持久卷重建保持身份，删除卷成为新实例。目录不可用时使用进程内随机身份并继续在线运行，$result->cacheWarning给出“此实例重启后是新实例，没有断连宽限”。

每个进程还产生独立的16随机字节Base64URL instance_session，不写缓存。共享缓存的新进程可以接管实例；服务端保留每个激活最近32个session历史。已收到完整认证INSTANCE_REPLACED的旧进程立即失败，不能进入宽限、不能重新创建Client忘记拒绝，也不能清除新进程缓存。它不是普通授权拒绝清缓存规则的放宽；其他已认证明确拒绝仍立即清除授权证据。

浮动授权只有连接故障或已认证临时错误才使用原签名grace_until，即使旧lease已过期也保留功能与解锁值。到期和时钟回拨仍优先拒绝；grace_hours=0不提供离线宽限。窗口结束返回SDK_GRACE_EXPIRED，不降级、不用镜像延长。恢复后心跳重新竞争席位；满额的明确拒绝绝不回退。只有实际观察过故障并成功回退的当前Client，才能在原宽限内通过本地validate及unlock继续使用过期lease票据。

正常退出时可调用：

```php
$client->releaseSeat();
```

它只释放浮动容量，不解绑、不扣解绑次数、不撤销激活token、不删除有效缓存；非浮动授权为本地无操作。连接故障/临时错误保留缓存；明确拒绝沿用授权分类，INSTANCE_REPLACED只停止旧进程。SDK不注册信号或退出程序，信号处理由业务程序负责。高层接口见下文。

VERSION_DISABLED为已认证拒绝，可从$error->latestVersion读取最新允许且未禁用的版本；未上报版本不受禁用标记影响。禁用旧版本不妨碍更新检查与客户自行拉取允许的新镜像版本，更新请求仍然不改变授权缓存。

边界：若已有持久缓存可读，但目录后来变为只读，故障回退必须先持久化最晚时间水位；写入失败与Go一样返回SDK_CACHE_UNAVAILABLE，不跳过时钟回拨保护。这不同于新实例一开始无法写目录时的纯内存运行。

## 高层接口：常驻CLI与请求式（FPM、Apache等）

```php
require '/app/sdk/Client.php';
require '/app/authgo-build.php'; // 构建生成，只读程序的一部分
$guard = AuthGo\start_guard(['config' => CONFIG, 'version' => VERSION]);
$guard->require('export'); // 不联网，关键入口可重复调用
$result = $guard->result(); // 独立快照
```

配置必填，由调用方传入；SDK不从环境变量或文件加载配置。仅license缺省或空时读取AUTHGO_LICENSE。首次检查失败直接抛AuthGo\Error，不启动循环、不退出进程。EXIT_LICENSE=77。心跳间隔来自已验签响应，写入加密缓存；旧缓存可从签名租约保守推导间隔，不延长租约/宽限。`on_change($result,$error)`在变化时通知，应及时返回、不抛异常。

### 常驻CLI

由业务定时器反复调用`$guard->tick()`，建议主循环每50毫秒检查一次；SDK只在到达验证/心跳/有效期截止时联网。原签名宽限内继续返回结果；最终失败设置`done()`，`error()`保留原因，并抛错误。require完成后必定失败。`close()`幂等，使用至多5秒的HTTP总预算释放席位，失败只抛错误。调用方提供的transport必须遵守传入的超时预算，不能在单线程PHP中强制中断不合作的任意回调。

examples/docker/php/采用CLI＋stream_socket_server，无守护子进程或gate。仅示例镜像启用PHP自带pcntl，由业务程序处理SIGTERM/SIGINT、关闭释放、最终失败退出77。SDK不注册信号、不启动子进程、不注册shutdown hook，除缓存外不写文件。真实测试覆盖全部19项，包括停止后立即释放。

### 请求式（FPM、Apache等）

examples/docker/php-fpm/采用真实php-fpm＋无特权nginx；examples/docker/php-apache/采用php:8.1-apache的真实mod_php、4个prefork进程。两者均非root、只读根文件系统、cap_drop ALL、no-new-privileges，使用命名缓存卷；Apache监听8080，运行文件只写/tmp的tmpfs，配置和SDK位于DocumentRoot之外。每个HTTP请求调用start_guard；只有PHP_SAPI为cli才是常驻模式，其余（fpm-fcgi、apache2handler、cgi-fcgi、litespeed、cli-server等及未知SAPI）统一为请求式，不新增模式配置。用本机缓存文件的flock串行化**重新载入缓存、校验、到期联网和持久化**。未到next_check_in/心跳截止时只本地验签；多个worker不会同时重复激活/验证。没有可写缓存时仍能按低层SDK规则在线运行，但不能跨worker共享身份/证据；请求式部署应始终挂载可写命名卷。

请求式不发送instance_session，使用请求式实例校验：依然完整校验加密信道、HMAC、Ed25519响应/票据、激活token、实例指纹、用户、授权和版本，**只不做进程替换检测**。代价是请求式多个副本共用同一卷时检测不到冲突，不能把它当成CLI的共卷接管保护。容器身份仍从同一卷取得，各worker共用一个席位。

请求式无后台心跳：空闲超过双心跳租约后容量回收，下次请求用heartbeat重新竞争，满额则拒绝。请求结束不调用close（否则每次请求都释放容器席位）；docker stop没有可靠的PHP退出释放钩子，依靠租约到期回收。授权拒绝不结束worker或Web服务器，由调用方返回503和稳定原因；下一次需要联网时才发现吊销/禁用，这是next_check_in窗口的边界。故障时原签名宽限内可继续服务和重启；窗口耗尽或空缓存时返回503。CLI则由业务程序选择exit(77)。

请求式真实容器测试使用 php-fpm 测试组，覆盖多 worker 合并联网、空闲回收/重抢、吊销清缓存、版本禁用、停服/重启宽限、席位耗尽和空卷拒绝；Apache 还覆盖多个进程并发、一次联网、一个席位、无 instance_session 以及吊销返回503而不退出。测试时钟路由只进入临时测试镜像，不进入正式示例。

### 更新维护期

Result公开`maintenanceUntil`、`latestEntitledVersion`，错误公开最高可用版本。可选字段缺失时表示不限/空值。维护期按服务端记录的版本发布时间判断，不是授权到期；SDK不使用本地时间拒绝。断网沿用已有缓存与宽限，联网收到`MAINTENANCE_EXPIRED`后按明确拒绝处理；高层守卫语义与`VERSION_DISABLED`相同。更新动作失败仍不清授权缓存。

### 免授权码试用

仅高层守卫在配置已由调用方传入、授权码和AUTHGO_LICENSE均为空时申请试用；低层check仍要求有效格式授权码。Result的`isTrial`表示当前是否试用。试用只保存在已有加密缓存，不打印授权码；重启复用。试用无断网宽限，网络故障最终失败，常驻程序退出77，请求式PHP返回503。管理员转正后下一次校验恢复正式授权宽限。TRIAL_DISABLED提示配置AUTHGO_LICENSE，TRIAL_IP_LIMIT及TRIAL_QUOTA_EXCEEDED为已认证明确拒绝。

## 运行时内容密钥解锁

```php
$client = new \AuthGo\Client(CONFIG); // CONFIG 在构建时固化，不从环境或文件读取
$client->check($licenseKey);
$payload = \AuthGo\Payload::parsePayload($payloadJson); // 完整原始 payload.json，含 config
$contentKey = $client->unlockPayload($payload);
try {
    // 在内存使用 32 字节内容密钥；不把明文或密钥写到磁盘。
} finally {
    sodium_memzero($contentKey);
}
```

`unlockPayload` 不隐式激活。必须先完成 `check`、`activate` 或 `verify`；从磁盘恢复一个 Client
并不足以解锁。请求式 Guard 通过既有缓存路径完成本地验签、有效期和状态检查后，也可使用其已接受结果。
载荷内公开 `config` 只参与信封绑定，不会改变连接目标。请求和响应仍经过既有 v2 加密、HMAC、
Nonce、Ed25519 和挑战认证，内容密钥再用独立 X25519 临时密钥解封。
`is_trial` 和零宽限不缓存；已认证明确拒绝清理内容密钥，`INSTANCE_REPLACED` 保留授权票据但禁止旧进程再解锁。
`PAYLOAD_INVALID` 是临时错误，不清旧缓存。新票据上下文错误和解封失败直接报错，不用旧缓存掩盖错误。
正常释放席位仍保留有效缓存，释放时收到明确拒绝才按分类清理。

缓存格式为跨语言 `AUTHGO-PAYLOAD-CACHE-v2`。派生、AAD、文件名与 Go/Python/Node/Java/C# 一致；
二进制 label 直接传给既有 HKDF，不转换为字符串编码。整数沿用 JsonNumber 原文，uint64 用十进制
字符串逐字节编码，不经过 float、不依赖 GMP；授权 ID 大于 PHP_INT_MAX 时也不会丢精度。
缓存只含密文，0600 权限，写入临时文件并 fsync 后原子改名；用 lstat 排除符号链接/非普通文件，
打开后比较 fstat 的设备号/inode，读取后再次复查路径和句柄。大小上限 256 字节，解密必须通过 AEAD。
PHP 的标准文件接口不提供 O_NOFOLLOW；这里依靠打开后的身份校验拒绝替换，不把路径检查当作句柄检查。
Windows、32 位 PHP 或无法可靠取得权限/整数设备号和 inode 时不落盘内容密钥；存储不可写不影响在线解锁。
内容密钥缓存仅在原签名票据宽限内可用，不使用镜像延长；内存缓存模式不写磁盘缓存；不再接受离线授权文件。
已成功进入离线宽限的同一票据直接读密钥缓存，不重复等待网络超时。复制到另一实例无法解开。
不生成、读取或删除 `payload_proof` 证据文件，不实现启动桩；PHP 流包装器见“PHP 流包装器与内存加载”小节。

### CLI 与请求式运行

仅 CLI 发送进程 `instance_session`；FPM、Apache、cli-server 等请求式运行仍不发送该字段。
CLI API 同步执行；请求式解锁及授权复用既有 guard 缓存锁，串行覆盖重新载入、验签、网络请求与写入。
锁可在同一同步调用链内嵌套，嵌套时不会再次加载缓存覆盖部分内存状态。
不能取得可写锁时，低层接口仍可在线执行，但不会获得跨 worker 的持久共享保证。
不要在自定义 transport 回调内重入同一 Client，也不要跨 Fiber 共享尚未完成操作的 Client。
请求式拒绝仍由应用返回 503，SDK 不结束 worker；常驻 CLI 的退出码由程序决定。

测试入口 `php sdk/php/tests/vectors.php` 包含 25 项载荷测试及三个载荷向量；
同时运行 `php sdk/php/tests/guard.php`。并发用例使用真实 PHP 子进程验证文件锁，
另以真实 cli-server 验证请求式恢复和不发送 session；FPM/Apache 测试使用对应的容器入口。

## PHP 内存加载器

```php
require_once '/app/sdk/Client.php';
$guard = AuthGo\Guard::start(['config' => CONFIG, 'version' => VERSION]);
$guard->installSealed('core');
require 'authgo-sealed://core/bootstrap.php';
```

`CONFIG`、`VERSION` 必须是发布时固定在程序源码中的常量；不能改为从客户文件或环境变量载入信任配置。
`AUTHGO_PAYLOAD_DIR`（默认 `/opt/authgo`）只定位公开密文，不能改变 SDK 的服务地址、公钥或版本。
沿用 `authgo-pack --php core=/app/core ... --out /opt/authgo` 的 USTAR、1 MiB 分块 AES-GCM 和原有信封格式，
不使用 `eval`，不解压到磁盘或临时文件。每块先认证，全部认证和 tar 校验完成后才发布整棵文件树。
密钥在解密结束的 `finally` 中用 `sodium_memzero` 清理，不在加载器中持有跨加载的裸密钥；
再次解锁仅通过现有 Client 的在线解锁/签名票据有效期内的加密缓存路径。试用、零宽限不写密钥缓存；
认证明确拒绝沿用原分类清缓存，损坏密文、未认证网络错误不能撤销磁盘上的合法缓存。

### 引用和自动加载

- 支持 `require` / `include` / `require_once` / `include_once`，`__FILE__`、`__DIR__` 指向虚拟 URL。
- 包内推荐 `require __DIR__.'/lib/Thing.php'`；允许在同一包根目录内使用 `../`，不能越过根目录。
  PHP 普通裸相对引用（如 `include 'lib/Thing.php'`）仍遵循 PHP 的 include_path / CWD / 调用者目录搜索规则；
  不要在不可信 CWD 或 include_path 下使用裸相对引用。显式 `authgo-sealed://...` 缺失时不会退回磁盘。
- 自动加载器由应用注册，例如 `spl_autoload_register` 中将命名空间映射到
  `authgo-sealed://core/Namespace/Class.php`。不自动修改 Composer 或全局 include_path。
- 虚拟文件只读，支持读、seek、stat；不提供写入、目录遍历、资源文件、原生扩展或 Phar。
  安装已挂载的同名包会报错，必须在第一次引用前安装；最后一个挂载关闭后，同进程的新 Guard 可以重新安装。
  wrapper 所有权通过无源码探针检查当前实际实现，不以挂载数量或历史注册标记判断；外来 wrapper 不会被覆盖或接管。
  每次安装具有独立的规范虚拟路径，避免跨请求/版本路径复用。
- 仅接受 UTF-8 的规范相对路径和 `.php` 普通条目；拒绝反斜杠、ASCII 控制/空白字符、冒号、百分号、查询/片段、
  重复文件、文件/目录冲突、链接、PAX/GNU/sparse 扩展、坏校验和、截断、非零 padding 和尾随内容。
  当前限制为 64 位 PHP、每包 tar 最大 256 MiB、最多 65535 个文件、路径最多 255 字节；
  内存用量包括 tar、源码表和 PHP 编译器副本，需为大包预留多倍空间。打包器可能接受更宽的文件名，发布前须按此限制整理。

### FPM、CLI、Swoole 的校验与清理

- FPM/Apache：每个请求都重新 `Guard::start`、`installSealed`；沿用请求式缓存锁，在每次请求本地验签和检查有效期，
  到签名调度时间才复验/心跳。每个请求重新取有效内容密钥或走既有离线缓存规则，不跨请求保留裸密钥。
  空闲 worker 不会后台心跳。拒绝时由控制器返回 503，不杀 FPM worker，不依赖退出码 77。
- 常驻 CLI：在应用现有事件循环中定时调用 `$guard->tick()`（例如每秒）；Swoole 以 CLI 启动时同样处理，
  可在应用已有 `Swoole\Timer::tick(1000, ...)` 回调里调用，错误时停止业务并关闭 Guard。
  SDK 不安装信号、后台线程或新的 Swoole 依赖，也不隐式退出进程。
- 流包装器每次实际执行打开、读取、seek、stat 回调时，还会按 Guard 的既有调度触发 `tick()` 和本地检查；不能用“代码已加载”替代定时校验。
  若业务永不再触及流且从不调用 `tick()`，SDK 没有办法中断已执行的 PHP 代码。
- Guard 关闭或校验失败会撤销其全部挂载并清理 SDK 持有的源码字符串；只处理本 Guard 所属流，不关闭其他 Guard 的流。
  空闲流句柄连同 PHP 原生预读缓冲一起关闭；若拒绝发生在该流的回调中，不在原生回调栈内释放句柄，
  而是撤销流并作空的 SEEK_END 使原生读缓冲失效，之后读取拒绝。重复安装和错误路径不会撤销无关合法包。
  关闭/临时错误不会额外删除合法的磁盘密钥缓存，认证明确拒绝仍按原规则删除。
  析构只清理内存，不隐式联网释放席位；CLI 正常退出应显式 `close()`。

### 安全边界与 opcache

PHP 在七种语言中保护最弱：解密后的源码可以被扩展、调试器、进程内存读取者取得。
`sodium_memzero` 用于 SDK 持有的裸密钥、tar 和源码表，但 PHP 引擎/扩展可能持有字符串副本、已编译 opcode、
函数或类；不能承诺对整个解释器堆做可靠擦除。拒绝后不能再从流加载新代码，但不能撤销已定义函数/类，
也不能撤回应用已经通过 `fread` 取得的明文；应用必须在 Guard 报错后停止受保护业务。
回归明确验证：关闭后不能再从 URI 加载，但先前编译的函数仍可被调用。新 Guard 重装不是函数/类热更新，
同名声明仍可能冲突，需要更换业务代码时应重启进程。
`require_once` 对已经包含过的文件可能直接返回，不是新的权限检查入口。不要设置 opcode 预加载来预载受保护文件。

**opcache 限制：**真实 PHP 8.1.34 实测发现，裸相对 `include` 虽最终由自定义流打开，仍可能被 opcache
缓存，单靠虚拟 URL 或 `mtime=0` 不够。因此 `installSealed` 在暴露源码前，固定关闭**当前请求**的
`opcache.enable`，不修改 php.ini、不重置共享缓存、不关闭其他请求的 opcache。CLI 则持续关闭至进程结束。
若管理员锁定该设置或禁用 `ini_set`，不能确认已关闭时直接返回 `PAYLOAD_INVALID`，不会解锁或发布源码。
这是支持裸相对加载且不把受保护 opcode 落盘的安全取舍，会影响受保护请求的 PHP 编译性能。
不要在首次安装前编译/预载受保护文件，也不要使用会独立缓存用户流的第三方扩展。

真实 FPM / opcache 测试入口为 `python3 scripts/test-php-sealed.py`：启动时启用 opcache、
关闭时间戳复查，并打开磁盘 file-cache，另测 file-cache-only 和禁用 `ini_set` 时的失败关闭；验证普通脚本确实入缓存、受保护请求关闭 opcache、随后普通探针请求
仍启用 opcache 且没有密封脚本入缓存。覆盖两个 worker、多次请求、相对引用、自动加载、关闭/吊销、
停服后重启宽限，以及卷、file-cache、容器文件系统和全部镜像层无源码标记。
此行为受 PHP/opcache 版本和扩展影响，目标部署版本必须复跑。

单元测试：`php sdk/php/tests/sealed.php`、`php sdk/php/tests/sealed-security.php`（均由既有 `vectors.php` 入口执行）。
补充覆盖 A 关闭/B 重装、外来 wrapper 首次/替换/空挂载后拒绝、预读缓冲、多个挂载隔离、重复安装、错误路径和已编译代码限制；旧向量和 Guard 测试断言不变。

## Payload v2 与运行时水印

SDK 只接受 payload v2。公开 manifest 必须且只能含一个 `__authgo_watermark` 条目（`kind: "watermark"`、`encoding: "raw"`）；私有槽位索引作为独立 AES-GCM 密文保存。先认证私有索引全部分块，再认证目标代码并验证槽位，最后写入签名响应中的水印。

公开解锁接口返回 K32；内部加载材料及内容缓存为 K32||WM32。WM 必须是非零 32 字节值，并由响应签名认证。缓存使用 `AUTHGO-PAYLOAD-CACHE-v2.` 和 `authgo-payload-v2-`，绑定原始载荷、授权、实例及签名宽限窗口。试用和零宽限不缓存。未知或未认证响应不能产生新证据，完整认证的明确拒绝按授权动作规则处理。

当前算法仍使用 `authgo/payload/v1/wrap`、`authgo/payload/v1/rewrap`、`authgo-payload-chunk-v1` 等密码学域，它们不是旧载荷格式入口。Go/Rust 启动桩证据使用独立的 `AUTHGO-PAYLOAD-PROOF-v1.` 当前格式。

水印用于事后追踪，不防宿主调试器或内存导出，不能保证反编译、重编译或修改后保留。运行中代码无法安全撤回，高层守卫与敏感入口必须继续校验授权。协议以 [完整协议](../../server/internal/apidocs/protocol.md) 为唯一来源。
