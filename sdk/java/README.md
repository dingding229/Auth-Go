# Auth Go Java SDK

Java 17+。依赖：JDK 内置密码与 HTTP，零 Maven 依赖。尚未发布到公共包仓库；从本仓库安装，不要使用不存在的公共包坐标。

## 本仓库安装与最简示例

在仓库根目录，先把后台配置写入示例的源码常量并构建，只设置`AUTHGO_LICENSE`后执行：

```sh
javac -d /tmp/authgo-java sdk/java/src/main/java/io/authgo/*.java sdk/java/Example.java
java -cp /tmp/authgo-java Example
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

缓存目录优先级：显式缓存目录 > 非空AUTHGO_CACHE_DIR > 容器默认/var/lib/authgo > 原用户缓存目录。显式空目录禁用磁盘缓存。对应本语言参数：Options.cacheDir / Options.fingerprint。

容器在缓存目录原子创建0600的instance-id文件，内容为32随机字节的小写十六进制（不附换行）。指纹是SHA256("authgo/instance/v1\0"+标识文本)的小写十六进制；AUTHGO_INSTANCE_ID也按原值使用同一算法，不做去空白或大小写转换。持久卷重建保持身份，删除卷成为新实例。目录不可用时使用进程内随机身份并继续在线运行，result.cacheWarning给出“此实例重启后是新实例，没有断连宽限”。

每个进程还产生独立的16随机字节Base64URL instance_session，不写缓存。共享缓存的新进程可以接管实例；服务端保留每个激活最近32个session历史。已收到完整认证INSTANCE_REPLACED的旧进程立即失败，不能进入宽限、不能重新创建Client忘记拒绝，也不能清除新进程缓存。它不是普通授权拒绝清缓存规则的放宽；其他已认证明确拒绝仍立即清除授权证据。

浮动授权只有连接故障或已认证临时错误才使用原签名grace_until，即使旧lease已过期也保留功能与解锁值。到期和时钟回拨仍优先拒绝；grace_hours=0不提供离线宽限。窗口结束返回SDK_GRACE_EXPIRED，不降级、不用镜像延长。恢复后心跳重新竞争席位；满额的明确拒绝绝不回退。只有实际观察过故障并成功回退的当前Client，才能在原宽限内通过本地validate及unlock继续使用过期lease票据。

正常退出时可调用：

```java
client.releaseSeat();
```

它只释放浮动容量，不解绑、不扣解绑次数、不撤销激活token、不删除有效缓存；非浮动授权为本地无操作。连接故障/临时错误保留缓存；明确拒绝沿用授权分类，INSTANCE_REPLACED只停止旧进程。SDK不注册信号或退出程序，信号处理由业务程序负责。高层接口见下文。

VERSION_DISABLED为已认证拒绝，可从error.latestVersion读取最新允许且未禁用的版本；未上报版本不受禁用标记影响。禁用旧版本不妨碍更新检查与客户自行拉取允许的新镜像版本，更新请求仍然不改变授权缓存。

边界：若已有持久缓存可读，但目录后来变为只读，故障回退必须先持久化最晚时间水位；写入失败与Go一样返回SDK_CACHE_UNAVAILABLE，不跳过时钟回拨保护。这不同于新实例一开始无法写目录时的纯内存运行。

## 容器高层接口

```java
var options = new io.authgo.GuardOptions();
options.config = BUILD_CONFIG; // 调用者从构建时打进jar的资源读取
options.version = BUILD_VERSION;
try (var guard = io.authgo.Guard.start(options)) {
    guard.require("export"); // 不联网，关键业务入口可重复调用
    var result = guard.result(); // 线程安全的深拷贝
    guard.done().join(); // 最终失败时完成，从error()读稳定错误码
}
```

配置必填，SDK不读取AUTHGO_CONFIG或文件获取配置；只有license为空时读取AUTHGO_LICENSE。首次Check失败直接抛AuthGoException，不启动后台线程。后台使用守护线程，按next_check_in、心跳、到期和宽限截止中的最早时间运行。宽限仅通过onChange通知；明确拒绝、宽限耗尽等最终失败完成done；error()保留原因，require此后必定失败。require仅使用现有本地票据验证及功能项，不联网。close并发安全且幂等，整体最多5秒，包括停止循环和释放席位；失败只抛错误，不清除正常缓存、不退出进程。SDK不注册信号、不启动新子进程，除既有缓存外不写文件；onChange应及时返回。EXIT_LICENSE=77。

完整HTTP程序与SIGTERM处理见examples/docker/java/。配置由构建生成的jar资源固定，客户只填授权码；主程序负责退出77。心跳间隔来自已验签响应，保存于加密缓存，票据本身不包含该字段；旧缓存通过签名双心跳租约保守推导重试间隔，不延长任何授权窗口。

### 更新维护期

Result公开`maintenanceUntil`、`latestEntitledVersion`，错误公开最高可用版本。可选字段缺失时表示不限/空值。维护期按服务端记录的版本发布时间判断，不是授权到期；SDK不使用本地时间拒绝。断网沿用已有缓存与宽限，联网收到`MAINTENANCE_EXPIRED`后按明确拒绝处理；高层守卫语义与`VERSION_DISABLED`相同。更新动作失败仍不清授权缓存。

### 免授权码试用

仅高层守卫在配置已由调用方传入、授权码和AUTHGO_LICENSE均为空时申请试用；低层check仍要求有效格式授权码。Result的`isTrial`表示当前是否试用。试用只保存在已有加密缓存，不打印授权码；重启复用。试用无断网宽限，网络故障最终失败，常驻程序退出77，请求式PHP返回503。管理员转正后下一次校验恢复正式授权宽限。TRIAL_DISABLED提示配置AUTHGO_LICENSE，TRIAL_IP_LIMIT及TRIAL_QUOTA_EXCEEDED为已认证明确拒绝。

## 运行时内容密钥解锁

```java
Client client = new Client(CONFIG); // 构建时固化的配置，不从环境或文件读取
client.check(licenseKey);
Payload payload = Payload.parsePayload(payloadJson); // 完整原始 payload.json，含 config
byte[] contentKey = client.unlockPayload(payload);
try {
  // 使用 32 字节内容密钥在内存解密；不要把明文或密钥写入磁盘。
} finally {
  java.util.Arrays.fill(contentKey, (byte) 0);
}
```

`unlockPayload` 不隐式激活，必须先成功完成 `check`、`activate` 或 `verify`。
载荷内的公开 `config` 仅用于重建绑定，不会改变 Client 的连接目标。
解锁、授权以及 `savePayloadKey` / `loadPayloadKey` / `clearPayloadKeys` 共用 Client 的锁。
内容密钥由现有签名响应认证后，用独立的 X25519 临时密钥解封；调用方负责用完清零。

缓存格式是跨语言的 `AUTHGO-PAYLOAD-CACHE-v2`，与 Go、Python、Node 的派生、AAD 和文件名一致。
文件仅含 AES-GCM 密文，0600 权限，临时文件强制落盘后原子改名。读取使用 NOFOLLOW，
检查普通文件、0600 权限及通道大小，并在打开和读取后复查路径的 fileKey；检测到符号链接、
路径替换或无法保证检查条件时拒绝缓存。解密还必须通过 AEAD 认证。
存储不可写时不影响在线解锁成功。缓存绑定实例、软件、服务端公钥、授权和完整载荷；
复制到另一实例不能解开。仅原签名票据的宽限有效，不用镜像延长。
试用、零宽限、内存缓存模式不缓存内容密钥。

已成功进入离线宽限的同一票据直接读取内容密钥缓存，不重复等待网络超时。
已认证的明确拒绝清理内容密钥缓存；`INSTANCE_REPLACED` 禁止旧进程再次解锁，保留授权票据。
`PAYLOAD_INVALID`、网络故障及通道认证失败不清缓存；新票据上下文错误或解封失败直接报错，
不会用旧缓存掩盖响应错误。不生成、读取或删除启动桩的 `payload_proof` 证据文件。
低层 unlockPayload 本身不执行代码；下述 Bootstrap 提供独立的内存加载层。

可用 `javac -Xlint:all -Werror` 编译主源码、测试及示例，再运行 `io.authgo.Vectors`；
该入口包含既有 Guard 测试、载荷测试及三个跨语言载荷向量，零第三方依赖。


## 加密普通 JAR：内存启动入口

业务代码通过 `io.authgo.Guards.current()` 取得进程内同一个 Guard（包括工作线程），
继续按普通 SDK 的功能项检查规则使用。SDK 不作为 sidecar 或额外进程运行。

方式一：把公开启动器 JAR 的 `Main-Class` 设为 `io.authgo.Bootstrap`，把以下类与 SDK
一起编译进**公开启动器**（不是加密的业务 JAR）：

```java
package io.authgo;
public final class BuildConfig {
  public static GuardOptions options() {
    var options = new GuardOptions();
    options.config = "authgo2.构建时固定的接入配置";
    return options;
  }
}
```

Bootstrap 固定调用该编译类的 `options()`，不是从文件、环境变量或 payload.config 读取配置。
客户只提供 `AUTHGO_LICENSE`，缺省时沿用 Guard 的试用流程。
方式二：已有的公开编译入口可直接调用 `Bootstrap.run(options, "app", args)`，见
`ProtectedExample.java`。不需要反射配置类，也不会隐式创建第二个 Guard 或席位。

构建时用 `authgo-pack --java app=/staging/business.jar ... --out /opt/authgo`，
将打包产物（payload.json 与编号 `.agc`）放进镜像；Bootstrap 默认加载清单名 `app`。
任务约定的 `AUTHGO_PAYLOAD_DIR` 可更换**公开密文**目录；payload.config 只参与原信封绑定，
绝不用于替换 Client 连接目标。Bootstrap 保留参数，设置当前线程的 context ClassLoader 后
调用清单中原 Main-Class 的 `public static void main(String[])`，支持 Manifest 续行。
新 Bootstrap 的 Guard 上报版本取自同一份 payload 的 version，信封成功认证后才加载代码，
后续在线检查继续上报该版本，不受入口 options.version 覆盖。
新建工作线程继承该 context ClassLoader；预先存在的线程池需由应用设置相应 context。业务 main 返回后 Guard 仍继续运行，直到 JVM 关闭；
shutdown hook 关闭内存载荷并释放实例。明确拒绝时输出不含授权码/密钥的提示，退出 77。
启动/解锁失败也退出 77；程序主动 `System.exit(n)` 时仍由程序决定正常退出码。

`PayloadFiles.decryptPayloadFile` 逐块独立 AES-256-GCM 认证后才写入 OutputStream，
分块缓冲约 1 MiB；支持 InputStream/byte[]，总长度必须与 `payloadCipherSize` 完全相同，
空文件也有一个标签。发生错误必须丢弃部分输出。加载器只在内存解析 JAR 的类与资源，不写
明文或临时文件。内容密钥、中间密文/明文缓冲用后 Arrays.fill；加载器 close 时清理保留的
条目字节。JDK 解压/加密内部可能保留副本，不能保证完全擦除；已经 define 的类也不能撤回，
应用仍须响应 Guard 状态。
整个 JAR、解压条目及 JVM 类对象会占用随包大小增长的内存，不能把“分块缓冲有界”理解为
整个加载过程常量内存。Java byte[] 的上限仍适用，不支持 ZIP64、WAR 或 multi-release JAR。

### 类、资源和框架边界

- 普通包、内部类、类与资源从内存加载；资源使用 `authgo-sealed:` URL。每次类加载/defineClass
  前、加密资源获取及流读取前检查 Guard，拒绝后不能继续加载或读取，即使流已提前取得。
- 业务 JAR 不能内嵌/覆盖 `io.authgo.*` SDK 类。公共依赖可放在启动器 classpath，机密依赖
  应合并成普通扁平 JAR（不是嵌套 JAR）。公共 classpath 内容不受本加载器的代码加密保护。
- ZIP 校验包括安全且唯一的路径、中央目录/本地条目一致性、Unix 类型位（拒绝符号链接和
  特殊文件）、大小及 CRC。原 JAR 的代码完整性由外层载荷 AEAD 保证，不提供额外的签名证书信任策略。
- Spring Boot 可执行 fat JAR / `BOOT-INF/lib/*.jar` **不支持**。远端使用真实 Spring Boot
  3.4.0 loader 实验：无落盘 ClassLoader 的 CodeSource 没有真实 archive location，JarLauncher
  启动时因 `CodeSource.getLocation()` 为空而失败。加载器会明确拒绝这种布局，不偷偷解压到磁盘。
- `java.class.path` 不会变成解密后的业务 JAR 路径；依赖真实 jar 文件、JarURLConnection、
  `Path.of(resource.toURI())`、自行扫描 classpath 或原生库提取的框架需要调整，不能承诺直接运行。
  数据文件可公开发布；本内存加载器不是 Java 沙箱，有效授权客户仍可能从 JVM 内存还原内容。

加载器使用相同的内容密钥缓存、试用和拒绝分类规则，不产生启动桩证据文件。
严格测试：`javac -Xlint:all -Werror` 编译主源码、测试和两个示例，再运行 `io.authgo.Vectors`；
该入口包括分块固定向量及 SealedTests。Spring Boot 加载边界测试单独运行 NestedJarLauncherTests，
需要提供真实 spring-boot-loader-3.4.0.jar 路径，不属于 SDK 运行依赖。

## Payload v2 与运行时水印

SDK 只接受 payload v2。公开 manifest 必须且只能含一个 `__authgo_watermark` 条目（`kind: "watermark"`、`encoding: "raw"`）；私有槽位索引作为独立 AES-GCM 密文保存。先认证私有索引全部分块，再认证目标代码并验证槽位，最后写入签名响应中的水印。

公开解锁接口返回 K32；内部加载材料及内容缓存为 K32||WM32。WM 必须是非零 32 字节值，并由响应签名认证。缓存使用 `AUTHGO-PAYLOAD-CACHE-v2.` 和 `authgo-payload-v2-`，绑定原始载荷、授权、实例及签名宽限窗口。试用和零宽限不缓存。未知或未认证响应不能产生新证据，完整认证的明确拒绝按授权动作规则处理。

当前算法仍使用 `authgo/payload/v1/wrap`、`authgo/payload/v1/rewrap`、`authgo-payload-chunk-v1` 等密码学域，它们不是旧载荷格式入口。Go/Rust 启动桩证据使用独立的 `AUTHGO-PAYLOAD-PROOF-v1.` 当前格式。

水印用于事后追踪，不防宿主调试器或内存导出，不能保证反编译、重编译或修改后保留。运行中代码无法安全撤回，高层守卫与敏感入口必须继续校验授权。协议以 [完整协议](../../server/internal/apidocs/protocol.md) 为唯一来源。
