# Auth Go 客户端协议 v2（gateway）

本文件是 v1.0.0 的跨语言实现规范。客户端仅使用 `POST /api/v1/client/gateway`，操作名位于加密内层。

## 1. 基础编码与配置

- 所有字符串 UTF-8，时间用 UTC。`timestamp` 是十进制 Unix 秒的**字符串**，无前导零，偏差不超过300秒。票据时间是 RFC3339 UTC（允许小数秒）；到期当秒即失效。
- `B64U` 为 RFC4648 URL-safe Base64，无 `=`，必须严格拒绝非规范编码。`HEX` 为小写十六进制。`||` 表示字节拼接，`\x00` 表示一个 NUL 字节，`\n` 表示一个 LF 字节。
- `authgo2.B64U(JSON)`：JSON字段为 `url,app_key,app_secret,public_key,gateway_key`（五项必需；配置串最大32768字节，未知或重复字段拒绝）。`public_key`仍为标准Base64的32字节Ed25519公钥；`gateway_key`是B64U的32字节X25519公钥。`url`可含部署子路径（如`https://example.com/auth`），也可以`/api/v1/client`结尾；不含查询/凭据，开发回环允许HTTP，生产必须HTTPS。
- 配置来自受信开发者，不能从被验证的响应下载公钥作为信任根。配置可以公开，但必须编译进程序，不能从环境变量或文件读取。app_secret不是调用方身份凭据；HMAC不代表调用方可信，安全依赖固定的Ed25519响应验签公钥、授权码及服务端授权判断。不得记录配置、授权码和令牌。直接构造 Client 必须固定同一配置中的 GatewayKey 及响应验签公钥。

## 2. 请求逐步构造

### 2.1 业务正文与内部认证

每次请求（包括verify/heartbeat）新生成32字节随机challenge（B64U）。前四个动作body是对象：

```json
{"license_key":"AUTH-…","activation_token":"act_…","device_fingerprint":"64位小写十六进制","client_version":"1.0.0","hostname":"pc","os":"linux","challenge":"32字节B64U"}
```

activate不带已有token（可空字符串）；其余使用activate返回的token。后三项body为`null`，其**HMAC正文按空字节串处理**，不是字符串`null`。不接受查询字符串。正文拒绝未知字段、控制字符、格式不符的授权码；仍先格式校验后查询授权。

nonce为16–128个`A-Za-z0-9_-`字符。Go SDK使用`HEX(SHA256(规范化上下文JSON)) || "_" || B64U(32随机字节)`，上下文键为endpoint/app_key/license_key/fingerprint/空domain/client_version/operation/token_hash；activate的token_hash为空，其他为token UTF-8的SHA256。此上下文用于缓存实例指纹与授权的对应关系，其他语言可使用相同方法。

HMAC输入按原规则精确拼接（**无分隔符**，仅以op替代旧METHOD和路径）：

```text
op || timestamp || nonce || HEX(SHA256(body原始UTF-8字节))
signature = HEX(HMAC-SHA256(app_secret字符串UTF-8字节, 上述输入))
```

不再含HTTP METHOD或路径。body不得在生成HMAC后重新格式化。app_key定位软件并决定验证secret；op也参与HMAC。IP令牌桶在任何解密前；IPv4使用完整地址，IPv6按/64归组。格式校验保留在查询前。HMAC通过后，需授权码的动作先按app_id+key做只读索引查询：不存在直接返回LICENSE_NOT_FOUND，不分配授权桶或nonce项，并按IP采样日志；存在才进入授权桶和nonce登记。nonce键按软件隔离，10分钟全进程100000容量，满时内层RATE_LIMITED，不驱逐有效记录；已有授权码的同值重放为REPLAY_DETECTED。public-key、announcement、version是幂等只读动作，不登记nonce，重复请求仍须通过HMAC/时间校验，响应仍绑定本次加密会话。

完整内层JSON：

```json
{"app_key":"app_…","op":"verify","timestamp":"1793692800","nonce":"…","signature":"小写hex","body":{"license_key":"…","challenge":"…"}}
```

### 2.2 填充

先序列化内层JSON为raw，前置4字节**无符号大端**长度L，追加密码学随机字节，使总长度为 `max(4096, ceil((4+L)/512)*512)`。接收方要求长度正好符合该公式，取长度字段之后的L字节为JSON，忽略其余随机填充。L必须为正数，不能越界。请求与响应均采用本规则。4096最小桶使正常短动作一致；超大正文仍只能隐藏到512字节桶，**不声称流量分析不可行**。

### 2.3 X25519与方向密钥

服务端全局X25519私钥用主密钥派生AES-GCM密钥和专用AAD加密存库，启动缺少时生成。每次请求客户端重新生成X25519临时私钥（CSPRNG），计算：

```text
k = HEX(SHA256(server_public_32_bytes))[0:16]
e = B64U(ephemeral_public_32_bytes)
shared = X25519(ephemeral_private, server_public)  // 拒绝低阶点/全零共享秘密
AAD = UTF8("authgo-gateway-v2\x00" || k || "\x00" || e)
salt = SHA256(AAD)
request_key = HKDF-SHA256(shared, salt, UTF8("authgo/v2/request"), 32)
response_key = HKDF-SHA256(shared, salt, UTF8("authgo/v2/response"), 32)
```

HKDF为RFC5869 Extract+Expand，不是将shared当作PRK直接Expand。AES-256-GCM使用12字节随机nonce、128位tag；密文尾部附tag。请求密文为`GCM(request_key,n,padded_plain,AAD)`。请求外层恰为：

```json
{"v":2,"k":"16位短ID","e":"B64U","n":"12字节B64U","c":"密文含tag的B64U"}
```

HTTP仅Content-Type: application/json，不再发送X-App-Key/X-Timestamp/X-Nonce/X-Signature。业务数据在密文内，但公开配置中的AppSecret不能提供调用方身份保证。外层大小上限65536字节（含JSON/Base64/填充），超出拒绝。

### 2.4 响应与请求绑定

```text
response_AAD = AAD || "\x00" || UTF8(HEX(SHA256(UTF8(request.n || "." || request.c))))
response.c = B64U(GCM(response_key,新的随机12字节nonce,填充响应JSON,response_AAD))
```

外层仅`{"n":"…","c":"…"}`。使用另一请求的响应必然GCM失败。能解密的业务结果（含暂停/吊销/用户停用/认证失败）均HTTP200且仅密文；未知/坏k、解密失败、外层解析/大小/查询错误、解密前IP限流均固定HTTP400、正文精确`{"error":"invalid request"}`。不泄露具体原因。固定400不是可信业务拒绝，SDK按连接故障处理：不清缓存，只能使用原有可信票据进入有效签名缓存宽限，绝不能返回online。响应Cache-Control:no-store。

内部响应保留：

```json
{"code":"OK","message":"验证成功","data":{"request_nonce":"…","ticket":"…","unlock_seed":"…","license_id":1,"status":"active","features":{},"starts_at":null,"expires_at":null,"next_check_in":3600,"heartbeat_interval":60,"grace_until":"…","satisfied_methods":["KEY","DEVICE"]},"signature":"标准Base64的Ed25519签名","ts":1793692800,"nonce":"…"}
```

Ed25519签名仍为规范化`{code,data,ts}`。规范化：UTF-8 JSON、递归按键的Unicode码点排序、数组原序、不加空格、字符串JSON转义（非ASCII原样，控制字符JSON转义；与当前Go服务保持一致，`<`、`>`、`&`分别转义为小写`\u003c`、`\u003e`、`\u0026`，U+2028/U+2029也转义）；保留数值原有合法JSON字面量、不转float、不做Unicode正规化，不是RFC8785 JCS。拒绝重复键、非法数值、尾随第二JSON。外层nonce必须等于data.request_nonce和本次nonce；响应ts须在±300秒内。早期错误可signature=null，SDK决不能把它视为成功。完整实现与大整数测试见[sdk/go/json.go](https://github.com/dingding229/Auth-Go/blob/main/sdk/go/json.go)。

## 3. 在线票据与代码载荷内部解锁

### 3.1 票据

票据字符串 `B64U(payload原始JSON) + "." + B64U(Ed25519("authgo-ticket-v2\x00" || payload原始字节))`。与外层响应签名是独立证据；**按载荷原字节验签**，不重新序列化。

字段：v=2、app_key、challenge、license_id、license_ref、device_hash、status=active、issued_at、starts_at、expires_at（永久null）、features、next_check_in、grace_until、lease_expires_at、floating、unlock_hash。device_hash是UTF8规范化指纹字符串的SHA256小写hex；unlock_hash是32字节unlock_seed的SHA256。license_ref为内部不可逆授权引用，不提供公开状态清单。

在线成功须同时：内层响应验签/nonce/ts有效、票据验签、软件/实例指纹/授权ID匹配、本次随机challenge相同、签发时间±300秒、有效期/浮动lease未到期、解锁seed哈希匹配。不能仅判断code。SDK `Ticket()`返回不可变字符串；`Validate(ticket)`独立在本地再次检查，不访问网络。`Result.Status`及Availability为online/grace；授权状态在票据内。刚在线成功的当前Client还可在已签名next_check_in窗口内使用该票据/资源（到期和lease仍优先），因此grace_hours=0不妨碍在线使用；一旦观察到连接故障或明确拒绝，此仅内存在线窗口立即取消，必须严格按原签名宽限策略判断，不把在线窗口写入缓存恢复。

### 3.2 内部代码载荷材料

不再提供公开资源 EncryptResource、RotateUnlock、Result.Unlock 或 Result.Decrypt 产品接口。内部 32 字节 unlock seed、其签名哈希及第 12 节 payload.unlock/内容密钥缓存、代码加载器继续使用；不能因删除旧资源工具而删除代码加密信任链。

## 4. 故障状态机

**动作作用域优先**：下表只决定 Check/Verify/Heartbeat 等授权动作的缓存失效。update.check 无论网络、认证、业务错误或成功都不修改授权票据、缓存和 Refused；即使更新检查收到已认证 LICENSE_REVOKED 或未知错误也只向更新调用方返回错误。授权动作仍按下表决定是否清 proof；不把更新成功当授权成功。

**仅通过完整认证的明确拒绝才能清缓存或写Refused=true。** 完整认证的顺序是：HTTP200 → 外层AES-GCM解密成功 → Ed25519响应验签通过 → nonce绑定本次请求 → ts在±300秒内。认证未完成前，不能相信响应宣称的任何code。

sdk所有SDK必须按以下同一张分类表实现：

| 分类 | 情况 | 有合法缓存时 | 无合法缓存时 | 清缓存/Refused |
| --- | --- | --- | --- | --- |
| 连接故障/不可信响应 | 传输错误、超时、TLS证书/协议校验失败、重定向、**任何非200**、截断/超大、200 HTML或非法密文、解密失败、验签失败/无签名、nonce不符、时间戳超窗、无效票据或challenge/实例指纹不匹配 | 仅按下述有效签名缓存宽限；绝不返回online | 保留原始错误码和原因返回 | 不清、不写Refused |
| 已认证临时错误 | **INTERNAL_ERROR、RATE_LIMITED、LOG_UNAVAILABLE、REPLAY_DETECTED、TIMESTAMP_INVALID、SIGNATURE_INVALID、INVALID_REQUEST、PAYLOAD_INVALID** | 同上 | 保留已认证的原始错误码返回 | 不清、不写Refused |
| 已认证明确拒绝（接管例外） | INSTANCE_REPLACED | 立即停止旧进程，不宽限 | 同样失败 | 不清、不写Refused |
| 已认证明确拒绝 | 除INSTANCE_REPLACED及上述显式非拒绝码外的其余任何非OK码，包括LICENSE_REVOKED、LICENSE_SUSPENDED、USER_DISABLED以及**所有未知错误码** | 立即失败，不宽限 | 同样失败 | 清可用proof，写Refused=true |

临时错误使用上述**显式白名单**，不是按HTTP状态、中文message或前缀猜测。新增/未知的已认证错误码默认拒绝，不能默认视为临时错误。机器可读向量见[sdk/vectors/error-classification.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/error-classification.json)。未签名的“LICENSE_REVOKED”也只是连接故障，不是明确拒绝。

连接故障和临时错误都不能制造新激活或online结果。无可用缓存时保留错误类型，例如未知证书为SDK_RESPONSE_INVALID并保留x509原因，普通断网为SDK_NETWORK_ERROR；HTTP非200在错误的HTTPStatus中保留状态。调用方取消操作直接返回context错误，不清缓存。首次无有效票据不能宽限/延长；不提供首次离线激活。

grace的Result.Reason包含本次故障/临时错误的原始code和原因；窗口结束的SDK_GRACE_EXPIRED包住原始错误，errors.Is/errors.As仍可取到原因。StartAutoCheck通过Verify/Heartbeat复用同一分类。Activate失败不会返回缓存成功；未经认证的失败不销毁同一授权的既有proof，换码不复用旧激活。Deactivate只有获得已认证的成功解绑回执才清除；失败保留原proof（后续在线复验会发现已经生效但回执丢失的解绑）。

1. 验证加密缓存内签名证据和票据，失败当作无缓存。
2. 本机时间比加密缓存中见过的最晚时间（本机与服务端时间取大值）早**超过300秒**，返回SDK_CLOCK_ROLLBACK，不宽限。在线验证成功重新建立可信水位，可恢复。磁盘文件回滚攻击无法仅靠用户可写文件完全防御。
3. starts_at/到期始终先检查，到期当秒拒绝。浮动授权只在本次连接故障或已认证临时错误时，可在票据grace_until之前忽略已过期lease并返回grace、Offline=true，保留features和内部代码载荷材料；在线成功仍严格检查lease。grace_until不晚于授权到期，直接使用软件现有grace_hours（默认72小时）；0没有离线宽限。窗口结束返回SDK_GRACE_EXPIRED并包住原错误，不degrade，不用清单延长浮动窗口。没有合法已在线票据时保留原故障错误。
4. 不拉取备用清单，不额外延长原票据允许的宽限。
5. 仅在原grace_until内返回grace；保留授权功能和内部代码载荷材料。
6. 窗口结束返回SDK_GRACE_EXPIRED，停止运行。
7. 服务恢复后浮动授权以heartbeat重新竞争席位；Go SDK检测已缓存lease过期时的Verify会改发heartbeat。席位满等明确拒绝立即失败并清proof。INSTANCE_REPLACED例外：立即停止被替换进程，不回退、不清缓存、不写Refused；进程内记住此拒绝，防止断网后又使用原proof。重启的新进程仍可用合法缓存。

**INSTANCE_REPLACED的有意例外**：必须完整认证后才能执行停止语义。它不是临时错误，不进入宽限；但不清除或写坏共享卷上的票据、缓存或Refused。更新动作仍遵守操作作用域，任何结果都不改本地授权缓存。release-seat成功、连接故障与临时错误保留缓存，已认证明确授权拒绝仍执行本节规则。

缓存包含已签名完整响应（含票据）、当前激活token/context和最大时间水位；由AppSecret与规范指纹通过HKDF派生AES-GCM密钥，0600原子写入。API不公开seed字段，不把缓存当信任根。更换授权码不沿用旧激活。


## 6. 可复现实例与向量

按顺序执行：生成body → challenge/nonce → HMAC → 内层JSON → 4字节长度+随机填充 → 临时ECDH → HKDF双向key → 请求GCM → 外层POST → 响应GCM → 内层Ed25519+nonce+ts → 票据Ed25519+challenge+实例指纹/时间 → 返回Result。任何一步失败不得返回成功。

[sdk/vectors/v2.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/v2.json) 给出**完整**内层示例、测试私钥/公钥、固定填充hex、双向key/AAD、请求密文、响应明文/密文、票据、内部 seed/HKDF/AEAD 测试值及密文；[sdk/vectors/hkdf.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/hkdf.json) 为RFC5869向量。各语言使用相同固定输入必须逐字节匹配。固定随机数只用于测试，生产必须CSPRNG。Go服务端和SDK共同使用仅标准库wire实现并分别有集成/验签测试。

## 7. 安全边界（必须阅读）

- 外层隐藏动作、码、实例指纹和结果，不隐藏主机/IP、时序、长度桶和请求频度；必须配HTTPS。静态服务端X25519密钥不提供对该密钥事后泄露的完美前向保密。
- 网络路径上的中间人只能让在线检查变为原策略允许的有效签名缓存宽限，效果与直接断网相同，不会产生online、新授权或突破签名有效期；不可信响应不能永久销毁本地票据。明确拒绝必须先完成全部认证，未知已认证错误码默认拒绝。
- Ed25519票据/challenge防伪服务器、重放和简单改布尔值；多处Validate/资源加密提高补丁成本。**客户端在用户手里，无法做到绝对防破解**；攻击者可修改整个SDK、时钟、存储，或从合法进程提取秘密/明文。
- 宽限期间停用/吊销可能滞后；高风险业务应使用短宽限。断网不延长原签名时间窗口。
- 无合法已在线签名票据不能回退；新实例不能失联首次激活。
- 已交付或已解密内容无法实时收回，代码加密仍有内存导出与重打包风险；不承诺绝对防破解。


## 8. 只读公告

Go SDK `Announcements(ctx)`不要求激活，内层op=announcement、body=null、HMAC正文为空字节串。通过同一gateway、Ed25519响应验签、nonce和ts校验后返回`items`（id/app_id/title/content/created_at/updated_at/published_at/expires_at）。不创建票据、不下载清单、不回退缓存、不读写或吊销激活缓存，即使新闻请求收到明确拒绝也不修改授权状态；失败原样返回错误。版本检查使用 CheckUpdate。

## 9. Docker Hub 更新检查

保留加密 op=update.check，要求有效 activation_token 和普通授权证明，current_version 为严格 semver。当前版本不阻止检查修复版本，但目标必须已发布、未撤回、未禁用并在维护期内。来源只有软件配置的 Docker Hub 标签；无镜像时 available=false。

响应经过同样 AES-GCM、Ed25519、双 nonce 和时间校验，data 包含 available/version/changelog/mandatory/published_at/docker_image/docker_pull，以及 maintenance_until/latest_entitled_version/renewal_required。更新检查的任何结果都不改授权缓存或 Refused。镜像由客户自行 docker pull 与部署。

## 10. 跨语言 SDK 实现要求

1. 严格解析 authgo2、规范 Base64URL、无重复键/非法 UTF-8/孤立代理项；配置错误不能包含输入或密钥。默认拒绝不可信 HTTP，仅开发回环可用。
2. 按第2节做临时X25519、全零共享秘密拒绝、HKDF双向派生、AES-GCM、随机填充和请求体绑定的response_AAD；不能混用请求/响应密钥或AAD。
3. 先认证完整响应，再使用code。规范化保留数字字面量（包括大于2^53、指数、小数）；HTML 字符转义遵循 canonical.json 的精确向量。
4. 校验票据签名/软件/实例指纹/授权ID/challenge/时间，资源seed哈希必须匹配；公开Result不把布尔成功当授权证据。Validate不联网；旧Result也受明确拒绝和时间水位约束。
5. 按第4节实现授权动作与更新动作的不同副作用。连接故障不能清缓存；未知已认证授权错误必须拒绝。更新检查永不撤销授权缓存。
6. 加密缓存按实例指纹、软件、服务器隔离，原子写入并限制权限/大小；保存时钟水位。首次激活不能通过断网放行。
7. 宽限、回拨、浮动lease、60秒失败退避和15秒总预算均不可缺少。SDK不得禁用TLS证书验证。
8. 指纹按Go采集同样的machine ID、主网卡MAC、CPU；小写/空白规范化后，以`authgo/fingerprint/v1\0machine\0mac\0cpu`的UTF-8字节SHA-256。Linux CPU按`/proc/cpuinfo`行序选择第一个非空`model name`、`Hardware`或`cpu model`，既有身份不变。三个字段均缺失时取第一组`CPU implementer`/`CPU part`（不跨空行组拼接），各自去掉全部空白、转小写，组成`arm:<implementer>:<part>`；再没有时取第一个非空`uarch`。原始硬件与cpuinfo解析样例见fingerprint.json。不可用时要求显式覆盖。
9. 授权码统一执行当前字符、分组和校验位验证；未知已认证错误默认拒绝。
10. 每种语言通过[sdk/vectors](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors)所有向量和[sdk/conformance](https://github.com/dingding229/Auth-Go/blob/main/sdk/conformance)同一组真实服务场景，再与Go结果JSON比较。不能以“能编译”代替安全状态机测试，也不能默默跳过缺少工具链的语言。

SDK从[sdk/python](https://github.com/dingding229/Auth-Go/blob/main/sdk/python)、[node](https://github.com/dingding229/Auth-Go/blob/main/sdk/node)、[java](https://github.com/dingding229/Auth-Go/blob/main/sdk/java)、[csharp](https://github.com/dingding229/Auth-Go/blob/main/sdk/csharp)、[php](https://github.com/dingding229/Auth-Go/blob/main/sdk/php)、[rust](https://github.com/dingding229/Auth-Go/blob/main/sdk/rust)源码安装，尚未发布公共包。各SDK独立原生实现，不调用Go二进制或其他语言运行时。各语言SDK使用独立于Go的本地缓存格式，缓存不可跨SDK复用；授权、票据及故障语义相同。HTTP/时钟注入仅由开发者代码提供，不来自远程响应或配置串。 Go、Rust整体保护另有第12.7节的语言中立启动桩证据，不互读上述私有缓存。

缓存身份另含 SDK 语言标识；同机同软件混用不同语言时不会互相覆盖缓存，不支持跨 SDK 迁移缓存文件。

### SDK 授权码输入校验

Check、Activate 在任何网络/缓存操作之前校验授权码：使用 `-` 分成五段，首段长 1–16，其余四段各长 5；全部字符只允许 `23456789ABCDEFGHJKLMNPQRSTUVWXYZ`（不转大写，不去空白）。令 `check = 首段长度 mod 32`，依次遍历首段、第二至第四段、第五段前四字符，每字符执行 `check = (check × 17 + 字母表下标) mod 32`；第五段最后一字符必须等于字母表的 `check` 项。失败返回 `INVALID_LICENSE_KEY`，不发请求、不改缓存。七种语言读取 [sdk/vectors/license-key.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/license-key.json)。

换码激活是候选操作：失败只返回新码的错误，不把旧码的成功结果用于本次调用，也不清掉原授权票据/Refused/磁盘缓存。格式正确但不存在的授权返回服务器已认证的 `LICENSE_NOT_FOUND`；同一当前授权的已认证明确拒绝仍按第4节清缓存。此规则不改变服务端协议。

## 11. 进程接管、释放与版本禁用

### 11.1 instance_session
客户端每次进程启动生成16随机字节，使用无填充Base64URL（22字符）；只保存在进程内，不写入缓存。activate、verify、heartbeat及release-seat正文带instance_session。PHP 请求式运行不发送该字段，按请求间共享的实例租约处理。该字段受正文HMAC和本次响应nonce/challenge保护，但它不是秘密。

激活token仍绑定客户端会话；常驻进程 FLOATING 载体使用规范指纹作为稳定实例标识。服务端在key载体/浮动激活记录保存当前instance_session，并按rowid保留每个激活最近32个已见session（更早记录会删除），防止服务重启遗忘近期被替换进程。第一次看到新session时，在授权策略、到期、版本及容量判断通过后接管；仍在最近32条历史保留范围内的已被替换session返回INSTANCE_REPLACED，不允许反复抢回；更早历史已被裁剪，不能承诺无限期识别所有旧进程。lease已经到期时的新进程验证按心跳竞争容量；PHP 请求式运行采用 token 会话标识。

### 11.2 release-seat
独立内层动作release-seat，正文使用与verify相同的授权码、token、指纹、challenge、instance_session。成功签名data为`{"request_nonce":"…","released":true}`；非浮动为false。在同一事务删除所属浮动实例记录、对应的浮动代次引用并写instance.release审计；独立KEY会话锚点、token及缓存保持有效，不扩大原签名宽限。释放后管理端列表/授权详情不再显示该实例；超时未心跳但未释放的实例仍保留为离线。下一次有权心跳可重新竞争并创建新实例及绑定引用；持有未撤销会话及有效KEY代次证明的新进程（新的instance_session）也可在普通Verify中重建已释放的实例，仍检查容量并拒绝历史已被接管的进程ID。更新检查和payload.unlock不能借此隐式占位。释放记录只保留在审计日志，不另写验证日志。Go Client.ReleaseSeat(ctx)对已知非浮动授权不发请求并返回nil；成功、连接故障或临时错误均不改本地状态与缓存；已认证明确授权拒绝仍清proof（INSTANCE_REPLACED例外）。Deactivate 撤销会话并清理缓存，不参与进程接管。更新动作使用已验证token与指纹查找载体，不要求进程接管；更新结果仍不改变本地授权状态。

### 11.3 VERSION_DISABLED
AppVersion.disabled与withdrawn独立：withdrawn只撤回更新下载，不禁止已有程序运行；disabled禁止明确上报该版本的实例。引擎返回已认证VERSION_DISABLED，data.latest_version给出该软件维护期内最新已发布、未撤回、未禁用版本，无可用版本时为空字符串；Go Error.LatestVersion可读取。未上报版本不受影响。更新动作不检查正在运行的旧版本，仍只提供允许且未禁用的目标，更新错误继续不影响授权缓存。管理端现有版本PATCH接口接受disabled布尔字段；禁用标记不被Docker Hub后续同步覆盖。

### 11.4 跨语言契约

七语言执行相同实例接管、释放和错误分类；行为向量见 [sdk/vectors/instance-session.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/instance-session.json)、[error-classification.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/error-classification.json)，一致性测试连接真实服务执行。

### 容器身份与进程同步

物理机指纹算法及既有向量不变。七语言SDK的默认身份优先级为显式指纹覆盖（Go为WithFingerprint）、AUTHGO_INSTANCE_ID、容器模式、原物理机采集。AUTHGO_CONTAINER=0强制关闭容器检测，=1强制开启；否则检测/.dockerenv、/run/.containerenv是否存在，或/proc/1/cgroup包含docker/containerd/kubepods/libpod。检测不需要采集硬件。

缓存目录优先级为显式缓存目录（Go为WithCacheDir，显式空字符串关闭磁盘）、非空AUTHGO_CACHE_DIR、容器默认/var/lib/authgo、原用户缓存目录。容器实例标识是缓存目录instance-id中的32字节随机数的小写十六进制文本（不附换行），0600。通过同目录临时文件加link原子发布，竞争失败读取获胜者，不允许读到半个标识；不得跟随标识文件的符号链接。容器设备指纹是UTF-8字节`authgo/instance/v1\0`加标识文本的SHA-256小写十六进制；显式AUTHGO_INSTANCE_ID也按原值使用同一算法，不去空白或转小写。实例标识与每进程临时instance_session是两件事，后者不持久化。

标识目录不可写或不可用时，用进程内随机标识继续在线验证，仅内存缓存，CacheWarning说明“此实例重启后是新实例，没有断连宽限”。容器模式不读取MAC、machine-id、CPU。StartGuard的Config必须由开发者编译进程序；绝不读取运行时AUTHGO_CONFIG或配置文件。只有License为空时读取AUTHGO_LICENSE。Guard使用既有Check/StartAutoCheck/ReleaseSeat和票据Validate，不新增网关动作；关闭不解绑、不删除仍有效票据。宽限不会关闭Done，最终失败（例如明确拒绝、宽限耗尽）才关闭。业务代码可多处调用不联网的Require检查票据与功能项。


Python、Node.js、Java、C#、PHP、Rust与Go采用相同的容器检测、实例指纹、缓存目录选择、进程session与32条历史语义。各语言release_seat/releaseSeat/ReleaseSeat沿用release-seat动作；VERSION_DISABLED错误公开latest_version/latestVersion/LatestVersion供调用方读取。Result的cache_warning/cacheWarning/CacheWarning报告持久化故障，不把已认证的在线成功改成失败。七语言共享container-identity.json，五组instance行为由conformance真实服务验证。StartGuard 是 Go 的高层接口名，各语言提供原生守卫接口。

已有身份与票据可读、但目录后来变为只读时，故障回退必须先持久化时间水位；失败返回SDK_CACHE_UNAVAILABLE，与Go参考实现一致，不绕过时钟回拨保护。这不等于新实例一开始无法建立持久目录时的纯内存运行。

### 11.5 更新维护期

授权可有可空的`maintenance_until`（RFC3339 UTC时间，空表示不限）。激活、校验和心跳依次检查授权有效性、VERSION_DISABLED、MAINTENANCE_EXPIRED。明确上报版本的记录发布时间严格晚于维护期时，返回已认证明确拒绝`MAINTENANCE_EXPIRED`，提示“当前授权的更新维护期已结束，此版本需要续期”；相等放行。未上报、版本未收录或缺少发布时间时放行，后两种通过现有采样验证日志记录。withdrawn不影响正在运行程序的维护期判断。

成功结果及签名票据可包含`maintenance_until`、`latest_entitled_version`；错误data包含`latest_entitled_version`。最高可用版本为发布时间不晚于维护期和当前时间、未禁用、未撤回且满足软件和授权版本范围的最高semver，没有时为空。没有维护期时不计算最高可用版本。新增票据字段为可选，验签仍针对原始payload字节，不以重新序列化结果验签；旧票据缺字段继续有效，旧SDK忽略新增字段。

七种SDK的Result公开维护期和最高可用版本，Error公开最高可用版本（遵循各语言既有命名风格）。SDK不以本地时间判断维护期到期。断网时已有签名缓存、宽限规则不变，联网收到MAINTENANCE_EXPIRED才按明确拒绝处理。高层守卫启动失败直接返回错误，运行中最终失败触发完成信号，常驻程序退出77；PHP请求式返回503及错误码而不退出worker。update.check错误始终不修改授权缓存。

更新建议只给维护期内版本，较新版本超出维护期时返回`renewal_required`及`latest_entitled_version`供界面提示；不提供托管文件下载。管理端发放和批量发放接受`maintenance_days`或`maintenance_until`；修改入口为POST `/api/v1/admin/licenses/{id}/maintenance`。续期也可显式传入，省略保持不变，维护期不随授权续期自动延长；`maintenance_days:0`或`maintenance_until:null`清除限制。

### 11.6 免授权码试用

新增网关动作`trial`，无需授权码或activation_token，但仍使用配置固定的网关加密、app_key、HMAC、时间戳、nonce和签名响应。正文为`{"device_fingerprint":"64位稳定实例指纹","challenge":"B64U的32字节随机数"}`；实例标识沿用容器身份/显式覆盖/物理机指纹，和进程instance_session不同。成功data包含`license_key`、原challenge和request_nonce。SDK必须完整验签、校验nonce/时间和challenge后才能使用授权码。授权码只保存在内存及已有加密缓存，不得写日志。

只有高层StartGuard/start_guard/startGuard/Guard.Start等在配置存在且AUTHGO_LICENSE为空时自动调用trial，拿到授权码后走普通Check/激活。低层Check仍拒绝空或错误格式授权码。缓存保留trial_key，重启沿用原试用；PHP请求式在已有缓存锁内读取/写入该值，多个worker只申领一次，不发送instance_session。没有配置仍立即报SDK_INVALID_CONFIG，首次无法联网时不启动。

默认关闭试用，默认14天，可设1至365天。申领按软件、实例指纹唯一；同一实例始终返回原授权（包括到期或已转正）。新实例在开关关闭或软件停用时返回已认证明确拒绝TRIAL_DISABLED，提示设置AUTHGO_LICENSE。已有实例仍可取回原授权，但普通认证仍遵守软件停用等全部规则。同软件、同IP键30天内复用未转正且未吊销的trial；IPv4为完整IP，IPv6归并/64。已转正或吊销返回TRIAL_IP_LIMIT；先检查IP规则，之后才判断全局UTC当日100个新建额度，超限TRIAL_QUOTA_EXCEEDED。复用不计新建。单独按软件/IP键每分钟最多10次，限流在申领事务之前并返回RATE_LIMITED。试用记录默认功能项为空对象，与当前发放默认值一致，不引入功能模板。

新建授权type=trial、source=self_trial、无用户，KEY+FLOATING、最多1个实例，有效期从申领计算。在线响应和签名票据新增可选`is_trial`布尔字段，Result按各语言风格公开。试用票据提供刷新重叠：grace_until为issued_at加next_check_in秒再加30秒，并且不得晚于expires_at（如有）；不提供降级或备用延长。这段重叠只用于在线刷新过程中校验旧票据，不是断网宽限，也不推迟按next_check_in进行的校验。任何连接故障都必须先按is_trial拒绝，不能利用grace_until退回宽限或降级。普通认证激活、校验、心跳均如此。

管理员可通过POST `/api/v1/admin/licenses/{id}/convert`选择用户、正式类型和有效期，可同时改实例数、维护期；保留授权码和激活，下一次在线检查恢复正式授权宽限，无需重启。客户设置正式AUTHGO_LICENSE重启并成功激活时，事务内释放同实例旧试用的全部席位并记录converted_at，旧试用终止为已吊销，防止重新占用第二个席位；不会把正式授权码返回给旧试用申领。关闭试用不终止已发放授权，普通到期由LICENSE_EXPIRED拒绝。TRIAL_DISABLED、TRIAL_IP_LIMIT、TRIAL_QUOTA_EXCEEDED属于已认证明确拒绝，处理与维护期拒绝一致；常驻最终失败退出77，请求式PHP返回503和原因而不结束worker。

## 12. 语言无关加密载荷与整体保护 v2

本节规定七种语言共用的当前加密载荷格式，与网关 v2 和签名票据配合使用。
打包器为独立标准库 Go 模块 [pack/](https://github.com/dingding229/Auth-Go/tree/main/pack/)，目标是静态 Linux amd64/arm64。
打包本身不代表授权成功。Go、Rust ELF 使用内嵌启动桩在线解锁，或在合法授权证据的宽限期内使用密钥缓存；解释型语言使用各 SDK 的内存加载器。

### 12.1 编码、元数据与清单

本节 `B64U` 为无 padding 的规范 Base64URL，拒绝 CR/LF、非零尾位及非规范编码；
`H` 为 SHA-256，`U32`/`U64` 为固定宽度无符号**大端**整数；
`LP(s) = U32(len(UTF8(s))) || UTF8(s)`，长度单位为字节。`||` 表示字节拼接。
所有 JSON 为有效 UTF-8，拒绝未配对的 UTF-16 代理转义，嵌套不超过 64 层，拒绝重复键、未知键（含大小写别名）、缺少必填字段、尾随第二个 JSON、错误字段类型。
JSON 对象键序不参与签名；**清单按解码后原始 JSON 字节哈希，不重新序列化或正规化**。

`--out` 必须是尚不存在的目录，父目录必须已经存在。目录包含 `payload.json` 和
按文件序号命名的 `00000000.agc`、`00000001.agc`……；均为 0600。
`payload.json` 恰有以下字段（`envelope` 恰有 `e,n,c`）：

```json
{"v":2,"app_key":"app_test","version":"1.2.3","built_at":"2026-11-07T00:00:00Z","key_id":"key-1","config":"authgo2.…","manifest":"B64U(清单原始JSON字节)","envelope":{"e":"B64U(32字节临时公钥)","n":"B64U(12字节nonce)","c":"B64U(32字节内容密钥的密文及16字节tag)"}}
```

- `app_key` 非空，最多 256 字节；`key_id` 为 1–128 字节 `[a-z0-9_-]+`。
- `version` 为严格 SemVer 2.0.0，最多 256 字节，无 `v` 前缀，核心数字与纯数字预发布标识不允许前导零。
- `built_at` 必须是精确 `YYYY-MM-DDTHH:mm:ssZ` UTC 秒精度。默认为打包时刻；
  `SOURCE_DATE_EPOCH` 可覆盖，必须为无前导零的非负十进制整数且年份不超过 9999。
- `config` 是公开但作为信任根的 `authgo2.` 配置；必须与 `app_key` 一致，HTTPS，
  有效的 32 字节 Ed25519 公钥（标准 Base64）和网关公钥（B64U），非空 `app_secret`。
  打包器不会从环境变量/配置文件加载它，后续启动桩须编译固定该配置。
  当前实现把它绑定到信封中保存，不提供启动时修改信任根的能力。

清单解码后最多 8 MiB，恰为 `{"files":[…]}`，2–65535 个条目，包含一个独立加密的 watermark 索引；数组位置就是文件序号 `i`，从 0 起。
每个条目的必填字段是 `name,kind,path,size,chunk_size,encoding`，可选字段为
`python_version,main_class,architecture`（只作对应类型的元数据，仍被清单哈希绑定）。例如：

```json
{"files":[{"name":"core","kind":"python","path":"00000000.agc","size":2048,"chunk_size":1048576,"encoding":"tar","python_version":"3.11"}]}
```

- `name` 为 1–128 字节 `[a-z0-9_-]+`，整个清单不重复，不是文件系统路径。
- `path` 必须恰为文件序号的 **8 位十进制、左补零**加 `.agc`；不接受任意相对/绝对路径。
- `size` 为加密前流的**精确字节数**，JSON 整数，范围 `0..4611686018427387903`；
  `chunk_size` 必须是 1048576。不允许 JSON 浮点、指数或负数。
- `kind`: `protect,node,java` 用 `encoding:"raw"`；`python,php,dotnet` 用 `encoding:"tar"`。
  tar 的 `size` 含 header、padding、两个结束块。清单是**密文文件布局清单**，不是密文字节散列列表；
  密文字节完整性由每块 GCM 保证。这样避免“清单哈希→信封→块AAD→密文哈希”的循环依赖。
- `python_version` 为目标 CPython 的 major.minor；当前实现识别正式版魔数
  `3413→3.8,3425→3.9,3439→3.10,3495→3.11,3531→3.12,3571→3.13,3627→3.14`
  （pyc 前两字节 little-endian，后两字节 `0d0a`），要求 16 字节 header、合法 flags，目录中版本一致。
- `main_class` 为 JAR 主清单 `Main-Class` 的值，支持清单换行续接；无主类时省略。
- `architecture` 在 `protect` 条目中为 `amd64` 或 `arm64`，由 ELF64 little-endian 头确定，不根据主机猜测。

目录流使用标准 **USTAR**：只含常规文件，mode 0600，uid/gid/mtime 为 0，无绝对路径、
`..`、`.`、空组件、反斜杠、冒号或 NUL，无符号链接、硬链接、设备、PAX/GNU 扩展。
Python/PHP 按条目 UTF-8 路径字节排序，只分别包含 `.pyc`/`.php`；不写目录项。
.NET tar 先程序集，再同名 `.deps.json`（如果存在）；条目名为 basename。
所有输入路径逐级 `O_NOFOLLOW` 打开；归档中的条目名同样校验。
JAR 内 ZIP 条目也校验唯一性、路径和非符号链接，但 JAR 原始字节不被改写。
后续加载器必须重复执行归档条目校验，不能把“GCM 验证通过”等同于“可直接解压到磁盘”。

### 12.2 内容密钥信封（X25519 + HKDF-SHA256 + AES-256-GCM）

每次打包使用 CSPRNG 独立生成新的 32 字节内容密钥 `K`；一次打包的所有文件共用 `K`。
软件打包公钥为原始 X25519 32 字节的 B64U，不是 PEM，不是网关公钥。
每次打包独立生成临时 X25519 私钥 `esk` 和随机 12 字节 `N`：

```text
E = X25519_public(esk)                       // 32 raw bytes
A = UTF8("authgo-payload-envelope-v2\x00")
    || LP(app_key) || LP(version) || LP(built_at) || LP(key_id) || LP(config)
    || H(B64U_DECODE(manifest)) || E
S = X25519(esk, software_pack_public)        // 拒绝低阶点/全零 shared
salt = H(A)
KEK = HKDF-SHA256(ikm=S, salt=salt,
                  info=UTF8("authgo/payload/v1/wrap"), length=32)
C = AES-256-GCM.Seal(key=KEK, nonce=N, plaintext=K, aad=A)
envelope = {e:B64U(E), n:B64U(N), c:B64U(C)}
B = H(A || N || C)                      // 固定 32 字节块绑定值
```

HKDF 必须执行 RFC5869 **Extract + Expand**，不能直接把 shared 当 PRK。
GCM 使用 128 位 tag，tag **附在密文末尾**，故 `C` 恰为 48 字节。
解封者用软件私钥和 `E` 计算同样的 shared/KEK，先验证 GCM 再返回 `K`。
篡改 app、版本、构建时刻、key_id、接入配置、清单任意原始字节或临时公钥编码都会解封失败；
临时公钥也在 AAD 中，拒绝 X25519 高位掩码产生的等价编码篡改。
错误和日志不得包含 `K`、私钥、授权码、令牌或完整配置串。

### 12.3 密文文件字节布局与随机读

`.agc` **没有头部、长度前缀或尾部**，仅为连续的 `ciphertext || tag` 块。
可信大小和块数都来自已认证的清单，不读取前面的块来定位后续块。
令 `L=size`、`Q=1048576`：

```text
count = max(1, ceil(L/Q))
plain_len(j) = min(Q, L - j*Q)               // 空文件 j=0 时是 0
last(j) = (j == count-1)
nonce(i,j) = U32(i) || U64(j)                // 恰 12 字节
D(i,j) = UTF8("authgo-payload-chunk-v1\x00") || B
         || U32(i) || U64(j) || BYTE(last(j) ? 1 : 0)
block(i,j) = AES-256-GCM.Seal(K, nonce(i,j), plaintext_chunk, D(i,j))
file_bytes = block(i,0) || … || block(i,count-1)
file_length = L + 16*count
offset(j) = j*(Q+16)
read_length(j) = plain_len(j)+16
```

同一 `K` 下 `(文件序号,块序号)` 永不重复，所以 nonce 唯一；打包器不能复用一次打包的
`K` 再生成另一个载荷。KEK 和内容密钥属于不同域，信封 nonce 不与文件 nonce 共用密钥。
空文件也必须有一个带 `last=1` 的 16 字节 tag；长度为零的文件不是合法空密文。
随机读只须一次 `ReadAt(offset,read_length)`，先校验**实际整个文件长度**与清单一致，再认证该块。
文件序号、块序号、末块标记和 `B` 都参与认证，跨文件替换、跨打包替换（即使误用了相同 `K`）、
重排和篡改末块标记都失败。截断整块、删末块、追加字节也因精确长度检查失败。
随机读一个块不会证明其他未读块未被篡改；加载完整流必须验证所有需要的块。
解块器只接受已通过解封/已认证服务器响应得到的密钥，不能据 `--verify` 的结果信任元数据。

### 12.4 构建落盘与原子发布

先把密文与 `payload.json` 写入目标父目录内的私有临时目录，逐文件 fsync，fsync 临时目录；
输入代码文件在各自目录中暂时 rename 到回滚槽，随后同文件系统 rename 发布输出并 fsync 父目录；
成功后才删除回滚槽并 fsync 输入父目录。普通 I/O 错误回滚输入并清理未完成输出；
不跟随输入/输出父路径中的符号链接。已有输出拒绝覆盖；数据文件和输入目录不删除。
构建目录必须静止，不能与其他进程并发改写输入、父目录或输出路径。
跨目录/跨文件系统的多个源文件不具备崩溃级事务保证；掉电/SIGKILL 或文件系统连回滚都拒绝时，
保留现场和 `.authgo-input-*` 回滚槽恢复，不能宣称整个过程具备跨文件系统原子性。

`--verify --out <目录>` **只检查结构**（schema、路径、长度），不解封、不验 GCM、不判断授权。
`--protect` 按 ELF 架构选择真实启动桩，在原文件旁准备完整受保护文件，成功后就地替换原 ELF，布局见12.8。构建工具缺少对应启动桩时直接失败并保留原文件，不产生不可用的占位程序。

### 12.5 可独立实现的公共测试向量

[sdk/vectors/payload-envelope.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/payload-envelope.json) 是完整可复现向量；其中所有私钥和内容密钥都只是**公开合成测试值**，
不是部署密钥。包含完整 payload、清单原始 JSON、接收者私/公钥、临时私钥、内容密钥、
`A`、shared、salt、KEK、`B`，以及每块的 nonce、AAD 与密文证据。

- 文件 0 为空，只有一个末块，提供完整 tag；
- 文件 1 为 `1048576` 个 `0x41` 后接 UTF-8 `hello`，分成两块；首块提供完整块
  `ciphertext||tag` 的 SHA-256、前 32 字节和末尾 tag，第二块给出完整密文和 tag；
- `plain_repeat_count` 是重复**字节**数；hex 不带 `0x`，字符串前缀里的 `\x00` 表示一个 NUL；
- 对照 `envelope_aad_hex`、`kek_hex` 和 `binding_hex` 可以逐步定位编码、HKDF 或拼接错误，
  不需要阅读 Go 代码即可解封、定位和解密任意块。

七种语言必须运行该向量；当前实现的 Go 测试从算法重新计算向量并与文件逐字节比较。

### 12.6 在线解锁 `payload.unlock`

通过现有 `/api/v1/client/gateway` 的加密内层动作调用，不提供明文入口。沿用请求HMAC、Nonce防重放、响应加密和Ed25519签名；现有网关请求上限仍为64KiB（外层和解密后的body均受限），不为加密载荷放大上限。

内层body沿用`license_key`、`activation_token`、`device_fingerprint`、`instance_session`、`challenge`等认证字段，并增加：

- `payload`：**完整、原始的payload.json对象，包含config**，字段见12.1。不删除config、不重建manifest，也不把manifest重新序列化。payload本身不得超过64KiB；config不得超过32768字节，manifest也必须容纳在网关上限内，超长返回`PAYLOAD_INVALID`（整个网关超限按现有非法请求流程处理）。
- `ephemeral_public_key`：客户端为本次解锁独立随机生成的X25519公钥，B64U编码的32字节；客户端私钥不传输。

`config`是公开内容，只用于重建原信封AAD并验证格式；服务端不使用它选择连接目标，不用当前配置替代，也不写入日志或审计。顶层`client_version`或`version`不能决定解锁使用的版本；版本和构建时间只取自信封认证后的字段。

检查严格依次执行：授权和软件有效 → 激活令牌属于该实例且席位/租约有效 → 信封校验及解封 → 信封版本未禁用 → 信封built_at不晚于maintenance_until。前两步失败不查询打包私钥、不调用解封；解锁不会新建席位或接管其他进程的实例。如授权启用FLOATING，即使配置为任一绑定方式满足，解锁也不能跳过有效租约。信封格式、软件/key_id不匹配、GCM校验等任一失败统一为`PAYLOAD_INVALID`。版本禁用返回`VERSION_DISABLED`；构建时间严格晚于维护期返回`MAINTENANCE_EXPIRED`，包含`latest_entitled_version`，相等放行。维护期为空不限制。

通过后重新封装内容密钥，成功响应data包含`e,n,c`（B64U）以及现有校验结果字段（包括`is_trial`）。不返回明文内容密钥。重封装算法：

```text
P = B64U_DECODE(ephemeral_public_key)       // 32 raw bytes
Q = B64U_DECODE(challenge)                  // 32 raw bytes
A = UTF8("authgo-payload-rewrap-v2\x00")
    || LP(app_key) || LP(version) || LP(built_at) || LP(key_id)
    || H(B64U_DECODE(manifest)) || P || Q
esk = CSPRNG X25519 private key            // 每次独立，不复用打包信封临时密钥
E = X25519_public(esk)
S = X25519(esk, P)                         // 拒绝低阶点/全零shared
salt = H(A)
KEK = HKDF-SHA256(ikm=S, salt=salt,
                  info=UTF8("authgo/payload/v1/rewrap"), length=32)
N = CSPRNG(12)
C = AES-256-GCM.Seal(key=KEK, nonce=N, plaintext=K, aad=A)
response.data.e = B64U(E)
response.data.n = B64U(N)
response.data.c = B64U(C)                   // 32字节内容密钥 + 16字节tag
```

重封装AAD**不含config**；变长字符串使用12.1的U32长度前缀，其余哈希、公钥和challenge均为固定32字节原始值。完整合成向量见[sdk/vectors/payload-unlock-v2.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/payload-unlock-v2.json)，包含每步输入及中间值，原[payload-envelope.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/payload-envelope.json)不变。

每个授权固定每分钟6次、突发3次，独立于可配置的IP/授权普通限流，原IP限流继续生效。超限返回`RATE_LIMITED`。验证日志只记录授权引用、认证后的版本、动作与结果，不记录信封、config、内容密钥或临时公钥。

`PAYLOAD_INVALID`表示这一份载荷损坏，**不是授权的明确拒绝，不清授权缓存**；加入显式非拒绝码表。试用与正式授权执行完全相同的认证、席位、版本和维护期检查，试用结果仍带`is_trial=true`，后续客户端不得为试用持久化内容密钥。

### 12.7 内容密钥缓存 v2（各语言相同）

缓存不是授权证据。必须先完成现有Check/高层守卫校验，并对本地票据完成签名、软件、实例、授权及时间检查；不能只因磁盘有文件就解锁。在线`payload.unlock`还须校验完整v2响应签名/nonce/时间，以及重新封装GCM和本次challenge。返回的内容密钥仅留在内存，调用方用完清零。

沿用第11节的稳定实例指纹`fingerprint`（AUTHGO_INSTANCE_ID按原文派生；没有覆盖时使用既有容器/物理机算法），不用每进程instance_session派生缓存，也不新造种子。缓存派生仅使用已签名票据中的`unlock_hash`（32字节十六进制解码）以及绑定实例的标签，不依赖任一SDK私有缓存的`unlock_seed`，不新增随机种子。`unlock_hash`不是授权凭据，读取缓存前仍必须验证签名和时效。

```text
L = UTF8("authgo-payload-cache-v2\x00")
    || LP(app_key) || LP(fingerprint) || LP(key_id) || LP(version)
    || H(B64U_DECODE(manifest)) || B
Kcache = ResourceKey(HEX_DECODE(verified_ticket.unlock_hash), L)
       = HKDF-SHA256(ikm=HEX_DECODE(verified_ticket.unlock_hash), salt=empty,
           info=UTF8("authgo-unlock-v2\x00") || L, length=32)
A = UTF8("authgo-payload-cache-file-v2\x00") || H(L) || U64(license_id)
N = CSPRNG(12)
C = AES-256-GCM.Seal(Kcache, N, K32 || WM32, A)
file_bytes = UTF8("AUTHGO-PAYLOAD-CACHE-v2.") || UTF8(B64U(N || C))
```

`B`是12.2节的完整信封绑定值：因此同一版本/同一清单结构的不同构建、配置或信封，不会错误命中另一个构建的密钥。`L`是二进制标签，不采用已删除公开资源接口的文本标签限制；沿用内部ResourceKey/HKDF机制。版本字段是固定前缀中的v2；其余文件内容只有nonce和经认证的密文，没有明文内容密钥、种子、授权码或到期时间。文件必须为0600普通文件，不跟随文件符号链接；同目录私有临时文件写入、fsync并原子rename，拒绝过长或格式不规范的文件。

缓存目录沿用第11节。为区分服务地址、软件、实例和信任根，令`endpoint`按v2 SDK规则规范化（小写host，移除结尾斜杠，必要时追加`/api/v1/client`）：

```text
I = UTF8(endpoint + "\x00" + app_key + "\x00" + fingerprint + "\x00"
         + hex_lower(H(Ed25519_public_key_raw)))
filename = "authgo-payload-v2-" + hex_lower(H(I)) + "-"
           + hex_lower(H(L)) + ".cache"
```

文件名不含授权码；即使手动重命名，把缓存复制到不同AUTHGO_INSTANCE_ID也不能通过GCM。AAD额外绑定已验证票据的license_id，不能把另一授权的票据用于打开缓存。

- 仅在本地**已签名票据的原grace_until**之前允许读取；授权到期、未开始、时钟回退、明确拒绝和实例被接管同样阻止使用。
- grace_until不晚于issued_at（正式授权grace_hours=0）时不缓存；is_trial=true时不缓存。试用的刷新重叠不是断网宽限。
- 已认证明确拒绝立即清理该软件/服务/实例上下文的全部内容密钥缓存。INSTANCE_REPLACED也清理内容密钥缓存，但不改变第11节对普通授权缓存的接管例外。PAYLOAD_INVALID不是明确拒绝，不清授权或内容密钥缓存。
- 校验网络失败后，只有既有合法票据和对应密钥缓存同时可用才可启动；空卷、缓存被篡改或超过grace均失败。目录不可写时只放弃缓存，不把成功在线解锁变成失败；清理失败也不能在已拒绝进程中继续使用。
- 缓存加密不防拥有实例身份和已授权票据、或宿主机root权限的人导出密钥。它不依赖配置串保密，不能代替服务器授权校验。

合成互操作向量为[sdk/vectors/payload-cache-v2.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/payload-cache-v2.json)，包括实例输入、指纹、ResourceKey标签、派生密钥、AAD、nonce、密文、文件文本和文件名；所有密钥均为公开测试值。

#### 12.7.1 启动桩共享授权证据 v1

Go、Rust受保护程序与启动桩共享下述证据，不互读各SDK私有授权缓存。仅当`AUTHGO_PROTECTED=1`时，程序每次在线激活、校验或心跳成功后原子替换证据；启动桩自己的首次在线校验也写入同一格式。网络失败和`PAYLOAD_INVALID`不改证据。试用或零宽限成功时删除证据和全部内容密钥缓存；已认证明确拒绝（包括`INSTANCE_REPLACED`）同样立即清理。正常释放席位不删除合法宽限证据。

```text
I = 12.7中的缓存上下文UTF8字节（endpoint、app_key、fingerprint、公钥哈希）
T = 最近一次在线成功得到的原始签名票据UTF8（不重新序列化）
Km = HKDF-SHA256(ikm=UTF8(fingerprint), salt=empty,
     info=UTF8("authgo/payload-proof/key/v1\x00") || I, length=32)
M = HMAC-SHA256(Km, UTF8("authgo-payload-proof-v1\x00") || T)
proof = UTF8("AUTHGO-PAYLOAD-PROOF-v1.") || UTF8(B64U(T)) || "." || UTF8(B64U(M))
proof_filename = "authgo-payload-proof-v1-" + hex_lower(H(I)) + ".cache"
```

证据文件为0600普通文件，拒绝符号链接和大于12MiB的证据。用同目录随机私有临时文件、fsync、rename原子写入；写失败不使在线授权失败。完整性保护绑定既有稳定实例指纹，不用`instance_session`，不是新的信任根。能读取实例标识的人可重算MAC，但不能伪造Ed25519票据签名；复制到另一个`AUTHGO_INSTANCE_ID`后MAC、票据device_hash及密钥缓存绑定都不成立。

启动桩每次先尝试在线Check和解锁；在线明确拒绝绝不退回缓存。离线时不依赖Go/Rust私有授权缓存：必须先读取共享证据，验证MAC、v2原始票据Ed25519签名、app_key、active状态、license_id、device_hash=H(UTF8(fingerprint))、挑战长度、策略字段及时间。票据不能晚于本地当前时间5分钟，授权须已开始且未到期，is_trial必须false，grace_until必须严格晚于issued_at，且当前时间严格早于grace_until才可用。缺失、篡改、过期均失败退出77。浮动租约按第11节离线宽限规则，不要求断网时仍能联网续租；之后才用该票据的unlock_hash打开内容密钥缓存，绑定license_id，逐块验证密文。

同一软件的unlock_hash稳定，更新原始签名票据不会使既有内容密钥缓存失效；程序在线运行超过首次启动票据的宽限期后，仍可凭最新证据在其宽限期内离线重启。证据可被同目录持有者回滚，安全上限始终是被重放的已签名grace_until；本地存储不提供抗宿主机root回滚能力。

### 12.8 Go/Rust整体保护的可执行文件尾部 v1

构建时把配置放在完整payload.json的config中；启动桩仅从自身`/proc/self/exe`读取，不从AUTHGO_CONFIG或其他文件加载信任根。授权码取AUTHGO_LICENSE，既有实例标识/缓存目录规则不变。文件精确布局：

```text
[架构匹配的静态Linux启动桩ELF，S字节]
[完整payload.json UTF-8，P字节]
[按manifest文件序号连接的全部.agc密文，共C字节]
[固定64字节footer]
```

footer各整数为无符号大端，不允许追加字节：

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 16 | 魔数`AUTHGO-STUB-v1`后接两个NUL（hex `41555448474f2d535455422d76310000`） |
| 16 | 4 | 版本1 |
| 20 | 4 | 保留flags=0 |
| 24 | 8 | S，至少64 |
| 32 | 8 | P，1至65536 |
| 40 | 8 | C |
| 48 | 16 | 保留，必须全零 |

必须用溢出安全加法确认`S+P+C+64=整个文件大小`。清单中恰有一个protect条目，架构与运行架构一致；所有密文分片的精确长度之和必须为C。读取某文件使用经过边界检查的SectionReader，仍须逐块验证12.3的GCM，完整主程序所有块都通过后才能exec。尾部无额外的可替换配置副本；修改config会改变原信封和密文块绑定。假服务器没有原打包私钥，不能仅靠签发一份假授权响应取得原内容密钥，错误内容密钥也不能通过块认证。

打包在构建阶段完成：先生成全部密文和受保护程序临时文件，发布--out后同文件系统rename替换原ELF，普通I/O失败沿用12.4的回滚机制；原文件在成功前保持可恢复，不留下半成品。`--out`继续是新的密文/元数据输出目录，--protect指定的ELF同时就地替换。生产authgo-pack通过go:embed包含amd64和arm64两个真实启动桩；缺少桩时普通单元测试可注入测试ELF，生产--protect则明确失败，不能把测试桩当成可执行保护。

### 12.9 Linux内存执行与实例接管

启动桩只做一次Check（空授权码按高层规则申请/恢复试用）和UnlockPayload。通过验证的主程序流式写入memfd，设置F_SEAL_SEAL、F_SEAL_SHRINK、F_SEAL_GROW、F_SEAL_WRITE，转为只读FD，清零调用方内容密钥，然后`syscall.Exec("/proc/self/fd/<n>",原argv,原env加AUTHGO_PROTECTED=1)`。argv[0]、业务参数及其他环境保持原值；不启动子进程、不注册信号处理、不启动校验循环、不在exec前释放席位。任一步失败输出固定中文阶段和错误码，退出77，不输出授权码、配置、密钥或远端可控错误文本。

memfd先尝试`MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_EXEC`（0x13），旧内核EINVAL时重试0x03；不放宽seccomp或宿主机内核策略。实际执行被策略拒绝时，仅回退到经过fstatfs确认为TMPFS_MAGIC且非noexec的/dev/shm或/tmp：通过目录FD创建私有文件，写完后打开只读FD、关闭写FD、**执行前unlink**，再用/proc/self/fd执行。绝不把明文程序写入持久盘；两种方式都不可用时明确失败。需要回退的部署应提供可执行tmpfs，不能把持久卷当回退目录。

启动桩和程序共享既有缓存目录/实例标识，但每进程instance_session不同。exec后的程序调用已有StartGuard，用新session按第11节接管同一个浮动载体；不是第二个席位。真正程序负责后续校验、心跳和SIGTERM退出释放。PID不变，PID 1的exe指向`memfd:authgo-main (deleted)`或已unlink的tmpfs文件，而cmdline仍保留原argv[0]；依赖/proc/self/exe所在目录、重新执行自身、相对自身路径找资源的程序必须调整。动态ELF的解释器和库由镜像提供。

Go及Rust高层守卫看到AUTHGO_PROTECTED=1时在Linux调用prctl(PR_SET_DUMPABLE,0)，失败只记录而不退出；启动桩在解密前也尽力关闭转储。它不防宿主机root读取内存或/proc，也不防已授权客户导出明文。


内存执行取决于宿主机内核和容器策略。memfd 或可执行 tmpfs 均不可用时明确退出77，不改变宿主机安全策略。

### 管理端构建展示元数据

版本管理 DTO/创建与更新接受 `encrypted` 和可空 RFC3339 `built_at`。管理员从打包产物登记；
启用加密展示必须填写构建时间，关闭时清空构建时间。手动和Docker Hub版本使用相同编辑入口，
自动同步保留已登记字段，列表批量读取，不按版本逐条请求。
这两个管理字段不是客户端授权协议或信任源；`payload.unlock` 的维护期判断仍只使用已认证信封中的
版本与 `built_at`，不能通过修改版本列表的显示时间改变解密授权。
系统设置的 `tools_image`、`tools_version` 只用于生成公开构建文件，不能改变已发布程序的运行时服务地址、公钥或信任根。

## 13. 授权水印派生与本地追查 v1

水印仅用于事后追查，不是授权证据，不防止内存导出、抹除或比较两个授权的副本。
以下规则和共享向量 [sdk/vectors/watermark.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/watermark.json) 固定标记/值的字节编码，与第12章当前信封和缓存格式配合使用。
**第12章当前的manifest是公开的base64 JSON，已由信封和分片绑定认证，但没有加密。**
不能将它称为“信封内加密清单”，也不能据此把槽位索引冒充已加密；运行时新格式/加密槽位索引的扩展应单独版本化。

### 13.1 确定性派生

- HKDF均为RFC5869 HKDF-SHA256的Extract+Expand，`salt`为空字节串（按RFC使用32字节零盐），不是只做Expand。
- IKM为数据库保存的原始32字节X25519公钥或私钥，不是其base64、hex或配置串编码；私钥不另做clamp/归一化后再派生。
- `tag = lowercase_hex(HKDF(public_key, salt=empty, info=UTF8("authgo/watermark/tag/v1"), length=16))`，恰32个ASCII小写十六进制字符。
- `watermark_key = HKDF(private_key, salt=empty, info=UTF8("authgo/watermark/key/v1"), length=32)`。
- `watermark = lowercase_hex(HMAC-SHA256(watermark_key, U64_BE(license_id)))`，恰64个ASCII小写十六进制字符。
- `license_id`为非零无符号64位数据库授权编号，序列化为固定8字节大端；不使用十进制文本、浮点数、授权码或JSON数字文本。
- 槽位为`ASCII(tag || watermark)`共96字节；构建时最后64字节为ASCII `0`。全0不是可追查授权值。
- 所有info均不附NUL。软件标记可以由持有公开打包公钥的人计算，不是秘密或认证凭据；管理接口仍仅限管理员。
- 旧key_id的加密私钥必须保留；追查遍历该软件全部历史key_id，不只使用当前key_id。跨软件编号不匹配。

### 13.2 管理接口与隐私边界

`GET /api/v1/admin/applications/{id}/watermark-tags`返回`{items:[{key_id,tag}]}`，只包含该软件全部新旧标记，不返回私钥。
`POST /api/v1/admin/applications/{id}/watermark-trace`仅接受`{"watermark":"<64位小写hex且非零>"}`，拒绝未知字段及文件/文件名/片段。
已找到时返回`found:true`、`license_id`、可用的`user_id/user_name`、`is_trial`、`key_id`、创建时间和自助试用来源记录`[{ip,instance_id,created_at}]`。
没有找到（包括授权已删除、属于别的软件）统一返回`{found:false}`；不返回授权码、密钥或提交的水印值。
两接口沿用管理员Bearer认证、软件边界及现有审计；审计只记动作/资源编号/结果，不保存请求体、水印值或文件内容。
一次追查批量读取软件密钥、授权和客户，不能逐授权读取数据库；自助试用来源仅在找到授权后批量读取。

### 13.3 CLI和浏览器一致的扫描规则

`authgo-pack trace --tag <tag> [--tag <old_tag>] <file>`只读本地文件，输出JSON结果；浏览器使用Worker和File.stream，文件不上传。
64KiB默认读取块，连续块至少保留95字节；相同tag输入去重，同一位置只计一次，必须精确匹配32字节tag及随后64个小写hex字符。
零值计入`slots/zeros`但不能识别授权；非零值按出现次数降序排序。唯一最高频非零值为`found`；最高频平票为`ambiguous`，不得自动提交任一候选。
只有零槽为`zero`，没有槽为`none`。结果包含`count/slots/zeros/complete/candidates/warnings`；`count`为最高频非零候选次数，没有非零值时为0。
ZIP/JAR只扫描解压条目，不重复扫描压缩容器本身；嵌套ZIP/JAR递归处理，条目CRC和声明长度通过后才计入该条目。
固定限额：总解压512MiB、单条目128MiB、嵌套深度4（根ZIP为0，深度5的ZIP拒绝）、总条目4096、不同非零候选4096。
加密ZIP、ZIP64/不支持的方法、坏CRC、截断、超限均为`partial`，保留此前完整条目的结果并明确“未扫描完”，不得自动查询。
取消为`cancelled`且`complete:false`；CLI中断亦如此。非ZIP格式按普通字节流扫描并提示其他压缩格式没有解包，不把普通扫描声称为已解压。
完整扫描的`found/zero/none/ambiguous`退出码0，`partial/cancelled`退出码2；非法参数/无法读取退出码1。
浏览器只有完整且唯一的`found`结果自动提交`{watermark}`；任何文件名、片段或二进制不得进入网络请求。

### 13.4 已认证解锁响应中的水印值

服务端`payload.unlock`在现有授权/实例校验及已认证built_at维护期检查全部通过后，使用该信封的key_id和本次授权的数据库ID派生水印。
成功的`data`追加`watermark`字符串，受现有v2响应加密、完整data签名、请求nonce和票据上下文保护；不在未认证错误或授权拒绝响应中发送水印。
内层内容密钥重封装的`e/n/c`字节布局仍为12.6的v1格式，只封装32字节K；新增水印不位于公开payload.json中，也不包含授权码。

### 13.5 受保护载荷v2：独立加密槽位索引

新加密构建使用`payload.v=2`，原v1包继续按原规则解析。v2的外层字段和公开manifest结构不增加位置字段；公开manifest仍**公开且已认证**，不改称加密。
v2在`files`中恰有一个附加条目：`name="__authgo_watermark"`、`kind="watermark"`、`encoding="raw"`、普通连续编号的`path`、`chunk_size=1048576`、`size`为1..8MiB。
此条目严格只允许上述6个字段；保留名不能用于业务代码，v2至少含一个业务条目。v1不接受watermark条目。
其明文是下面的私有索引，像其他文件一样使用内容K和12.3的分片GCM加密；**不是信封内联字段**，是由信封所封装K保护、由B/文件编号/分片编号认证绑定的独立密文条目。

```json
{"v":"1","tag":"<32 lowercase hex>","files":[{"index":"0","entries":[{"path":[],"offsets":["1234","1450"]}]}]}
```

示例offsets只展示编码，不是满足8槽要求的完整实例。索引私有版本固定为字符串`"1"`；`index`和`offsets`均为规范十进制字符串，不允许前导零（0本身除外）、符号、小数或指数。
`index`范围0..65534，必须恰好覆盖所有业务文件且不指向索引本身；`offsets`范围0..MaxInt64/2，按数值严格递增，相邻至少96字节。
每业务文件至少8槽。文件、条目、偏移总数各最多65535；path最多8级，条目和路径唯一，沿用严格相对路径规则，拒绝控制字符、NUL、反斜杠、冒号、绝对路径和路径别名。
raw保护程序/Node的path为空数组；Python/PHP tar及.NET为单个条目名；Java为嵌套JAR条目链后接class条目名。空数组不能写成null。
重复/未知/大小写别名字段、错误类型、溢出、重叠、缺失条目或越界均拒绝。GCM成功不替代这些结构校验。
加载器先完整认证并校验索引，再完整认证需要执行的代码；所有槽位须匹配索引tag与64个ASCII `0`，全部验证后才将后64字节改成当前授权的水印hex，必须在执行/defineClass/LoadFromStream之前完成。
只在进程内存、匿名memfd或已验证的临时内存文件系统进行；敏感K/材料按现有约定及时清理，不写明文源码到缓存卷或持久可写层。

实现侧的槽位放置与保留（不改变上述索引 schema/加密域）：
- Python 新 pack 在模块、函数、嵌套函数和闭包的每个实际 code 对象 `co_consts` 末尾加入8个不同字符串；共享的代码常量表仍共享8槽，不把8个不同字面量合并成1槽。
  Go 标准库解析/重发 marshal 全局引用，原 `co_code`、原常量索引前缀/值及普通字段元组引用保持；需要扩容的 `co_consts` 和普通元组 alias 分域，普通 `names/varnames/freevars` 不得随之扩容。
  原co_consts为空时，先放一个None文档哨兵再放8个字符串，空表总增9；原表没有旧索引可移，非空表仅末尾加8。此举防止CPython把第一段水印当作新函数__doc__，普通共享空元组仍保持空。
  格式覆盖匹配的 pyc 3.8–3.14，与 Python SDK 最低3.9分开。SDK 继续把文件名虚拟化为 `authgo-sealed://...`，用图 memo 保留重复 code/元组/容器的共享引用；不为水印改业务字节码。
  非法/未完成引用、不能安全拆分的递归常量表/不可重建的不可变 code 循环、未知格式及资源超限失败关闭，不能退回无印代码。
- Node 在 Directive Prologue 后插入不访问标识符/宿主 constructor 的 `void [字符串…]`，不修改公开 exports 或全局业务对象。
  V8可优化表达式；SDK只在 `_compile` 成功后，私有保留传给这次实际执行的同一份源码字符串，Guard清理释放引用；不是未执行资源副本。
- PHP 词法识别真实 `function [ & ] [name] (` 声明，变量/成员调用/namespace限定名不是声明。函数中的字面量放在立即调用的私有闭包作用域，不向业务函数 `get_defined_vars()` 增加局部 static，也不向匿名类增加属性。
  根常量仍可反射观察；私有闭包常量不再作为调用方公开 static 字段。已执行函数的 Reflection `opened_path` 可在 Guard 有效时定位同一已安装内存源文件；VM静态值序列化只是辅助证据，不是完整核心代码导出。
这些改动会被源码/代码常量反射发现，不提供“水印不可检测”的保证；不保证擦除不可变字符串、V8/Zend/CPython副本或撤回已编译代码。

信封AAD前缀为`authgo-payload-envelope-v2\x00`，重封装AAD前缀为`authgo-payload-rewrap-v2\x00`，各字段顺序及LP/哈希/临时公钥/challenge编码保持12章不变。
HKDF的wrap/rewrap info分别为`authgo/payload/v1/wrap`、`authgo/payload/v1/rewrap`；salt中的AAD哈希已提供版本域分离。分片AAD前缀为v1，B已绑定v2信封和完整公开manifest。
受保护ELF尾部容器的magic、版本1及布局保持不变，它携带的payload为v2；不能把尾部布局版本当成载荷版本。

### 13.6 水印材料缓存

对v2载荷，已认证解锁响应的watermark必须是非零64位小写hex；缺失/错误格式的**新鲜已签名响应**立即失败，不得借旧缓存或启动桩旧证明回退。
底层公开UnlockPayload仍可返回32字节K（直接用K解密产生全0副本是已知限制）；受保护加载器必须使用绑定同一响应的私有`K32 || WM32`材料，WM32为hex解码的32字节。
v2缓存明文恰为64字节；材料必须恰为64字节且水印非零。

缓存使用以下域前缀；LP、原始manifest哈希、B、指纹及已签名授权ID均参与绑定：
- 缓存标签：`authgo-payload-cache-v2\x00`。
- 文件AAD前缀：`authgo-payload-cache-file-v2\x00`。
- 文件文本前缀：`AUTHGO-PAYLOAD-CACHE-v2.`，其后仍为B64U(nonce||GCM密文)，密文部分为64+16字节。
- 文件名固定前缀：`authgo-payload-v2-`，保留缓存身份和标签哈希命名规则、0600/非符号链接/私有临时文件/fsync/原子rename要求。

已认证明确拒绝清理当前上下文的缓存；未知/未认证错误与更新动作的分类遵循第11节。
试用和零宽限不缓存，缓存必须先通过原授权/实例/窗口及时间回拨检查，不能扩展签名的grace_until、到期或维护期边界。
展示加密状态与 built_at 不作为授权来源；载荷版本和独立加密索引经过完整认证。
