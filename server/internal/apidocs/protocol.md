# Auth Go 客户端协议 v2（gateway）
供自行实现 SDK、打包器或启动桩使用。业务接入见[快速开始](?tab=quickstart)和[SDK 示例](?tab=sdk)。

## 1. 概览
| 顺序 | 实现 |
| --- | --- |
| 1 | 固定接入配置；生成正文、challenge、nonce 与 HMAC |
| 2 | 长度填充；临时 X25519、HKDF 双向密钥、AES-GCM；POST `/api/v1/client/gateway` |
| 3 | 解密响应，验证 Ed25519、nonce、时间，再使用 code |
| 4 | 验证票据的软件、授权、实例、challenge、时间及 seed 哈希，保存缓存 |
| 5 | 定期校验/心跳、退出释放；故障按第 7 节处理，不能仅凭布尔值放行 |

## 2. 编码约定
| 项目 | 规则 |
| --- | --- |
| 字节 | UTF-8；`\|\|` 为拼接；`\x00` 是一个 NUL，`\n` 是 LF；HEX 为小写十六进制 |
| timestamp | 无前导零的十进制 Unix 秒字符串，偏差最多 300 秒 |
| 票据时间 | RFC3339 UTC，可有小数秒；到期当秒失效 |
| B64U | RFC4648 URL-safe Base64，无 `=`，严格拒绝非规范编码 |
| 接入配置 | `authgo2.B64U(JSON)`，最大 32768 字节；恰有 `url,app_key,app_secret,public_key,gateway_key`，拒绝未知/重复字段 |
| url | HTTPS，可有部署子路径或以 `/api/v1/client` 结尾，无查询和凭据；HTTP 仅供开发回环 |
| app_key / app_secret | 定位软件 / 按字符串原始 UTF-8 字节做 HMAC；secret 不证明调用方身份 |
| public_key / gateway_key | 标准 Base64 的 32 字节 Ed25519 公钥 / B64U 的 32 字节 X25519 公钥 |
| 信任根 | 配置可公开，但须编译固定，不读客户环境变量、文件或待验证响应；直接构造 Client 也须固定两种公钥 |

## 3. 请求构造
### 3.1 内层认证
内层恰为 `{"app_key":"…","op":"verify","timestamp":"…","nonce":"…","signature":"小写hex","body":{…}}`。不接受查询字符串，正文拒绝未知字段、控制字符及格式错误授权码；先校验格式再查询。

```text
signature = HEX(HMAC-SHA256(UTF8(app_secret), op || timestamp || nonce || HEX(SHA256(body原始UTF-8字节))))
```

输入无分隔符，不含 HTTP METHOD 或路径；生成 HMAC 后不得重排正文。`public-key/announcement/version` 的 body 为 null，HMAC 正文按空字节串而非 `null` 处理。

| 字段/顺序 | 规则 |
| --- | --- |
| challenge | 授权动作每次（包括 verify/heartbeat）重新生成 32 随机字节，B64U |
| nonce | 16–128 个 `A-Za-z0-9_-` 字符；Go 使用 `HEX(SHA256(规范化上下文JSON)) + "_" + B64U(32随机字节)` |
| nonce 上下文 | endpoint/app_key/license_key/fingerprint/空 domain/client_version/operation/token_hash；activate 的 token_hash 为空，其余为 token UTF-8 的 SHA256；用于对应缓存上下文 |
| IP 限流 | 解密前执行；IPv4 完整地址，IPv6 /64。默认速率 10、突发 60；每授权默认 5/30，系统设置显示推荐范围并要求突发不小于速率 |
| 授权桶与防重放 | HMAC 通过后按 app_id+key 只读查询；不存在返回 LICENSE_NOT_FOUND，不分配桶或 nonce 项，按 IP 采样日志；存在才登记 |
| nonce 存储 | 按软件隔离，保留 10 分钟，全进程容量 100000，满时 RATE_LIMITED，不驱逐有效项；同值重放 REPLAY_DETECTED |
| 只读动作 | public-key/announcement/version 不登记 nonce，但仍验证 HMAC、时间及本次响应会话 |

### 3.2 长度与随机填充
请求、响应都先序列化为 raw，前置无符号大端 U32 长度 L，再追加密码学随机字节至 `max(4096, ceil((4+L)/512)*512)`。接收方检查精确桶长，L 必须为正且不越界，仅读取后续 L 字节 JSON。大正文只隐藏到 512 字节桶，不提供抗流量分析保证。

## 4. 加密与响应验证
### 4.1 X25519 与方向密钥
服务端全局 X25519 私钥通过主密钥派生 AES-GCM 密钥和专用 AAD 加密存库，缺失时生成。客户端每次请求使用新临时私钥：

```text
k = HEX(SHA256(server_public_32_bytes))[0:16]; e = B64U(ephemeral_public_32_bytes)
shared = X25519(ephemeral_private, server_public)  // 拒绝低阶点/全零共享秘密
AAD = UTF8("authgo-gateway-v2\x00" || k || "\x00" || e); salt = SHA256(AAD)
request_key = HKDF-SHA256(shared, salt, UTF8("authgo/v2/request"), 32)
response_key = HKDF-SHA256(shared, salt, UTF8("authgo/v2/response"), 32)
```

HKDF 为 RFC5869 Extract+Expand，不将 shared 直接当 PRK。AES-256-GCM 使用 12 随机字节 nonce、128 位 tag，tag 附在密文后。请求 `c=B64U(GCM(request_key,n,padded_plain,AAD))`。

请求外层恰为 `{"v":2,"k":"16位短ID","e":"B64U","n":"12字节B64U","c":"含tag的B64U"}`，总大小（含 JSON/Base64/填充）最多 65536 字节。仅用 `Content-Type: application/json`，不发送 X-App-Key/X-Timestamp/X-Nonce/X-Signature。

### 4.2 响应绑定与签名
```text
response_AAD = AAD || "\x00" || UTF8(HEX(SHA256(UTF8(request.n || "." || request.c))))
response.c = B64U(GCM(response_key,新的随机12字节nonce,填充响应JSON,response_AAD))
```

外层仅 `{"n":"…","c":"…"}`，另一请求的响应无法通过 GCM。可解密业务结果均 HTTP 200，仅密文；坏 k、解密/外层解析/大小/查询错误及解密前限流，统一 HTTP 400，正文精确 `{"error":"invalid request"}`。这是连接故障，不是可信业务拒绝。响应 `Cache-Control: no-store`。

| 内层响应字段 | 检查 |
| --- | --- |
| code、message、data | code 决策须等完整认证；message 仅展示；完整 data 参与签名 |
| signature | 标准 Base64 Ed25519，对规范化 `{code,data,ts}` 签名；早期错误可为 null，不能视为成功 |
| ts | Unix 秒数值，当前时间 ±300 秒 |
| nonce、data.request_nonce | 两者均等于本次 nonce |
| data.ticket.challenge / trial 的 data.challenge | 等于本次随机 challenge |

规范化 JSON：递归按键 Unicode 码点排序、数组原序、无空格、非 ASCII 原样、控制字符 JSON 转义；`<>&` 分别用小写 `\u003c/\u003e/\u0026`，U+2028/U+2029 也转义。保留合法数字原字面量（大整数、指数、小数），不转 float、不做 Unicode 正规化，不是 RFC8785 JCS；拒绝重复键、非法数值和尾随第二 JSON。[参考实现](https://github.com/dingding229/Auth-Go/blob/main/sdk/go/wire/json.go)。

## 5. 票据与缓存
### 5.1 在线票据
`B64U(payload原始JSON) + "." + B64U(Ed25519("authgo-ticket-v2\x00" || payload原始字节))`。按原字节验签，不重新序列化，与响应签名独立。

| 字段 | 规则 |
| --- | --- |
| v、app_key、status | 2、匹配固定软件、active |
| challenge、license_id、license_ref | 本次 32 字节挑战、匹配当前授权、内部不可逆授权引用（无公开状态清单） |
| device_hash | 规范指纹 UTF-8 的 SHA256 小写 hex |
| issued_at、starts_at、expires_at | 签发偏差最多 300 秒；已开始且未到期；永久授权 expires_at=null |
| features | 功能对象 |
| next_check_in、grace_until | 已签名的下次间隔、宽限截止；宽限不晚于授权到期 |
| lease_expires_at、floating | 租约截止、浮动标记；在线成功必须租约有效 |
| unlock_hash | 32 字节内部 unlock_seed 的 SHA256，须匹配响应 seed |
| maintenance_until、latest_entitled_version、is_trial | 可选维护期、最高可用版本、试用标记；缺少可选字段仍按原字节验签 |

响应签名/nonce/ts、票据签名及所有绑定同时有效才能在线成功。`Ticket()` 返回不可变字符串；`Validate(ticket)` 本地复验，不联网。Result.Status/Availability 为 online/grace，授权状态在票据中。

当前 Client 可在已签名 next_check_in 内存窗口使用刚验证票据（到期/租约优先），故 grace_hours=0 仍可在线使用；连接故障或明确拒绝立即取消此窗口，不将它持久化为离线宽限。内部 seed/哈希仅供载荷解锁，不是公开资源接口。

### 5.2 身份、守卫与持久化
| 项目 | 规则 |
| --- | --- |
| 身份优先级 | 显式覆盖（Go WithFingerprint）→ AUTHGO_INSTANCE_ID → 容器身份 → 原物理机指纹 |
| 容器检测 | AUTHGO_CONTAINER=0/1 强制关闭/开启；否则检查 `/.dockerenv`、`/run/.containerenv` 或 `/proc/1/cgroup` 的 docker/containerd/kubepods/libpod，不读取硬件 |
| 缓存目录 | 显式（WithCacheDir，空值禁磁盘）→ 非空 AUTHGO_CACHE_DIR → 容器 `/var/lib/authgo` → 用户缓存目录 |
| instance-id | 缓存目录 32 随机字节的小写 hex 文本，无换行、0600；同目录临时文件+link 原子发布，竞争者读获胜者；拒绝符号链接 |
| 容器指纹 | SHA256(UTF8(`authgo/instance/v1\0` + 标识文本)) 小写 hex；显式 INSTANCE_ID 原文参与，不裁空白/转小写 |
| 无可写身份目录 | 进程内随机身份、内存缓存；CacheWarning 提示重启为新实例、无断连宽限，不将在线成功改为失败 |
| 已有目录变只读 | 回退须先持久化时间水位，失败 SDK_CACHE_UNAVAILABLE；不能按新实例内存模式绕过回拨 |
| Guard | Config 编译固定，不读 AUTHGO_CONFIG；License 为空才读 AUTHGO_LICENSE；使用 Check/自动校验/ReleaseSeat/Validate，不新增动作 |
| 生命周期 | 宽限不关闭 Done；最终失败关闭。正常关闭仅释放席位，不解绑/删除有效票据；Require 本地校验票据与功能项 |
| 各语言 | 同一身份/session/32 条历史语义；缓存格式和语言身份隔离，不跨 SDK 复用；Go/Rust 启动桩共享证据另见 8.8 |

## 6. 各操作说明
### 6.1 字段与操作速查
共同授权正文：`license_key`（合法授权码）、`activation_token`（activate 可空，其余用激活结果）、`device_fingerprint`（64 位小写 hex）、`challenge`（32 字节 B64U）、`client_version`、`hostname`、`os`；常驻另带 `instance_session`。

| op | 专有请求 | data / 行为 |
| --- | --- | --- |
| activate | 无已有 token | activation_token、ticket 和校验结果，建立实例 |
| verify / heartbeat | 共同正文 | ticket、unlock_seed、license_id、status、features、starts_at、expires_at、next_check_in、heartbeat_interval、grace_until、satisfied_methods；心跳续租，不能跳过容量 |
| deactivate | 共同正文 | 撤销会话；仅完整认证成功后清本地 proof，失败保留 |
| release-seat | 共同正文 | request_nonce、released 布尔；释放浮动席位，保留激活凭据和有效授权 |
| public-key | null | public_key、previous_public_key、algorithm=Ed25519；不替换信任根 |
| announcement | null | items，字段见 6.5；不改授权缓存 |
| version | null | 最新 version 对象；无版本 VERSION_NOT_FOUND |
| update.check | 共同正文 + 严格 SemVer current_version | available/version/changelog/mandatory/published_at/docker_image/docker_pull/maintenance_until/latest_entitled_version/renewal_required |
| versions | 共同正文 + 可选 limit、before | items（已发布版本历史）、next_cursor；须有效激活，详见 6.3.1 |
| trial | device_fingerprint、challenge | license_key、challenge、request_nonce，取得后普通激活 |
| payload.unlock | 共同正文 + payload、ephemeral_public_key | e/n/c、watermark 和校验结果，见 8.6 |

### 6.2 进程会话与席位释放
- 常驻进程每次启动生成 16 随机字节 B64U（22 字符）instance_session，只存内存；activate/verify/heartbeat/release-seat 携带。PHP 请求式不发送，使用 token 会话租约。
- 服务端在 KEY 载体/浮动记录保存当前 session，并按 rowid 保留每激活最近 32 个已见 session。新 session 经策略、到期、版本、容量检查后接管；历史内已替换 session 返回 INSTANCE_REPLACED，裁剪外不能保证识别。
- 稳定浮动实例仍是规范指纹。租约到期按心跳竞争容量；正常 release-seat 事务删除实例与浮动代次引用并写 instance.release 审计，不另写验证日志；保留独立 KEY 锚点、token、缓存，不扩宽限。非浮动 released=false，Go 已知非浮动时不发请求。
- 释放后列表不显示实例；未释放的超时实例保留为离线。合法心跳可重建，持有效会话和 KEY 证明的新 session 也可 Verify 重建，仍校验容量及历史；update.check/payload.unlock/versions 不隐式占位。
- release-seat 成功/连接故障/临时错误不改缓存，明确拒绝按第 7 节；deactivate 撤销会话，不参与接管。七语言 VERSION_DISABLED 公开 latest_version，维护期错误公开 latest_entitled_version。

### 6.3 Docker Hub 更新与维护期
- update.check 须有效 token 与普通授权证明；当前版本不阻止找修复版本。来源仅软件的 Docker Hub 标签，无镜像 available=false；目标须已发布、未撤回、未禁用、在软件/授权版本范围及维护期内，客户自行拉取。
- 激活/校验/心跳依次判断授权、VERSION_DISABLED、MAINTENANCE_EXPIRED。上报版本发布时间严格晚于维护期才拒绝，相等放行；未上报/未收录/无发布时间放行，后两者采样记录。withdrawn 不影响运行版本判断，禁用不被同步覆盖。
- 有维护期时，最高可用版本为发布时间不晚于维护期和当前时间、未禁用/撤回且在版本范围内的最高 SemVer；无结果为空，无维护期不计算。更新超期提示 renewal_required。SDK 不凭本地时间拒绝维护期，断网仍仅原签名宽限。
- 发放/批量接受 maintenance_days 或 maintenance_until；POST `/api/v1/admin/licenses/{id}/maintenance` 修改；续期省略保留、不自动延长，0 天或 null 清除。

### 6.3.1 持证客户端版本历史（versions）
`versions` 是加密网关动作，不是免激活的 `version`。与 `update.check` 相同，需要有效授权码、激活 token、设备证明与 challenge，受相同 IP/授权限流、nonce 重放防护和验证日志约束；不会通过此操作占用/重建浮动席位，也不会写客户端授权缓存。返回按照 `published_at DESC, id DESC` 排序；仅本软件、发布时间不为空且不晚于服务端当前时间、未禁用且未撤回的版本。无记录返回空 `items` 而非 `VERSION_NOT_FOUND`。它不要求软件配置 Docker 镜像，历史条目不保证镜像可拉取。
内层 `body` 示例（占位符不得当作真实凭据；HMAC、外层加密、响应解密与验签均按第 3–4 节，不能直接发明文）：
```json
{"license_key":"<授权码>","activation_token":"<激活令牌>","device_fingerprint":"<设备指纹>","challenge":"<32字节随机值的B64U>","client_version":"1.0.0","hostname":"host","os":"linux","limit":2,"before":"<上一页next_cursor，可省略>"}
```
`limit` 省略为 50，整数范围 1–200；分页字段不接受 `null`。`before` 省略或空串表示第一页，否则必须原样使用上一页 `next_cursor`（不超过 256 字节，base64url 无填充的不透明游标，包含排序时间和 ID，禁止自行构造或解读）。每页同时有大小上限，返回数量可能小于 `limit`；以非空 `next_cursor` 而非条数判断是否继续。新增发布或修改、撤回版本时分页不保证跨请求的快照一致性。
完整成功响应解密后的示例（签名为占位符，`data.request_nonce` 及外层 `nonce` 均与本次请求绑定）：
```json
{"code":"OK","message":"验证成功","data":{"request_nonce":"<请求nonce>","items":[{"version":"1.2.0","changelog":"修复问题","published_at":"2026-11-18T00:00:00Z","mandatory":true,"entitled":false},{"version":"1.1.0","changelog":"初始发布","published_at":"2026-11-10T00:00:00Z","mandatory":false,"entitled":true}],"next_cursor":"<下一页游标或空字符串>"},"signature":"<Ed25519签名>","ts":1794960000,"nonce":"<请求nonce>"}
```
`mandatory` 与 `update.check` 一样采用版本记录的强制更新值；`entitled` 为授权维护期的发布时间判断：未设置维护期或发布时间不晚于维护期且版本为严格 SemVer 时为 true，晚于维护期或版本格式无效为 false。历史可以包含未获维护期权益的条目；此标记不授予下载或运行权限。`published_at` 返回 RFC3339 时间，`changelog` 是纯文本，展示时不得作为 HTML 执行。请求语法/游标/范围非法返回 `INVALID_REQUEST`；授权码/令牌无效分别可能为 `INVALID_LICENSE_KEY`、`LICENSE_NOT_FOUND`、`ACTIVATION_INVALID`，还可能返回 `LICENSE_NOT_STARTED`、`LICENSE_EXPIRED`、`LICENSE_REVOKED`、`LICENSE_SUSPENDED`、`USER_DISABLED`、`APP_DISABLED`、`LEASE_EXPIRED`、`INSTANCE_REPLACED`、`RATE_LIMITED`、`REPLAY_DETECTED` 或 `INTERNAL_ERROR`。认证失败前不得信任错误码。Go SDK 提供 `Client.Versions`；其余语言当前仅规定此 wire 格式，尚未实现此方法。

### 6.4 免授权码试用
- trial 无授权码/token，但使用完整网关认证和响应挑战校验；授权码仅存内存及加密缓存 trial_key，不写日志。仅高层 Guard 在有配置且 AUTHGO_LICENSE 为空时申领/恢复，低层 Check 仍拒绝空码；无配置 SDK_INVALID_CONFIG，首次断网失败。
- 软件仅开关，默认关闭；全局天数默认 14、范围 1–365，已有截止不变；type=trial、source=self_trial、无用户、KEY+FLOATING、单实例、features={}，不带模板。
- 软件+稳定指纹唯一，始终返回原授权（包括到期/转正）；新实例在软件停用/开关关闭时 TRIAL_DISABLED，已有实例可取回但普通认证仍受停用等规则约束。PHP 在缓存锁内只申领一次，不带 session。
- 同软件/IP（IPv4 完整、IPv6 /64）30 天内复用未转正未吊销 trial，已转正/吊销 TRIAL_IP_LIMIT；先 IP 规则后全局 UTC 当日 100 个新建额度，超限 TRIAL_QUOTA_EXCEEDED，复用不计额度；事务前软件/IP 每分钟 10 次，超限 RATE_LIMITED。
- is_trial 进入响应及票据；grace_until=issued_at+next_check_in+30 秒且不晚于到期，仅在线刷新重叠，不推迟检查；任何连接故障先拒绝试用，不能宽限/降级。
- POST `/api/v1/admin/licenses/{id}/convert` 选用户、正式类型/有效期，可改实例数/维护期，保留码和激活，下次在线恢复正式规则。客户换正式码重启并激活时，事务释放同实例旧试用席位、记 converted_at 并吊销旧试用，不向旧申领返回正式码；关闭开关不终止已发试用。

### 6.5 公告与公开读取接口
七语言签名读取：Go `Announcements(ctx)`；Python/Java/PHP/Rust `announcements()`；Node.js `await announcements()`；C# `Announcements()`。不要求激活，完整验证 gateway、Ed25519、nonce、ts 后展示纯文本，不读写授权缓存、不下载清单，错误原样返回。

| 接口 | 返回与限制 |
| --- | --- |
| gateway announcement | items：id/app_id/title/content/level/created_at/updated_at/published_at/expires_at |
| GET `/api/v1/public/announcements?app_key=...` | data.items：id/title/content/level/published_at/expires_at，仅有效软件的已发布且未到期公告；最多 20 条、256 KiB；未知软件与无公告均空列表 |
| 公开入口保护 | 每 IP 每分钟 30 次（IPv6 /64）；缓存最多 60 秒且不晚于最近到期；不签名、可被中间人篡改，需要防篡改用 SDK |

## 7. 错误码与故障状态机
仅通过完整认证的明确拒绝才能清缓存或写 Refused=true：HTTP 200 → GCM → Ed25519 → 本次 nonce → ts ±300 秒。认证前不能相信 code；操作作用域优先，update.check 和公告的所有结果都不改变授权缓存/Refused。

| 类别 / 错误码 | 含义与处理 |
| --- | --- |
| OK | 完整响应与票据认证成功后才可按在线结果使用 |
| 连接故障 | 传输/超时/TLS/重定向/任何非 200/截断或超大/HTML/密文/解密/签名/nonce/ts/票据/挑战/实例不匹配：不清缓存，有合法签名票据仅原宽限，不能制造 online；无缓存保留原错误 |
| INTERNAL_ERROR、RATE_LIMITED、LOG_UNAVAILABLE | 内部失败、限流、日志不可用；完整认证后仍属临时错误，不清缓存，可按原宽限 |
| REPLAY_DETECTED、TIMESTAMP_INVALID、SIGNATURE_INVALID、INVALID_REQUEST、PAYLOAD_INVALID | 重放、请求时钟/HMAC、请求格式、载荷无效；同上，是显式临时白名单，不能按 HTTP/message/前缀扩张 |
| INSTANCE_REPLACED | 已认证接管拒绝：立即停止旧进程，不宽限，进程内记住拒绝；不清普通缓存/写 Refused，重启的新进程可用合法缓存；载荷缓存与共享证据须清 |
| APP_NOT_FOUND、APP_DISABLED、USER_DISABLED | 软件不存在/停用、用户停用，明确拒绝 |
| INVALID_LICENSE_KEY、LICENSE_NOT_FOUND、LICENSE_NOT_ACTIVATED | 授权码格式错误、不存在、未激活，明确拒绝；本地格式错误不联网、不改缓存 |
| LICENSE_EXPIRED、LICENSE_NOT_STARTED、LICENSE_SUSPENDED、LICENSE_REVOKED | 到期、未开始、暂停、吊销，明确拒绝 |
| INVALID_POLICY、VERSION_NOT_ALLOWED、VERSION_DISABLED、MAINTENANCE_EXPIRED | 策略错误、版本范围不允许/禁用、超维护期，明确拒绝 |
| FLOATING_LIMIT_REACHED、LEASE_EXPIRED、ACTIVATION_INVALID、ACTIVATION_LIMIT_REACHED | 席位满、租约过期、会话无效、激活数量限制，明确拒绝 |
| TRIAL_DISABLED、TRIAL_IP_LIMIT、TRIAL_QUOTA_EXCEEDED | 试用关闭、IP 限制、每日额度，明确拒绝 |
| VERSION_NOT_FOUND、所有未知错误码 | 非 OK 默认明确拒绝；仅授权动作清可用 proof、写 Refused=true |
| SDK_NETWORK_ERROR、SDK_RESPONSE_INVALID | 本地网络/响应故障；证书错误保留 x509 原因，非 200 保留 HTTPStatus |
| SDK_RESPONSE_SIGNATURE_INVALID、SDK_RESPONSE_NONCE_INVALID、SDK_RESPONSE_TIMESTAMP_INVALID | 本地响应验签/nonce/时间检查失败，按不可信响应 |
| SDK_CLOCK_ROLLBACK、SDK_GRACE_EXPIRED、SDK_CACHE_UNAVAILABLE | 回拨、宽限耗尽、无法持久化时间水位，停止；宽限耗尽包住原错误，可 errors.Is/As |
| SDK_INVALID_CONFIG、SDK_FINGERPRINT_UNAVAILABLE、SDK_NOT_ACTIVATED、SDK_CACHE_INVALID、SDK_AUTO_CHECK_RUNNING | 配置、身份、未激活、缓存、重复自动检查错误，不冒充服务端签名拒绝 |

1. 先验证缓存完整响应、票据、实例/授权绑定；失败视为无缓存。缓存含 token/context 和最晚本机/服务端时间，用 AppSecret+指纹经 HKDF 派生 AES-GCM，0600 原子写入；不公开 seed，不将缓存当信任根，换码不复用旧激活。
2. 本机比最晚时间早超过 300 秒时 SDK_CLOCK_ROLLBACK，不宽限；在线成功重建水位。用户可写磁盘无法完全防回滚。
3. starts_at/到期优先。仅连接故障或临时错误可在原 grace_until 内忽略过期浮动 lease，返回 grace、Offline=true 并保留 features/载荷材料；正式默认 grace_hours=72，0 无宽限，试用无宽限，不拉备用清单、不降级、不延长。
4. 过窗 SDK_GRACE_EXPIRED，无合法在线票据保留原故障；Result.Reason 保留触发原因，调用方取消直接返回 context 错误、不清缓存。自动校验复用 Verify/Heartbeat 分类，连接故障 60 秒退避、总请求预算 15 秒。
5. 恢复后 heartbeat 竞争席位，Go Verify 发现旧 lease 过期时改发 heartbeat；满额等明确拒绝立即清 proof。Activate 失败不返回缓存成功，不破坏同码既有证据；换码是候选操作，失败不复用旧成功或改旧票据/Refused/磁盘。Deactivate 只在认证成功后清，回执丢失由后续复验发现。

## 8. 代码加密载荷格式
仅实现打包器、加载器或启动桩时需要。Go/Rust 用静态 Linux amd64/arm64 启动桩，其余用 SDK 内存加载器；打包不代表授权成功。[pack 源码](https://github.com/dingding229/Auth-Go/tree/main/pack)。

### 8.1 编码、元数据与清单
H=SHA256，U32/U64=无符号大端，`LP(s)=U32(len(UTF8(s))) || UTF8(s)`；B64U 还拒绝 CR/LF、非零尾位。JSON 须 UTF-8，无孤立 UTF-16 代理，嵌套最多 64，拒绝重复/未知/大小写别名/缺必填/错误类型/第二 JSON。清单哈希按原始解码字节，不正规化。

`--out` 为不存在的目录，父目录已存在；包含 0600 的 payload.json 与依次编号 `00000000.agc` 等。顶层恰为：

```json
{"v":2,"app_key":"app_test","version":"1.2.3","built_at":"2026-11-07T00:00:00Z","key_id":"key-1","config":"authgo2.…","manifest":"B64U(原始清单JSON)","envelope":{"e":"B64U32","n":"B64U12","c":"B64U48"}}
```

| 字段/结构 | 约束 |
| --- | --- |
| app_key、key_id | 非空 app_key 最多 256 字节；key_id 为 1–128 字节 `[a-z0-9_-]+` |
| version、built_at | 严格 SemVer 2.0.0，最多 256 字节、无 v 前缀、核心/数字预发布无前导零；built_at 精确 UTC 秒 `YYYY-MM-DDTHH:mm:ssZ`；SOURCE_DATE_EPOCH 可覆盖，为无前导零非负十进制、年不超过 9999 |
| config | 与 app_key 一致的 HTTPS authgo2 配置，非空 secret、合法两种 32 字节公钥；原配置绑定信封并固化，不供运行时替换 |
| manifest | 解码最多 8 MiB，恰 `{"files":[…]}`，2–65535 条，含一个独立 watermark 索引；位置为文件号 i，从 0 开始 |
| files 条目 | 必填 name/kind/path/size/chunk_size/encoding；可选 python_version/main_class/architecture，仅对应类型使用，均被清单哈希绑定 |
| name、path | name 1–128 字节 `[a-z0-9_-]+`、唯一、非路径；path 恰为 i 的 8 位零补十进制+.agc |
| size、chunk_size | JSON 整数 size=0..4611686018427387903，不允许负/浮点/指数；chunk_size=1048576；tar size 含 header/padding/两结束块 |
| kind/encoding | protect/node/java=raw；python/php/dotnet=tar；watermark=raw；清单是布局不是密文散列，每块 GCM 保完整性 |
| python_version | CPython major.minor；pyc 魔数前两字节 LE：3413→3.8、3425→3.9、3439→3.10、3495→3.11、3531→3.12、3571→3.13、3627→3.14，后两字节 0d0a，16 字节 header、合法 flags、目录版本一致 |
| main_class、architecture | JAR Main-Class，支持清单续行，无则省略；protect 架构从 ELF64 little-endian 头取 amd64/arm64，不猜主机 |
| USTAR | 常规文件、mode0600、uid/gid/mtime=0；禁绝对路径、空/点/..组件、反斜杠、冒号、NUL、软硬链接、设备、PAX/GNU 扩展 |
| 归档顺序 | Python/PHP 仅 .pyc/.php，UTF-8 路径字节排序、无目录项；.NET 先程序集后同名 .deps.json（如有），basename；输入逐级 O_NOFOLLOW，JAR 原字节保留但验证 ZIP 路径/唯一性/非链接；加载器重做校验，不盲解包 |

### 8.2 内容密钥信封
每次打包独立 CSPRNG K32、X25519 esk、N12；一次所有文件共用 K，软件打包公钥为原始 32 字节 B64U，不是网关公钥/PEM。

```text
E = X25519_public(esk)
A = UTF8("authgo-payload-envelope-v2\x00") || LP(app_key) || LP(version) || LP(built_at) || LP(key_id) || LP(config) || H(B64U_DECODE(manifest)) || E
S = X25519(esk, software_pack_public); salt = H(A)  // 拒绝低阶点/全零 S
KEK = HKDF-SHA256(S, salt, UTF8("authgo/payload/v1/wrap"), 32)
C = AES-256-GCM.Seal(KEK, N, K, A); envelope = {e:B64U(E), n:B64U(N), c:B64U(C)}
B = H(A || N || C)
```

HKDF Extract+Expand，C=32+16 字节、B=32 字节；解封先验 GCM。元数据、原清单字节、config、公钥编码均绑定，等价 X25519 高位编码篡改也拒绝。不得记录 K/私钥/授权码/token/config。

### 8.3 密文分片与随机读
.agc 无头/前缀/尾部，只有连续 ciphertext||tag。令 L=size、Q=1048576：

```text
count = max(1, ceil(L/Q)); plain_len(j) = min(Q, L-j*Q); last(j) = (j==count-1)
nonce(i,j) = U32(i) || U64(j)
D(i,j) = UTF8("authgo-payload-chunk-v1\x00") || B || U32(i) || U64(j) || BYTE(last(j)?1:0)
block(i,j) = AES-256-GCM.Seal(K, nonce(i,j), plaintext_chunk, D(i,j))
file_bytes = block(i,0) || … || block(i,count-1); file_length = L+16*count
offset(j) = j*(Q+16); read_length(j) = plain_len(j)+16
```

空文件仍有末块 tag16；先验整个文件精确长度，再 ReadAt 并认证块。K 不跨打包复用，文件/块号确保 nonce 唯一；KEK 与 K 分域。替换/重排/截断整块/删末块/追加失败，随机读不证明未读块；完整加载验所需全部块。仅用已解封或已认证响应给出的 K，不能信任 `--verify`。

### 8.4 落盘与发布
父目录内私有暂存 → 写密文/payload、逐文件 fsync、目录 fsync → 输入在各自目录 rename 到 `.authgo-input-*` 回滚槽 → 同文件系统 rename 发布并 fsync 父目录 → 删除回滚槽、fsync 输入父目录。普通 I/O 失败回滚并清未完成输出，拒绝路径符号链接/覆盖，不删数据文件/输入目录。输入与父目录不能并发修改；跨目录/文件系统、掉电/SIGKILL 不保证崩溃级原子，保留回滚槽恢复。

`--verify --out <目录>` 仅查 schema/路径/长度，不解封、不验 GCM、不判断授权；`--protect` 用匹配架构真实桩就地替换 ELF，缺桩失败保留原文件，不能产生占位程序。

### 8.5 公共载荷测试向量
[payload-envelope.json](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/payload-envelope.json) 的密钥均为公开合成值，含 payload/原清单/收发密钥/A/shared/salt/KEK/B/每块 nonce/AAD/密文。文件 0 为空末块；文件 1 为 1048576 个 0x41+UTF-8 hello，两块，首块散列/前 32 字节/tag 及第二块完整密文；plain_repeat_count 是字节数，hex 无 0x，\x00 是 NUL。七语言逐字节对照 envelope_aad_hex/kek_hex/binding_hex 等重算，不以编译代替验证。

### 8.6 在线解锁 payload.unlock
现有 gateway 上限仍 64 KiB（外层/解密 body），不扩大。共同授权正文另带完整原始 payload 对象（含 config，不重建 manifest，payload≤64 KiB、config≤32768，超限 PAYLOAD_INVALID；整体网关超限走非法请求）和本次独立 X25519 `ephemeral_public_key`（B64U32）。config 仅重建 AAD/校验格式，不选连接目标或记录日志。

严格顺序：软件/授权 → token 属于实例及有效席位/租约 → 信封校验解封 → 认证版本未禁用 → 认证 built_at≤maintenance_until（相等放行，空不限）。前两步失败不查打包私钥/解封，不新建/接管席位；启用 FLOATING 即使任一绑定满足也须有效租约；不信顶层 client_version/version。格式/软件/key_id/GCM 错统为 PAYLOAD_INVALID；禁用 VERSION_DISABLED，维护超期 MAINTENANCE_EXPIRED 含 latest_entitled_version。

```text
P = B64U_DECODE(ephemeral_public_key); Q = B64U_DECODE(challenge)  // 各32字节
A = UTF8("authgo-payload-rewrap-v2\x00") || LP(app_key) || LP(version) || LP(built_at) || LP(key_id) || H(B64U_DECODE(manifest)) || P || Q
esk = 新独立X25519私钥; E = X25519_public(esk); S = X25519(esk,P)  // 拒绝低阶/全零
KEK = HKDF-SHA256(S, H(A), UTF8("authgo/payload/v1/rewrap"), 32); N = CSPRNG(12)
C = AES-256-GCM.Seal(KEK,N,K,A); data.e/n/c = B64U(E)/B64U(N)/B64U(C)
```

AAD 不含 config，LP 字符串外均原始固定 32 字节，C=48 字节，不返回明文 K；响应另含校验字段/is_trial/已认证 watermark。试用检查相同但不缓存材料。每授权独立每分钟 6 次、突发 3，IP 普通限流保留，超限 RATE_LIMITED。日志仅授权引用、认证版本、动作/结果，无信封/密钥/临时公钥。[向量](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/payload-unlock-v2.json)。

### 8.7 内容密钥缓存 v2
先 Check/Guard 并验证票据绑定、时间，再在线验完整响应、重封装 GCM、challenge；缓存不是授权证据。指纹用稳定实例而非 session，派生用签名 unlock_hash（hex 解码 32），不依赖 SDK 私有 seed，不新造种子：

```text
L = UTF8("authgo-payload-cache-v2\x00") || LP(app_key) || LP(fingerprint) || LP(key_id) || LP(version) || H(B64U_DECODE(manifest)) || B
Kcache = ResourceKey(HEX_DECODE(verified_ticket.unlock_hash), L) = HKDF-SHA256(HEX_DECODE(verified_ticket.unlock_hash), empty, UTF8("authgo-unlock-v2\x00") || L, 32)
A = UTF8("authgo-payload-cache-file-v2\x00") || H(L) || U64(license_id); N = CSPRNG(12)
C = AES-256-GCM.Seal(Kcache,N,K32 || WM32,A)
file_bytes = UTF8("AUTHGO-PAYLOAD-CACHE-v2.") || UTF8(B64U(N || C))
I = UTF8(endpoint + "\x00" + app_key + "\x00" + fingerprint + "\x00" + hex_lower(H(Ed25519_public_key_raw)))
filename = "authgo-payload-v2-" + hex_lower(H(I)) + "-" + hex_lower(H(L)) + ".cache"
```

endpoint 规范化小写 host、去结尾斜杠、必要时补 `/api/v1/client`。沿用身份目录，文件 0600、非符号链接、同目录私有临时文件/fsync/rename。AAD 绑定已验 license_id，改名/复制到其他实例无效；材料仅内存，用完清零。

仅在原签名 grace_until 内且已开始/未到期/未回拨/未拒绝时可读；试用或 grace_until≤issued_at 不缓存。明确拒绝（包括 INSTANCE_REPLACED）清当前服务/软件/实例全部载荷缓存，PAYLOAD_INVALID 不清。网络失败须同时有合法票据及对应材料，空卷/篡改/过窗失败；目录不可写只放弃缓存、不否定在线成功，清理失败不允许已拒绝进程继续用。持有身份、票据或 root 者可导出密钥，不依赖配置保密。[缓存向量](https://github.com/dingding229/Auth-Go/blob/main/sdk/vectors/payload-cache-v2.json)。

### 8.8 启动桩共享授权证据 v1
Go/Rust 仅 AUTHGO_PROTECTED=1 时每次在线成功替换证据，启动桩初次成功同写；网络失败/PAYLOAD_INVALID 不改，试用/零宽限及明确拒绝（含接管）清证据和材料；释放席位不删合法证据。不互读 SDK 私有授权缓存。

```text
T = 最近在线成功的原始签名票据UTF8; I = 8.7缓存上下文
Km = HKDF-SHA256(UTF8(fingerprint), empty, UTF8("authgo/payload-proof/key/v1\x00") || I, 32)
M = HMAC-SHA256(Km, UTF8("authgo-payload-proof-v1\x00") || T)
proof = UTF8("AUTHGO-PAYLOAD-PROOF-v1.") || UTF8(B64U(T)) || "." || UTF8(B64U(M))
proof_filename = "authgo-payload-proof-v1-" + hex_lower(H(I)) + ".cache"
```

0600 普通文件，拒绝符号链接、>12 MiB；私有临时文件/fsync/rename，写失败不否定在线成功。MAC 绑定指纹非 session，不是新信任根。每次先在线 Check/解锁，明确拒绝不回退；离线验证 MAC、原票据 Ed25519、v2/app/active/license_id/device_hash/challenge 长度/策略/时间，issued_at 不晚于本地 5 分钟，已开始未到期、非试用、grace_until>issued_at 且 now<grace_until；失败退出 77。浮动 lease 按第 7 节，再用 unlock_hash/绑定 license_id 解缓存并逐块认证。unlock_hash 同软件稳定，最新票据可延续原合法重启；回滚上限仍为被重放签名 grace_until，不抗 root 回滚。

### 8.9 Go 与 Rust ELF 尾部 v1
配置仅从自身 `/proc/self/exe` 完整 payload 读取，不读 AUTHGO_CONFIG/外部配置。布局 `[静态架构匹配桩 S][payload.json P][按文件号拼接全部.agc C][footer64]`，无尾随字节：

| footer 偏移/长度 | 无符号大端字段 |
| --- | --- |
| 0/16 | AUTHGO-STUB-v1 后两 NUL，hex `41555448474f2d535455422d76310000` |
| 16/4、20/4 | version=1、flags=0 |
| 24/8、32/8、40/8 | S≥64、P=1..65536、C |
| 48/16 | 全零保留 |

溢出安全检查 S+P+C+64=文件大小；恰一个 protect 条目、架构匹配、密文长度和=C。边界 SectionReader 逐块 GCM，完整主程序认证后才 exec；改 config 改信封与块绑定，假服务器无原私钥无法取得 K。先准备全部临时受保护文件，发布 --out 后同文件系统 rename 原 ELF，普通失败按 8.4 回滚；生产 go:embed 双架构真实桩，测试注入桩不得进入生产。

### 8.10 Linux 内存执行与接管
一次 Check（空码按 Guard 试用）+UnlockPayload → 流式写 memfd → F_SEAL_SEAL/F_SEAL_SHRINK/F_SEAL_GROW/F_SEAL_WRITE → 只读 FD → 清 K → `syscall.Exec("/proc/self/fd/<n>",原argv,原env加AUTHGO_PROTECTED=1)`。不创建子进程/信号处理/校验循环，不在 exec 前释放；argv[0]/参数/其他环境保留。失败固定中文阶段及错误码、退出 77，不打印远端可控文案/秘密。

memfd 标志 0x13（MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_EXEC），旧内核 EINVAL 重试 0x03；策略拒绝时仅回退 fstatfs 确认 TMPFS_MAGIC 且非 noexec 的 /dev/shm 或 /tmp，目录 FD 建私有文件、写完开只读 FD/关写 FD、执行前 unlink、/proc/self/fd 执行。不写持久盘，不放宽 seccomp/内核，均不可用失败。

桩/程序共享实例身份但 session 不同，业务 StartGuard 新 session 接管同一席位，负责心跳和 SIGTERM 释放。PID 不变，exe=memfd:authgo-main (deleted) 或 unlink tmpfs，cmdline 保留；自定位/重执行需适配，动态解释器/库由镜像提供。Linux 受保护 Go/Rust Guard 调用 prctl(PR_SET_DUMPABLE,0)，失败仅记录，桩解密前也尽力禁转储，不防 root 读内存/proc。

### 8.11 构建展示元数据
已有版本在 payload.unlock 成功时自动登记 encrypted=true、build_verified=true 和认证的 built_at，多架构保留最早时间；无记录时不创建。未确认时可手动登记（加密必填、关闭清空），确认后更新接口忽略这两项修改；自动同步保留，列表批量读。它们仅展示，维护期仅看认证信封版本/built_at，不可通过列表时间改变解锁。打包工具说明见[Docker 接入](?tab=docker#4-代码加密可选)。

## 9. 水印
### 9.1 派生与接口
HKDF 均 RFC5869 Extract+Expand，空盐按 32 零字节；IKM 为数据库原 32 字节 X25519 公/私钥，不用文本编码，私钥不另 clamp。info 不带 NUL：

```text
tag = lowercase_hex(HKDF(public_key,empty,UTF8("authgo/watermark/tag/v1"),16))
watermark_key = HKDF(private_key,empty,UTF8("authgo/watermark/key/v1"),32)
watermark = lowercase_hex(HMAC-SHA256(watermark_key,U64_BE(license_id)))
slot = ASCII(tag || watermark)  // 32+64=96字节，构建时后64字节为ASCII 0
```

license_id 非零 U64，固定 8 字节大端，不用文本/浮点/码；tag 公开、零水印不可追查。保留历史 key_id 加密私钥，追查遍历软件全部密钥，不跨软件。

| 管理接口 | 内容与隐私 |
| --- | --- |
| GET `/api/v1/admin/applications/{id}/watermark-tags` | items:[{key_id,tag}]，无私钥 |
| POST `/api/v1/admin/applications/{id}/watermark-trace` | 仅 {"watermark":"64 位非零小写 hex"}，拒绝未知字段/文件/文件名/片段；found:true、license_id、可用 user_id/user_name、is_trial、key_id、创建时间、试用来源[{ip,instance_id,created_at}]；未找到/已删/别软件均 found:false，不返回码/密钥/提交值 |
| 权限/查询 | 管理员 Bearer/软件边界；批量读密钥/授权/客户，找到后批量读试用来源；审计仅动作/资源/结果，无请求体/水印/文件 |

### 9.2 扫描规则
`authgo-pack trace --tag <tag> [--tag <old_tag>] <file>` 只读输出 JSON；浏览器 Worker/File.stream 本地扫描。64 KiB 块保留至少 95 字节，tag 去重、位置只计一次，匹配 32 字节 tag+64 小写 hex。零值计 slots/zeros，非零按频率降序，count 为最高候选次数，无非零为 0；结果另有 complete/candidates/warnings。

| 状态 | 规则 / 退出码 |
| --- | --- |
| found / ambiguous / zero / none | 唯一最高频非零 / 最高频平票 / 仅零槽 / 无槽；完整时 0 |
| partial | ZIP 加密/ZIP64/不支持方法/坏 CRC/截断/超限，保留此前完整条目，标“未扫描完”，2 |
| cancelled | complete:false，CLI 中断相同，2 |
| 非法参数/无法读取 | 1 |

ZIP/JAR 仅扫描解压条目，不扫容器本身，嵌套递归；CRC/声明长度通过才计条目。总解压 512 MiB、单条 128 MiB、深度 4（根 0、深度 5 拒绝）、总条目 4096、不同非零候选 4096。其他格式按字节流并提示未解压；仅完整唯一 found 自动提交{watermark}，其他状态不自动查。

### 9.3 独立加密槽位索引
仅 payload.v=2；公开 manifest 已认证但未加密，不增加槽位位置字段。恰一个保留条目 name=__authgo_watermark、kind=watermark、encoding=raw、连续编号 path、chunk_size=1048576、size=1..8 MiB，只允许这 6 字段；至少一个业务条目，保留名不可作业务。索引作为普通文件用 K 和分片 GCM 独立加密，由 B/文件号/块号绑定，非信封内联。

```json
{"v":"1","tag":"32位小写hex","files":[{"index":"0","entries":[{"path":[],"offsets":["1234","1450"]}]}]}
```

示例仅示编码；每业务文件至少 8 槽。v 固定字符串"1"，index/offsets 规范十进制字符串，无前导零（0 除外）/符号/小数/指数；index=0..65534，恰覆盖全部业务文件不指索引；offsets=0..MaxInt64/2，严格递增、间隔≥96。文件/条目/偏移总数各≤65535，path≤8 级，条目/路径唯一，禁控制字符/NUL/反斜杠/冒号/绝对/路径别名；raw protect/Node path=[]，Python/PHP/.NET 为单条目名，Java 为嵌套 JAR 链+class。空数组非 null；重复/未知/别名/类型/溢出/重叠/缺失/越界均拒绝。

加载器完整认证校验索引及将执行代码，所有槽位匹配 tag+64 个 ASCII0 后才改成授权水印，须在执行/defineClass/LoadFromStream 前完成；只在进程内存、匿名 memfd 或验证的 tmpfs，不写明文核心到卷/持久层。GCM 不替代结构校验。

| 语言实现 | 保留行为 |
| --- | --- |
| Python | 模块/函数/嵌套/闭包每实际 code 的 co_consts 末尾 8 个不同字符串，共享表仍 8 槽、不合并；解析/重发 marshal 全局引用，保留 co_code、旧常量索引前缀/值/普通字段元组引用；扩容常量表与普通 tuple alias 分域，不扩 names/varnames/freevars；原空表先 None 文档哨兵再 8 槽（共增 9），非空增 8，普通共享空 tuple 仍空；pyc3.8–3.14 与 SDK 最低 3.9 不同；虚拟文件名 authgo-sealed://、图 memo 保留共享引用，非法/未完成引用、不可安全拆分递归表/不可重建 code 循环/未知格式/超限失败，不退无印代码 |
| Node | Directive Prologue 后插入不访问标识符/宿主 constructor 的 void[字符串…]，不改 exports/全局对象；V8 可优化，SDK 仅_compile 成功后私有保留实际执行同份源码，Guard 清理释放，不用未执行资源副本 |
| PHP | 词法识别真实 function[&][name](声明，排除变量/成员调用/namespace 名；字面量置立即调用私有闭包，不给业务 get_defined_vars 增加 static 或匿名类属性；根常量可反射，已执行 Reflection opened_path 可定位 Guard 安装的同份内存源，VM 静态值仅辅助非完整代码导出 |

### 9.4 水印响应与材料缓存
payload.unlock 在授权/席位/认证 built_at 检查后用信封 key_id+授权 ID 派生 watermark，随完整签名 data/加密/nonce/票据上下文返回，非认证错误/拒绝不发；e/n/c 仍仅 K32，不将水印放公开 payload。

新鲜已签名响应须有非零 64 位小写 hex 水印，缺失/格式错立即失败，不借旧缓存/证明回退；底层公开 UnlockPayload 仍可只返回 K32（直接解密可得全零副本），受保护加载器须同响应私有 K32 || WM32，恰 64 字节，WM32=hex 解码非零水印。8.7 缓存 C 为 64+16 字节，绑定 LP/原 manifest 哈希/B/指纹/签名授权 ID；试用/零宽限不缓存，明确拒绝清理，不扩签名窗口或维护期。信封/重封装仍 v2 域，wrap/rewrap info 及分片 v1 域/ELF 尾 v1 不变，尾部版本不是 payload 版本。

## 10. 测试向量
[sdk/vectors](https://github.com/dingding229/Auth-Go/tree/main/sdk/vectors)：v2.json、hkdf.json、canonical.json、fingerprint.json、license-key.json、container-identity.json、instance-session.json、error-classification.json、payload-envelope.json、payload-unlock-v2.json、payload-cache-v2.json、watermark.json。逐步重算 HMAC→填充→ECDH/HKDF→请求 GCM→响应 GCM→Ed25519/nonce/ts→票据/challenge/身份/时间；任一步失败不得成功。各语言通过同一[真实服务场景](https://github.com/dingding229/Auth-Go/tree/main/sdk/conformance)，不跳过缺工具链语言。

## 11. 安全边界
### 11.1 实现要求
- 七语言原生实现，不调用其他语言运行时；公开 API/线格式/指纹与向量一致，HTTP/时钟注入仅开发者代码提供。严格 UTF-8/Base64URL/JSON，配置错误不含输入，TLS 证书验证不能关闭。
- 物理指纹为规范化 machine ID/主网卡 MAC/CPU 后 `SHA256(UTF8("authgo/fingerprint/v1\0machine\0mac\0cpu"))`。Linux 按 `/proc/cpuinfo` 行序取首个非空 model name/Hardware/cpu model；均无则同组首个 CPU implementer/CPU part，各去全部空白并小写成 arm:<implementer>:<part>，不跨空行；再无用首个非空 uarch，不可用须显式覆盖。
- SDK 授权码在网络/缓存前验证：`-`分 5 段，首段 1–16 字符，其余各 5；仅 23456789ABCDEFGHJKLMNPQRSTUVWXYZ，不转大写/裁空白。check=首段长度 mod32，遍历首段/第 2–4 段/第 5 段前 4 字符，每字 `check=(check*17+字母表下标)mod32`；末字等于字母表 check 项，失败 INVALID_LICENSE_KEY、不发请求/改缓存。格式正确不存在则服务端签名 LICENSE_NOT_FOUND。

### 11.2 边界
固定签名根、挑战和票据抵御假服务器/重放，多处校验提高补丁成本，但客户能改 SDK/时钟/存储、导出内存明文和密钥。缓存加密不防身份持有者或 root；代码/常量反射可见水印，不承诺不可检测/抹除，不保证擦除不可变字符串或 V8/Zend/CPython 副本，不撤回已编译代码。已交付内容不可实时收回；吊销在宽限期间可能滞后，高风险业务应缩短宽限，不能延长原签名边界。
