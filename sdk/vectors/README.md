# SDK 跨语言固定向量

所有密钥、nonce 和时间均为公开合成测试值，不可用于生产。测试只读取预期值，不按运行结果自动覆盖。

- `v2.json`：当前加密信道、HMAC、Ed25519 票据及域隔离、内部 seed/HKDF/AEAD 原语。
- `canonical.json`、`hkdf.json`：精确 JSON 规范化与 RFC5869 派生。
- `error-classification.json`：认证未完成不清证据；临时允许名单外的已认证非 OK 码（含未知码）默认拒绝。更新检查失败不改变授权缓存；INSTANCE_REPLACED 停止被替换进程但保留共享证据。
- `update-response.json`：当前 Docker Hub 更新、维护期与续费提示的签名响应。
- `fingerprint.json`、`container-identity.json`、`instance-session.json`：稳定物理指纹、容器身份及进程接管/席位/宽限。指纹预期值不可改变。
- `license-key.json`：授权码字符、大小写、分组和校验位。
- `payload-envelope.json`：当前 payload v2 信封绑定、AES-GCM 分块、nonce 与认证数据。
- `payload-unlock-v2.json`、`payload-cache-v2.json`：当前在线重封装、K32||WM32 缓存及 Go/Rust 独立启动桩证明。
- `watermark.json`：水印派生与边界。

票据按原始 UTF-8 字节验签，业务响应按规范化 JSON 验签。纯密码学固定时间向量不用当前时间；运行时窗口、回拨和拒绝由功能测试覆盖。协议唯一来源为 [完整协议](../../server/internal/apidocs/protocol.md)，直接维护该嵌入文档。
