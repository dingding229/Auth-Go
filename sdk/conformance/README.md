# SDK 向量与互操作测试

可用 `make test-sdks` 或本目录的运行脚本执行测试。协调器仅需 Docker daemon、POSIX shell/tar，源码流式传入，七语言使用独立官方容器逐个执行，不发布包或访问真实 Docker Hub。

真实 SQLite、生产 client.Service、验证引擎和 Docker Hub 更新由 opt-in fixture host 提供，仅在 `AUTHGO_SDK_CONFORMANCE=1` 时启用。当前签名/nonce/时间错误、临时错误、未知已认证拒绝、接管、席位、维护期、版本禁用、试用、宽限、回拨和缓存安全均有功能场景。

`instance-session.json` 定义实例必需场景。稳定物理指纹、容器身份及密码学向量由七语言读取。`test_disk_guard.py` 保证相关文件系统低于 10 GiB 时停止，不调用 Docker。

资源 scope 从 checkout 父目录派生；合法小写 ASCII 字母/数字/下划线/连字符用于 `authgo-${scope}-sdk-*`，非法名回落 `sdk`。缓存卷同 scope；流式协调器复用已有会话 scope。不新增环境设置。

协调器及语言容器限制 1536 MiB、2 CPU，fixture host 为 512 MiB、1 CPU。只清理本次运行创建的命名资源，不运行 prune。默认全部七语言；现有 `AUTHGO_SDK_LANGUAGES` 可选择调试子集。保留逐语言日志及 `results.json`，控制台仅打印摘要。

只读缓存不能持久化水位时返回 `SDK_CACHE_UNAVAILABLE`；新实例不可写目录可在线内存运行并警告，但新 Client 不得恢复无磁盘证据的宽限。
