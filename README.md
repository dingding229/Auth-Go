# Auth Go

Auth Go 是面向软件发布者的授权服务器：你可以为发布在 Docker Hub 的程序发放授权码、限制同时运行的实例，并在管理后台维护用户、授权和运行记录。普通程序也可以直接使用同一套 SDK 接入。

## 主要功能

- 授权码、FLOATING 实例席位和有效期管理，支持续期、暂停、恢复、吊销和批量发码。
- 批量授权 CSV 导入导出，支持库存授权和按用户分配。
- Go、Python、Node.js、Java、C#、PHP、Rust 七种语言 SDK。
- 授权服务器暂时不可达时，已验证的正式授权可凭签名票据在宽限期内继续运行。
- Docker 程序接入向导，生成接入代码、Dockerfile 和 GitHub Actions 配置。
- Docker Hub 公开版本同步、版本禁用和用户更新提示。
- 用户中心 `/portal`，支持邮箱登录、授权码登录、授权查看、实例释放和密码管理。
- 管理员 TOTP 两步验证、审计日志、验证日志和会话撤销。
- 本地 IP 库查询与疑似共享提示，不改变客户端授权结果（见[IP 库与疑似共享](#ip-库与疑似共享)）。
- 可在“系统设置 → 后台地址”修改管理页面和管理 API 的路径。
- 数据库与 `master.key` 完整备份和离线恢复。

## 目录

- [安装](#安装docker-compose) · [使用教程](#使用教程)
- [日常运维](#日常运维) · [离线恢复到命名卷](#离线恢复到命名卷)
- [HTTPS 反向代理与受信代理](#https-反向代理与受信代理)
- [高级配置](#高级配置) · [IP 库与疑似共享](#ip-库与疑似共享)
- [安全说明](#安全说明) · [协议概要](#协议概要) · [错误码](#错误码)
- [开发](#开发) · [七种语言 SDK](#七种语言-sdk)

## 安装（Docker Compose）

这是唯一的生产安装方式。需要 Docker Engine、Compose v2 和 curl，不需要下载项目源码，也不需要创建 `.env`。

```sh
mkdir authgo && cd authgo
curl -fsSLO https://raw.githubusercontent.com/dingding229/Auth-Go/main/docker-compose.yml
docker compose up -d
```

首次启动后查看初始化链接：

```sh
docker compose logs authgo
```

在日志中找到 `setup_token`，把它填入 `http://服务器地址:8080/admin/setup?token=...`，在浏览器完成管理员初始化。初始化完成后，其余部署配置都在管理端“系统设置”中完成：在“基础与安全”配置“对外服务地址”和“受信代理”，在“邮件服务”配置 SMTP，在“基础与安全”中的“后台地址”修改管理路径。初始化链接只能使用一次；不要公开包含令牌的日志。

Compose 默认发布为 `8080:8080`，装好后可直接访问 `http://服务器地址:8080`。要改端口，直接编辑 Compose 中这一行，例如改成 `9090:8080`。生产环境建议放在 HTTPS 反向代理后面，并在管理端“系统设置 → 受信代理”填写代理实际 IP/CIDR；如只想本机访问，把端口行改成 `127.0.0.1:8080:8080`。修改 Compose 后执行 `docker compose up -d` 应用。代理配置示例见[HTTPS 反向代理与受信代理](#https-反向代理与受信代理)。

## 使用教程

### 1. 初始化管理员

查看一次性初始化令牌：

```sh
docker compose logs authgo
```

未设置初始密码时，从日志找到 `setup_token`，将它替换进 `http://localhost:8080/admin/setup?token=...`；自定义域名或端口时改用实际服务地址。填写“管理员用户名”“管理员密码”和“再次输入密码”，点击“完成初始化并登录”。链接只能使用一次，重启会更换令牌。

### 2. 添加软件并复制接入配置

进入“软件 → 新建软件”，填写“名称”并保存。在“接入程序”中确认“程序可以访问的服务地址”，点击“显示接入配置”，再点击“一键复制配置”。配置可以公开，但必须编译进客户程序，不能从环境变量或文件读取。

### 3. 添加用户

进入“用户 → 新建用户”，填写“姓名”。需要用户中心登录时填写邮箱，并在“更多选项”设置“用户中心密码”。邮箱验证码需另在“系统设置 → 邮件服务”启用；用户由管理员创建，不开放自助注册。

### 4. 发放授权

进入“授权 → 创建授权”，或从用户详情点击“发放授权”。在“发给谁”中选择用户，再选择所属软件，设置有效期和“同时运行实例数”。“生成数量”大于 1 时会批量发码，结果中可“复制全部授权码”或“下载批次CSV”。

### 5. 在程序中接入

下面是最短的 Go 示例；完整协议与七语言 SDK 说明见[SDK 文档](#七种语言-sdk)。

```go
package main

import (
    "context"
    "log"
    "os"
    sdk "authgo/sdk"
)

const authConfig = "authgo2.请在构建时替换为后台接入配置"

func main() {
    client, err := sdk.New(authConfig)
    if err != nil { log.Fatal(err) }
    result, err := client.Check(context.Background(), os.Getenv("AUTHGO_LICENSE"))
    if err != nil { log.Fatal(err) }
    defer client.ReleaseSeat(context.Background())
    log.Printf("授权状态：%s", result.Status)
}
```

接入配置由开发者编译固定；客户只需设置 `AUTHGO_LICENSE`。首次激活必须联网，长期运行的服务应使用 SDK 的高层守卫持续校验、心跳并在退出时释放席位。

### 6. Docker 程序接入

在软件详情的“接入程序”中按向导操作：

- 选择 Go、Python、Node.js、Java、C#、PHP 或 Rust；PHP 还需选择 CLI、PHP-FPM 或 Apache 运行方式。
- 将接入配置和程序版本编译固定，使用高层守卫检查授权、维持心跳并在退出时释放实例；不使用常驻网关或 sidecar。
- 填写 Docker Hub 公开镜像名，使用向导生成的 Dockerfile、发布配置和客户 Compose。版本同步只收录完整正式版本标签，维护期限制可使用的程序版本。
- 客户部署只设置 `AUTHGO_LICENSE`；保留缓存命名卷才能在票据允许的宽限内应对服务器不可达，扩容须预留足够实例席位。
- 需要代码保护时按向导启用加密与水印，不把明文核心复制进最终镜像层；试用不持久化可离线复用的内容密钥。

详细步骤、版本维护期、镜像层安全和 PHP-FPM/Apache 约束见[Docker 程序完整说明](server/internal/apidocs/docker.md)。

### 7. 用户中心

将 `/portal` 地址提供给用户。用户用管理员设置的邮箱和用户中心密码登录；启用邮件服务后也可使用邮箱验证码。用户可以查看名下授权、释放自己的实例、查看公告与更新，并在“账号安全”修改密码；授权码登录入口用于查看单个授权。

## 日常运维

### 升级

更新前先备份。在原安装目录执行：

```sh
docker compose pull && docker compose up -d
```

默认镜像使用 `latest`。需要固定版本时，把 Compose 文件中的 `docker.io/dingding229/authgo:latest` 改为 `docker.io/dingding229/authgo:1.0.0`，再执行上面的升级命令。v1.0.0 只支持当前初始数据库结构，不支持从其他版本升级。

### 备份与恢复

默认数据库和自动生成的 `master.key` 都在 `authgo_data` 数据卷（容器内 `/data`），必须一起备份。在“系统设置 → 数据库备份”创建并下载完整 ZIP；系统每天自动备份，默认保留最新 7 份。备份使用一致的 SQLite 快照，ZIP 只包含 `authgo.db` 和**当前实际使用的** `master.key`，不包含 IP 库或历史备份目录。备份内含主密钥，必须加密离线保存、限制访问，不能放到公开下载地址。

主密钥优先级为非空 `AUTHGO_MASTER_KEY` → `/data/master.key` → 空库首次自动生成。只有数据库尚不存在时才允许自动生成；已有库缺少密钥或密钥格式损坏会拒绝启动。不要每次启动都生成新密钥，原环境密钥部署必须保留原值。

#### 离线恢复到命名卷

恢复是**停机替换**，只接受 v1.0.0 的完整 ZIP，并使用匹配的 v1.0.0 镜像。先停止所有写入同一卷的服务或工具；不要直接覆盖运行中的 SQLite 数据库，不要把旧 WAL/SHM 混入备份快照。

在原 Compose 目录执行下列步骤。`authgo_data` 是 Compose 卷名，实际名称可能带项目名前缀，因此通过容器挂载信息取得真实卷名。工具容器仅做一次性离线文件操作，不是另一种安装方式。

<details>
<summary>展开：校验备份、保留回滚现场并恢复文件</summary>

将可信的完整备份保存为 `.restore/backup.zip`（也可先执行前三条准备命令再复制文件），再依次执行：

```sh
set -eu
umask 077
mkdir -p .restore
# 将安全保存的完整备份复制到 .restore/backup.zip，不使用来历不明的ZIP
CID=$(docker compose ps -aq authgo)
DATA_VOLUME=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$CID")
[ -n "$DATA_VOLUME" ] || { echo "不是命名数据卷，请先确认实际挂载"; exit 1; }
# 用于检查本次仍生效的ENV密钥；文件含敏感信息，不要cat
docker inspect "$CID" > .restore/original-container.json
docker compose stop authgo
# 必须确认容器已停止；其他程序也不得持有此数据库
[ "$(docker inspect --format '{{.State.Running}}' "$CID")" = false ] || exit 1
# 完整保留停机现场（含互相匹配的WAL/SHM）以便回滚；不是在线复制SQLite
docker run --rm --name authgo-restore-safety --memory=256m \
  -v "$DATA_VOLUME":/data:ro -v "$PWD/.restore":/work alpine:3.22 \
  sh -ec 'tar -czf /work/before-restore.tgz -C /data .; chmod 600 /work/before-restore.tgz'
# 校验ZIP成员、SQLite快照、密钥及原容器的有效ENV；不打印密钥
docker run --rm -i --name authgo-restore-validate --memory=256m \
  -v "$PWD/.restore":/work python:3.13-alpine python - <<'PYRESTORE'
import base64, json, os, sqlite3, zipfile
with zipfile.ZipFile('/work/backup.zip') as z:
    assert sorted(z.namelist()) == ['authgo.db', 'master.key']
    assert z.testzip() is None
    os.makedirs('/work/staged', mode=0o700, exist_ok=True)
    for name in ['authgo.db', 'master.key']:
        with z.open(name) as src, open('/work/staged/'+name, 'wb') as dst:
            import shutil
            shutil.copyfileobj(src, dst)
        os.chmod('/work/staged/'+name, 0o600)
key = base64.b64decode(open('/work/staged/master.key', 'rb').read().strip(), validate=True)
assert len(key) == 32
old = json.load(open('/work/original-container.json'))[0]
env = dict(x.split('=', 1) for x in old['Config']['Env'] if '=' in x)
if env.get('AUTHGO_MASTER_KEY'):
    assert base64.b64decode(env['AUTHGO_MASTER_KEY'], validate=True) == key, 'ENV与快照密钥不一致，停止恢复'
# 若之后改动容器环境配置，启动前必须重新确认实际密钥；ENV优先于文件
with sqlite3.connect('file:/work/staged/authgo.db?mode=ro', uri=True) as db:
    assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    assert db.execute('SELECT version,name FROM schema_migrations').fetchall() == [(1, 'authgo_1_0_0')], '本版本不支持从旧版本升级'
print('备份格式、数据库、主密钥和环境配置校验完成（不输出密钥）')
PYRESTORE
# 快照已是完整DB，绝不把原库或其他备份的WAL/SHM混入新快照
docker run --rm --name authgo-restore-files --memory=256m \
  -v "$DATA_VOLUME":/data -v "$PWD/.restore/staged":/restore:ro alpine:3.22 \
  sh -ec 'rm -f /data/authgo.db-wal /data/authgo.db-shm
    cp /restore/authgo.db /data/authgo.db
    cp /restore/master.key /data/master.key
    chown 65532:65532 /data /data/authgo.db /data/master.key
    chmod 700 /data; chmod 600 /data/authgo.db /data/master.key
    if [ -d /data/backups ]; then chown -R 65532:65532 /data/backups; chmod 700 /data/backups; find /data/backups -type f -exec chmod 600 {} \;; fi
    ls -ldn /data; ls -ln /data/authgo.db /data/master.key'
docker compose up -d authgo
docker compose ps
# 自定义端口时，相应替换下面的 8080
curl --fail --silent http://127.0.0.1:8080/healthz
```

</details>

恢复前的容器环境信息和停机现场都含敏感数据，`.restore` 仅限管理员访问。命令会校验 ZIP 成员、完整性、密钥长度、SQLite 完整性及初始结构；当前容器若配置了 `AUTHGO_MASTER_KEY`，必须与备份相同。**启动前若更改 Compose 的容器环境配置，须再次确认最终生效的密钥匹配**，环境值优先于密钥文件。

恢复后 `/data` 属主应为 `65532:65532`、权限 `0700`，数据库与主密钥为 `0600`；不要改成 `0777/0644` 或以 root 启动服务。确认容器健康、使用快照时的管理员账号登录，核对软件、用户、授权、版本及接入配置可读取，再用 SDK 校验原授权，并创建一次完整备份。IP 库需要单独恢复或重新启用/上传。

若密钥无法解密，立即停机检查配对关系，不得生成替代密钥掩盖问题。回滚时仍须停机，整体恢复停机现场的匹配文件集合及原镜像/环境，不能只恢复某个旧 WAL 文件。确认恢复成功后，清理 `.restore/staged` 和容器环境信息等明文副本，原备份及回滚包加密离线保存。

### 自定义后台地址

登录后进入“系统设置 → 后台地址”，保存后管理页面与管理 API 一起切换，管理员需要重新登录。忘记地址时，在 Compose 目录执行：

```sh
docker compose exec -T authgo /authgo admin-path
docker compose exec -T authgo /authgo admin-path reset
```

第一条显示当前地址，第二条恢复 `/admin` 并撤销管理员会话；运行中的服务立即生效，不需要重启。

### 查看日志

```sh
docker compose logs --tail=100 authgo
docker compose ps
```

## HTTPS 反向代理与受信代理

生产环境建议由宿主机上的 HTTPS 反向代理接收公网流量。默认 Compose 端口直接发布；如果改为 `127.0.0.1:8080:8080`，反代仍可通过回环地址转发。代理应覆盖客户端传入的转发头；Go 只在来源属于管理端“受信代理”范围时采信 `X-Forwarded-For`、`X-Real-IP`、`X-Forwarded-Proto` 和 `X-Forwarded-Host`。

最小 Nginx 示例：

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;
    ssl_certificate /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

Compose 不指定网段，由 Docker 自动分配默认网络；生产默认端口直接对外发布，因此 Compose 不设置任何受信代理，全新安装时服务端不会采信客户端带来的转发头。使用 HTTPS 反向代理时，在管理端“系统设置 → 受信代理”填写实际代理 IP/CIDR，并在“对外服务地址”填写 HTTPS 地址；这些设置保存后按当前服务机制立即生效。不要仅因来源是私有 IP 就信任它，也不要允许不可信容器接入受信网络。受信代理设置影响客户端 IP、限流、日志、Cookie Secure 和生成的公开地址。

备份和 IP 库上传可能超过代理的默认请求体或超时限制：仅对相应位置调整（普通请求仍保留原限制），备份创建需预留超过 6 分钟、下载超过 5 分钟，IP 库上传请求体最高 513 MiB。管理 API 文档在登录后的“接入文档 → 管理API”查看；自定义后台地址后位置匹配规则也要随之调整。

## 高级配置

一般不需要环境变量。若确有需要，可在现有 `authgo` 服务下添加 `environment:`，例如：

```yaml
services:
  authgo:
    environment:
      AUTHGO_LOG_LEVEL: info
      AUTHGO_SWAGGER_ENABLED: "false"
```

这里只展示要添加的部分，不要删除原文件的镜像、端口、数据卷和安全配置。修改后执行 `docker compose up -d` 重建容器以应用环境配置；管理端“系统设置”则在保存后生效，通常无需重启。主密钥、初始管理员密码、日志级别和公开 Swagger 等高级变量见下表。

### 环境变量

下表列出可由 Compose `environment:` 注入的服务端变量；SDK 和打包工具的参数见各自说明。空值通常使用默认值，格式非法的密钥、布尔值、地址或范围会拒绝启动。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AUTHGO_MASTER_KEY` | 可选 | Base64 编码的 32 字节主密钥；优先于 `/data/master.key`，已有环境必须保留原值。 |
| `AUTHGO_ADDR` | `:8080` | Go 监听地址；Dockerfile 的运行时默认值。 |
| `AUTHGO_DATA_DIR` | `/data`（Docker 镜像） | SQLite、备份和 IP 库目录；Dockerfile 为容器设置 `/data`。 |
| `AUTHGO_ADMIN_USER` | `admin` | 首次管理员用户名，非空且最多 128 字节。 |
| `AUTHGO_ADMIN_PASSWORD` | 空 | 仅无管理员时生效；最多 72 字节，为空时用日志令牌初始化。 |
| `AUTHGO_PUBLIC_URL` | 空 | 外部 HTTP/HTTPS 来源地址，不含路径。 |
| `AUTHGO_TRUSTED_PROXIES` | 空 | 高级部署选项；在 Compose `environment:` 中添加后才由环境注入，逗号分隔 IP/CIDR。生产优先在管理端“系统设置 → 受信代理”配置。 |
| `AUTHGO_LOG_LEVEL` | `info` | `debug`、`info`、`warn` 或 `error`。 |
| `AUTHGO_SWAGGER_ENABLED` | `false` | 是否启用公开 Swagger；管理 API 文档仍在登录管理端内查看。 |
| `AUTHGO_DB_BUSY_TIMEOUT_MS` | `5000` | SQLite 锁等待毫秒数，范围 1–60000。 |
| `AUTHGO_SHUTDOWN_TIMEOUT` | `10s` | 每阶段优雅退出时限，大于零且不超过 5 分钟。 |
| `AUTHGO_CLIENT_IP_RATE` | `10` | 每 IP 每秒请求补充数，范围 1–100000。 |
| `AUTHGO_CLIENT_IP_BURST` | `60` | IP 令牌桶容量，范围 1–100000。 |
| `AUTHGO_CLIENT_LICENSE_RATE` | `5` | 每授权码每秒请求补充数，范围 1–100000。 |
| `AUTHGO_CLIENT_LICENSE_BURST` | `30` | 授权码令牌桶容量，范围 1–100000。 |
| `AUTHGO_CLIENT_LOG_CAPACITY` | `4096` | 验证日志内存队列容量，范围 1–100000。 |

数据库中保存的“系统设置”优先于初始环境默认值；已保存的公开地址非空时优先于 `AUTHGO_PUBLIC_URL`，环境为空时仍以管理端保存的地址为准。若通过 Compose `environment:` 添加 `AUTHGO_TRUSTED_PROXIES`，它作为部署基线与管理端列表共同生效；默认 Compose 文件不添加它，因此直接安装默认不信任任何代理。SMTP、日志保留、版本同步、备份和站点信息均在“系统设置”中管理，不需要新增环境变量。验证日志尽力写入，队列过载丢弃日志不改变授权结果。

## IP 库与疑似共享

在“系统设置 → IP 库”可以查看状态、启用下载、立即更新、上传 City/ASN 的 MMDB，或停用并删除本地库。查询在本地完成，不向第三方发送待查询 IP；未启用时不会自动下载。验证日志、审计日志、实例和用户中心可以显示位置与 ASN，用户中心使用脱敏 IP。

默认数据源是 [DB-IP Lite City/ASN](https://db-ip.com)（CC BY 4.0），每月更新；月初未发布时保留原库或回退上月，最多每天重试一次。上传库兼容 DB-IP/MaxMind 字段，不被自动更新覆盖。官方库仅通过受限的官方 HTTPS 来源下载；压缩文件上限 128 MiB，解压和上传库上限 512 MiB，上传请求体上限 513 MiB。文件位于 `/data/ipdb/`，目录 `0700`、文件 `0600`，校验完成后原子替换；上传和删除记录审计。

服务按最近 24 小时成功的 activate、verify、heartbeat 来源汇总；同一授权按公网 IP 去重，超过 3 个国家或 5 个 ASN 时提示“疑似共享”。这只是管理提示，不封禁授权，也不改变客户端校验结果；VPN、云服务器跨区和代理可能造成误报。在授权列表筛选标记，在授权详情“概览 → 共享检测”查看分布并可忽略 30 天；去重来源数不等于同时在线实例数。指标回落会清除标记，忽略期结束后须由下一轮汇总重新判断；IP 库不可用时不展示旧标记。

## 安全说明

- 公网使用 HTTPS、强管理员密码和“个人安全”中的 TOTP 两步验证；不要公开初始化链接、包含令牌的日志、备份、主密钥或会话令牌。
- 接入配置可以公开，但必须由开发者编译固定；不要由客户环境变量、配置文件或未经认证的响应替换信任根，也不要把授权码或配置串写入日志。
- 客户控制运行主机，无法承诺绝对防破解；关键入口应持续执行授权守卫。代码加密和水印提高还原或追查成本，但不能阻止宿主机 root 调试和内存导出。
- 宽限只适用于已有可信票据；到期或收到已认证明确拒绝后不得继续受保护业务。常驻进程停止，PHP-FPM/Apache 按请求式 SDK 拒绝响应。
- 主密钥与数据库必须成对保存；v1.0.0 不支持从其他版本升级或恢复旧格式备份。

## 协议概要

客户端只向 `/api/v1/client/gateway` 发起 POST，请求正文、动作、HMAC、nonce、挑战和票据都在加密内层；配置串包含固定服务地址、应用标识、密钥和响应验签公钥，必须在构建时编译进程序。服务端响应先完成解密、绑定、时间、nonce 和 Ed25519 签名校验，再解释业务错误码。

网络故障、超时、TLS/协议错误、未签名或不可信响应不能制造新的在线结果；已有合法签名票据时，仅在 `grace_until` 之前宽限，宽限由软件的 `grace_hours` 控制（默认 72 小时）且不超过授权到期时间，零宽限授权不离线放行。已认证临时错误（如 `INTERNAL_ERROR`、`RATE_LIMITED`、`REPLAY_DETECTED`、`TIMESTAMP_INVALID`、`SIGNATURE_INVALID`、`INVALID_REQUEST`、`PAYLOAD_INVALID`）可按同一票据宽限。已认证明确拒绝和未知错误码立即停止并清理可用授权缓存；`INSTANCE_REPLACED` 立即停止旧进程，但不清理共享票据。详细字节格式和状态机见[客户端协议完整规范](server/internal/apidocs/protocol.md)。

## 错误码

客户端和前端必须按机器可读的 `code` 处理，不能按中文提示或 HTTP 状态猜测。下表中“清缓存”均仅指**完成解密、验签、nonce 与时间绑定校验的同一授权上下文中的明确拒绝**：清可用票据并写入拒绝状态，不是删除任意磁盘数据。未认证响应不触发清理；宽限必须有尚未过期的可信票据，首次激活失败不能用缓存伪装成功。管理端、门户和初始化错误不参与 SDK 宽限。

### 客户端在线 API

| code | 含义 | 客户端处理 |
| --- | --- | --- |
| `OK` | 验证成功 | 正常运行并更新票据。 |
| `INVALID_REQUEST` | 请求格式无效 | 已认证时可宽限，不清缓存。 |
| `PAYLOAD_INVALID` | 加密载荷无效 | 可宽限，不清缓存，联系提供方重新构建。 |
| `INVALID_LICENSE_KEY` | 授权码格式或校验位无效 | 明确失败，清缓存。 |
| `APP_NOT_FOUND` | 软件不存在 | 明确失败，清缓存。 |
| `APP_DISABLED` | 软件已停用 | 明确失败，清缓存。 |
| `LICENSE_NOT_FOUND` | 授权不存在 | 明确失败，清缓存。 |
| `LICENSE_NOT_ACTIVATED` | 授权尚未激活 | 明确失败，清缓存。 |
| `LICENSE_EXPIRED` | 授权已到期 | 明确失败，清缓存。 |
| `LICENSE_NOT_STARTED` | 授权尚未生效 | 明确失败，清缓存。 |
| `LICENSE_SUSPENDED` | 授权已暂停 | 明确失败，清缓存。 |
| `LICENSE_REVOKED` | 授权已吊销 | 终态失败，清缓存。 |
| `INVALID_POLICY` | 授权策略配置无效 | 明确失败，清缓存，不靠重试绕过。 |
| `INSTANCE_REPLACED` | 此进程已被新的进程接管 | 立即停止，不宽限、不清共享缓存。 |
| `VERSION_DISABLED` | 当前版本已禁用 | 明确失败，清缓存。 |
| `MAINTENANCE_EXPIRED` | 授权维护期已结束 | 明确失败，清缓存。 |
| `VERSION_NOT_ALLOWED` | 客户端版本不被允许 | 明确失败，清缓存。 |
| `DEVICE_INVALID` | 实例指纹无效 | 明确失败，清缓存。 |
| `FLOATING_LIMIT_REACHED` | 浮动席位已满 | 明确失败，清缓存。 |
| `LEASE_EXPIRED` | 浮动席位已过期 | 收到已认证拒绝则不宽限、清票据；恢复时以 heartbeat 重新竞争席位。 |
| `ACTIVATION_INVALID` | 激活凭据无效或已失效 | 已认证拒绝不宽限、清票据；需重新激活而非重复心跳。 |
| `ACTIVATION_LIMIT_REACHED` | 客户端会话数已达上限 | 明确失败，清缓存。 |
| `SIGNATURE_INVALID` | 请求签名无效 | 已认证临时错误可宽限；未认证响应不可信。 |
| `TIMESTAMP_INVALID` | 请求时间戳无效或超出范围 | 已认证临时错误可宽限；未认证响应不可信。 |
| `REPLAY_DETECTED` | nonce 已使用 | 已认证临时错误可宽限，不清缓存。 |
| `RATE_LIMITED` | 请求过于频繁或安全缓存已满 | 已认证临时错误可宽限，不清缓存。 |
| `VERSION_NOT_FOUND` | 没有已发布版本 | 报错；更新检查不修改授权缓存，授权动作中视为明确拒绝。 |
| `USER_DISABLED` | 授权所属用户已停用 | 明确失败，清缓存。 |
| `TRIAL_DISABLED` | 软件未开放试用 | 明确拒绝、不宽限；同一授权上下文执行拒绝清理。 |
| `TRIAL_IP_LIMIT` | 此网络已领取过试用 | 明确拒绝、不宽限；同一授权上下文执行拒绝清理。 |
| `TRIAL_QUOTA_EXCEEDED` | 今日试用名额已满 | 明确拒绝、不宽限；同一授权上下文执行拒绝清理。 |
| `INTERNAL_ERROR` | 服务器内部错误 | 已认证临时错误可宽限，不清缓存。 |

`update.check` 是只读更新动作：成功、故障和业务错误都不修改授权票据或拒绝状态，维护期错误可附带 `latest_entitled_version`；授权拒绝由后续授权校验处理。`release-seat` 的成功回执释放容量但保留授权票据，故障不清票据；`INSTANCE_REPLACED` 始终停止旧进程且不破坏共享缓存。

### 管理端、门户与初始化

| code | 含义 | 处理 |
| --- | --- | --- |
| `UNAUTHORIZED` | 管理端未认证、会话撤销或过期 | 重新登录。 |
| `INVALID_CREDENTIALS` | 用户名、密码、TOTP、授权码、邮箱、查询密码或验证码错误 | 修正凭据，不重试敏感信息。 |
| `LOGIN_LOCKED` | 登录失败触发锁定 | 等待锁定期结束并检查来源。 |
| `INVALID_REQUEST` | 字段、分页、过滤或 JSON 不合法 | 修正请求。 |
| `NOT_FOUND` | 管理端资源或路由不存在 | 检查路径和资源 ID。 |
| `CONFLICT` | 重名或数据冲突 | 检查现有记录后再操作。 |
| `RESOURCE_IN_USE` | 软件仍有关联数据 | 先处理关联数据。 |
| `INVALID_TRANSITION` | 非法授权状态流转 | 按当前状态选择操作。 |
| `UNSUPPORTED_MEDIA_TYPE` | CSV 媒体类型不支持 | 使用规定的 CSV 类型。 |
| `CSV_TOO_LARGE` | CSV 超过大小或数量限制 | 拆分后重试。 |
| `KEY_GENERATION_FAILED` | 授权码生成重试耗尽 | 检查服务状态后重试。 |
| `AUDIT_UNAVAILABLE` | 写操作审计无法持久化，业务未执行 | 先恢复数据库写入。 |
| `NOT_IMPLEMENTED` | 接口尚未实现 | 不重试，联系提供方。 |
| `INTERNAL_ERROR` | 非预期内部错误 | 查看日志，勿泄露 SQL 或密钥。 |
| `SMTP_NOT_CONFIGURED` | SMTP 尚未启用 | 配置邮件服务，或使用密码登录。 |
| `SMTP_SEND_FAILED` | 测试邮件发送失败 | 检查 SMTP 配置。 |
| `PORTAL_UNAUTHORIZED` | 用户中心令牌无效或过期 | 重新登录用户中心。 |
| `CODE_COOLDOWN` | 同一邮箱发送验证码未满 60 秒 | 等待冷却结束。 |
| `RATE_LIMITED` | 门户或初始化触发限流 | 等待后再试。 |
| `SETUP_TOKEN_INVALID` | 初始化令牌缺失或不匹配 | 仅使用当前日志中的链接。 |
| `SETUP_UNAVAILABLE` | 初始化入口不存在或已完成 | 不能重复初始化。 |
| `USER_DISABLED` | 用户已停用 | 联系管理员。 |
| `LICENSE_NOT_SELECTED` | 用户中心没有选中授权 | 先选择本人授权。 |
| `SHARING_UNAVAILABLE` | IP 库未启用，无法进行共享汇总 | 先在“系统设置 → IP 库”启用。 |
| `SHARING_NOT_FLAGGED` | 当前没有需要忽略的疑似共享提示 | 不需要重试忽略操作。 |

### SDK 本地错误

| code | 含义 | 处理 |
| --- | --- | --- |
| `SDK_CLOCK_ROLLBACK` | 本机时间比缓存水位早超过 5 分钟 | 不宽限；校准时间后重新在线认证。 |
| `SDK_GRACE_EXPIRED` | 原票据宽限已结束 | 停止受保护功能，等待在线恢复。 |
| `SDK_CACHE_INVALID` | 缓存损坏、绑定不匹配或认证失败 | 不宽限，重新在线认证。 |
| `SDK_CACHE_UNAVAILABLE` | 无法持久化安全水位 | 不宽限，修复缓存目录权限。 |
| `SDK_RESPONSE_INVALID` | 响应格式、TLS 或绑定无效 | 不清缓存；仅校验票据有效时可宽限，不能当作在线成功。 |
| `SDK_INVALID_CONFIG` | 编译固定的接入配置无效 | 不清可信缓存、不放行；重新复制并构建配置。 |
| `SDK_FINGERPRINT_UNAVAILABLE` | 无法生成实例指纹 | 不清可信缓存、不放行，检查实例标识环境。 |
| `SDK_NOT_ACTIVATED` | 尚无可用激活上下文 | 不放行，先联网激活。 |
| `SDK_NETWORK_ERROR` | 连接故障或超时 | 不清缓存；已有有效票据才可宽限。 |
| `SDK_RESPONSE_SIGNATURE_INVALID` | 响应签名无效 | 不清缓存；仅有效票据可宽限。 |
| `SDK_RESPONSE_NONCE_INVALID` | 响应 nonce 不匹配 | 不清缓存；仅有效票据可宽限。 |
| `SDK_RESPONSE_TIMESTAMP_INVALID` | 响应时间超出窗口 | 不清缓存；仅有效票据可宽限。 |
| `SDK_AUTO_CHECK_RUNNING` | 重复启动自动检查循环 | 不清缓存，不启动第二个循环；不是新的授权结果。 |

未知的已认证错误码默认按明确拒绝处理；未知或未签名响应不能作为授权成功。

## 开发

### 环境与本地命令

需要 Go 1.26、Node.js 22、Docker Engine 和 Compose v2。依赖由 `go.sum` 与 `package-lock.json` 锁定。开发时分别运行 `make dev-server` 和 `make dev-web`；`make build` 生成内嵌前端的单个服务二进制。从源码构建本地镜像只使用：

```sh
docker build -t authgo:local .
```

### 架构与维护

Go 内嵌 Vue 页面，一个非 root 容器和端口提供服务；SQLite、主密钥、备份及 IP 库写入 `/data`，根文件系统只读。管理端和用户中心使用隔离的身份令牌；用户、授权与浮动实例在服务端事务中维护，释放实例同步释放席位并写审计。调度器负责日志保留、邮件、备份、共享检测和公开 Docker Hub 版本同步。

各业务包持有服务和路由注册入口，`httpserver` 只组装。协议和 Docker 接入说明直接编辑 `server/internal/apidocs/protocol.md` 与 `docker.md`，不维护第二份副本；修改 API 注释后执行 `make docs` 更新 OpenAPI。不得放宽签名、未知错误默认拒绝、权限、限流、指纹、主密钥和 HTTPS 断言。

### 源码结构

- `server/internal`：SQLite schema、管理员、用户、授权与实例席位、加密网关、备份、IP 库、Docker Hub 和 HTTP 组装。
- `web/src`：管理端、用户中心、共享组件及统一请求封装。
- `sdk`：七种语言 SDK、共享向量和一致性驱动。
- `pack`：加密打包、水印和启动桩生成工具。
- `examples`：最小接入和 Docker 加密程序示例。
- `tests`：当前载荷、水印和安全夹具。

### 测试入口

运行测试：`make test`（Go、SDK、示例和前端）、`make test-sdks`（七语言一致性）、`make test-pack`（加密载荷与水印）、`sh scripts/smoke-docker.sh`（真实单容器流程）和 `sh scripts/test-docker-license.sh`（七语言容器授权生命周期）。 水印浏览器测试必须先运行 `python3 scripts/test-watermark-e2e.py`，再用其输出目录运行 `AUTHGO_WATERMARK_E2E_OUT=/path/to/watermark-e2e-<pid> node web/scripts/test-watermark-layout.mjs`。其他功能入口包括 `scripts/test-protected-*`、`scripts/test-watermark-e2e.py` 和 `scripts/test-php-sealed.py`；`scripts/check-examples.sh` 编译 Go 示例。正式 Dockerfile 只构建，不在镜像构建时运行测试。

前端路由契约使用真实服务端 Router 注册表，覆盖默认和自定义后台路径；`make test` 先生成 `server/.route-contract.json` 再执行前端测试。单独运行前端测试时，先执行 `(cd server && go test -count=1 ./internal/httpserver -run '^TestExportFrontendRouteContract$')` 导出当前源码的注册表，再执行 `(cd web && npm test)`；修改相关源码后须重新导出。源码构建的冒烟镜像来自临时 Compose override，不影响生产 Compose。冒烟测试要求 Compose v2.24.4 或更新版本，用 `!override` 完全替换生产端口，避免合并后额外发布公网端口；这个要求仅用于测试脚本。

## 文档与规范

- [Docker 程序完整说明](server/internal/apidocs/docker.md)：接入向导、七语言运行方式、版本和代码加密边界。
- [客户端协议完整规范](server/internal/apidocs/protocol.md)：通信、票据、加密载荷和跨语言实现要求。
- [各语言 SDK](#七种语言-sdk)：Go、Python、Node.js、Java、C#、PHP、Rust。

### 七种语言 SDK

[Go](sdk/go/README.md) · [Python](sdk/python/README.md) · [Node.js](sdk/node/README.md) · [Java](sdk/java/README.md) · [C#](sdk/csharp/README.md) · [PHP](sdk/php/README.md) · [Rust](sdk/rust/README.md)
