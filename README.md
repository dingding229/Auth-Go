# Auth Go

Auth Go 是面向软件发布者的授权服务器：你可以为发布在 Docker Hub 的程序发放授权码、限制同时运行的实例，并在管理后台维护用户、授权和运行记录。普通程序也可以直接使用同一套 SDK 接入。

## 主要功能

- 授权码、FLOATING 实例席位和有效期管理，支持续期、暂停、恢复、吊销和批量发码。
- 批量授权 CSV 导入导出，支持库存授权和按用户分配。
- Go、Python、Node.js、Java、C#、PHP、Rust 七种语言 SDK。
- 授权服务器暂时不可达时，已验证的正式授权可凭签名票据在宽限期内继续运行。
- Docker 程序接入向导，生成接入代码与 Dockerfile，可通过 GitHub Actions 一键构建双架构镜像并推送到 Docker Hub。
- Docker Hub 公开版本同步、版本禁用和用户更新提示。
- 用户中心 `/portal`，支持邮箱登录、授权码登录、授权查看、实例释放和密码管理。
- 管理员密码登录、审计日志、验证日志和会话撤销。
- 本地 IP 库查询与疑似共享提示，不改变客户端授权结果（见[IP 库与疑似共享](#ip-库与疑似共享)）。
- 可在“系统设置 → 后台地址”修改管理页面和管理 API 的路径。
- 数据库与 `master.key` 完整备份和离线恢复。

## 目录

- [安装](#安装docker-compose) · [使用教程](#使用教程)
- [日常运维](#日常运维) · [离线恢复](#离线恢复)
- [HTTPS 反向代理与受信代理](#https-反向代理与受信代理)
- [高级配置](#高级配置) · [IP 库与疑似共享](#ip-库与疑似共享)
- [安全说明](#安全说明) · [协议概要](#协议概要) · [错误码](#错误码)
- [开发](#开发) · [七种语言 SDK](#七种语言-sdk)

## 安装（Docker Compose）

这是唯一的生产安装方式。需要 Docker Engine、Compose v2 和 curl，不需要下载项目源码，也不需要创建 `.env`。

```sh
mkdir authgo && cd authgo
curl -fsSLO https://raw.githubusercontent.com/dingding229/Auth-Go/main/docker-compose.yml
mkdir -m 700 data && chown 65532:65532 data
docker compose up -d
```

数据保存在安装目录下的 `data` 文件夹（容器内 `/data`）。容器以非 root 用户（UID 65532）运行，所以启动前要先建好 `data` 并交给该用户；不是 root 时在 `chown` 前加 `sudo`。若漏了这一步，Docker 会自动建成 root 所有的目录，容器将因无法写入而启动失败，补执行 `chown` 后再 `docker compose up -d` 即可。

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

authgo-pack 已内置在 `docker.io/dingding229/authgo` 镜像中，代码加密构建会自动使用，无需配置。离线追查可从主镜像运行工具（将占位值替换为软件标记与实际文件名）：

```sh
docker run --rm --entrypoint /authgo-pack -v "$PWD:/work:ro" docker.io/dingding229/authgo:1.0.5 trace --tag "<tag>" "/work/<文件>"
```

### 7. 用户中心

将 `/portal` 地址提供给用户。用户用管理员设置的邮箱和用户中心密码登录；启用邮件服务后也可使用邮箱验证码。用户可以查看名下授权、释放自己的实例、查看公告与更新，并在“账号安全”修改密码；授权码登录入口用于查看单个授权。

### 8. 自动构建并发布到 Docker Hub

1. 在 GitHub 个人设置的 **Developer settings → Personal access tokens → Fine-grained tokens** 创建令牌。选择仓库所属账号或组织，只授权要发布的仓库；仓库权限设为 **Contents、Secrets、Variables、Actions、Workflows：Read and write**，**Metadata：Read-only**。组织仓库可能需要组织管理员批准。详见 [GitHub 令牌创建说明](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)。
2. 在 Docker Hub 的账号设置中打开 **Personal access tokens**，创建具有 **Read & Write** 权限的访问令牌，并确认该账号可推送软件已保存的镜像名。
3. 在 AuthGo **系统设置 → GitHub 与 Docker Hub 发布** 保存 GitHub 访问令牌、Docker Hub 用户名和 Docker Hub 访问令牌。令牌用服务主密钥加密，只能写入，页面只显示是否已设置；留空保留原值，可分别清除。新令牌保存时联网验证，失败不保存；仅修改 Docker Hub 用户名时也验证已有令牌。点击“验证”可复查已保存凭据并显示账号名。经典 GitHub 令牌须包含 `repo` 和 `workflow` 权限，细粒度令牌的仓库权限仍由软件“测试连接”检查。清除仅删除 AuthGo 保存值，不删除仓库已同步的 Secrets；如需撤销令牌，请在对应平台吊销。备份时须保留数据库与 `master.key`。
4. 在软件详情的 **接入程序 → Docker接入向导** 保存 Docker Hub 镜像名、选择语言和是否加密，将向导给出的 Dockerfile、SDK 和业务文件放进 GitHub 仓库对应目录。启用加密时先生成当前打包公钥。AuthGo 不会自动上传业务代码或 Dockerfile。
5. 打开 **4. 自动发布**，填写 `owner/repo` 与分支（默认 `main`），点击 **保存仓库与构建选项 → 测试连接 → 同步配置到仓库**。检查通过后，服务仅创建或更新 `.github/workflows/authgo-publish.yml`，以仓库公钥密封加密写入 `DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN` 两个 Secret，并保存构建用 Variable `AUTHGO_CONFIG`。同步会覆盖该固定路径的工作流；如中途失败，修正权限后可重新同步。
6. 输入版本号，例如 `1.0.0` 或 `1.1.0-rc.1`，点击 **发布新版本**。版本必须为可用作 Docker 标签的严格语义版本，不带 `v` 前缀或 `+` 构建元数据。GitHub 要求可手动运行的工作流已存在于仓库默认分支；发布其他分支前，也须把工作流合入默认分支。仓库需启用 Actions，并允许工作流中使用的 Actions。

构建在 GitHub Actions 上运行，发布 `linux/amd64` 与 `linux/arm64` 两种架构，推送 `<版本>` 和 `latest`；PHP-FPM 同时发布配套的 `-nginx` 镜像。页面显示最近五次运行的状态、时间和 GitHub 链接，运行中自动刷新。构建成功后，现有 Docker Hub 版本同步会自动收录正式版本标签，预发布标签不收录。修改镜像、接入地址、密钥、发布凭据或构建选项后，先重新同步再发布。触发结果不明确时，先查看 GitHub，避免重复触发。

也可直接复制同一份工作流、手动配置上述 Secrets/Variable 后打 `v1.0.0` 标签，或在 GitHub Actions 中手动输入版本运行。AuthGo 容器不执行构建、不需要 `docker.sock`，也不会将两个令牌放进构建参数或镜像。

## 日常运维

### 升级

更新前先下载完整备份。在原安装目录执行：

```sh
docker compose pull && docker compose up -d
```

默认镜像使用 `latest`。需要固定版本时，把 Compose 文件中的 `docker.io/dingding229/authgo:latest` 改为 `docker.io/dingding229/authgo:1.0.5`，再执行上面的升级命令。升级时自动在同一事务中补齐受支持的数据库迁移并保留数据（1.0.6 含 4 条迁移记录）；未知迁移记录会被拒绝。旧版本程序不能直接读取升级后的数据库，回滚必须同时恢复升级前的备份和原镜像。

已吊销的正式授权可在详情或列表中永久删除，也可按软件批量清理；激活与会话会删除，验证日志保留。试用及保留试用领取记录的授权不可删除，以免绕过重复领取限制。

### 备份与恢复

默认数据库和自动生成的 `master.key` 都在安装目录的 `data` 文件夹（容器内 `/data`），必须一起备份。在“系统设置 → 数据库备份”创建并下载完整备份；下载时可选填至少 12 个字符的密码，未填下载原有 ZIP，填写后下载 `.zip.enc`（Argon2id + 分块 XChaCha20-Poly1305），密码不存储，丢失无法恢复。系统每天自动备份，默认保留最新 7 份。备份使用一致的 SQLite 快照，ZIP 只包含 `authgo.db` 和**当前实际使用的** `master.key`，不包含 IP 库或历史备份目录。备份内含主密钥，必须加密离线保存、限制访问，不能放到公开下载地址。

主密钥优先级为非空 `AUTHGO_MASTER_KEY` → `/data/master.key` → 空库首次自动生成。只有数据库尚不存在时才允许自动生成；已有库缺少密钥或密钥格式损坏会拒绝启动。不要每次启动都生成新密钥，原环境密钥部署必须保留原值。

#### 离线恢复

恢复是**停机替换**，接受完整 ZIP 和密码加密的 ZIP 包，1.0.3 及以后版本可接受 1.0.0–1.0.2 的基线备份及包含已知后续迁移的备份，恢复后启动时自动补齐迁移。未知结构或高于当前程序的迁移版本会被拒绝。先停止所有写入 `data` 目录的服务或工具；不要直接覆盖运行中的 SQLite 数据库，不要把旧 WAL/SHM 混入备份快照。

加密包先解封为 ZIP，再执行下方原有的离线校验及替换步骤；旧的未加密 ZIP 不需要密码，也仍可按原步骤恢复。解封不会修改数据库，错误密码、篡改或截断均失败且不发布输出文件。密码只能由 `AUTHGO_BACKUP_PASSWORD` 或管道标准输入提供，不使用命令行密码参数：

```sh
mkdir -p .restore && chmod 700 .restore
# 将加密备份放入 .restore/backup.zip.enc；在可信终端读取密码，不回显
read -rs AUTHGO_BACKUP_PASSWORD; export AUTHGO_BACKUP_PASSWORD; printf '\n'
docker run --rm --memory=256m --user "$(id -u):$(id -g)" --workdir /work -e AUTHGO_BACKUP_PASSWORD -v "$PWD/.restore:/work" \
  --entrypoint /authgo docker.io/dingding229/authgo:1.0.5 \
  backup-unlock /work/backup.zip.enc /work/backup.zip
unset AUTHGO_BACKUP_PASSWORD
# 解封失败立即停止；成功后再执行下方校验，勿覆盖已有输出 ZIP。
```

在原 Compose 目录（即 `data` 所在目录）执行下列步骤。工具容器仅做一次性离线文件操作，不是另一种安装方式。

<details>
<summary>展开：校验备份、保留回滚现场并恢复文件</summary>

将可信的完整备份保存为 `.restore/backup.zip`（也可先执行前三条准备命令再复制文件），再依次执行：

```sh
set -eu
umask 077
mkdir -p .restore
# 将安全保存的完整备份复制到 .restore/backup.zip，不使用来历不明的ZIP
CID=$(docker compose ps -aq authgo)
DATA_DIR=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$CID")
[ -n "$DATA_DIR" ] || { echo "未找到 /data 挂载，请先确认实际挂载"; exit 1; }
# 用于检查本次仍生效的ENV密钥；文件含敏感信息，不要cat
docker inspect "$CID" > .restore/original-container.json
docker compose stop authgo
# 必须确认容器已停止；其他程序也不得持有此数据库
[ "$(docker inspect --format '{{.State.Running}}' "$CID")" = false ] || exit 1
# 完整保留停机现场（含互相匹配的WAL/SHM）以便回滚；不是在线复制SQLite
docker run --rm --name authgo-restore-safety --memory=256m \
  -v "$DATA_DIR":/data:ro -v "$PWD/.restore":/work alpine:3.22 \
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
    known = [(1, 'authgo_1_0_0'), (2, 'authgo_1_0_3_build_verified'), (3, 'authgo_1_0_3_license_template'), (4, 'authgo_1_0_6_version_architectures')]
    applied = db.execute('SELECT version,name FROM schema_migrations ORDER BY version').fetchall()
    assert applied and applied == known[:len(applied)], '数据库结构不受支持：迁移版本或名称不匹配'
print('备份格式、数据库、主密钥和环境配置校验完成（不输出密钥）')
PYRESTORE
# 快照已是完整DB，绝不把原库或其他备份的WAL/SHM混入新快照
docker run --rm --name authgo-restore-files --memory=256m \
  -v "$DATA_DIR":/data -v "$PWD/.restore/staged":/restore:ro alpine:3.22 \
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

恢复前的容器环境信息和停机现场都含敏感数据，`.restore` 仅限管理员访问。命令会校验 ZIP 成员、完整性、密钥长度、SQLite 完整性及有序的已知迁移记录；当前容器若配置了 `AUTHGO_MASTER_KEY`，必须与备份相同。**启动前若更改 Compose 的容器环境配置，须再次确认最终生效的密钥匹配**，环境值优先于密钥文件。

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

Compose 不指定网段，由 Docker 自动分配默认网络。受信代理为空时，默认信任内部直接对端（环回、RFC1918、链路本地、IPv6 ULA），而公网直接对端的转发头一律忽略。管理员填写列表后，仅信任所填地址，不再自动信任私网。代理必须覆盖并传递 X-Forwarded-For/Proto/Host；XFF 自右向左跳过受信地址，无 XFF 时才使用 X-Real-IP。使用 HTTPS 反向代理后，在“对外服务地址”填写 HTTPS 地址；保存后立即生效。不要允许不可信的私网客户端或容器直接接触服务，应为此类部署配置明确的代理 IP/CIDR。日志旁出现“内网”时，请检查代理转发头。解析结果统一用于限流、试用、审计和客户端日志，可信来源同时决定 Cookie Secure 与公开地址。

部署在 Cloudflare 后面时，在“系统设置 → 基础与安全 → 受信代理”点击“填入 Cloudflare”后保存。
按钮将内网和 Cloudflare 网段合并进当前列表，保留已有行、去重，不自动保存；未填入时可能记录 Cloudflare 节点 IP（AS13335），而非客户端真实 IP。
本机 Nginx 反代应使用 `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` 保留 Cloudflare 的转发链，不能用上述直连示例的 `$remote_addr` 覆盖。
网段来自 [Cloudflare 官网](https://www.cloudflare.com/ips/)，偶有调整，请定期核对并更新。

备份和 IP 库上传可能超过代理的默认请求体或超时限制：仅对相应位置调整（普通请求仍保留原限制），备份创建需预留超过 6 分钟、下载超过 5 分钟，IP 库上传请求体最高 513 MiB。管理 API 文档在登录后的“接入文档 → 管理 API”查看；自定义后台地址后位置匹配规则也要随之调整。

## 高级配置

一般不需要环境变量。若确有需要，可在现有 `authgo` 服务下添加 `environment:`，例如：

```yaml
services:
  authgo:
    environment:
      AUTHGO_LOG_LEVEL: info
      AUTHGO_SWAGGER_ENABLED: "false"
```

这里只展示要添加的部分，不要删除原文件的镜像、端口、数据目录和安全配置。修改后执行 `docker compose up -d` 重建容器以应用环境配置；管理端“系统设置”则在保存后生效，通常无需重启。主密钥、初始管理员密码、日志级别和公开 Swagger 等高级变量见下表。

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
| `AUTHGO_TRUSTED_PROXIES` | 空 | 初始受信代理列表，后续可在系统设置修改；为空时默认信任内部直接对端，填写后仅信任所填 IP/CIDR。 |
| `AUTHGO_LOG_LEVEL` | `info` | `debug`、`info`、`warn` 或 `error`。 |
| `AUTHGO_SWAGGER_ENABLED` | `false` | 是否启用公开 Swagger；管理 API 文档仍在登录管理端内查看。 |
| `AUTHGO_DB_BUSY_TIMEOUT_MS` | `5000` | SQLite 锁等待毫秒数，范围 1–60000。 |
| `AUTHGO_SHUTDOWN_TIMEOUT` | `10s` | 每阶段优雅退出时限，大于零且不超过 5 分钟。 |
| `AUTHGO_CLIENT_IP_RATE` | `10` | 每 IP 每秒请求补充数，范围 1–100000。 |
| `AUTHGO_CLIENT_IP_BURST` | `60` | IP 令牌桶容量，范围 1–100000。 |
| `AUTHGO_CLIENT_LICENSE_RATE` | `5` | 每授权码每秒请求补充数，范围 1–100000。 |
| `AUTHGO_CLIENT_LICENSE_BURST` | `30` | 授权码令牌桶容量，范围 1–100000。 |
| `AUTHGO_CLIENT_LOG_CAPACITY` | `4096` | 验证日志内存队列容量，范围 1–100000。 |

受信代理为空时，默认信任环回、RFC1918 私网、链路本地和 IPv6 ULA 的直接对端；公网直接对端的转发头一律忽略。填写受信代理列表后，只按列表判断，不再自动信任私网。代理须覆盖并传递 `X-Forwarded-For`、`X-Real-IP`、`X-Forwarded-Proto`、`X-Forwarded-Host`；XFF 从右向左取首个非受信地址，无 XFF 时才使用 X-Real-IP。日志旁显示“内网”时，请检查反向代理是否传递转发头。不要让不可信的私网客户端直接接触服务；这类部署应填写明确的代理 IP/CIDR。

系统设置中客户端每 IP 速率/突发默认 10/60，推荐 5–50/30–300；每授权默认 5/30，推荐 1–20/10–100。超出推荐范围仅提示，硬性范围仍为 1–100000，突发容量不得小于对应速率。

## IP 库与疑似共享

在“系统设置 → IP 库”可以查看状态、启用下载、立即更新、上传 City/ASN 的 MMDB，或停用并删除本地库。查询在本地完成，不向第三方发送待查询 IP；未启用时不会自动下载。验证日志、审计日志、实例和用户中心可以显示位置与 ASN，用户中心使用脱敏 IP。

默认数据源是 [DB-IP Lite City/ASN](https://db-ip.com)（CC BY 4.0），源数据每月发布；月初未发布时保留原库或回退上月。上传库兼容 DB-IP/MaxMind 字段，只有开启定时同步时才会被 DB-IP 免费库替换。文件位于 `/data/ipdb/`，目录 `0700`、文件 `0600`，完整校验后原子替换，操作写入审计。

服务按最近 24 小时成功的 activate、verify、heartbeat 来源汇总；同一授权按公网 IP 去重，超过 3 个国家或 5 个 ASN 时提示“疑似共享”。这只是管理提示，不封禁授权，也不改变客户端校验结果；VPN、云服务器跨区和代理可能造成误报。在授权列表筛选标记，在授权详情“概览 → 共享检测”查看分布并可忽略 30 天；去重来源数不等于同时在线实例数。指标回落会清除标记，忽略期结束后须由下一轮汇总重新判断；IP 库不可用时不展示旧标记。

在“系统设置 → IP 库”可设置定时同步开关和标准 5 段 cron（分 时 日 月 周，UTC），默认 `0 3 1 * *`、计划关闭；不支持描述符或秒字段，两次执行至少间隔 1 小时。可点选每天 `0 3 * * *`、每周一 `0 3 * * 1`、每月 `0 3 1 * *`。来源固定为 DB-IP 免费库，开启后下次同步会替换上传库，关闭则保留。界面显示上次结果、下次同步或重试的 UTC 与本地时间，并可立即同步。MMDB 最多 512 MiB、gzip 最多 128 MiB，校验通过后原子替换；失败保留原库，5 分钟起指数退避、最长 6 小时重试，重启沿用持久化下次时间。查询 IP 不会发送给第三方。

### 免授权码试用

软件只设置“启用免授权码试用”开关。系统设置中的“免授权码试用天数（所有软件）”统一控制新试用，默认 14 天，可设为 1–365 天；功能项为空，实例数固定为 1，不使用功能模板。已领取的试用不会因修改天数而延长。相同软件的同一 IPv4 或 IPv6 /64 网络 30 天内复用原试用，全部软件每天最多新建 100 个；试用需要联网，不提供正式授权的断网宽限。

### 公告读取

七种 SDK 的公告方法均通过加密通道验证服务端签名，不需要先激活，也不修改授权缓存。后台接入代码区域提供每种语言的获取与显示示例；前端应用应按纯文本展示公告内容。

不使用 SDK 的网页可调用 `GET /api/v1/public/announcements?app_key=<软件标识>`，返回 `data.items`，每项包含 `id`、`title`、`content`、`level`（info/warning/critical）、`published_at`、`expires_at`。仅返回已发布且未过期的公告，最多 20 条、响应最多 256 KiB，同一来源每分钟最多 30 次（IPv6 按 /64 归并），缓存 60 秒。软件不存在、已停用或无公告均返回同样的空列表。此接口不签名，可被中间人篡改；需要防篡改时使用 SDK。



## 安全说明

- 公网使用 HTTPS和强管理员密码；不要公开初始化链接、包含令牌的日志、备份、主密钥或会话令牌。
- 接入配置可以公开，但必须由开发者编译固定；不要由客户环境变量、配置文件或未经认证的响应替换信任根，也不要把授权码或配置串写入日志。
- 客户控制运行主机，无法承诺绝对防破解；关键入口应持续执行授权守卫。代码加密和水印提高还原或追查成本，但不能阻止宿主机 root 调试和内存导出。
- 宽限只适用于已有可信票据；到期或收到已认证明确拒绝后不得继续受保护业务。常驻进程停止，PHP-FPM/Apache 按请求式 SDK 拒绝响应。
- 主密钥与数据库必须成对保存；可恢复受支持旧版本的备份并在启动时升级，未知迁移结构会被拒绝；原有未加密完整 ZIP 备份仍可恢复。

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
| `INVALID_CREDENTIALS` | 用户名、密码、授权码、邮箱、查询密码或验证码错误 | 修正凭据，不重试敏感信息。 |
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

各业务包持有服务和路由注册入口，`httpserver` 只组装。接入文档的五份 Markdown 直接编辑 `server/internal/apidocs/` 下对应文件：`quickstart.md`、`docker.md`、`customer.md`、`offline.md`、`protocol.md`；管理端和用户中心共用嵌入内容，不维护副本；修改 API 注释后执行 `make docs` 更新 OpenAPI。不得放宽签名、未知错误默认拒绝、权限、限流、指纹、主密钥和 HTTPS 断言。

### 源码结构

- `server/internal`：SQLite schema、管理员、用户、授权与实例席位、加密网关、备份、IP 库、Docker Hub 和 HTTP 组装。
- `web/src`：管理端、用户中心、共享组件及统一请求封装。
- `sdk`：七种语言 SDK、共享向量和一致性驱动。
- `pack`：加密打包、水印和启动桩生成工具。
- `examples`：最小接入和 Docker 加密程序示例。
- `tests`：当前载荷、水印和安全夹具。

### 测试入口

运行测试：`make test`（Go、SDK、示例和前端）、`make test-sdks`（七语言一致性）、`make test-pack`（加密载荷与水印）、`sh scripts/smoke-docker.sh`（真实单容器流程）和 `sh scripts/test-docker-license.sh`（七语言容器授权生命周期）。 水印浏览器测试必须先运行 `python3 scripts/test-watermark-e2e.py`，再用其输出目录运行 `AUTHGO_WATERMARK_E2E_OUT=/path/to/watermark-e2e-<pid> node web/scripts/test-watermark-layout.mjs`。其他功能入口包括 `scripts/test-image-pack.py`（双架构主镜像内置打包工具）、`scripts/test-protected-*`、`scripts/test-watermark-e2e.py` 和 `scripts/test-php-sealed.py`；`scripts/check-examples.sh` 编译 Go 示例。正式 Dockerfile 只构建，不在镜像构建时运行测试。

前端路由契约使用真实服务端 Router 注册表，覆盖默认和自定义后台路径；`make test` 先生成 `server/.route-contract.json` 再执行前端测试。单独运行前端测试时，先执行 `(cd server && go test -count=1 ./internal/httpserver -run '^TestExportFrontendRouteContract$')` 导出当前源码的注册表，再执行 `(cd web && npm test)`；修改相关源码后须重新导出。源码构建的冒烟镜像来自临时 Compose override，不影响生产 Compose。冒烟测试要求 Compose v2.24.4 或更新版本，用 `!override` 完全替换生产端口，避免合并后额外发布公网端口；这个要求仅用于测试脚本。

## 文档与规范

- [快速开始](server/internal/apidocs/quickstart.md)：创建软件、发放授权、安装 SDK 和交付。
- [给客户的运行说明](server/internal/apidocs/customer.md)：部署、缓存卷、席位和反向代理。
- [离线与故障](server/internal/apidocs/offline.md)：故障分类、宽限和恢复。
- [Docker 程序完整说明](server/internal/apidocs/docker.md)：接入向导、七语言运行方式、版本和代码加密边界。
- [客户端协议完整规范](server/internal/apidocs/protocol.md)：通信、票据、加密载荷和跨语言实现要求。
- [各语言 SDK](#七种语言-sdk)：Go、Python、Node.js、Java、C#、PHP、Rust。

### 七种语言 SDK

[Go](sdk/go/README.md) · [Python](sdk/python/README.md) · [Node.js](sdk/node/README.md) · [Java](sdk/java/README.md) · [C#](sdk/csharp/README.md) · [PHP](sdk/php/README.md) · [Rust](sdk/rust/README.md)
