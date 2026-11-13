#!/usr/bin/env python3
"""Real Go/Rust protected ELF test. Run from the repository root.

Uses the existing real-server/container harness, but builds pinned HTTPS-only
configs. CA/diagnostic changes live solely in temporary test contexts. Never
weakens TLS, existing docker-test assertions, or the official example builds.
"""
import base64
import hashlib
import datetime
import traceback
import http.server
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("license_harness", ROOT / "scripts/test-docker-license.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
PREFIX = "authgo-protect-" + str(os.getpid()) + "-"
d.PREFIX = PREFIX
d.API = PREFIX + "api"
d.API2 = PREFIX + "fake-api"
d.IMAGE = PREFIX + "api-image"
PROXY = None
report = []
MARKER = "HTTP已启动".encode()


def checked(args, cwd=None, sensitive=()):
    p = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode:
        text = p.stdout.decode(errors="replace")
        for value in sensitive:
            text = text.replace(value, "<redacted>")
        (d.TMP / "failed-command.log").write_text(text)
        raise AssertionError("命令失败，日志: " + str(d.TMP / "failed-command.log"))
    return p.stdout


def certificates():
    qa = d.TMP / "tls"
    qa.mkdir()
    def openssl(*args):
        checked(["openssl", *args], qa)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-subj", "/CN=AuthGo public-test CA", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=127.0.0.1")
    (qa / "server.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.crt", "-days", "2", "-extfile", "server.ext")
    openssl("x509", "-in", "ca.crt", "-outform", "DER", "-out", "ca.der")
    return qa


class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.forward()

    def do_GET(self):
        self.forward()

    def forward(self):
        # The fixture is deliberately only a transport proxy to a real backend.
        length = int(self.headers.get("Content-Length", "0"))
        assert length <= 2 * 1024 * 1024
        body = self.rfile.read(length) if length else None
        request = urllib.request.Request(d.state["base"] + self.path, data=body, method=self.command, headers={"Content-Type": self.headers.get("Content-Type", "application/json")})
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                raw, status = response.read(), response.status
        except urllib.error.HTTPError as err:
            raw, status = err.read(), err.code
        except OSError:
            raw, status = b'{"transport":"unreachable"}', 502
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass


def tls_proxy(qa):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(qa / "server.crt", qa / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "https://127.0.0.1:" + str(server.server_port)


def copy_context(lang, qa):
    root = d.TMP / (lang + "-context")
    root.mkdir()
    ignore = shutil.ignore_patterns("target", ".git", "node_modules", "__pycache__", "*.cache", "*.db")
    for source, dest in (("sdk/go", "sdk/go"), ("sdk/rust", "sdk/rust"), ("examples/docker", "examples/docker")):
        shutil.copytree(ROOT / source, root / dest, ignore=ignore)
    (root / "qa").mkdir()
    shutil.copy2(ROOT / "bin/authgo-pack", root / "qa/authgo-pack")
    shutil.copy2(qa / "ca.crt", root / "qa/ca.crt")
    # Never copy the CA private key, even into an intermediate Docker layer.
    if lang == "go":
        path = root / "examples/docker/main.go"
        source = path.read_text().replace('import (', 'import (\n qa_sha "crypto/sha256"\n qa_fmt "fmt"')
        source = source.replace('func main() {', '''func main() {
 if os.Getenv("AUTHGO_PROTECTED")=="1" {
  raw,_:=os.ReadFile("/proc/1/exe"); exe,_:=os.Readlink("/proc/1/exe"); f,_:=os.Open("/proc/1/exe"); var seals uintptr
  if f!=nil {seals,_,_=syscall.Syscall(syscall.SYS_FCNTL,f.Fd(),1034,0);f.Close()}
  qa_fmt.Printf("QA_EXE %s QA_PID %d QA_ARGV0 %s QA_HASH %x QA_SEALS %d\\n",exe,os.Getpid(),os.Args[0],qa_sha.Sum256(raw),seals)
 }
''')
        path.write_text(source)
        original = (ROOT / "examples/docker/Dockerfile").read_text()
        binary = "/out/app"
    else:
        path = root / "examples/docker/rust/src/main.rs"
        source = path.read_text().replace('let options = GuardOptions {', '''let options = GuardOptions {
        sdk_options: authgo::Options {root_cert_der: Some(include_bytes!("qa-ca.der").to_vec()), ..Default::default()},''')
        source = source.replace('fn main() {', '''fn main() {
 if std::env::var("AUTHGO_PROTECTED").as_deref()==Ok("1") {
  use std::os::fd::AsRawFd;
  let raw=std::fs::read("/proc/1/exe").unwrap();let exe=std::fs::read_link("/proc/1/exe").unwrap();let f=std::fs::File::open("/proc/1/exe").unwrap();
  unsafe extern "C" {fn fcntl(fd:i32,cmd:i32)->i32;}
  let seals=unsafe {fcntl(f.as_raw_fd(),1034)};
  println!("QA_EXE {} QA_PID {} QA_ARGV0 {} QA_HASH {} QA_SEALS {}",exe.display(),std::process::id(),std::env::args().next().unwrap(),authgo::hash(&raw),seals);
 }
''')
        path.write_text(source)
        shutil.copy2(qa / "ca.der", root / "examples/docker/rust/src/qa-ca.der")
        original = (ROOT / "examples/docker/rust/Dockerfile").read_text()
        binary = "/src/examples/docker/rust/target/release/authgo-docker-example"
    runtime_at = original.index("FROM gcr.io/")
    runtime = original[runtime_at:].replace("COPY --from=build " + binary, "COPY --from=protected " + binary)
    stage = f'''FROM build AS protected
COPY qa/authgo-pack /usr/local/bin/authgo-pack
ARG PAYLOAD_PUBLIC_KEY
ARG PAYLOAD_KEY_ID
ARG PAYLOAD_APP_KEY
RUN authgo-pack --protect {binary} --public-key "$PAYLOAD_PUBLIC_KEY" --key-id "$PAYLOAD_KEY_ID" --app-key "$PAYLOAD_APP_KEY" --version '1.0.0' --config "$AUTHGO_CONFIG" --out /out/protected-payload
'''
    runtime += '\nCOPY qa/ca.crt /qa/ca.crt\nENV SSL_CERT_FILE=/qa/ca.crt\n'
    (root / "Dockerfile").write_text(original[:runtime_at] + stage + runtime)
    return root, binary


def build(lang, config, key, qa):
    context, binary = copy_context(lang, qa)
    original, protected = PREFIX + lang + "-original", PREFIX + lang + "-protected"
    args = ["docker", "build", "--memory=1536m", "--build-arg", "AUTHGO_CONFIG=" + config, "--build-arg", "VERSION=1.0.0"]
    for name, value in (("PAYLOAD_PUBLIC_KEY", key["public_key"]), ("PAYLOAD_KEY_ID", key["key_id"]), ("PAYLOAD_APP_KEY", d.state["app"]["app_key"])):
        args += ["--build-arg", name + "=" + value]
    for tag, target in ((original, "build"), (protected, None)):
        d.images.append(tag)
        checked(args + ["-t", tag] + (["--target", target] if target else []) + ["."], context, (config,))
    container = PREFIX + lang + "-inspect-original"
    d.containers.append(container)
    d.docker("create", "--name", container, "--memory=128m", "--entrypoint=/bin/true", original)
    path = d.TMP / (lang + "-original.elf")
    d.docker("cp", container + ":" + binary, str(path))
    data = path.read_bytes()
    assert MARKER in data, "原始程序没有明文基准标记，不能证明层扫描有效"
    expected_hash = hashlib.sha256(data).hexdigest()
    d.docker("rm", container)
    d.docker("image", "rm", original)
    return protected, expected_hash


def cache_files(volume):
    # Host-side read-only inspection; no helper container or privileged mode.
    path = pathlib.Path(json.loads(d.docker("volume", "inspect", volume))[0]["Mountpoint"])
    return list(path.iterdir())


def content_keys(volume):
    return [p for p in cache_files(volume) if p.name.startswith(("authgo-payload-v2-",))]


def proofs(volume):
    return [p for p in cache_files(volume) if p.name.startswith("authgo-payload-proof-v1-")]


def active_seats(license):
    now = datetime.datetime.now(datetime.timezone.utc)
    return [a for a in d.activations(license)
            if a["kind"] == "floating" and a["status"] == "active"
            and not a.get("offline_at") and a.get("lease_expires_at")
            and datetime.datetime.fromisoformat(a["lease_expires_at"].replace("Z", "+00:00")) > now]

def http_ok(address):
    try:
        with urllib.request.urlopen("http://" + address, timeout=2) as r:
            return r.status == 200 and "features" in json.load(r)
    except (OSError, ValueError):
        return False


def start(label, license, volume, image):
    address = "127.0.0.1:" + str(d.port())
    begin = time.monotonic()
    name = d.start(label, {"key": license}, volume, image, listen=address)
    d.wait(lambda: http_ok(address) or not d.running(name), 45, "受保护程序没有就绪")
    assert d.running(name) and http_ok(address), "受保护程序未返回200: " + name + " exit=" + str(d.inspect(name)["State"]["ExitCode"]) + " codes=" + ",".join(sorted(set(re.findall(r"[A-Z][A-Z_]{3,}",d.logs(name)))))
    return name, address, time.monotonic() - begin


def layers_have_no_plaintext(image, lang):
    archive = d.TMP / (lang + "-layers.tar")
    try:
        checked(["docker", "save", "-o", str(archive), image])
        layers = 0
        with tarfile.open(archive) as outer:
            manifest = json.load(outer.extractfile("manifest.json"))
            names = {name for item in manifest for name in item["Layers"]}
            for name in names:
                layers += 1
                with tarfile.open(fileobj=outer.extractfile(name), mode="r|*") as layer:
                    for member in layer:
                        if not member.isfile():
                            continue
                        data, carry = layer.extractfile(member), b""
                        while True:
                            chunk = data.read(1024 * 1024)
                            if not chunk:
                                break
                            block = carry + chunk
                            assert MARKER not in block, "生产镜像层含原程序明文标记"
                            carry = block[-len(MARKER):]
        assert layers > 0, "没有扫描镜像层"
        print(f"EVIDENCE {lang} docker-save layers={layers} plaintext-marker=absent", flush=True)
    finally:
        archive.unlink(missing_ok=True)


def case(lang, title, fn):
    try:
        fn()
    except Exception:
        print("FAILED_CASE " + lang + " " + title, flush=True)
        raise
    report.append((lang, title))
    print("PASS " + lang + " " + title, flush=True)


def suite(lang, qa, endpoint):
    assert shutil.disk_usage(ROOT).free >= 10 * 1024**3, "磁盘不足10GB，停止，不清理其他项目"
    app = d.request("/api/v1/admin/applications", {"name": "ELF保护" + lang, "heartbeat_interval": 5, "next_check_in": 1, "grace_hours": 72})
    d.state["app"] = app
    key = d.request("/api/v1/admin/applications/" + str(app["id"]) + "/payload-keys", {}, "POST")
    config = d.request("/api/v1/admin/applications/" + str(app["id"]) + "/connection", {"url": endpoint})["config"]
    d.SENSITIVE.add(config)
    print("BUILD " + lang + " real launcher + protected image", flush=True)
    image, original_hash = build(lang, config, key, qa)
    lic, volume = d.license_new(1), d.volume_new(lang + "-cache")
    name, address, elapsed = start(lang + "-valid", lic["key"], volume, image)
    def valid():
        assert len(active_seats(lic)) == 1, "有效浮动席位数不为1"
        log = d.logs(name)
        assert "INSTANCE_REPLACED" not in log
        # watermark intentionally changes ONLY the 8 SDK string spans. Do not compare
        # a stamped executable with the old unstamped SHA, or drop the exact
        # executable assertion: independently patch original bytes using the
        # licensed trace value, then compare every byte and the business hash.
        actual_pid = d.inspect(name)["State"]["Pid"]
        actual = pathlib.Path(f"/proc/{actual_pid}/exe").read_bytes()
        tag = d.request("/api/v1/admin/applications/" + str(app["id"]) + "/watermark-tags")["items"][0]["tag"]
        values = re.findall(re.escape(tag.encode()) + b"([0-9a-f]{64})", actual)
        assert len(values) >= 8 and len(set(values)) == 1 and values[0] != b"0"*64, "实际执行程序缺少8个一致的非零水印"
        traced = d.request("/api/v1/admin/applications/" + str(app["id"]) + "/watermark-trace", {"watermark": values[0].decode()})
        assert traced["found"] and traced["license_id"] == lic["id"], "实际水印不属于当前授权"
        baseline = (d.TMP / (lang + "-original.elf")).read_bytes()
        assert hashlib.sha256(baseline).hexdigest() == original_hash, "未加印基准被修改"
        expected = baseline
        for i in range(8):
            placeholder = ("c0dec0dec0dec0de" + format(i, "016x") + "0"*64).encode()
            assert placeholder in expected, "基准缺少SDK占位符"
            expected = expected.replace(placeholder, tag.encode() + values[0])
        assert actual == expected, "除规定96字节槽位外原程序有变化"
        expected_hash = hashlib.sha256(expected).hexdigest()
        assert "QA_PID 1 QA_ARGV0 /app QA_HASH " + expected_hash in log, "PID1不是水印化原业务程序或argv改变"
        assert "QA_EXE /memfd:authgo-main (deleted)" in log or "QA_EXE /tmp/" in log or "QA_EXE /dev/shm/" in log
        if "memfd:authgo-main" in log:
            assert "QA_SEALS 15" in log, "memfd缺少seal"
        else:
            assert "(deleted)" in log, "tmpfs未在exec前unlink"
        pid = d.inspect(name)["State"]["Pid"]
        cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
        assert cmdline.startswith(b"/app\0-listen\0"), "PID1 cmdline不符"
        status = pathlib.Path(f"/proc/{pid}/status").read_text()
        rss = int(re.search(r"VmRSS:\s+(\d+)", status).group(1))
        info = d.inspect(name)
        assert info["Config"]["User"] == "65532:65532"
        assert info["HostConfig"]["ReadonlyRootfs"] and "ALL" in info["HostConfig"]["CapDrop"]
        assert not info["HostConfig"]["Privileged"]
        assert any(x.startswith("no-new-privileges") for x in info["HostConfig"]["SecurityOpt"])
        assert not any("seccomp=unconfined" in x for x in info["HostConfig"]["SecurityOpt"])
        assert info["HostConfig"]["Memory"] == 128 * 1024**2
        for secret in d.SENSITIVE:
            assert secret not in log, "日志泄漏敏感数据"
        print(f"EVIDENCE {lang} PID1_exe=sealed-memfd original-after-exact8-slot-rewrite-sha256=match cmdline=/app startup={elapsed:.3f}s RSS={rss}KiB seats=1 security=nonroot,ro,cap_drop_ALL,no-new-privileges,default-seccomp", flush=True)
    case(lang, "有效授权、HTTP200、单席位、真正程序PID1及安全设置", valid)
    case(lang, "docker-save全部镜像层没有原程序明文标记", lambda: layers_have_no_plaintext(image, lang))
    def refreshed():
        before = proofs(volume)
        assert len(before) == 1
        initial = before[0].read_bytes()
        d.wait(lambda: proofs(volume)[0].read_bytes() != initial, 12, "程序在线校验没有刷新共享证据")
        assert content_keys(volume), "证据刷新破坏了密钥缓存"
        assert http_ok(address)
    case(lang, "程序在线校验持续原子刷新共享授权证据", refreshed)

    def redirect_tail():
        alternate, alternate_url = tls_proxy(qa)
        try:
            folder = d.TMP / (lang + "-redirect")
            folder.mkdir()
            path = folder / "app"
            d.docker("cp", name + ":/app", str(path))
            raw = path.read_bytes()
            footer = bytearray(raw[-64:])
            stub_length, payload_length, cipher_length = struct.unpack_from(">QQQ", footer, 24)
            assert stub_length + payload_length + cipher_length + 64 == len(raw)
            payload = json.loads(raw[stub_length:stub_length + payload_length])
            config = json.loads(base64.urlsafe_b64decode(payload["config"][8:] + "==="))
            config["url"] = alternate_url
            payload["config"] = "authgo2." + base64.urlsafe_b64encode(json.dumps(config, separators=(",", ":")).encode()).decode().rstrip("=")
            encoded = json.dumps(payload, separators=(",", ":")).encode()
            struct.pack_into(">Q", footer, 32, len(encoded))
            path.write_bytes(raw[:stub_length] + encoded + raw[stub_length + payload_length:-64] + footer)
            path.chmod(0o755)
            tag = PREFIX + lang + "-redirect"
            d.images.append(tag)
            (folder / "Dockerfile").write_text("FROM " + image + "\nCOPY app /app\n")
            checked(["docker", "build", "--memory=512m", "-t", tag, "."], folder)
            own_license, own_volume = d.license_new(1), d.volume_new(lang + "-redirect")
            redirected = d.start(lang + "-redirect", own_license, own_volume, tag, listen="127.0.0.1:0")
            d.ended(redirected, 77, seconds=30)
            assert not content_keys(own_volume), "替换尾部配置竟取得原内容密钥"
            assert "QA_PID" not in d.logs(redirected), "篡改配置后运行了业务程序"
            # This proxy preserves genuine signing/channel authentication and even
            # forwards to the real packing-key holder: envelope AAD must reject it.
            print("EVIDENCE " + lang + " modified-tail-config authenticated-proxy unlock=denied", flush=True)
        finally:
            alternate.shutdown()
            alternate.server_close()
    case(lang, "替换完整尾部配置及HTTPS地址仍无法取得内容密钥", redirect_tail)
    def stop():
        before = active_seats(lic)
        assert len(before) == 1
        begin = time.monotonic()
        d.stop(name)
        d.wait(lambda: not active_seats(lic), 5, "5秒内未释放席位")
        released = [a for a in d.activations(lic) if a["id"] == before[0]["id"]]
        assert not released, "释放后实例记录仍然存在"
        release_elapsed = time.monotonic() - begin
        assert release_elapsed <= 5, "席位未在停止后的5秒内释放"
        print(f"EVIDENCE {lang} stop-and-release={release_elapsed:.3f}s exit=0", flush=True)
    case(lang, "docker-stop正常退出0，5秒内释放席位", stop)
    assert content_keys(volume) and proofs(volume), "正式授权未生成两种共享缓存"
    d.stop_api()
    def outage():
        d.docker("start", name)
        d.wait(lambda: http_ok(address) or not d.running(name), 45)
        assert d.running(name) and http_ok(address), "有宽限缓存仍无法离线启动"
    case(lang, "服务不可达，有合法共享证据和密钥缓存仍可启动", outage)
    def empty():
        v = d.volume_new(lang + "-empty")
        empty_name = d.start(lang + "-empty", lic, v, image, listen="127.0.0.1:0")
        d.ended(empty_name, 77, seconds=45)
        assert not content_keys(v) and not proofs(v)
    case(lang, "空卷新实例断网失败退出77", empty)
    d.restore_api()
    # HTTP remains available during grace, so HTTP200 is not proof of online
    # session takeover. Match the existing docker-test recovery assertion.
    d.wait(lambda: "授权状态: online" in d.logs(name).rsplit("HTTP已启动", 1)[-1], 20, "恢复后没有完成在线实例接管")
    d.stop(name)
    def revoke_live():
        live, addr, _ = start(lang + "-live-revoke", lic["key"], volume, image)
        assert content_keys(volume) and proofs(volume)
        d.request("/api/v1/admin/licenses/" + str(lic["id"]) + "/revoke", {}, "POST")
        # Keep the existing instance revoke semantics: management revoke retires
        # activation carriers, so the next check is ACTIVATION_INVALID.
        d.ended(live, 77, text="ACTIVATION_INVALID", seconds=30)
        assert not content_keys(volume) and not proofs(volume), "明确拒绝后共享缓存未清除"
        d.docker("start", live)
        d.ended(live, 77, seconds=30)
        assert not content_keys(volume) and not proofs(volume)
    case(lang, "运行中吊销退出77、证据和密钥删除，重启仍退出77", revoke_live)
    def trial():
        d.request("/api/v1/admin/applications/" + str(app["id"]) + "/trial", {"trial_enabled": True, "trial_days": 14}, "PATCH")
        v = d.volume_new(lang + "-trial")
        trial_name, _, _ = start(lang + "-trial", "", v, image)
        assert "当前为试用" in d.logs(trial_name)
        assert not content_keys(v) and not proofs(v), "试用写了启动桩证据或密钥缓存"
        d.stop(trial_name)
    case(lang, "不提供授权码的试用正常运行，卷无密钥和证据缓存", trial)
    for container in d.containers:
        if container.startswith(PREFIX + lang + "-"):
            log = d.docker("logs", container, check=False)
            assert "INSTANCE_REPLACED" not in log, "启动桩与程序发生了实例冲突"
            for secret in d.SENSITIVE:
                assert secret not in log, "程序日志泄漏凭据"
    for resource in (image,):
        d.docker("image", "rm", resource, check=False)
    print("SUMMARY " + lang + " 9/9 PASS", flush=True)


def validate_stub_artifacts():
    for architecture, machine in (("amd64", 62), ("arm64", 183)):
        raw = (ROOT / "pack/stubs" / ("authgo-stub-linux-" + architecture)).read_bytes()
        assert raw[:6] == b"\x7fELF\x02\x01"
        assert struct.unpack_from("<H", raw, 18)[0] == machine
        offset = struct.unpack_from("<Q", raw, 32)[0]
        entry_size, count = struct.unpack_from("<HH", raw, 54)
        assert entry_size == 56 and offset + entry_size * count <= len(raw)
        assert all(struct.unpack_from("<I", raw, offset + i * entry_size)[0] != 3 for i in range(count)), "启动桩不是静态ELF"
        print("EVIDENCE static-launcher " + architecture + " ELF=valid PT_INTERP=absent", flush=True)

def main():
    global PROXY
    languages = [p for arg in sys.argv[1:] for p in arg.split(",")] or ["go", "rust"]
    assert all(lang in ("go", "rust") for lang in languages)
    assert shutil.disk_usage(ROOT).free >= 10 * 1024**3, "磁盘不足10GB，先报告，不清理"
    d.TMP = pathlib.Path(tempfile.mkdtemp(prefix=PREFIX, dir=ROOT.parent))
    print("Protected ELF test: real backend, HTTPS, sequential, memory bounded", flush=True)
    try:
        assert (ROOT / "bin/authgo-pack").is_file(), "先运行 make build-pack"
        validate_stub_artifacts()
        security = json.loads(d.docker("info", "--format", "{{json .SecurityOptions}}"))
        assert any("seccomp" in setting for setting in security), "Docker默认seccomp未启用"
        d.build("Dockerfile", d.IMAGE)
        d.api_start()
        d.state["user_id"] = d.request("/api/v1/admin/users", {"name": "ELF授权用户", "email": "elf-test@example.invalid"})["id"]
        qa = certificates()
        PROXY, endpoint = tls_proxy(qa)
        for lang in languages:
            suite(lang, qa, endpoint)
        print(f"PROTECTED_DONE 0; {len(report)}/{len(languages) * 9} PASS", flush=True)
    except Exception:
        diagnostic = []
        failure_states = {}
        for container in d.containers:
            if container.startswith(PREFIX + "go-") or container.startswith(PREFIX + "rust-"):
                try:
                    info = d.inspect(container)
                    failure_states[container] = {"State": info["State"], "RestartCount": info.get("RestartCount")}
                except Exception as state_error:
                    failure_states[container] = {"unavailable": type(state_error).__name__}
                data = d.docker("logs", "--timestamps", container, check=False)
                for secret in d.SENSITIVE:
                    data = data.replace(secret, "<redacted>")
                diagnostic.append(container + "\n" + data)
        (ROOT.parent / "protected-runtime-failure.log").write_text("\n".join(diagnostic))
        (ROOT.parent / "watermark-protected-elf-failure-state.json").write_text(json.dumps(failure_states, indent=2) + "\n")
        for frame in traceback.extract_tb(sys.exc_info()[2]):
            print(f"FAIL_LOCATION {pathlib.Path(frame.filename).name}:{frame.lineno} {frame.name}", flush=True)
        raise
    finally:
        if PROXY:
            PROXY.shutdown()
            PROXY.server_close()
        failed_log = d.TMP / "failed-command.log"
        if failed_log.exists():
            shutil.copy2(failed_log, ROOT.parent / "protected-build-failure.log")
        d.cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Never print raw command arguments, tickets, config or authorization codes.
        print("PROTECTED_DONE 1; " + type(exc).__name__ + ": " + str(exc)[:240], flush=True)
        raise SystemExit(1)
