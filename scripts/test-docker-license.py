#!/usr/bin/env python3
"""In-process Guard real-container test, sequential and resource bounded."""
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCOPE = ROOT.parent.name if re.fullmatch(r"[a-z0-9][a-z0-9-]*", ROOT.parent.name) else "test"
PREFIX = "authgo-" + SCOPE + "-dockertest-" + str(os.getpid()) + "-"
containers, volumes, images = [], [], []
results = []
TMP = None
API = PREFIX + "api"
API2 = PREFIX + "other-api"
IMAGE = PREFIX + "server"
APP_IMAGE = PREFIX + "example"
CLOCK_IMAGE = PREFIX + "clock"
state = {}
SENSITIVE = set()
LANGUAGE = "go"
EXAMPLE_FILE = "examples/docker/Dockerfile"
CLOCK_FILE = "scripts/fixtures/docker-clock.Dockerfile"


def command(args, check=True):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if check and p.returncode:
        # Never include argv: build arguments/environment may contain config/key.
        raise AssertionError("命令失败（输出保留在测试目录，未回显参数）")
    return p.stdout.strip()


def docker(*args, **kw):
    return command(["docker", *args], **kw)


def wait(fn, seconds=15, message="等待条件超时"):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if fn():
            return
        time.sleep(0.2)
    raise AssertionError(message)


def inspect(name):
    return json.loads(docker("inspect", name))[0]


def running(name):
    return inspect(name)["State"]["Running"]


def logs(name):
    return docker("logs", name)


def ended(name, code=77, text=None, seconds=15):
    wait(lambda: not running(name), seconds, "实例没有按预期退出")
    assert inspect(name)["State"]["ExitCode"] == code, "退出码不符"
    if text:
        codes = sorted(set(re.findall(r"\b(?:SDK_|LICENSE_|ACTIVATION_|INSTANCE_|VERSION_|FLOATING_)[A-Z_]+\b", logs(name))))
        assert text in logs(name), "日志缺少预期错误码/说明；实际代码=" + ",".join(codes)


def request(path, data=None, method=None, other=False):
    headers = {"Content-Type": "application/json"}
    token = state.get("other_token" if other else "token")
    if token:
        headers["Authorization"] = "Bearer " + token
    url = state["other_base" if other else "base"] + path
    payload = None if data is None else json.dumps(data).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=payload, headers=headers, method=method), timeout=8) as r:
            body = json.load(r)
    except urllib.error.HTTPError as err:
        # Only return the stable code, never echo payload, URL or credentials.
        try:
            body = json.load(err)
            code = body.get("code", "HTTP_ERROR") + ": " + body.get("message", "")
        except ValueError:
            code = "HTTP_ERROR"
        raise AssertionError("接口失败 " + path.split("?")[0] + ": " + str(code)) from None
    assert body.get("code") == "OK", "接口未成功: " + str(body.get("code"))
    return body["data"]


def api_ready(other=False):
    try:
        with urllib.request.urlopen(state["other_base" if other else "base"] + "/healthz", timeout=1) as r:
            return r.status == 200
    except (OSError, urllib.error.URLError):
        return False


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def api_start(other=False):
    name = API2 if other else API
    p = port()
    state["other_base" if other else "base"] = "http://127.0.0.1:" + str(p)
    volume = PREFIX + ("other-data" if other else "data")
    volumes.append(volume)
    if not other: state["data_volume"]=volume
    containers.append(name)
    docker("volume", "create", volume)
    # A real compose project; network=host is mandatory for loopback HTTP SDKs.
    compose = {
        "services": {"api": {
            "image": IMAGE, "container_name": name, "network_mode": "host",
            "environment": {"AUTHGO_ADDR": "127.0.0.1:" + str(p), "AUTHGO_DATA_DIR": "/data", "AUTHGO_LOG_LEVEL": "info"},
            "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
            "mem_limit": "512m", "volumes": [volume + ":/data"],
        }}, "volumes": {volume: {"external": True}},
    }
    compose_file = TMP / ("other-compose.json" if other else "compose.json")
    compose_file.write_text(json.dumps(compose))
    docker("compose", "-p", PREFIX + ("other" if other else "main"), "-f", str(compose_file), "up", "-d", "--no-build")
    wait(lambda: api_ready(other), 30, "Auth Go启动失败")
    wait(lambda: bool(re.search(r'"setup_token":"([A-Za-z0-9_-]+)"', logs(name))), 10)
    setup = re.search(r'"setup_token":"([A-Za-z0-9_-]+)"', logs(name)).group(1)
    auth = request("/api/v1/admin/auth/setup", {"token": setup, "username": "docker-owner", "password": secrets.token_hex(24)}, other=other)
    state["other_token" if other else "token"] = auth["access_token"]


def patch_app(**values):
    return request("/api/v1/admin/applications/" + str(state["app"]["id"]), values, "PATCH")


def license_new(limit=2):
    return request("/api/v1/admin/licenses", {"app_id": state["app"]["id"], "user_id": state["user_id"], "verify_methods": ["KEY", "FLOATING"], "max_activations": limit})


def activations(lic):
    return request("/api/v1/admin/activations?page_size=100&license_id=" + str(lic["id"]))["items"]


def volume_new(label):
    volume = PREFIX + label
    if volume not in volumes:
        volumes.append(volume)
    docker("volume", "create", volume)
    return volume


def start(label, lic, volume=None, image=None, extra_env=None, listen=None, command_args=None):
    name = PREFIX + label
    assert name not in containers, "重复测试容器名称"
    containers.append(name)

    if lic["key"]: SENSITIVE.add(lic["key"])
    args = ["run", "-d", "--name", name, "--memory=128m", "--network=host", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--stop-timeout=8", "--label", "com.docker.compose.project=" + PREFIX + "main", "-e", "AUTHGO_LICENSE=" + lic["key"]]
    if volume:
        args += ["-v", volume + ":/var/lib/authgo"]
    for k, v in (extra_env or {}).items():
        args += ["-e", k + "=" + v]
    args.append(image or APP_IMAGE)
    if command_args is not None:
        args += command_args
    elif image != CLOCK_IMAGE:
        args += ["-listen", listen or "127.0.0.1:0"]
    docker(*args)
    return name


def ready(name):
    wait(lambda: "HTTP已启动" in logs(name) or not running(name), 15, "示例未就绪")
    if not (running(name) and "HTTP已启动" in logs(name)):
        codes = sorted(set(re.findall(r"\b(?:SDK_|LICENSE_|ACTIVATION_|INSTANCE_|VERSION_|FLOATING_)[A-Z_]+\b", logs(name))))
        raise AssertionError("示例启动失败: " + name + " exit=" + str(inspect(name)["State"]["ExitCode"]) + " codes=" + ",".join(codes))


def stop(name):
    started = time.monotonic()
    docker("stop", "-t", "8", name)
    assert time.monotonic() - started < 10, "docker stop超过10秒"
    ended(name, 0)
    assert not inspect(name)["State"].get("OOMKilled"), "停止时被强杀/OOM"


def stop_api():
    docker("stop", "-t", "8", API)


def restore_api():
    docker("start", API)
    wait(api_ready, 20)


def build(file, image, config=None):
    images.append(image)
    args = ["docker", "build", "--memory=1536m", "-f", file, "-t", image]
    if config is not None:
        SENSITIVE.add(config)
        args += ["--build-arg", "AUTHGO_CONFIG=" + config, "--build-arg", "VERSION=1.0.0"]
    args.append(".")
    p = subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # Build output is not dumped on failure; it can contain a compiler command.
    (TMP / (image + ".build.log")).write_text(p.stdout)
    assert p.returncode == 0, "镜像构建失败: " + image


def case(number, title, fn):
    try:
        fn()
    except Exception as e:
        # Print only our assertions; never leak subprocess args or HTTP bodies.
        detail = str(e) if isinstance(e, AssertionError) else type(e).__name__
        print(f"FAIL {number:02d} {title}: {detail}", flush=True)
        results.append(False)
        raise
    print(f"PASS {number:02d} {title}", flush=True)
    results.append(True)


def suite():
    print("LANGUAGE " + LANGUAGE + ": 准备真实Auth Go与编译配置（不输出凭据）", flush=True)
    build("Dockerfile", IMAGE)
    api_start()
    app = request("/api/v1/admin/applications", {"name": "instance真实容器", "heartbeat_interval": 5, "next_check_in": 1, "grace_hours": 72})
    state["app"] = app
    state["user_id"] = request("/api/v1/admin/users", {"name": "容器测试用户", "email": "docker-test@example.invalid"})["id"]
    config = request("/api/v1/admin/applications/" + str(app["id"]) + "/connection", {"url": state["base"]})["config"]
    build(EXAMPLE_FILE, APP_IMAGE, config)
    build(CLOCK_FILE, CLOCK_IMAGE, config)

    lic, v = license_new(), volume_new("persistent")
    a = start("first", lic, v)
    def secure():
        ready(a)
        info = inspect(a)
        assert info["Config"]["User"] == "65532:65532"
        assert info["HostConfig"]["ReadonlyRootfs"] and "ALL" in info["HostConfig"]["CapDrop"]
        assert "no-new-privileges:true" in info["HostConfig"]["SecurityOpt"]
        assert any(m["Destination"] == "/var/lib/authgo" and m["RW"] for m in info["Mounts"])
        # Extra assertion; none of the original 19 cases are relaxed. A real
        # paused backend leaves initial verification in flight, not a fixture.
        pending_license = license_new()
        docker("pause", API)
        try:
            pending = start("stop-during-startup", pending_license, volume_new("startup-stop"))
            time.sleep(0.5)
            assert running(pending) and "HTTP已启动" not in logs(pending), "首次验证没有按预期等待后端"
            started = time.monotonic()
            docker("stop", "-t", "8", pending)
            assert time.monotonic() - started < 10, "首次验证期间停止超过10秒"
            info = inspect(pending)["State"]
            assert not info["Running"] and info["ExitCode"] != 137 and not info["OOMKilled"], "首次验证期间停止被强杀"
        finally:
            docker("unpause", API)

    case(1, "只读根/非root/drop ALL/缓存卷激活", secure)
    original = sorted((r["kind"], r["instance_id"]) for r in activations(lic))
    original_instance_ids = {r["id"] for r in activations(lic) if r["kind"] == "floating"}
    def restart():
        docker("restart", "-t", "8", a)
        wait(lambda: running(a) and logs(a).count("HTTP已启动") >= 2)
        time.sleep(1)
        assert original == sorted((r["kind"], r["instance_id"]) for r in activations(lic)), "重启改变了稳定实例或会话锚点"
        assert not original_instance_ids.intersection(r["id"] for r in activations(lic) if r["kind"] == "floating"), "正常停止没有删除旧实例"
    case(2, "restart保持稳定身份并重建已释放实例", restart)
    def recreate():
        nonlocal a
        stop(a)
        docker("rm", a)
        a = start("recreated", lic, v)
        ready(a)
        assert original == sorted((r["kind"], r["instance_id"]) for r in activations(lic))
    case(3, "保留卷重建保持实例", recreate)
    def new_volume():
        nonlocal a
        stop(a)
        docker("rm", a)
        docker("volume", "rm", v)
        volume_new("persistent")
        a = start("fresh-volume", lic, v)
        ready(a)
        assert len(activations(lic)) > len(original), "删除卷没有生成新会话锚点"
        assert {r["instance_id"] for r in activations(lic) if r["kind"] == "floating"} != {value for kind,value in original if kind == "floating"}, "删除卷没有生成新实例身份"
        stop(a)
    case(4, "删除卷生成新实例", new_volume)

    seats = license_new()
    one = start("seat-one", seats, volume_new("seat-one"))
    two = start("seat-two", seats, volume_new("seat-two"))
    ready(one); ready(two)
    three_volume = volume_new("seat-three")
    three = start("seat-denied", seats, three_volume)
    case(5, "上限2/第三实例退出77并说明", lambda: ended(three, text="FLOATING_LIMIT_REACHED"))
    def release():
        nonlocal three
        stop(one)
        three = start("seat-after-stop", seats, three_volume)
        ready(three)
    case(6, "docker stop立即释放席位", release)
    def kill_reclaim():
        probe = None
        if LANGUAGE == "java":
            probe = start("reclaim-probe", seats, volume_new("reclaim-probe"), CLOCK_IMAGE, command_args=["--reclaim-probe"])
            wait(lambda: "reclaim probe ready" in logs(probe) or not running(probe), 15, "真实SDK回收探针未就绪")
            assert running(probe) and "authenticated FLOATING_LIMIT_REACHED" in logs(probe), "回收前必须完整认证并拒绝满额实例"
        docker("kill", two)
        started = time.monotonic()
        deadline = started + 10
        trace = {"killed_wall_time": time.time(), "deadline_seconds": 10.7, "attempts": []}
        try:
            if probe is not None:
                # JVM bootstrap is outside the lease timer. Real signed SDK checks,
                # the original 250ms cadence, and the original 10.7s bound remain.
                docker("exec", probe, "sh", "-c", "touch /var/lib/authgo/reclaim.trigger")
                wait(lambda: "RECLAIM_GRANTED" in logs(probe) or not running(probe), 10.7, "席位回收超时")
                elapsed = time.monotonic() - started
                trace["probe"] = "prewarmed real Java SDK; no clock override"
                trace["attempts"].append({"observed_seconds": elapsed})
                assert "RECLAIM_GRANTED" in logs(probe), "真实SDK未重新取得席位"
                assert elapsed <= deadline - started + 0.7, "席位回收超过2个心跳间隔"
                ended(probe, code=0)
                return
            # Retry real activation until its original lease expires, bounded by 2H.
            for i in range(30):
                n = start("after-kill-" + str(i), seats, volume_new("after-kill"))
                wait(lambda: "HTTP已启动" in logs(n) or not running(n), 3)
                trace["attempts"].append({"attempt": i, "observed_seconds": time.monotonic() - started})
                if running(n) and "HTTP已启动" in logs(n):
                    assert time.monotonic() <= deadline + 0.7, "席位回收超过2个心跳间隔"
                    stop(n)
                    return
                ended(n, text="FLOATING_LIMIT_REACHED")
                assert time.monotonic() < deadline + 0.7, "席位回收超时"
                time.sleep(0.25)
            raise AssertionError("未回收席位")
        finally:
            # Observe the failed/successful boundary. Never persist keys or configurations.
            try:
                trace["leases_after"] = [
                    {key: row.get(key) for key in ("id", "created_at", "last_seen_at", "lease_expires_at", "status")}
                    for row in activations(seats) if row["kind"] == "floating"
                ]
                trace["online_instances_after"] = request("/api/v1/admin/licenses/" + str(seats["id"]))["online_instances"]
            except Exception as error:
                trace["snapshot_error_type"] = type(error).__name__
            report = ROOT / "sdk/conformance/reports"
            report.mkdir(parents=True, exist_ok=True)
            (report / ("docker-" + LANGUAGE + "-reclaim-timing.json")).write_text(json.dumps(trace, indent=2))
    case(7, "docker kill在两个心跳间隔内回收", kill_reclaim)
    stop(three)

    outage = license_new()
    va, vb = volume_new("outage-a"), volume_new("outage-b")
    oa, ob = start("outage-running", outage, va), start("outage-stopped", outage, vb)
    ready(oa); ready(ob); stop(ob)
    clock_license = license_new()
    clock = start("short-grace", clock_license, volume_new("clock"), CLOCK_IMAGE)
    wait(lambda: "clock ready" in logs(clock))
    def beyond_lease():
        stop_api()
        wait(lambda: "授权状态: grace" in logs(oa))
        time.sleep(11)
        assert running(oa), "原lease到期后错误退出"
    case(8, "停Auth Go超过原lease仍运行", beyond_lease)
    def outage_restarts():
        docker("restart", "-t", "8", oa)
        wait(lambda: logs(oa).count("HTTP已启动") >= 2 and running(oa))
        n = start("outage-released-restart", outage, vb)
        ready(n)
        assert "授权状态: grace" in logs(n)
        docker("kill", n)
    case(9, "断网重启含正常释放过的缓存实例", outage_restarts)
    no_cache = start("outage-empty", outage, volume_new("empty"))
    case(10, "断网空卷新实例退出77", lambda: ended(no_cache, text="SDK_NETWORK_ERROR"))
    case(11, "短宽限窗口结束退出（仅测试时钟推进）", lambda: ended(clock, text="SDK_GRACE_EXPIRED"))
    def zero():
        restore_api()
        # A separate application: changing the running outage instance's policy
        # to zero would destroy the very recovery behavior tested by case 13.
        app_zero = request("/api/v1/admin/applications", {"name": "零宽限容器", "heartbeat_interval": 5, "next_check_in": 1, "grace_hours": 0})
        zero_config = request("/api/v1/admin/applications/" + str(app_zero["id"]) + "/connection", {"url": state["base"]})["config"]
        zero_image = PREFIX + "zero"
        build(EXAMPLE_FILE, zero_image, zero_config)
        l = request("/api/v1/admin/licenses", {"app_id": app_zero["id"], "user_id": state["user_id"], "verify_methods": ["KEY", "FLOATING"], "max_activations": 2})
        n = start("zero-grace", l, volume_new("zero"), zero_image)
        ready(n)
        stop_api()
        ended(n, text="SDK_GRACE_EXPIRED")
        restore_api()
    case(12, "grace_hours=0不提供离线宽限", zero)
    def recover():
        wait(lambda: "授权状态: online" in logs(oa).split("授权状态: grace")[-1])
        assert running(oa)
    case(13, "恢复Auth Go回online", recover)
    def revoke():
        request("/api/v1/admin/licenses/" + str(outage["id"]) + "/revoke", {}, "POST")
        # Existing management revoke retires the carriers too; sessionValid
        # therefore returns authenticated ACTIVATION_INVALID before evaluation.
        # Keep that protocol behavior: the requirement is immediate exit 77.
        ended(oa, text="ACTIVATION_INVALID")
    case(14, "吊销后下次校验退出77", revoke)

    def shared():
        l = license_new()
        vol = volume_new("shared")
        a = start("shared-old", l, vol); ready(a)
        b = start("shared-new", l, vol); ready(b)
        ended(a, text="INSTANCE_REPLACED")
        time.sleep(2)
        assert running(b), "共享卷两实例都退出"
        stop(b)
    case(15, "共卷接管/旧实例INSTANCE_REPLACED", shared)
    def disabled():
        l = license_new()
        n = start("version-disabled", l, volume_new("version")); ready(n)
        version = request("/api/v1/admin/applications/" + str(app["id"]) + "/versions", {"version": "1.0.0", "changelog": "测试"})
        request("/api/v1/admin/versions/" + str(version["id"]), {"disabled": True}, "PATCH")
        ended(n, text="VERSION_DISABLED")
        request("/api/v1/admin/versions/" + str(version["id"]), {"disabled": False}, "PATCH")
    case(16, "禁用当前版本退出77", disabled)
    def readonly():
        l = license_new()
        n = start("unwritable", l)
        ready(n)
        assert "此实例重启后是新实例，没有断连宽限" in logs(n)
        assert running(n)
        stop(n)
    case(17, "缓存不可写仍运行并明确警告", readonly)
    def crash_takeover():
        l = license_new()
        v = volume_new("crash")
        a = start("crash-old", l, v); ready(a)
        b = start("crash-other", l, volume_new("crash-other")); ready(b)
        before = [(r["id"],r["instance_id"]) for r in activations(l)]
        docker("kill", a)
        new = start("crash-new", l, v); ready(new)
        assert before == [(r["id"],r["instance_id"]) for r in activations(l)]
        assert running(b)
        stop(new); stop(b)
    case(18, "满额崩溃立即重启接管自己的席位", crash_takeover)
    def pinned():
        api_start(True)
        other_app = request("/api/v1/admin/applications", {"name": "不受信的另一台Auth Go"}, other=True)
        attacker = request("/api/v1/admin/applications/" + str(other_app["id"]) + "/connection", {"url": state["other_base"]}, other=True)["config"]
        l = license_new()
        n = start("pinned-config", l, volume_new("pinned"), extra_env={"AUTHGO_CONFIG": attacker})
        ready(n)
        assert activations(l), "没有连接编译时的服务器"
        assert request("/api/v1/admin/activations", other=True)["total"] == 0, "环境变量改变了信任根"
        stop(n)
    case(19, "AUTHGO_CONFIG环境变量不能替换编译信任根", pinned)
    import importlib.util
    spec=importlib.util.spec_from_file_location("authgo_trial_cases",ROOT/"scripts/trial-docker-cases.py")
    trial_cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(trial_cases)
    trial_cases.cli(sys.modules[__name__])


def failure_logs():
    # Only our business examples: never dump the API's setup/authentication log.
    report = ROOT / "sdk" / "conformance" / "reports" / ("docker-" + LANGUAGE + ".log")
    report.parent.mkdir(parents=True, exist_ok=True)
    sections = []
    for name in containers:
        if name in (API, API2): continue
        try:
            info = inspect(name)["State"]
            text = logs(name)
            for secret in SENSITIVE:
                text = text.replace(secret, "[redacted]")
            text = re.sub(r"authgo[12]\.[A-Za-z0-9_-]+|act_[A-Za-z0-9_-]+", "[redacted]", text)
            sections.append(name + " " + json.dumps(info) + "\n" + "\n".join(text.splitlines()[-12:]))
        except (AssertionError, ValueError): pass
    report.write_text("\n\n".join(sections))
    print("容器诊断: " + str(report), flush=True)


def cleanup():
    for name in reversed(containers):
        docker("rm", "-f", name, check=False)
    if TMP:
        for file, project in (("compose.json", "main"), ("other-compose.json", "other")):
            if (TMP / file).exists():
                docker("compose", "-p", PREFIX + project, "-f", str(TMP / file), "down", check=False)
    for name in reversed(volumes):
        docker("volume", "rm", name, check=False)
    for name in reversed(images):
        docker("image", "rm", name, check=False)
    if TMP:
        shutil.rmtree(TMP, ignore_errors=True)


def main():
    global TMP, LANGUAGE, EXAMPLE_FILE, CLOCK_FILE
    selected = [part for arg in sys.argv[1:] for part in arg.split(",")]
    if not selected: selected = ["all"]
    if selected == ["all"]: selected = ["go", "python", "node", "rust", "java", "csharp", "php", "php-fpm"]
    if any(lang not in ["go", "python", "node", "rust", "java", "csharp", "php", "php-fpm"] for lang in selected):
        print("用法: test-docker-license.sh [go,python,node,rust,java,csharp,php,php-fpm|all]", flush=True)
        return 2
    if len(selected) > 1:
        codes = []
        for lang in selected:
            code = subprocess.call([sys.executable, str(pathlib.Path(__file__).resolve()), lang])
            codes.append(code)
        print("DOCKER_SUMMARY " + " ".join(lang + "=" + str(code) for lang, code in zip(selected, codes)), flush=True)
        return 0 if not any(codes) else 1
    LANGUAGE = selected[0]
    if LANGUAGE != "go":
        EXAMPLE_FILE = "examples/docker/" + LANGUAGE + "/Dockerfile"
        CLOCK_FILE = "scripts/fixtures/docker-clock-" + LANGUAGE + ".Dockerfile"
    for directory in (ROOT, pathlib.Path(tempfile.gettempdir())):
        if shutil.disk_usage(directory).free < 10 * 1024**3:
            print("FAIL 可用磁盘不足10GB: " + str(directory), flush=True)
            return 1
    TMP = pathlib.Path(tempfile.mkdtemp(prefix=".authgo-dockertest-", dir=ROOT))
    os.chmod(TMP, 0o700)
    ok = False
    try:
        if LANGUAGE == "php-fpm":
            import importlib.util
            spec=importlib.util.spec_from_file_location("authgo_fpm_test",ROOT / "scripts/test-php-fpm-license.py")
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            module.suite(sys.modules[__name__])
        else:
            suite()
        ok = True
    except Exception as e:
        if not results or results[-1]:
            detail = str(e) if isinstance(e, AssertionError) else type(e).__name__
            print("FAIL 容器测试准备/执行: " + detail, flush=True)
    finally:
        try:
            if not ok: failure_logs()
        finally:
            cleanup()
    expected=15 if LANGUAGE=="php-fpm" else 26
    print(f"SUMMARY {LANGUAGE} {sum(results)}/{expected} PASS; failures={expected - sum(results)}", flush=True)
    return 0 if ok and len(results) == expected and all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
