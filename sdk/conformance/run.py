#!/usr/bin/env python3
"""Official-image test runner. No bind mounts, Git, real GitHub, or package publishing."""

import threading
import io, hashlib
import contextlib, json, os, pathlib, shutil, subprocess, sys, tarfile, tempfile, time, urllib.request, uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
scope = ROOT.parent.name
if not scope or not scope[0].isascii() or not scope[0].isalnum() or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in scope):
    scope = "sdk"
RESOURCE_PREFIX = f"authgo-{scope}-sdk"
# run.sh preserves the checkout scope when sources are streamed into /work.
_session = os.environ.get("AUTHGO_SDK_SESSION", "")
if _session.startswith("authgo-") and "-sdk-" in _session and all(c in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in _session):
    RESOURCE_PREFIX = _session.rsplit("-sdk-", 1)[0] + "-sdk"
IMAGES = {
    "go": "alpine:3.22.2",
    "python": "python:3.9-slim",
    "node": "node:22-alpine",
    "java": "eclipse-temurin:17-jdk",
    "csharp": "mcr.microsoft.com/dotnet/sdk:8.0",
    "php": "php:8.1-cli",
    "rust": "rust:1.96.1",
}
COMMANDS = {
    "go": "cd /work/sdk/go && /work/go.test -test.v && AUTHGO_SDK_RUNNER=1 /work/go.test -test.run ^TestConformanceRunner$",
    "python": "pip -q install ./sdk/python && python -m py_compile sdk/python/example.py && python sdk/python/tests/vectors.py && python -m unittest discover -s sdk/python/tests -p 'test_*.py' && python sdk/python/tests/guard.py && python sdk/conformance/python.py",
    "node": "node --check sdk/node/example.mjs && node --test sdk/node/test/*.test.js && node sdk/conformance/node.mjs",
    "java": "mkdir -p /tmp/java-out && javac -d /tmp/java-out sdk/java/src/main/java/io/authgo/*.java sdk/java/src/test/java/io/authgo/*.java sdk/java/Example.java && java -cp /tmp/java-out io.authgo.Vectors && java -cp /tmp/java-out io.authgo.Runner",
    "csharp": "dotnet build sdk/csharp/Example/Example.csproj --nologo && dotnet run --project sdk/csharp/Tests/Tests.csproj && dotnet run --no-build --project sdk/csharp/Tests/Tests.csproj -- runner",
    "php": "php -l sdk/php/example.php && php sdk/php/tests/vectors.php && php sdk/php/tests/guard.php && php sdk/conformance/php.php",
    "rust": "cd sdk/rust && rustup component add clippy rustfmt && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test -- --nocapture && cargo run --quiet --example runner",
}


def docker(*args, **kw):
    return subprocess.run(["docker", *args], check=True, **kw)


def package(dest, paths):
    with tarfile.open(dest, "w") as t:
        for name in paths:
            p = ROOT / name
            t.add(
                p,
                arcname=name,
                filter=lambda i: (
                    None
                    if any(
                        s in pathlib.PurePosixPath(i.name).parts
                        for s in [
                            "reports",
                            "target",
                            "node_modules",
                            "bin",
                            "obj",
                            "out",
                            "__pycache__",
                            ".venv",
                        ]
                    )
                    or pathlib.PurePosixPath(i.name).name.startswith(("._", ".env"))
                    or pathlib.PurePosixPath(i.name).name == "master.key"
                    or pathlib.PurePosixPath(i.name).suffix
                    in [".db", ".cache", ".lic", ".test"]
                    else i
                ),
            )


def api(path, data=None):
    r = urllib.request.Request(
        "http://127.0.0.1:18091" + path,
        json.dumps(data).encode() if data is not None else None,
        {"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(r, timeout=20) as response:
        return response.read()


def main():
    subprocess.run([sys.executable, str(ROOT / "sdk/conformance/test_disk_guard.py")], check=True)
    subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL)
    work = pathlib.Path(
        os.environ.get("AUTHGO_SDK_REPORT_DIR")
        or tempfile.mkdtemp(prefix=RESOURCE_PREFIX + "-")
    )
    work.mkdir(parents=True, exist_ok=True)
    (work / "results.json").write_text("{}\n")
    names = []
    runid = uuid.uuid4().hex[:10]
    try:
        arch = subprocess.check_output(
            ["docker", "info", "--format", "{{.Architecture}}"], text=True
        ).strip()
        arch = "arm64" if arch in ["aarch64", "arm64"] else "amd64"
        env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH=arch)
        with (work / "build.log").open("w") as build_log:
            subprocess.run(
                ["go", "test", "-c", "-o", str(work / "host.test"), "./internal/sdkconformance"],
                cwd=ROOT / "server",
                env=env,
                check=True, stdout=build_log, stderr=subprocess.STDOUT,
            )
            subprocess.run(
                ["go", "test", "-c", "-o", str(work / "go.test"), "."],
                cwd=ROOT / "sdk/go",
                env=env,
                check=True, stdout=build_log, stderr=subprocess.STDOUT,
            )
        host = RESOURCE_PREFIX + "-host-" + runid
        names.append(host)
        docker(
            "create",
            "--memory", "512m", "--cpus", "1",
            "--label",
            "authgo.sdk.session=" + os.environ.get("AUTHGO_SDK_SESSION", runid),
            "--name",
            host,
            "-p",
            "127.0.0.1:18091:18091",
            "-w",
            "/work",
            "-e",
            "AUTHGO_SDK_CONFORMANCE=1",
            IMAGES["go"],
            "/work/host.test",
            "-test.run",
            "^TestSDKConformanceHost$",
            "-test.timeout",
            "30m",
            stdout=subprocess.DEVNULL,
        )
        with tarfile.open(work / "host.tar", "w") as t:
            t.add(work / "host.test", arcname="host.test")
        with open(work / "host.tar", "rb") as f:
            docker("cp", "-", host + ":/work", stdin=f, stdout=subprocess.DEVNULL)
        docker("start", host, stdout=subprocess.DEVNULL)
        for _ in range(100):
            @contextlib.contextmanager
            def peer(env=None, user=None):
                nonlocal process
                commands = {
                    "go": "AUTHGO_SDK_RUNNER=1 /work/go.test -test.run '^TestConformanceRunner$'",
                    "python": "python sdk/conformance/python.py",
                    "node": "node sdk/conformance/node.mjs",
                    "java": "java -cp /tmp/java-out io.authgo.Runner",
                    "csharp": "dotnet sdk/csharp/Tests/bin/Debug/net8.0/Tests.dll runner",
                    "php": "php sdk/conformance/php.php",
                    "rust": "/work/sdk/rust/target/debug/examples/runner",
                }
                args=["docker","exec","-i"]
                if user:args += ["--user",user]
                for k,v in (env or {}).items():args += ["-e",k+"="+v]
                args += [name,"sh","-c",commands[lang]]
                child=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,bufsize=1)
                parent=process;process=child
                try:yield
                finally:
                    child.stdin.close()
                    try:child.wait(timeout=10)
                    except subprocess.TimeoutExpired:child.terminate()
                    process=parent

            try:
                fixture = json.loads(api("/fixture"))
                break
            except urllib.error.HTTPError as error:
                raise RuntimeError(f"conformance fixture HTTP {error.code}") from None
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("conformance host unavailable")
        results = {}
        failures = []
        for lang, image in IMAGES.items():
            if os.environ.get("AUTHGO_SDK_LANGUAGES") and lang not in os.environ[
                "AUTHGO_SDK_LANGUAGES"
            ].split(","):
                continue
            name = RESOURCE_PREFIX + "-" + lang + "-" + runid
            names.append(name)
            archive = work / (lang + ".tar")
            package(archive, ["sdk/" + lang, "sdk/vectors", "sdk/conformance"])
            if lang == "go":
                with tarfile.open(archive, "a") as t:
                    t.add(work / "go.test", arcname="go.test")
            docker(
                "create",
                "--memory", "1536m", "--cpus", "2",
                "--label",
                "authgo.sdk.session=" + os.environ.get("AUTHGO_SDK_SESSION", runid),
                "--name",
                name,
                "--network",
                "container:" + host,
                "-i",
                "-w",
                "/work",
                image,
                "sh",
                "-c",
                COMMANDS[lang],
                stdout=subprocess.DEVNULL,
            )
            with open(archive, "rb") as f:
                docker("cp", "-", name + ":/work", stdin=f, stdout=subprocess.DEVNULL)
            log = open(work / (lang + ".log"), "w")
            process = subprocess.Popen(
                ["docker", "start", "-ai", name],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=log,
                text=True,
                bufsize=1,
            )

            watchdog = threading.Timer(1200, process.kill)
            watchdog.daemon = True
            watchdog.start()

            def command(p):
                proc=process
                def timed_out():
                    # Kill only this language's owned runtime; killing docker CLI
                    # alone would leave a busy SDK process on the shared server.
                    subprocess.run(["docker","kill",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    with contextlib.suppress(ProcessLookupError):proc.kill()
                timer=None
                if getattr(proc,"_authgo_ready",False):
                    timer=threading.Timer(45,timed_out)
                    timer.daemon=True
                    timer.start()
                try:
                    process.stdin.write(json.dumps(p) + "\n")
                    process.stdin.flush()
                    while True:
                        line = process.stdout.readline()
                        if not line:
                            raise RuntimeError(
                                lang
                                + " exited before response; see "
                                + str(work / (lang + ".log"))
                            )
                        safe_line=line
                        try:
                            safe=json.loads(line)
                            if isinstance(safe,dict) and "request" in safe:
                                safe_line=json.dumps(dict(safe,request="[redacted offline request]"))+"\n"
                        except (ValueError,TypeError):
                            pass
                        log.write(safe_line)
                        log.flush()
                        try:
                            out = json.loads(line)
                            if "code" in out:
                                process._authgo_ready = True
                                return out
                        except (ValueError, TypeError):
                            pass
                finally:
                    if timer is not None:timer.cancel()

            def cache_snapshot(directory="/tmp/authgo-sdk-conformance"):
                raw = subprocess.check_output(["docker", "cp", name + ":" + directory + "/.", "-"])
                with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                    return {item.name: hashlib.sha256(archive.extractfile(item).read()).hexdigest()
                            for item in archive if item.isfile()}

            samples = []

            def expect(label, request, code="OK", status=None):
                out = command(request)
                check = {"code": out.get("code")}
                if status is not None:
                    check["status"] = out.get("status")
                want = {"code": code}
                if status is not None:
                    want["status"] = status
                record = dict(scenario=label, **check)
                for field in ["available", "version", "docker_image", "docker_pull", "count", "latest_version", "latest_entitled_version", "maintenance_until", "is_trial", "cache_warning"]:
                    if field in out:
                        record[field] = out[field]
                samples.append(record)
                if check != want:
                    raise AssertionError(f"{lang}/{label}: {out!r}, expected {want!r}")
                return out

            try:
                fixture = json.loads(api("/fixture"))
                key = fixture["key"]
                other = fixture["other_key"]
                base = dict(
                    op="init",
                    config=fixture["config"],
                    time=fixture["time"],
                    cache_dir="/tmp/authgo-sdk-conformance",
                )
                expect("init", base, status="ready")
                expect("activate", dict(op="check", key=key), status="online")
                expect("verify", dict(op="check", key=key), status="online")
                unknown = json.loads((ROOT / "sdk/vectors/license-key.json").read_text())["cases"][0]["key"]
                if unknown == key:
                    raise AssertionError("unknown key fixture collision")
                for scenario, candidate, code in [
                    ("invalid_key_format", "abc", "INVALID_LICENSE_KEY"),
                    ("unknown_key", unknown, "LICENSE_NOT_FOUND"),
                ]:
                    for entry in ["check", "activate"]:
                        before = cache_snapshot()
                        if not before:
                            raise AssertionError("activation cache missing")
                        expect(scenario + "_" + entry, dict(op=entry, key=candidate), code=code)
                        if cache_snapshot() != before:
                            raise AssertionError(lang + "/" + scenario + ": activation cache changed")
                        api("/control", dict(mode="disconnect"))
                        expect(scenario + "_" + entry + "_memory", dict(op="verify"), status="grace")
                        expect(scenario + "_" + entry + "_restart", base, status="ready")
                        expect(scenario + "_" + entry + "_cached", dict(op="check", key=key), status="grace")
                        api("/control", dict(mode=""))
                        expect(scenario + "_" + entry + "_recovered", dict(op="check", key=key), status="online")

                expect("heartbeat", dict(op="heartbeat"), status="online")
                expect("announcements", dict(op="announcements"))
                expect("update", dict(op="check_update", version="1.0.0"))
                for mode, label in [
                    ("disconnect", "offline"),
                    ("502", "proxy_502"),
                    ("html", "html"),
                    ("INTERNAL_ERROR", "temporary"),
                    ("tamper", "tamper"),
                    ("bad-ticket", "bad_ticket"),
                    ("no-ticket", "missing_ticket"),
                    ("expired-ticket", "expired_ticket"),
                    ("no-signature", "no_signature"),
                ]:
                    api("/control", dict(mode=mode))
                    expect(label, dict(op="verify"), status="grace")
                    expect(label + "_reload", base, status="ready")
                    expect(label + "_restart_grace", dict(op="verify"), status="grace")
                api("/control", dict(mode=""))
                expect("recover", dict(op="verify"), status="online")
                api("/control", dict(mode="LICENSE_REVOKED"))
                expect("update_refusal", dict(op="check_update"), code="LICENSE_REVOKED")
                api("/control", dict(mode="502"))
                expect("update_preserves_cache", dict(op="verify"), status="grace")
                api("/control", dict(mode=""))
                expect("clock_back", dict(op="clock", seconds=-301))
                api("/control", dict(mode="502"))
                expect("clock_rollback", dict(op="verify"), code="SDK_CLOCK_ROLLBACK")
                expect("clock_restore", dict(op="clock", seconds=301))
                api("/control", dict(mode=""))
                expect("clock_recovery", dict(op="verify"), status="online")
                expect("clock_forward", dict(op="clock", seconds=73 * 3600))
                api("/control", dict(mode="502"))
                expect("expired_grace", dict(op="verify"), code="SDK_GRACE_EXPIRED")
                expect("clock_normal", dict(op="clock", seconds=-73 * 3600))
                api("/control", dict(mode=""))
                expect("online_after_expiry", dict(op="verify"), status="online")
                api("/control", dict(user="disabled"))
                expect("disabled", dict(op="verify"), code="USER_DISABLED")
                api("/control", dict(user="active"))
                expect("enabled", dict(op="verify"), status="online")
                api("/control", dict(status="suspended"))
                expect("suspended", dict(op="verify"), code="LICENSE_SUSPENDED")
                api("/control", dict(status="active"))
                expect("resumed", dict(op="verify"), status="online")
                api("/control", dict(status="suspended"))
                expect(
                    "activate_refusal",
                    dict(op="activate", key=key),
                    code="LICENSE_SUSPENDED",
                )
                api("/control", dict(mode="502", status="active"))
                expect("activate_refusal_reload", base, status="ready")
                expect(
                    "activate_refusal_clears",
                    dict(op="verify"),
                    code="SDK_NOT_ACTIVATED",
                )
                api("/control", dict(mode=""))
                expect("activate_recovery", dict(op="check", key=key), status="online")
                expect("switch_key", dict(op="check", key=other), status="online")
                expect("switch_back", dict(op="check", key=key), status="online")
                api("/control", dict(mode="UNKNOWN_AUTHENTICATED_ERROR"))
                before = cache_snapshot()
                expect("unknown_update_refusal", dict(op="check_update"), code="UNKNOWN_AUTHENTICATED_ERROR")
                assert cache_snapshot() == before, "informational update failure changed authorization cache"
                expect("unknown_authorization_refusal", dict(op="verify"), code="UNKNOWN_AUTHENTICATED_ERROR")
                api("/control", dict(mode="502"))
                denied=command(dict(op="verify"))
                assert denied.get("code") != "OK" and "status" not in denied, "unknown authenticated refusal reopened cached grace"
                api("/control", dict(mode=""))
                expect("unknown_refusal_online_recovery", dict(op="check", key=key), status="online")

                api("/control", dict(status="active"))
                expect("dockerhub_recovery", dict(op="verify"), status="online")
                expect("grace_expiry_clock", dict(op="clock", seconds=73*3600))
                api("/control", dict(mode="disconnect"))
                expect("grace_expired", dict(op="verify"), code="SDK_GRACE_EXPIRED")
                expect("grace_expiry_reset", dict(op="clock", seconds=-73*3600))
                api("/control", dict(mode=""))
                expect("grace_online_recovery", dict(op="verify"), status="online")
                api("/control", dict(status="revoked"))
                expect(
                    "revoked_update_check", dict(op="check_update"), code="LICENSE_REVOKED"
                )
                expect("revoked", dict(op="verify"), code="LICENSE_REVOKED")
                expect(
                    "unbind_prepare",
                    dict(op="check", key=fixture["third_key"]),
                    status="online",
                )
                api("/control", dict(mode="LICENSE_SUSPENDED"))
                expect(
                    "unbind_failure", dict(op="deactivate"), code="LICENSE_SUSPENDED"
                )
                api("/control", dict(mode="502"))
                expect("unbind_failure_preserves", dict(op="verify"), status="grace")
                api("/control", dict(mode=""))
                expect("unbind", dict(op="deactivate"))
                expect("unbound_no_cache", dict(op="verify"), code="SDK_NOT_ACTIVATED")
                expect(
                    "rebind",
                    dict(op="check", key=fixture["third_key"]),
                    status="online",
                )

                # Instance and floating-lease scenarios exercised by every real SDK.
                def control(**values):return json.loads(api("/control",values))
                def fresh(label, **policy):
                    f=json.loads(api("/fixture"))
                    if policy:control(**policy)
                    b=dict(op="init",config=f["config"],time=f["time"],cache_dir="/tmp/authgo-sdk-"+label)
                    expect(label+"_init",b,status="ready")
                    return f,b

                f,b=fresh("floating",floating=True,heartbeat=2,grace_hours=1)
                expect("floating_online",dict(op="check",key=f["key"]),status="online")
                assert control()["session_valid"], "invalid instance_session encoding"
                expect("floating_lease_passed",dict(op="clock",seconds=10))
                expect("floating_validate_before_fault",dict(op="validate"),code="LEASE_EXPIRED")
                control(mode="disconnect")
                expect("floating_outage_after_lease",dict(op="verify"),status="grace")
                expect("floating_grace_ticket_valid",dict(op="validate"))
                expect("floating_restart_init",dict(b,time=f["time"]+10),status="ready")
                expect("floating_restart_outage",dict(op="check",key=f["key"]),status="grace")
                for temporary in "INTERNAL_ERROR RATE_LIMITED REPLAY_DETECTED TIMESTAMP_INVALID SIGNATURE_INVALID INVALID_REQUEST".split():
                    control(mode=temporary)
                    expect("floating_temporary_"+temporary,dict(op="heartbeat"),status="grace")
                expect("floating_grace_advance",dict(op="clock",seconds=3601))
                control(mode="disconnect")
                expect("floating_grace_expired",dict(op="heartbeat"),code="SDK_GRACE_EXPIRED")
                expect("floating_restore_clock",dict(op="clock",seconds=-3611))
                control()
                expect("floating_online_recovery",dict(op="heartbeat"),status="online")
                expect("floating_again_pass_lease",dict(op="clock",seconds=120))
                control(clock_seconds=120)
                expect("floating_verify_reacquires",dict(op="verify"),status="online")
                expect("floating_heartbeat_reacquire_or_full",dict(op="heartbeat"),status="online")
                # A second identity obtains the now-expired seat; original instance
                # must be refused on recovery, not silently granted outage grace.
                expect("floating_competition_clock",dict(op="clock",seconds=120))
                control(clock_seconds=240)
                other_b=dict(b,time=f["time"]+240,fingerprint="b"*64,cache_dir=b["cache_dir"]+"-other")
                expect("floating_other_init",other_b,status="ready")
                expect("floating_other_wins",dict(op="check",key=f["key"]),status="online")
                expect("floating_original_init",dict(b,time=f["time"]+240),status="ready")
                expect("floating_reacquire_full",dict(op="heartbeat"),code="FLOATING_LIMIT_REACHED")
                control(mode="502")
                expect("floating_full_no_grace",dict(op="verify"),code="SDK_RESPONSE_INVALID")

                f,b=fresh("zero",floating=True,heartbeat=3600,grace_hours=0)
                expect("floating_zero_online",dict(op="check",key=f["key"]),status="online")
                expect("floating_zero_clock",dict(op="clock",seconds=10))
                control(mode="disconnect")
                expect("floating_grace_zero",dict(op="verify"),code="SDK_GRACE_EXPIRED")
                f,b=fresh("expiry",floating=True,heartbeat=2,grace_hours=1,expires_in=5)
                expect("floating_expiry_online",dict(op="check",key=f["key"]),status="online")
                expect("floating_expiry_clock",dict(op="clock",seconds=10))
                control(mode="disconnect")
                expect("floating_expiry_priority",dict(op="heartbeat"),code="LICENSE_EXPIRED")

                f,b=fresh("release",floating=True,heartbeat=2,grace_hours=1)
                expect("release_online",dict(op="check",key=f["key"]),status="online")
                before=cache_snapshot(b["cache_dir"]); stats=control()
                expect("release_seat_preserves_cache",dict(op="release_seat"))
                after=control()
                assert before==cache_snapshot(b["cache_dir"]), "release changed cache"
                assert after["live_leases"]==0 and after["sessions"]==stats["sessions"], "release changed sessions or retained seat"
                control(mode="502")
                expect("release_restart_init",b,status="ready")
                expect("release_offline_restart",dict(op="check",key=f["key"]),status="grace")
                before=cache_snapshot(b["cache_dir"])
                expect("release_network_failure",dict(op="release_seat"),code="SDK_RESPONSE_INVALID")
                assert before==cache_snapshot(b["cache_dir"]),"failed release changed cache"
                control()
                expect("release_recovery",dict(op="heartbeat"),status="online")
                expect("release_other_init",dict(b,fingerprint="b"*64,cache_dir=b["cache_dir"]+"-other"),status="ready")
                expect("release_still_owns_activation",dict(op="check",key=f["key"]),code="FLOATING_LIMIT_REACHED")
                f,b=fresh("key-only",floating=False)
                expect("release_device_online",dict(op="check",key=f["key"]),status="online")
                before=cache_snapshot(b["cache_dir"]);stats=control()
                expect("release_seat_key_only_noop",dict(op="release_seat"))
                assert control()["gateway_calls"]==stats["gateway_calls"] and cache_snapshot(b["cache_dir"])==before,"device release was not a local no-op"

                f,b=fresh("takeover",floating=True,heartbeat=2,grace_hours=1)
                expect("instance_original_online",dict(op="check",key=f["key"]),status="online")
                with peer():
                    expect("instance_peer_init",b,status="ready")
                    expect("instance_session_takeover",dict(op="check",key=f["key"]),status="online")
                control(restart=True)
                before=cache_snapshot(b["cache_dir"])
                expect("instance_replaced_no_cache_clear",dict(op="verify"),code="INSTANCE_REPLACED")
                assert before==cache_snapshot(b["cache_dir"]),"old process invalidated replacement cache"
                expect("instance_old_validate",dict(op="validate"),code="INSTANCE_REPLACED")
                control(mode="502")
                expect("instance_old_no_fallback",dict(op="heartbeat"),code="INSTANCE_REPLACED")
                expect("instance_old_new_client",b,status="ready")
                expect("instance_old_cannot_forget",dict(op="check",key=f["key"]),code="INSTANCE_REPLACED")
                expect("instance_old_fresh_cache_init",dict(b,cache_dir=b["cache_dir"]+"-fresh"),status="ready")
                expect("instance_old_cannot_forget_other_cache",dict(op="check",key=f["key"]),code="INSTANCE_REPLACED")
                with peer():
                    expect("instance_new_restart_init",b,status="ready")
                    expect("instance_new_cache_survived",dict(op="check",key=f["key"]),status="grace")

                f,b=fresh("versions")
                expect("version_original_online",dict(op="check",key=f["key"]),status="online")
                control(disabled_version="1.0.0")
                out=expect("disabled_version_latest_and_update",dict(op="verify"),code="VERSION_DISABLED")
                assert out.get("latest_version")=="2.1.0","missing latest allowed version"
                expect("disabled_version_update",dict(op="check_update",version="1.0.0"))
                expect("version_unreported_init",dict(b,unversioned=True),status="ready")
                expect("version_unreported_unaffected",dict(op="check",key=f["other_key"]),status="online")

                # Maintenance decisions are online-only and apply identically to
                # activation, verification, heartbeat and recovered cached grants.
                for boundary in ["before", "equal"]:
                    f,b=fresh("maintenance-"+boundary)
                    control(maintenance_case=boundary)
                    expect("maintenance_"+boundary+"_online",dict(op="check",key=f["key"]),status="online")
                    fields=expect("maintenance_"+boundary+"_fields",dict(op="entitlement"))
                    assert fields["maintenance_until"]=="2020-01-02T00:00:00Z" and fields["latest_entitled_version"]=="2.0.0"
                    update=expect("maintenance_"+boundary+"_update",dict(op="check_update",version="1.0.0"))
                    assert update["available"] and update["version"]=="2.0.0"
                f,b=fresh("maintenance-refusal")
                control(maintenance_case="after")
                refused=expect("maintenance_start_refused",dict(op="check",key=f["key"]),code="MAINTENANCE_EXPIRED")
                assert refused["latest_entitled_version"]=="2.0.0"
                control(maintenance_case="equal")
                expect("maintenance_activate_restored",dict(op="check",key=f["key"]),status="online")
                for operation in ["verify", "heartbeat"]:
                    control(maintenance_case="after")
                    refused=expect("maintenance_"+operation+"_refused",dict(op=operation),code="MAINTENANCE_EXPIRED")
                    assert refused["latest_entitled_version"]=="2.0.0"
                    control(maintenance_case="renew")
                    expect("maintenance_"+operation+"_renewed",dict(op=operation),status="online")
                control(maintenance_case="none")
                refused=expect("maintenance_no_entitled_version",dict(op="verify"),code="MAINTENANCE_EXPIRED")
                assert refused["latest_entitled_version"]==""
                for case in ["unknown", "missing"]:
                    f,b=fresh("maintenance-"+case)
                    control(maintenance_case=case)
                    expect("maintenance_"+case+"_allowed",dict(op="check",key=f["key"]),status="online")
                f,b=fresh("maintenance-unreported")
                control(maintenance_case="after")
                expect("maintenance_unreported_init",dict(b,unversioned=True),status="ready")
                expect("maintenance_unreported_allowed",dict(op="check",key=f["key"]),status="online")
                f,b=fresh("maintenance-grace")
                control(maintenance_case="equal")
                expect("maintenance_grace_online",dict(op="check",key=f["key"]),status="online")
                control(maintenance_case="after",mode="disconnect")
                expect("maintenance_disconnected_cached",dict(op="verify"),status="grace")
                fields=expect("maintenance_cached_fields",dict(op="entitlement"))
                assert fields["maintenance_until"]=="2020-01-02T00:00:00Z" and fields["latest_entitled_version"]=="2.0.0"
                expect("maintenance_cached_ticket_valid",dict(op="validate"))
                expect("maintenance_restart_init",b,status="ready")
                expect("maintenance_restart_grace",dict(op="check",key=f["key"]),status="grace")
                control()
                expect("maintenance_reconnect_refused",dict(op="verify"),code="MAINTENANCE_EXPIRED")
                control(mode="disconnect")
                expect("maintenance_refusal_no_cached_grace",dict(op="verify"),code="SDK_NETWORK_ERROR")
                control(maintenance_case="renew")
                expect("maintenance_recovery_without_reactivation",dict(op="verify"),status="online")

                f,b=fresh("trial-disabled",floating=True,heartbeat=2)
                expect("trial_not_enabled",dict(op="guard_check"),code="TRIAL_DISABLED")
                expect("trial_low_check_still_requires_key",dict(op="check",key=""),code="INVALID_LICENSE_KEY")
                f,b=fresh("trial-start",floating=True,heartbeat=2)
                control(trial_enabled=True)
                expect("trial_start_without_key",dict(op="guard_check"),status="online")
                assert expect("trial_public_result",dict(op="trial_info"))["is_trial"]
                assert control()["trial_count"]==1
                expect("trial_restart_client",b,status="ready")
                calls=control()["gateway_calls"]
                expect("trial_restart_reuses_key",dict(op="guard_check"),status="online")
                assert control()["gateway_calls"]==calls+1 and control()["trial_count"]==1
                with peer():
                    expect("trial_no_volume_new_instance",dict(b,fingerprint="b"*64,cache_dir=b["cache_dir"]+"-other"),status="ready")
                    expect("trial_same_nat_same_license",dict(op="guard_check"),code="FLOATING_LIMIT_REACHED")
                    assert control()["trial_count"]==1
                control(trial_enabled=False)
                expect("trial_disabled_existing_continues",dict(op="verify"),status="online")
                control(mode="disconnect")
                expect("trial_outage_no_grace",dict(op="verify"),code="SDK_GRACE_EXPIRED")
                control()
                expect("trial_online_recovery",dict(op="verify"),status="online")
                control(trial_expire=True)
                expect("trial_expired_refusal",dict(op="verify"),code="LICENSE_EXPIRED")
                expect("trial_expired_restart_init",b,status="ready")
                expect("trial_expired_restart_not_new_trial",dict(op="guard_check"),code="LICENSE_EXPIRED")
                assert control()["trial_count"]==1
                control(trial_convert=True)
                expect("trial_admin_conversion_no_restart",dict(op="verify"),status="online")
                assert not expect("trial_converted_result",dict(op="trial_info"))["is_trial"]
                control(mode="disconnect")
                expect("trial_converted_restores_grace",dict(op="verify"),status="grace")
                f,b=fresh("trial-formal",floating=True,heartbeat=2)
                control(trial_enabled=True)
                expect("trial_before_formal",dict(op="guard_check"),status="online")
                expect("trial_formal_license_activation",dict(op="guard_check",key=f["key"]),status="online")
                assert not expect("trial_formal_result",dict(op="trial_info"))["is_trial"]
                stats=control();assert stats["trial_converted"]==1 and stats["trial_active"]==0
                control(mode="disconnect")
                expect("trial_empty_cache_outage_init",dict(b,cache_dir=b["cache_dir"]+"-empty"),status="ready")
                expect("trial_empty_cache_outage_refuses",dict(op="guard_check"),code="SDK_NETWORK_ERROR")

                # Automatic container identities are tested without a fingerprint
                # override, with a real persisted ID shared across SDK processes.
                f,b=fresh("container",floating=True,heartbeat=2,grace_hours=1)
                b=dict(b,automatic=True)
                expect("container_auto_init",b,status="ready")
                original=expect("container_auto_identity",dict(op="identity"))["fingerprint"]
                expect("container_auto_online",dict(op="check",key=f["key"]),status="online")
                expect("container_same_process_init",b,status="ready")
                assert expect("container_same_identity",dict(op="identity"))["fingerprint"]==original
                expect("container_same_activation",dict(op="check",key=f["key"]),status="online")
                snapshot=cache_snapshot(b["cache_dir"])
                assert any(pathlib.PurePosixPath(k).name=="instance-id" for k in snapshot),"instance identity was not persisted"
                with peer():
                    expect("container_peer_init",b,status="ready")
                    assert expect("container_peer_identity",dict(op="identity"))["fingerprint"]==original
                    expect("container_peer_takeover",dict(op="check",key=f["key"]),status="online")
                with peer({"AUTHGO_INSTANCE_ID":"0","AUTHGO_CONTAINER":"0","AUTHGO_CACHE_DIR":"/tmp/authgo-sdk-env"}):
                    expect("container_env_init",dict(b,cache_dir=b["cache_dir"]+"-explicit"),status="ready")
                    expected=hashlib.sha256(b"authgo/instance/v1\x000").hexdigest()
                    assert expect("container_env_identity",dict(op="identity"))["fingerprint"]==expected
                    expect("container_override_init",dict(b,automatic=False,fingerprint="c"*64),status="ready")
                    assert expect("container_override_identity",dict(op="identity"))["fingerprint"]=="c"*64
                # Existing Go behavior requires persisting the clock watermark
                # before fallback: read-only existing caches fail closed. This
                # differs from a NEW unwritable instance's in-memory fallback.
                subprocess.run(["docker","exec",name,"sh","-c","chown -R 65532:65532 "+b["cache_dir"]+" && chmod 0555 "+b["cache_dir"]],check=True,stdout=subprocess.DEVNULL,stderr=log)
                control(mode="502")
                with peer({"HOME":"/tmp"},user="65532:65532"):
                    expect("container_readonly_init",b,status="ready")
                    expect("container_readonly_watermark_required",dict(op="check",key=f["key"]),code="SDK_CACHE_UNAVAILABLE")
                control()
                bad=dict(b,cache_dir="/proc/authgo-unwritable")
                expect("container_unwritable_init",bad,status="ready")
                expect("container_unwritable_online",dict(op="check",key=f["other_key"]),status="online")
                assert expect("container_unwritable_warning",dict(op="cache_warning"))["cache_warning"],"missing nonpersistent instance warning"
                control(mode="disconnect")
                expect("container_unwritable_memory_grace",dict(op="verify"),status="grace")
                expect("container_unwritable_reload",bad,status="ready")
                expect("container_unwritable_no_restart_grace",dict(op="check",key=f["other_key"]),code="SDK_NETWORK_ERROR")

                required_cases=json.loads((ROOT/"sdk/vectors/instance-session.json").read_text())["conformance_cases"]
                assert set(required_cases).issubset({x["scenario"] for x in samples}),"required instance scenarios not covered"

                results[lang] = samples
                if lang != "go" and "go" in results and samples != results["go"]:
                    raise AssertionError("Go reference differs")
                print(
                    json.dumps(
                        dict(language=lang, conformance="PASS", scenarios=len(samples)),
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
            except Exception as e:
                failures.append(str(e))
                print(
                    json.dumps(
                        dict(language=lang, conformance="FAIL", error=str(e), last_scenario=samples[-1]["scenario"] if samples else "startup"),
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
            finally:
                watchdog.cancel()
                with contextlib.suppress(Exception):
                    process.stdin.close()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                log.close()
                subprocess.run(["docker","rm","-f",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (work / "results.json").write_text(json.dumps(results, indent=2))
        print("SDK test reports:", work)
        print(
            json.dumps({"reference": "go", "languages": list(results), "reports": "results.json"}, ensure_ascii=False),
            flush=True,
        )
        if failures:
            raise SystemExit("\n".join(failures))
    finally:
        for name in names:
            if "-host-" in name:
                with (work / "host.log").open("w") as host_log:
                    subprocess.run(["docker", "logs", name], stdout=host_log, stderr=subprocess.STDOUT)
        for name in reversed(names):
            subprocess.run(
                ["docker", "rm", "-f", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    main()
