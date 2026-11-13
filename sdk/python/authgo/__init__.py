"""Auth Go synchronous SDK. Credentials never appear in exception messages."""

import http.client
import math
import base64, datetime, hashlib, hmac, json, os, pathlib, platform, re, socket, struct, subprocess, tempfile, threading, time, ssl, urllib.error, urllib.parse, urllib.request
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TEMPORARY = frozenset(
    "INTERNAL_ERROR RATE_LIMITED REPLAY_DETECTED TIMESTAMP_INVALID SIGNATURE_INVALID INVALID_REQUEST PAYLOAD_INVALID".split()
)


class Error(Exception):
    def __init__(self, code, message="", authenticated=False, cause=None):
        self.code, self.authenticated, self.cause = (code, authenticated, cause)
        self.latest_version = ""
        self.latest_entitled_version = ""
        super().__init__(code + (": " + message if message else ""))

    @property
    def refusal(self):
        return self.authenticated and self.code != "OK" and (self.code not in TEMPORARY)


class Number(str):
    pass


def loads(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf8", errors="strict")

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate JSON key")
            out[k] = v
        return out

    value = json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_int=Number,
        parse_float=Number,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("number")),
    )
    canonical(value).encode("utf8")
    return value


def canonical(v):
    if isinstance(v, Number):
        return str(v)
    if isinstance(v, dict):
        return (
            "{"
            + ",".join((canonical(k) + ":" + canonical(v[k]) for k in sorted(v)))
            + "}"
        )
    if isinstance(v, list):
        return "[" + ",".join(map(canonical, v)) + "]"
    return (
        json.dumps(v, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def standard(s):
    raw = base64.b64decode(s, validate=True)
    if base64.b64encode(raw).decode() != s:
        raise ValueError("base64")
    return raw


def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64(s):
    if not isinstance(s, str) or not re.fullmatch("[A-Za-z0-9_-]*", s):
        raise ValueError("base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64(b) != s:
        raise ValueError("base64url")
    return b


def sha(b):
    return hashlib.sha256(b).hexdigest()


def hkdf(ikm, salt, info, n=32):
    return HKDF(
        algorithm=hashes.SHA256(), length=n, salt=salt or None, info=info
    ).derive(ikm)


def pad(raw):
    n = max(4096, (len(raw) + 4 + 511) // 512 * 512)
    return struct.pack(">I", len(raw)) + raw + os.urandom(n - 4 - len(raw))


def unpad(raw):
    n = struct.unpack(">I", raw[:4])[0]
    if n < 1 or n + 4 > len(raw) or len(raw) != max(4096, (n + 4 + 511) // 512 * 512):
        raise ValueError("padding")
    return raw[4 : 4 + n]


def stamp(v):
    if v is None:
        return float("inf")
    if isinstance(v, str):
        return datetime.datetime.fromisoformat(
            re.sub("(\\.\\d{6})\\d+", "\\1", v).replace("Z", "+00:00")
        ).timestamp()
    return float(v)


def validate_key(key):
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    p = key.split("-")
    if (
        len(p) != 5
        or not 1 <= len(p[0]) <= 16
        or any(len(v) != 5 for v in p[1:])
        or any(c not in alphabet for v in p for c in v)
    ):
        raise Error("INVALID_LICENSE_KEY")
    check = len(p[0]) % 32
    for c in p[0] + "".join(p[1:4]) + p[4][:4]:
        check = (check * 17 + alphabet.index(c)) % 32
    if p[4][4] != alphabet[check]:
        raise Error("INVALID_LICENSE_KEY")


def parse_linux_cpu(raw):
    fields = [line.partition(":") for line in raw.splitlines()]
    for k, sep, v in fields:
        if sep and k.strip() in ["model name", "Hardware", "cpu model"] and v.strip():
            return v.strip()
    implementer = part = uarch = ""
    seen = done = False
    for k, sep, v in fields:
        if not (k + sep + v).strip() and seen:
            done = True
        k, v = k.strip(), v.strip()
        if k == "uarch" and not uarch:
            uarch = v
        if not done:
            if k == "CPU implementer":
                seen = True
                if not implementer:
                    implementer = "".join(v.split()).lower()
            if k == "CPU part":
                seen = True
                if not part:
                    part = "".join(v.split()).lower()
    return "arm:" + implementer + ":" + part if implementer and part else uarch


def identity_hash(machine, mac, cpu):
    mac = mac.strip().lower().replace("-", ":")
    machine = machine.strip().lower()
    cpu = " ".join(cpu.lower().split())
    if (
        not machine
        or not cpu
        or (not re.fullmatch("[0-9a-f]{2}(:[0-9a-f]{2}){5}(:[0-9a-f]{2}){0,2}", mac))
    ):
        raise Error("SDK_FINGERPRINT_UNAVAILABLE")
    return sha(
        ("authgo/fingerprint/v1\x00" + machine + "\x00" + mac + "\x00" + cpu).encode()
    )


def command(*args):
    return subprocess.check_output(args, timeout=3).decode(errors="strict").strip()


def fingerprint():
    try:
        system = platform.system()
        preferred = ""
        items = []
        if system == "Linux":
            machine = next(
                (
                    pathlib.Path(p).read_text()
                    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"]
                    if pathlib.Path(p).exists() and pathlib.Path(p).read_text().strip()
                )
            )
            cpu = parse_linux_cpu(pathlib.Path("/proc/cpuinfo").read_text())
            for row in pathlib.Path("/proc/net/route").read_text().splitlines()[1:]:
                f = row.split()
                if f[1] == "00000000":
                    preferred = f[0]
                    break
            for index, name in socket.if_nameindex():
                p = pathlib.Path("/sys/class/net") / name
                if int(p.joinpath("flags").read_text(), 16) & 8 == 0:
                    items.append(
                        (
                            index,
                            name,
                            p.joinpath("address").read_text().strip(),
                            bool(int(p.joinpath("flags").read_text(), 16) & 1),
                        )
                    )
        elif system == "Darwin":
            machine = re.search(
                '"IOPlatformUUID"\\s*=\\s*"([^"]+)"',
                command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"),
            )[1]
            try:
                cpu = command("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string")
            except Exception:
                cpu = command("/usr/sbin/sysctl", "-n", "hw.model")
            route = command("/sbin/route", "-n", "get", "default")
            m = re.search("interface:\\s*(\\S+)", route)
            preferred = m[1] if m else ""
            for index, name in socket.if_nameindex():
                text = command("/sbin/ifconfig", name)
                m = re.search("ether\\s+([0-9a-f:]+)", text)
                if m:
                    items.append((index, name, m[1], "UP" in text.splitlines()[0]))
        elif system == "Windows":
            root = os.environ.get("SystemRoot", "C:\\Windows")
            reg = os.path.join(root, "System32", "reg.exe")
            machine = re.search(
                "MachineGuid\\s+REG_SZ\\s+(.+)",
                command(
                    reg,
                    "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                    "/v",
                    "MachineGuid",
                    "/reg:64",
                ),
            )[1]
            cpu = re.search(
                "ProcessorNameString\\s+REG_SZ\\s+(.+)",
                command(
                    reg,
                    "query",
                    "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                    "/v",
                    "ProcessorNameString",
                ),
            )[1]
            ps = os.path.join(
                root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
            )
            preferred = command(
                ps,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex",
            )
            rows = json.loads(
                command(
                    ps,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -IncludeHidden | Select-Object ifIndex,Name,MacAddress,Status)",
                )
            )
            items = [
                (
                    int(v["ifIndex"]),
                    str(v["ifIndex"]),
                    v["MacAddress"],
                    v["Status"] == "Up",
                )
                for v in rows
                if v["MacAddress"]
            ]
        else:
            raise ValueError("platform")
        items = sorted(
            (
                v
                for v in items
                if v[2] and v[2].replace(":", "").replace("-", "").strip("0")
            )
        )
        chosen = (
            next(
                (v for v in items if v[1] == preferred or str(v[0]) == preferred), None
            )
            or next((v for v in items if v[3]), None)
            or items[0]
        )
        return identity_hash(machine, chosen[2], cpu)
    except Exception:
        raise Error(
            "SDK_FINGERPRINT_UNAVAILABLE", "无法采集实例指纹，请提供 fingerprint 覆盖"
        ) from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def http_request(url, body=None, headers=None, timeout=10, limit=5 * 1024 * 1024):
    start = time.monotonic()
    try:
        with urllib.request.build_opener(NoRedirect).open(
            urllib.request.Request(url, body, headers or {}), timeout=timeout
        ) as r:
            chunks = []
            size = 0
            while True:
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    raise Error("SDK_NETWORK_ERROR", "连接超时")
                try:
                    r.fp.raw._sock.settimeout(remaining)
                except AttributeError:
                    pass
                chunk = r.read1(min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > limit:
                    break
            data = b"".join(chunks)
            if len(data) > limit:
                raise Error("SDK_RESPONSE_INVALID", "响应过大")
            return (r.status, dict(r.headers), data)
    except Error:
        raise
    except http.client.RemoteDisconnected as e:
        # No HTTP response was received. This is a connection failure, not a
        # received-but-malformed response (RemoteDisconnected is a BadStatusLine).
        raise Error("SDK_NETWORK_ERROR", "连接被关闭", cause=e) from None
    except (
        http.client.IncompleteRead,
        http.client.BadStatusLine,
    ):
        raise Error("SDK_RESPONSE_INVALID", "响应不完整") from None
    except urllib.error.HTTPError:
        raise Error("SDK_RESPONSE_INVALID", "HTTP请求被拒绝") from None
    except Exception as e:
        reason = e.reason if isinstance(e, urllib.error.URLError) else e
        if isinstance(reason, ssl.SSLError):
            raise Error("SDK_RESPONSE_INVALID", "TLS校验失败", cause=reason) from None
        raise Error("SDK_NETWORK_ERROR", "连接失败", cause=reason) from None


def _heartbeat_interval(data, cached=0):
    try:
        value = int(cached)
        if not isinstance(cached, bool) and 1 <= value <= 3600:
            return value
    except (ValueError, TypeError):
        pass
    # Before Guard existed these SDKs cached only the signed grant. A floating
    # grant's remaining two-heartbeat lease gives a conservative earlier retry.
    if data.get("floating"):
        span = stamp(data.get("lease_expires_at")) - stamp(data.get("issued_at"))
        if math.isfinite(span) and span > 0:
            return max(1, min(3600, math.ceil(span / 2)))
    return max(1, min(3600, int(data.get("next_check_in", 1))))


class Result:
    def __init__(
        self,
        client,
        data,
        ticket="",
        seed=b"",
        status="online",
        end=float("inf"),
        reason="",
    ):
        self._client, self.data, self._ticket, self._seed, self._end = (
            client,
            data,
            ticket,
            seed,
            end,
        )
        self.status, self.availability, self.offline, self.reason = (
            status,
            status,
            status != "online",
            reason,
        )
        self.heartbeat_interval = _heartbeat_interval(data, getattr(client, "state", {}).get("heartbeat_interval"))
        self.maintenance_until = data.get("maintenance_until")
        self.latest_entitled_version = data.get("latest_entitled_version", "")
        self.is_trial = bool(data.get("is_trial", False))
        self.source = "online" if status == "online" else "offline" if status == "offline" else "cache"
        self.features = data.get("features", {})
        self.cache_warning = client.cache_warning
        self.remaining_seconds = (
            max(0, int(end - client.now())) if end != float("inf") else 0
        )

    def ticket(self):
        return self._ticket




_process_pid = os.getpid()
_process_sessions = {_process_pid: b64(os.urandom(16))}
_replaced = set()
_memory_instances = {}
_identity_lock = threading.RLock()


def _session():
    global _process_pid, _identity_lock
    pid = os.getpid()
    if _process_pid != pid:
        # A pre-fork import must not retain a lock held by a vanished thread.
        _identity_lock = threading.RLock()
        _process_pid = pid
    value = _process_sessions.get(pid)
    if value is None:
        value = _process_sessions.setdefault(pid, b64(os.urandom(16)))
    return value


def detect_container(read=None, env=None):
    read = read or (lambda p: pathlib.Path(p).read_bytes())
    env = os.environ if env is None else env
    if env.get("AUTHGO_CONTAINER") in ("0", "1"):
        return env["AUTHGO_CONTAINER"] == "1"
    for p in ("/.dockerenv", "/run/.containerenv"):
        try:
            read(p)
            return True
        except OSError:
            pass
    try:
        raw = read("/proc/1/cgroup").decode()
        return any(x in raw for x in ("docker", "containerd", "kubepods", "libpod"))
    except OSError:
        return False


def instance_fingerprint(value):
    return sha(("authgo/instance/v1\x00" + value).encode())


def container_identity(directory):
    with _identity_lock:
        try:
            if not directory: raise OSError("cache disabled")
            directory = pathlib.Path(directory)
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            target = directory / "instance-id"
            def existing():
                info = target.lstat()
                if target.is_symlink() or info.st_size != 64 or info.st_mode & 0o777 != 0o600:
                    raise OSError("invalid identity")
                value = target.read_text()
                if not re.fullmatch("[0-9a-f]{64}", value):
                    raise OSError("invalid identity")
                return value
            if target.exists():
                return existing(), False
            fd, temp = tempfile.mkstemp(dir=directory)
            try:
                with os.fdopen(fd, "w") as f:
                    os.fchmod(f.fileno(), 0o600)
                    f.write(os.urandom(32).hex()); f.flush(); os.fsync(f.fileno())
                try: os.link(temp, target)
                except FileExistsError: pass
            finally: os.unlink(temp)
            return existing(), False
        except OSError:
            key = (os.getpid(), os.path.abspath(str(directory)))
            return _memory_instances.setdefault(key, os.urandom(32).hex()), True


class Client:
    def __init__(
        self,
        config,
        *,
        fingerprint=None,
        cache_dir=None,
        version="",
        clock=time.time,
        transport=http_request,
    ):
        try:
            if not (len(config) <= 32768 and config.startswith("authgo2.")):
                raise ValueError("协议字段无效") from None
            c = loads(unb64(config[8:]))
            if not set(c) <= set(
                [
                    "url",
                    "app_key",
                    "app_secret",
                    "public_key",
                    "gateway_key",
                                    ]
            ):
                raise ValueError("协议字段无效") from None
            if not all(
                (
                    isinstance(c[k], str) and c[k]
                    for k in [
                        "url",
                        "app_key",
                        "app_secret",
                        "public_key",
                        "gateway_key",
                    ]
                )
            ):
                raise ValueError("协议字段无效") from None
            self.public = ed25519.Ed25519PublicKey.from_public_bytes(
                standard(c["public_key"])
            )
            self.gateway = unb64(c["gateway_key"])
            if not len(self.gateway) == 32:
                raise ValueError("协议字段无效") from None
            u = urllib.parse.urlsplit(c["url"])
            if not (
                u.hostname
                and (not u.username)
                and (not u.password)
                and (not u.query)
                and (not u.fragment)
            ):
                raise ValueError("协议字段无效") from None
            if not (
                u.scheme == "https"
                or (
                    u.scheme == "http"
                    and u.hostname in ["localhost", "127.0.0.1", "::1"]
                )
            ):
                raise ValueError("协议字段无效") from None
            if not (
                all((p not in [".", ".."] for p in u.path.split("/")))
                and "%" not in u.path
                and ("//" not in u.path)
            ):
                raise ValueError("协议字段无效") from None
            self.endpoint = c["url"].rstrip("/")
            self.endpoint += (
                "" if self.endpoint.endswith("/api/v1/client") else "/api/v1/client"
            )
        except Exception:
            raise Error("SDK_INVALID_CONFIG", "请在后台重新复制接入配置") from None
        self.config = c
        _session()
        self.now = clock
        self.transport = transport
        container = detect_container()
        root = (
            os.environ.get("LOCALAPPDATA") or str(pathlib.Path.home() / "AppData/Local")
            if os.name == "nt"
            else str(
                pathlib.Path.home()
                / ("Library/Caches" if platform.system() == "Darwin" else ".cache")
            )
        )
        directory = cache_dir if cache_dir is not None else (os.environ.get("AUTHGO_CACHE_DIR") or ("/var/lib/authgo" if container else os.path.join(os.environ.get("XDG_CACHE_HOME", root), "authgo", sha(c["app_key"].encode()))))
        self.cache = pathlib.Path(directory)
        self.memory_cache = directory == ""
        self.cache_warning = None
        if fingerprint is not None:
            self.fp = fingerprint.lower()
        elif os.environ.get("AUTHGO_INSTANCE_ID"):
            self.fp = instance_fingerprint(os.environ["AUTHGO_INSTANCE_ID"])
        elif container:
            value, memory = container_identity(directory)
            self.fp = instance_fingerprint(value)
            self.memory_cache = memory
            if memory: self.cache_warning = Error("SDK_CACHE_UNAVAILABLE", "此实例重启后是新实例，没有断连宽限")
        else:
            self.fp = globals()["fingerprint"]().lower()
        if not re.fullmatch("[0-9a-f]{64}", self.fp): raise Error("SDK_INVALID_CONFIG", "设备指纹无效")
        self.version = version
        self.lock = threading.RLock()
        self.state = {}
        self.payload_ready = False
        self.payload_no_cache = False
        self.online_ticket, self.online_until = "", 0
        self.offline_ticket, self.offline_until = "", 0
        self.aad = (
            "authgo/python/cache/v2\x00"
            + self.endpoint
            + "\x00"
            + c["app_key"]
            + "\x00"
            + self.fp
        ).encode()
        self.cachekey = hkdf(
            c["app_secret"].encode(),
            hashlib.sha256(self.aad).digest(),
            b"authgo/multi/cache/key",
        )
        self.path = self.cache / (sha(self.aad) + ".cache")
        self.cache_error = None
        try:
            if not self.memory_cache and self.path.exists():
                if self.path.stat().st_size > 16 * 1024 * 1024:
                    raise Error("SDK_CACHE_INVALID")
                with open(self.path, "rb") as cached:
                    raw = cached.read(16 * 1024 * 1024 + 1)
                if not len(raw) <= 16 * 1024 * 1024:
                    raise ValueError("协议字段无效") from None
                self.state = loads(
                    AESGCM(self.cachekey).decrypt(raw[:12], raw[12:], self.aad)
                )
        except Exception:
            self.state = {}
            self.cache_error = Error("SDK_CACHE_INVALID")

    def save(self):
        if self.memory_cache: return
        try:
            self.cache.mkdir(mode=448, parents=True, exist_ok=True)
            n = os.urandom(12)
            raw = n + AESGCM(self.cachekey).encrypt(
                n, canonical(self.state).encode(), self.aad
            )
            fd, p = tempfile.mkstemp(dir=self.cache)
            try:
                os.fchmod(fd, 384)
                with os.fdopen(fd, "wb") as f:
                    f.write(raw)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(p, self.path)
            finally:
                if os.path.exists(p):
                    os.unlink(p)
        except Exception:
            raise Error("SDK_CACHE_UNAVAILABLE", "无法保存缓存") from None

    def save_warning(self):
        if not self.memory_cache: self.cache_warning = None
        try: self.save()
        except Error as warning: self.cache_warning = warning

    def revoke_cache(self):
        self.payload_ready = False
        self.clear_payload_keys()
        self.state.update(ticket="", seed="", refused=True)
        try:
            self.save()
        except Error:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass

    def request(self, op, body=None):
        challenge = b64(os.urandom(32))
        nonce = b64(os.urandom(32))
        ts = str(int(self.now()))
        if body is not None:
            body = dict(body, challenge=challenge)
        raw = b"" if body is None else canonical(body).encode()
        sig = hmac.digest(
            self.config["app_secret"].encode(),
            (op + ts + nonce + sha(raw)).encode(),
            "sha256",
        ).hex()
        inner = canonical(
            dict(
                app_key=self.config["app_key"],
                op=op,
                timestamp=ts,
                nonce=nonce,
                signature=sig,
                body=body,
            )
        ).encode()
        private = x25519.X25519PrivateKey.generate()
        ep = b64(
            private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
        kid = sha(self.gateway)[:16]
        aad = ("authgo-gateway-v2\x00" + kid + "\x00" + ep).encode()
        salt = hashlib.sha256(aad).digest()
        try:
            shared = private.exchange(
                x25519.X25519PublicKey.from_public_bytes(self.gateway)
            )
            n = os.urandom(12)
            ciphertext = AESGCM(hkdf(shared, salt, b"authgo/v2/request")).encrypt(
                n, pad(inner), aad
            )
            packet = canonical(
                dict(v=2, k=kid, e=ep, n=b64(n), c=b64(ciphertext))
            ).encode()
            status, _, raw = self.transport(
                self.endpoint + "/gateway",
                packet,
                {"Content-Type": "application/json"},
                10,
                2 * 1024 * 1024,
            )
            if status != 200:
                raise Error("SDK_RESPONSE_INVALID")
            outer = loads(raw)
            if not set(outer) == {"n", "c"}:
                raise ValueError("协议字段无效") from None
            plain = unpad(
                AESGCM(hkdf(shared, salt, b"authgo/v2/response")).decrypt(
                    unb64(outer["n"]),
                    unb64(outer["c"]),
                    aad
                    + b"\x00"
                    + sha((b64(n) + "." + b64(ciphertext)).encode()).encode(),
                )
            )
            env = loads(plain)
        except Error:
            raise
        except Exception:
            raise Error("SDK_RESPONSE_INVALID", "加密响应无效") from None
        try:
            self.public.verify(
                standard(env["signature"]),
                canonical({k: env[k] for k in ["code", "data", "ts"]}).encode(),
            )
        except Exception:
            raise Error("SDK_RESPONSE_SIGNATURE_INVALID") from None
        if env.get("nonce") != nonce or env["data"].get("request_nonce") != nonce:
            raise Error("SDK_RESPONSE_NONCE_INVALID")
        if abs(int(env["ts"]) - self.now()) > 300:
            raise Error("SDK_RESPONSE_TIMESTAMP_INVALID")
        if env["code"] != "OK":
            error = Error(env["code"], "服务器拒绝请求", True)
            error.latest_version = env["data"].get("latest_version", "")
            error.latest_entitled_version = env["data"].get("latest_entitled_version", "")
            raise error
        return (env["data"], challenge)

    def body(self):
        return dict(
            instance_session=_session(),
            license_key=self.state.get("key", ""),
            activation_token=self.state.get("token", ""),
            device_fingerprint=self.fp,
            client_version=self.version,
            hostname=socket.gethostname()[:128],
            os={"Windows": "windows", "Darwin": "darwin"}.get(
                platform.system(), "linux"
            ),
        )

    def grant(self, ticket):
        try:
            p, s = ticket.split(".")
            raw = unb64(p)
            self.public.verify(unb64(s), b"authgo-ticket-v2\x00" + raw)
            g = loads(raw)
            if not (
                int(g["v"]) == 2
                and g["app_key"] == self.config["app_key"]
                and (g["status"] == "active")
                and (int(g["license_id"]) > 0)
                and (g["device_hash"] == sha(self.fp.encode()))
            ):
                raise ValueError("协议字段无效") from None
            if not (
                len(unb64(g["challenge"])) == 32
                and 1 <= int(g["next_check_in"]) <= 86400
            ):
                raise ValueError("协议字段无效") from None
            if not stamp(g["issued_at"]) <= stamp(g["grace_until"]):
                raise ValueError("协议字段无效") from None
            return g
        except Exception as e:
            raise Error("SDK_RESPONSE_SIGNATURE_INVALID", "票据无效", cause=e) from None



    def validate(self, ticket):
        with self.lock:
            self.ensure_instance()
            g = self.grant(ticket)
            now = self.now()
            if self.state.get("refused"):
                raise Error("SDK_NOT_ACTIVATED")
            if now + 300 < int(self.state.get("observed", 0)):
                raise Error("SDK_CLOCK_ROLLBACK")
            if g.get("starts_at") and now < stamp(g["starts_at"]):
                raise Error("LICENSE_NOT_STARTED")
            if now >= stamp(g.get("expires_at")):
                raise Error("LICENSE_EXPIRED")
            if g["floating"] and (not g.get("lease_expires_at") or now >= stamp(g.get("lease_expires_at"))) and not (ticket == self.offline_ticket and now < self.offline_until):
                raise Error("LEASE_EXPIRED")
            if now < stamp(g["grace_until"]) or (
                ticket == self.online_ticket and now < self.online_until
            ):
                return g
            if now >= stamp(g["grace_until"]):
                raise Error("SDK_GRACE_EXPIRED")
            return g

    def fallback(self, error):
        try:
            if self.state.get("refused") or not self.state.get("ticket"):
                raise error
            g = self.grant(self.state["ticket"])
            if g.get("is_trial"): raise Error("SDK_GRACE_EXPIRED", "试用需要稳定联网")
            now = self.now()
            if sha(unb64(self.state.get("seed", ""))) != g["unlock_hash"]:
                raise error
            if now + 300 < int(self.state.get("observed", 0)):
                raise Error("SDK_CLOCK_ROLLBACK")
            self.state["observed"] = max(int(now), int(self.state.get("observed", 0)))
            self.save()
            if now >= stamp(g.get("expires_at")):
                raise Error("LICENSE_EXPIRED")
            if g.get("starts_at") and now < stamp(g["starts_at"]):
                raise Error("LICENSE_NOT_STARTED")
            end = min(stamp(g["grace_until"]), stamp(g.get("expires_at")))
            self.offline_ticket, self.offline_until = self.state["ticket"], end
            self.state["observed"] = max(int(now), int(self.state.get("observed", 0)))
            self.save_warning()
            if now < end:
                return Result(
                    self,
                    g,
                    self.state["ticket"],
                    unb64(self.state.get("seed", "")),
                    "grace",
                    end,
                    str(error),
                )
            raise Error("SDK_GRACE_EXPIRED", cause=error)
        except Error as e:
            if e.code == "SDK_RESPONSE_SIGNATURE_INVALID":
                raise error
            raise

    def valid_grant_time(self, g):
        try:
            now = self.now()
            if g.get("starts_at") and now < stamp(g["starts_at"]):
                raise Error("LICENSE_NOT_STARTED")
            if now >= stamp(g.get("expires_at")):
                raise Error("LICENSE_EXPIRED")
            if g.get("floating") and (
                not g.get("lease_expires_at") or now >= stamp(g["lease_expires_at"])
            ):
                raise Error("LEASE_EXPIRED")
        except Error:
            raise
        except Exception:
            raise Error("SDK_RESPONSE_INVALID") from None

    def authorization(self, op, key=None):
        with self.lock:
            try:
                result = self._authorization(op, key)
            except Error as error:
                if error.refusal:
                    self.payload_ready = False
                    self.clear_payload_keys()
                raise
            if op == "deactivate":
                self.payload_ready = False
                self.clear_payload_keys()
            elif result is not None:
                _payload.record_payload_result(self, result)
            return result

    def unlock_payload(self, payload):
        """Return the authenticated 32-byte content key; never implicitly activate."""
        return _payload.unlock_payload(self, payload)

    def _unlock_payload_material(self, payload):
        """Loader-only K32 (v1) or K32 || WM32 (v2); never implicitly activate."""
        return _payload._unlock_payload_material(self, payload)

    def save_payload_key(self, payload, result, key):
        with self.lock:
            return _payload.save_payload_key(self, _payload._coerce(payload), result, key)

    def load_payload_key(self, payload, result):
        with self.lock:
            return _payload.load_payload_key(self, _payload._coerce(payload), result)

    def clear_payload_keys(self):
        with self.lock:
            _payload.clear_payload_keys(self)

    def _authorization(self, op, key=None):
        with self.lock:
            if key is not None:
                validate_key(key)
            self.ensure_instance(key if op == "activate" else None)
            if op == "verify" and self.state.get("ticket"):
                try:
                    cached = self.grant(self.state["ticket"])
                    if cached.get("floating") and self.now() >= stamp(cached.get("lease_expires_at")): op = "heartbeat"
                except Error: pass
            previous = self.state.copy()
            if op == "activate":
                if key != self.state.get("key"):
                    self.state = {
                        k: self.state[k]
                        for k in ["observed", "trial_key"]
                        if k in self.state
                    }
                self.state["key"] = key
            elif not self.state.get("token"):
                raise Error("SDK_NOT_ACTIVATED")
            try:
                request_body = self.body()
                if op == "deactivate": request_body.pop("instance_session", None)
                if op == "activate":
                    request_body["activation_token"] = ""
                d, ch = self.request(op, request_body)
                if op == "deactivate":
                    if not d.get("deactivated"):
                        raise Error("SDK_RESPONSE_INVALID")
                    self.state.update(token="", ticket="", seed="", refused=True)
                    self.save()
                    return None
                g = self.grant(d["ticket"])
                if str(g["license_id"]) != str(d.get("license_id")) or str(
                    g["next_check_in"]
                ) != str(d.get("next_check_in")):
                    raise Error("SDK_RESPONSE_INVALID")
                if g["challenge"] != ch:
                    raise Error("SDK_RESPONSE_NONCE_INVALID")
                if abs(stamp(g["issued_at"]) - self.now()) > 300:
                    raise Error("SDK_RESPONSE_TIMESTAMP_INVALID")
                seed = unb64(d["unlock_seed"])
                if len(seed) != 32 or sha(seed) != g["unlock_hash"]:
                    raise Error("SDK_RESPONSE_SIGNATURE_INVALID")
                self.valid_grant_time(g)
                if op == "activate":
                    token = d.get("activation_token", "")
                    if not re.fullmatch("act_[A-Za-z0-9_-]{43}", token):
                        raise Error("SDK_RESPONSE_INVALID")
                    self.state["token"] = token
                self.state.update(
                    ticket=d["ticket"],
                    heartbeat_interval=_heartbeat_interval(g, d.get("heartbeat_interval")),
                    seed=d["unlock_seed"],
                    refused=False,
                    observed=max(int(self.now()), int(stamp(g["issued_at"]))),
                )
                self.offline_ticket, self.offline_until = "", 0
                self.online_ticket = d["ticket"]
                self.online_until = self.now() + int(g["next_check_in"])
                self.save_warning()
                self.validate(d["ticket"])
                return Result(
                    self,
                    g,
                    d["ticket"],
                    seed,
                    "online",
                    min(
                        max(stamp(g["grace_until"]), self.online_until),
                        stamp(g.get("expires_at")),
                    ),
                )
            except Error as e:
                if e.authenticated and e.code == "INSTANCE_REPLACED":
                    self.state = previous
                    _replaced.add(self.instance_key(key if op == "activate" else None))
                    self.offline_until = self.online_until = 0
                    raise
                if op == "activate" and previous.get("key") != key:
                    self.state = previous
                    raise
                if op == "activate" and e.refusal:
                    self.state["token"] = ""
                    self.revoke_cache()
                    raise
                if op in ["verify", "heartbeat"]:
                    self.online_until = 0
                    if e.refusal:
                        self.revoke_cache()
                        raise
                    return self.fallback(e)
                raise
            except Exception as cause:
                if op == "activate" and previous.get("key") != key:
                    self.state = previous
                error = Error("SDK_RESPONSE_INVALID", cause=cause)
                if op in ["verify", "heartbeat"]:
                    self.online_until = 0
                    return self.fallback(error)
                raise error from None

    def _guard_check(self, key):
        if key: return self.check(key)
        with self.lock:
            key = self.state.get("trial_key", "")
            if not key:
                data, challenge = self.request("trial", {"device_fingerprint": self.fp})
                if data.get("challenge") != challenge: raise Error("SDK_RESPONSE_NONCE_INVALID")
                key = data.get("license_key", "")
                validate_key(key)
                self.state["trial_key"] = key
                self.save_warning()
            return self.check(key)

    def check(self, key):
        with self.lock:
            validate_key(key)
            return (
                self.authorization("verify")
                if key == self.state.get("key") and self.state.get("token")
                else self.authorization("activate", key)
            )

    def activate(self, key):
        return self.authorization("activate", key)

    def verify(self):
        return self.authorization("verify")

    def heartbeat(self):
        return self.authorization("heartbeat")

    def deactivate(self):
        return self.authorization("deactivate")

    def instance_key(self, key=None):
        return (self.endpoint, self.config["app_key"], self.fp, self.config["public_key"], key if key is not None else self.state.get("key", ""), _session())

    def ensure_instance(self, key=None):
        if self.instance_key(key) in _replaced: raise Error("INSTANCE_REPLACED")

    def release_seat(self):
        with self.lock:
            if not self.state.get("ticket"): return
            g = self.grant(self.state["ticket"])
            if not g.get("floating"): return
            try: self.request("release-seat", self.body())
            except Error as e:
                if e.refusal:
                    self.payload_ready = False
                    self.clear_payload_keys()
                if e.authenticated and e.code == "INSTANCE_REPLACED":
                    _replaced.add(self.instance_key())
                    self.offline_until = self.online_until = 0
                elif e.refusal: self.revoke_cache()
                raise

    def announcements(self):
        return self.request("announcement")[0].get("items", [])



    def check_update(self, current_version):
        with self.lock:
            if not self.state.get("token"):
                raise Error("SDK_NOT_ACTIVATED")
            d, _ = self.request(
                "update.check",
                dict(
                    self.body(),
                    current_version=current_version,
                    client_version=current_version,
                ),
            )
            return {key:value for key,value in d.items() if key in ("available", "docker_image", "docker_pull", "version", "changelog", "mandatory", "published_at", "maintenance_until", "latest_entitled_version", "renewal_required")}




# Import after Client/Result to keep the low-level API independent.
from . import payload as _payload
from .payload import Payload, PayloadEnvelope, parse_payload, payload_binding
from .guard import EXIT_LICENSE, Guard, start_guard

from .sealed import decrypt_payload_file, payload_cipher_size
