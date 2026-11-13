"""Payload v2 and authenticated material cache (no launcher proof files)."""

from dataclasses import asdict, dataclass
import hashlib
import os
import re
import stat
import struct
import tempfile
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import (
    Error,
    Number,
    Result,
    _replaced,
    b64,
    canonical,
    hkdf,
    loads,
    sha,
    stamp,
    standard,
    unb64,
)


_CACHE_PREFIX = b"AUTHGO-PAYLOAD-CACHE-v2."
_NAME = re.compile(r"[a-z0-9_-]+\Z")
_VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?"
    r"(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?\Z"
)
_FIELDS = {
    "v",
    "app_key",
    "version",
    "built_at",
    "key_id",
    "config",
    "manifest",
    "envelope",
}
_FILE_REQUIRED = {"name", "kind", "path", "size", "chunk_size", "encoding"}
_FILE_OPTIONAL = {"python_version", "main_class", "architecture"}


@dataclass(frozen=True)
class PayloadEnvelope:
    e: str
    n: str
    c: str


@dataclass(frozen=True)
class Payload:
    v: int
    app_key: str
    version: str
    built_at: str
    key_id: str
    config: str
    manifest: str
    envelope: PayloadEnvelope

    def to_dict(self):
        return asdict(self)

    def payload_binding(self):
        return payload_binding(self)


def _invalid():
    return Error("PAYLOAD_INVALID", "加密载荷无效")


def _object(value, required, optional=frozenset()):
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or not value.keys() <= required | optional
    ):
        raise ValueError("schema")


def _integer(value):
    if type(value) is int:
        return value
    if isinstance(value, Number) and re.fullmatch(r"-?(0|[1-9][0-9]*)", value):
        return int(value)
    raise ValueError("integer")


def _text(value):
    if not isinstance(value, str) or isinstance(value, Number):
        raise ValueError("string")
    value.encode("utf8", errors="strict")
    return value


def _lp(value):
    raw = value.encode("utf8")
    return struct.pack(">I", len(raw)) + raw


def _https(value):
    value = _text(value)
    # Match Go net/url.Parse's HTTPS predicate, not Python urlsplit (which
    # silently strips controls, imposes IPv6 syntax, and defers port checks).
    if re.search(r"[\x00-\x1f\x7f]", value):
        raise ValueError("https")
    match = re.fullmatch(
        r"(?i:https)://([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?", value
    )
    if match is None:
        raise ValueError("https")
    authority, path, query, fragment = match.groups()
    if not authority or "@" in authority or query or fragment:
        raise ValueError("https")
    if "[" in authority and not authority.startswith("["):
        raise ValueError("host")
    host = authority
    if host.startswith("["):
        end = host.rfind("]")
        if end < 0 or not host[1:end]:
            raise ValueError("host")
        suffix = host[end + 1 :]
        if suffix and not re.fullmatch(r":[0-9]*", suffix):
            raise ValueError("port")
    elif ":" in host:
        host, port = host.rsplit(":", 1)
        if not host or not re.fullmatch(r"[0-9]*", port):
            raise ValueError("port")
    if re.search(r"[^a-zA-Z0-9_.~!$&'()*+,;=:\[\]<>\"%\x80-\U0010ffff-]", authority):
        raise ValueError("host")
    if re.search(r"%(?![0-9a-fA-F]{2})", authority + path):
        raise ValueError("escape")
    for escaped in re.findall(r"%([0-9a-fA-F]{2})", authority):
        code = int(escaped, 16)
        if code < 128 and code != 37:
            raise ValueError("host escape")


def _config(value, app_key):
    if len(value.encode()) > 32768 or not value.startswith("authgo2."):
        raise ValueError("config")
    c = loads(unb64(value[8:]))
    _object(
        c,
        {"url", "app_key", "app_secret", "public_key", "gateway_key"},
        set(),
    )
    for field in ("url", "app_key", "app_secret", "public_key", "gateway_key"):
        _text(c[field])
    if c["app_key"] != app_key or not c["app_secret"]:
        raise ValueError("config")
    _https(c["url"])
    if len(standard(c["public_key"])) != 32 or len(unb64(c["gateway_key"])) != 32:
        raise ValueError("keys")


def _manifest(value, version=2):
    raw = unb64(value)
    if len(raw) > 8 << 20:
        raise ValueError("manifest size")
    m = loads(raw)
    _object(m, {"files"})
    files = m["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= 65535:
        raise ValueError("files")
    names = set()
    metadata = 0
    for index, file in enumerate(files):
        _object(file, _FILE_REQUIRED, _FILE_OPTIONAL)
        for field in file.keys() - {"size", "chunk_size"}:
            _text(file[field])
        name = file["name"]
        if not _NAME.fullmatch(name) or len(name.encode()) > 128 or name in names:
            raise ValueError("name")
        names.add(name)
        if (
            file["path"] != f"{index:08d}.agc"
            or not 0 <= _integer(file["size"]) <= (2**63 - 1) // 2
            or _integer(file["chunk_size"]) != 1048576
        ):
            raise ValueError("file bounds")
        kind = file["kind"]
        if version == 2 and name == "__authgo_watermark" and kind != "watermark":
            raise ValueError("reserved name")
        if kind == "watermark":
            if (
                version != 2
                or name != "__authgo_watermark"
                or file.keys() != _FILE_REQUIRED
                or file["encoding"] != "raw"
                or not 1 <= _integer(file["size"]) <= 8 << 20
            ):
                raise ValueError("watermark metadata")
            metadata += 1
            continue
        if kind in ("python", "php", "dotnet"):
            encoding = "tar"
        elif kind in ("node", "java", "protect"):
            encoding = "raw"
        else:
            raise ValueError("kind")
        if (
            file["encoding"] != encoding
            or kind == "python"
            and not file.get("python_version")
            or kind == "protect"
            and file.get("architecture") not in ("amd64", "arm64")
        ):
            raise ValueError("file metadata")
    if version != 2 or version == 2 and (metadata != 1 or len(files) < 2):
        raise ValueError("watermark count")
    return raw


def _payload_aad(p):
    if type(p.v) is not int or p.v != 2:
        raise ValueError("version")
    for field in ("app_key", "version", "built_at", "key_id", "config", "manifest"):
        _text(getattr(p, field))
    if (
        not 1 <= len(p.app_key.encode()) <= 256
        or len(p.key_id.encode()) > 128
        or not _NAME.fullmatch(p.key_id)
        or len(p.version.encode()) > 256
        or not _VERSION.fullmatch(p.version)
    ):
        raise ValueError("metadata")
    pre = p.version.split("+", 1)[0].split("-", 1)
    if len(pre) == 2 and any(
        len(i) > 1 and i[0] == "0" and i.isascii() and i.isdigit()
        for i in pre[1].split(".")
    ):
        raise ValueError("semver")
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", p.built_at
    ):
        raise ValueError("built_at")
    year, month, day, hour, minute, second = map(int, re.findall(r"[0-9]+", p.built_at))
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if (
        not 1 <= month <= 12
        or not 1 <= day <= days[month - 1]
        or hour > 23
        or minute > 59
        or second > 59
    ):
        raise ValueError("built_at")
    _config(p.config, p.app_key)
    manifest = _manifest(p.manifest, p.v)
    return (
        f"authgo-payload-envelope-v{p.v}\x00".encode()
        + b"".join(
            _lp(s) for s in (p.app_key, p.version, p.built_at, p.key_id, p.config)
        )
        + hashlib.sha256(manifest).digest()
    )


def payload_binding(payload):
    try:
        aad = _payload_aad(payload)
        if not isinstance(payload.envelope, PayloadEnvelope):
            raise ValueError("envelope")
        e, n, c = (unb64(getattr(payload.envelope, field)) for field in ("e", "n", "c"))
        if len(e) != 32 or len(n) != 12 or len(c) != 48:
            raise ValueError("envelope lengths")
        # E occurs once in envelope AAD, then N and C form the block binding.
        return hashlib.sha256(aad + e + n + c).digest()
    except Exception:
        raise _invalid() from None


def parse_payload(raw):
    """Validate a complete original payload.json (maximum 65536 UTF-8 bytes)."""
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf8")
        if not isinstance(raw, bytes) or len(raw) > 65536:
            raise ValueError("payload size")
        obj = loads(raw)
        _object(obj, _FIELDS)
        env = obj["envelope"]
        _object(env, {"e", "n", "c"})
        for field in env:
            _text(env[field])
        fields = dict(obj, v=_integer(obj["v"]), envelope=PayloadEnvelope(**env))
        p = Payload(**fields)
        payload_binding(p)
        return p
    except Exception:
        raise _invalid() from None


def _coerce(payload):
    try:
        if isinstance(payload, Payload):
            payload = payload.to_dict()
        if isinstance(payload, dict):
            payload = canonical(payload).encode()
        return parse_payload(payload)
    except Exception:
        raise _invalid() from None


def payload_rewrap_aad(payload, ephemeral, challenge):
    if payload.v != 2 or len(ephemeral) != 32 or len(challenge) != 32:
        raise _invalid()
    return (
        f"authgo-payload-rewrap-v{payload.v}\x00".encode()
        + b"".join(
            _lp(s)
            for s in (
                payload.app_key,
                payload.version,
                payload.built_at,
                payload.key_id,
            )
        )
        + hashlib.sha256(unb64(payload.manifest)).digest()
        + ephemeral
        + challenge
    )


def unwrap_payload(payload, wrapped, private, challenge):
    try:
        e, n, c = (unb64(wrapped[field]) for field in ("e", "n", "c"))
        if len(e) != 32 or len(n) != 12 or len(c) != 48:
            raise ValueError("rewrap lengths")
        shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(e))
        ephemeral = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        aad = payload_rewrap_aad(payload, ephemeral, challenge)
        kek = hkdf(shared, hashlib.sha256(aad).digest(), b"authgo/payload/v1/rewrap")
        key = AESGCM(kek).decrypt(n, c, aad)
        if len(key) != 32:
            raise ValueError("key length")
        return key
    except Exception:
        raise Error("SDK_RESPONSE_INVALID", "内容密钥响应认证失败") from None


def payload_cache_label(payload, fingerprint):
    return (
        f"authgo-payload-cache-v{payload.v}\x00".encode()
        + b"".join(
            _lp(s)
            for s in (payload.app_key, fingerprint, payload.key_id, payload.version)
        )
        + hashlib.sha256(unb64(payload.manifest)).digest()
        + payload_binding(payload)
    )


def cache_identity(client):
    # Match Go's normalized host and raw Ed25519 key, not Python's private AAD.
    url = urllib.parse.urlsplit(client.endpoint)
    endpoint = urllib.parse.urlunsplit(
        (url.scheme, url.netloc.lower(), url.path, url.query, url.fragment)
    )
    return "\x00".join(
        (
            endpoint,
            client.config["app_key"],
            client.fp,
            sha(standard(client.config["public_key"])),
        )
    )


def _cache_base(client, version=2):
    return f"authgo-payload-v{version}-" + sha(cache_identity(client).encode()) + "-"


def _material_size(payload):
    if payload.v != 2:
        raise _invalid()
    return 64


def _valid_material(payload, material):
    return len(material) == _material_size(payload) and (
        any(material[32:])
    )


def _cache_prefix(payload):
    return f"AUTHGO-PAYLOAD-CACHE-v{payload.v}.".encode()


def _period(client, grant):
    now = client.now()
    if (
        grant.get("is_trial")
        or stamp(grant["grace_until"]) <= stamp(grant["issued_at"])
        or now >= stamp(grant["grace_until"])
        or stamp(grant["issued_at"]) > now + 300
    ):
        raise Error("SDK_GRACE_EXPIRED", "内容密钥宽限期已结束")
    if grant.get("starts_at") and now < stamp(grant["starts_at"]):
        raise Error("LICENSE_NOT_STARTED")
    if now >= stamp(grant.get("expires_at")):
        raise Error("LICENSE_EXPIRED")


def _cache_material(client, payload, result):
    if (
        client.payload_no_cache
        or result is None
        or result.is_trial
        or client.memory_cache
        or result.source == "offline"
    ):
        raise Error("SDK_CACHE_UNAVAILABLE", "此授权不允许内容密钥缓存")
    grant = client.grant(result.ticket())
    _period(client, grant)
    seed_text = grant["unlock_hash"]
    if type(seed_text) is not str or not re.fullmatch(r"[0-9a-fA-F]{64}", seed_text):
        raise Error("SDK_CACHE_INVALID", "票据解锁绑定无效")
    label = payload_cache_label(payload, client.fp)
    key = hkdf(bytes.fromhex(seed_text), b"", b"authgo-unlock-v2\x00" + label)
    digest = hashlib.sha256(label).digest()
    license_id = _integer(grant["license_id"])
    if not 0 < license_id < 2**64:
        raise Error("SDK_CACHE_INVALID")
    aad = f"authgo-payload-cache-file-v{payload.v}\x00".encode() + digest + struct.pack(">Q", license_id)
    return client.cache / (_cache_base(client, payload.v) + digest.hex() + ".cache"), key, aad


def save_payload_key(client, payload, result, key):
    if not _valid_material(payload, key):
        return
    temp = None
    try:
        path, derived, aad = _cache_material(client, payload, result)
        nonce = os.urandom(12)
        raw = (
            _cache_prefix(payload)
            + b64(nonce + AESGCM(derived).encrypt(nonce, bytes(key), aad)).encode()
        )
        client.cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                return
        except FileNotFoundError:
            pass
        fd, temp = tempfile.mkstemp(
            prefix=".authgo-payload-", suffix=".tmp", dir=client.cache
        )
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    except Exception:
        # Caching is best effort; unwritable storage never revokes online success.
        pass
    finally:
        if temp is not None:
            try:
                os.unlink(temp)
            except OSError:
                pass


def load_payload_key(client, payload, result):
    path, derived, aad = _cache_material(client, payload, result)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > 256
        ):
            raise OSError("cache")
        with open(path, "rb") as source:
            if not os.path.samestat(before, os.fstat(source.fileno())):
                raise Error("SDK_CACHE_INVALID", "内容密钥缓存已变化")
            raw = source.read(257)
    except OSError:
        raise Error("SDK_CACHE_UNAVAILABLE", "没有可用的内容密钥缓存") from None
    try:
        prefix = _cache_prefix(payload)
        if len(raw) > 256 or not raw.startswith(prefix):
            raise ValueError("cache format")
        encrypted = unb64(raw[len(prefix) :].decode("ascii"))
        if len(encrypted) != 12 + _material_size(payload) + 16:
            raise ValueError("cache size")
        key = AESGCM(derived).decrypt(encrypted[:12], encrypted[12:], aad)
        if not _valid_material(payload, key):
            raise ValueError("key")
        return bytearray(key)
    except Exception:
        raise Error("SDK_CACHE_INVALID", "内容密钥缓存认证失败") from None


def clear_payload_keys(client):
    if client.memory_cache or not client.fp or not client.endpoint:
        return
    try:
        prefix = _cache_base(client)
        for entry in client.cache.iterdir():
            if entry.name.startswith(prefix) and entry.name.endswith(".cache"):
                try:
                    entry.unlink()
                except OSError:
                    pass
    except OSError:
        pass


def record_payload_result(client, result):
    if result is None:
        return
    client.payload_ready = True
    grant = client.grant(result.ticket())
    client.payload_no_cache = bool(grant.get("is_trial")) or stamp(
        grant["grace_until"]
    ) <= stamp(grant["issued_at"])
    if client.payload_no_cache:
        clear_payload_keys(client)


def _cached_result(client):
    ticket = client.state["ticket"]
    grant = client.grant(ticket)
    try:
        seed = unb64(client.state.get("seed", ""))
    except Exception:
        raise Error("SDK_RESPONSE_INVALID", "缓存授权数据无效") from None
    if len(seed) != 32 or sha(seed) != grant["unlock_hash"]:
        raise Error("SDK_RESPONSE_SIGNATURE_INVALID")
    # Like Go cachedResult: signed periods are checked, but an expired floating
    # lease alone does not invalidate an already accepted offline-grace result.
    now = client.now()
    if grant.get("starts_at") and now < stamp(grant["starts_at"]):
        raise Error("LICENSE_NOT_STARTED")
    if now >= stamp(grant.get("expires_at")):
        raise Error("LICENSE_EXPIRED")
    return Result(client, grant, ticket, seed)


def _fresh_result(client, data, challenge, previous):
    try:
        required = {
            "license_id",
            "status",
            "expires_at",
            "features",
            "next_check_in",
            "grace_until",
            "heartbeat_interval",
            "satisfied_methods",
            "ticket",
            "unlock_seed",
        }
        if not isinstance(data, dict) or not required <= data.keys():
            raise ValueError("fields")
        grant = client.grant(data["ticket"])
        if (
            _integer(data["license_id"]) != _integer(grant["license_id"])
            or not 0 < _integer(data["license_id"]) < 2**63
            or data["status"] != "active"
            or not isinstance(data["features"], dict)
            or _integer(data["next_check_in"]) != _integer(grant["next_check_in"])
            or not 1 <= _integer(data["heartbeat_interval"]) <= 3600
        ):
            raise ValueError("grant")
        methods = data["satisfied_methods"]
        if (
            not isinstance(methods, list)
            or not all(
                type(m) is str and m in ("KEY", "FLOATING")
                for m in methods
            )
            or len(set(methods)) != len(methods)
            or "KEY" not in methods
            or "FLOATING" in methods
            and not data.get("lease_expires_at")
        ):
            raise ValueError("methods")
        if not data["grace_until"] or stamp(data["grace_until"]) == float("inf"):
            raise ValueError("grace")
        client.valid_grant_time(dict(data, floating="FLOATING" in methods))
        if abs(stamp(grant["issued_at"]) - client.now()) > 300:
            raise Error("SDK_RESPONSE_TIMESTAMP_INVALID")
        seed = unb64(data["unlock_seed"])
        if len(seed) != 32 or sha(seed) != grant["unlock_hash"]:
            raise ValueError("seed")
        if grant["challenge"] != challenge or _integer(grant["license_id"]) != _integer(
            previous.data["license_id"]
        ):
            raise ValueError("context")
        return Result(client, grant, data["ticket"], seed)
    except Error:
        raise
    except Exception:
        raise Error("SDK_RESPONSE_INVALID", "解锁票据上下文不符") from None


def _unlock_failure(client, payload, result, error):
    if error.refusal:
        client.payload_ready = False
        clear_payload_keys(client)
        if error.code == "INSTANCE_REPLACED":
            _replaced.add(client.instance_key())
            client.offline_until = client.online_until = 0
        else:
            client.revoke_cache()
        raise error
    try:
        return load_payload_key(client, payload, result)
    except Error:
        raise error from None


def unlock_payload(client, payload):
    """Public API always returns K32, including for payload v2."""
    material = _unlock_payload_material(client, payload)
    if not isinstance(material, bytearray):
        material = bytearray(material)
    try:
        return bytes(material[:32])
    finally:
        material[:] = b"\0" * len(material)


def _unlock_payload_material(client, payload):
    with client.lock:
        if (
            not client.payload_ready
            or client.state.get("refused")
            or not client.state.get("ticket")
            or client.instance_key() in _replaced
        ):
            raise Error("SDK_NOT_ACTIVATED", "请先完成授权校验")
        p = _coerce(payload)
        if p.app_key != client.config["app_key"]:
            raise _invalid()
        result = _cached_result(client)
        if client.now() + 300 < int(client.state.get("observed", 0)):
            raise Error("SDK_CLOCK_ROLLBACK")
        if client.offline_ticket == result.ticket() and not client.online_until:
            return load_payload_key(client, p, result)
        private = x25519.X25519PrivateKey.generate()
        ephemeral = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        # request supplies the independent 32-byte challenge, wraps/authenticates
        # the v2 channel, checks signature/nonce/time, and returns that challenge.
        base_body = client.body()
        body = {
            k: base_body[k]
            for k in (
                "license_key",
                "activation_token",
                "device_fingerprint",
                        "instance_session",
            )
        }
        body.update(payload=p.to_dict(), ephemeral_public_key=b64(ephemeral))
        try:
            data, challenge = client.request("payload.unlock", body)
        except Error as error:
            return _unlock_failure(client, p, result, error)
        except Exception:
            return _unlock_failure(
                client, p, result, Error("SDK_RESPONSE_INVALID", "解锁响应无效")
            )
        # Match Go: a malformed fresh ticket or failed unwrap is not an online
        # success and must not silently fall back to a cached key.
        fresh = _fresh_result(client, data, challenge, result)
        grant = fresh.data
        if grant.get("is_trial") or stamp(grant["grace_until"]) <= stamp(
            grant["issued_at"]
        ):
            client.payload_no_cache = True
            clear_payload_keys(client)
        # Only examine watermark after request authentication and fresh grant /
        # UID / challenge validation. This is terminal even with a valid cache.
        watermark = bytearray()
        if p.v == 2:
            value = data.get("watermark")
            if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise Error("SDK_RESPONSE_INVALID", "内容水印响应无效")
            watermark.extend(bytes.fromhex(value))
            if not any(watermark):
                raise Error("SDK_RESPONSE_INVALID", "内容水印响应无效")
        try:
            wrapped = {}
            for field in ("e", "n", "c"):
                # Missing/non-string envelope fields follow the authenticated recovery path;
                # bad encodings/GCM fail terminally, never masking a fresh error.
                if (
                    field not in data
                    or data[field] is not None
                    and type(data[field]) is not str
                ):
                    return _unlock_failure(
                        client, p, result, Error("SDK_RESPONSE_INVALID", "内容密钥响应无效")
                    )
                wrapped[field] = data[field] if data[field] is not None else ""
            key = unwrap_payload(p, wrapped, private, unb64(challenge))
            if p.v == 2:
                material = bytearray(key)
                material.extend(watermark)
                key = material
            save_payload_key(client, p, fresh, key)
            return key
        finally:
            watermark[:] = b"\0" * len(watermark)
