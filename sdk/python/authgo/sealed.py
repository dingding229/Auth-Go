"""Authenticated chunk decryption and CPython imports without plaintext files."""

import importlib.abc
import importlib.machinery
import importlib.util
import io
import marshal
import os
import pathlib
import re
import struct
import sys
import tarfile
import threading
import types

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import Error, loads, unb64
from .payload import _coerce, _integer, _invalid
from .watermark import parse_watermark_index, apply_watermark

_INSTALL_LOCK = threading.RLock()

PAYLOAD_CHUNK_SIZE = 1 << 20
_MAGICS = {
    "3.8": 3413,
    "3.9": 3425,
    "3.10": 3439,
    "3.11": 3495,
    "3.12": 3531,
    "3.13": 3571,
    "3.14": 3627,
}


def payload_cipher_size(size):
    """Ciphertext length, including one tag even for an empty plaintext."""
    if type(size) is not int or not 0 <= size <= (2**63 - 1) // 2:
        raise _invalid()
    return size + 16 * max(1, (size + PAYLOAD_CHUNK_SIZE - 1) // PAYLOAD_CHUNK_SIZE)


def decrypt_payload_file(payload, key, index, ciphertext):
    """Yield authenticated blocks (<= 1 MiB) from bytes or a memoryview.

    The caller may consume incrementally; never use a partial result after an
    authentication error. No unverified block is yielded, including the last.
    """
    try:
        p = _coerce(payload)
        files = loads(unb64(p.manifest))["files"]
        if type(index) is not int or not 0 <= index < len(files) or len(key) != 32:
            raise ValueError("index/key")
        view = memoryview(ciphertext).cast("B")
        size = _integer(files[index]["size"])
        if len(view) != payload_cipher_size(size):
            raise ValueError("ciphertext size")
        binding = p.payload_binding()
        cipher = AESGCM(bytes(key))
        count = max(1, (size + PAYLOAD_CHUNK_SIZE - 1) // PAYLOAD_CHUNK_SIZE)
        for j in range(count):
            n = min(PAYLOAD_CHUNK_SIZE, size - j * PAYLOAD_CHUNK_SIZE)
            nonce = struct.pack(">IQ", index, j)
            aad = (
                b"authgo-payload-chunk-v1\0"
                + binding
                + nonce
                + bytes([int(j == count - 1)])
            )
            offset = j * (PAYLOAD_CHUNK_SIZE + 16)
            plain = cipher.decrypt(nonce, bytes(view[offset : offset + n + 16]), aad)
            yield plain
    except Exception:
        raise _invalid() from None


class _ChunkReader(io.RawIOBase):
    def __init__(self, chunks):
        super().__init__()
        self.chunks = iter(chunks)
        self.pending = memoryview(b"")

    def readable(self):
        return True

    def readinto(self, buffer):
        while not self.pending:
            try:
                self.pending = memoryview(next(self.chunks))
            except StopIteration:
                return 0
        count = min(len(buffer), len(self.pending))
        buffer[:count] = self.pending[:count]
        self.pending = self.pending[count:]
        return count


def _module_name(root, path, version):
    if (
        not path
        or "\\" in path
        or "\0" in path
        or ":" in path
        or path.startswith("/")
        or any(p in ("", ".", "..") for p in path.split("/"))
    ):
        raise _invalid()
    parts = path.split("/")
    leaf = parts.pop()
    if parts and parts[-1] == "__pycache__":
        parts.pop()
        match = re.fullmatch(
            r"(.+)\.cpython-" + version.replace(".", "") + r"(?:\.opt-[12])?\.pyc", leaf
        )
        if match is None:
            raise _invalid()
        leaf = match[1]
    elif leaf.endswith(".pyc"):
        leaf = leaf[:-4]
    else:
        raise _invalid()
    package = leaf == "__init__"
    if not package:
        parts.append(leaf)
    if any(not part.isidentifier() for part in parts):
        raise _invalid()
    return ".".join([root] + parts), package


def _virtual_code(code, filename):
    """Virtualize traceback paths without destroying shared code/constant graphs.

    The old recursive .replace cloned each code occurrence independently. Use
    one graph memo for all references, including code inside ordinary tuples or
    containers. Mutable containers are reserved before descending; tuple cycles
    use the same post-recursion memo check as deepcopy. No code is executed.
    """
    memo, active_codes = {}, set()

    def rewrite(value):
        if not isinstance(value, (types.CodeType, tuple, list, dict, set, frozenset)):
            return value
        identity = id(value)
        if identity in memo:
            return memo[identity]
        if isinstance(value, types.CodeType):
            if identity in active_codes:
                # Immutable code/tuple self cycles cannot be rebuilt through
                # CodeType.replace. Reject rather than silently break aliases.
                raise _invalid()
            active_codes.add(identity)
            try:
                constants = rewrite(value.co_consts)
                result = value.replace(co_filename=filename, co_consts=constants)
                memo[identity] = result
                return result
            finally:
                active_codes.remove(identity)
        if isinstance(value, list):
            result = []
            memo[identity] = result
            result.extend(rewrite(item) for item in value)
        elif isinstance(value, dict):
            result = {}
            memo[identity] = result
            for key, item in value.items():
                result[rewrite(key)] = rewrite(item)
        elif isinstance(value, set):
            result = set()
            memo[identity] = result
            result.update(rewrite(item) for item in value)
        else:
            items = [rewrite(item) for item in value]
            if identity in memo:
                return memo[identity]
            result = (value if all(a is b for a, b in zip(value, items))
                      else tuple(items)) if isinstance(value, tuple) else frozenset(items)
            memo[identity] = result
        return result

    return rewrite(code)


def _archive(root, version, chunks, private_index=None, file_index=None, watermark=None):
    # Retain only writable bytecode buffers until the entire archive has been
    # authenticated and every referenced watermark slot has been validated.
    modules = {}
    targets, descriptions, aliases = {}, {}, set()
    try:
        with io.BufferedReader(_ChunkReader(chunks)) as stream:
            with tarfile.open(fileobj=stream, mode="r|") as archive:
                for entry in archive:
                    if not entry.isfile() or entry.pax_headers:
                        raise _invalid()
                    name, package = _module_name(root, entry.name, version)
                    if name in descriptions or entry.size < 16:
                        raise _invalid()
                    if private_index is not None:
                        alias = entry.name.lower()
                        if alias in aliases:
                            raise _invalid()
                        aliases.add(alias)
                    source = archive.extractfile(entry)
                    raw = bytearray(source.read())
                    targets[(entry.name,)] = raw
                    if len(raw) != entry.size:
                        raise _invalid()
                    descriptions[name] = (entry.name, package)
            # tar readers stop at their end marker; authenticate all remaining
            # chunks before patching, decoding, or publishing modules.
            while stream.read(65536):
                pass
        if private_index is not None:
            apply_watermark(targets, private_index, file_index, watermark)
        for name, (entry_name, package) in descriptions.items():
            with io.BytesIO(targets[(entry_name,)]) as source:
                header = source.read(16)
                if (
                    len(header) != 16
                    or header[:4] != importlib.util.MAGIC_NUMBER
                    or struct.unpack("<I", header[4:8])[0] & ~3
                ):
                    raise _invalid()
                code = marshal.load(source)
                if not isinstance(code, types.CodeType) or source.read(1):
                    raise _invalid()
                filename = "authgo-sealed://" + root + "/" + entry_name
                modules[name] = (_virtual_code(code, filename), package, filename)
    finally:
        for raw in targets.values():
            raw[:] = b"\0" * len(raw)
    if not modules:
        raise _invalid()
    for name in list(modules):
        parent = name.rpartition(".")[0]
        while parent == root or parent.startswith(root + "."):
            if parent in modules and not modules[parent][1]:
                raise _invalid()
            modules.setdefault(parent, (None, True, "authgo-sealed://" + parent + "/"))
            parent = parent.rpartition(".")[0]
    return modules


class SealedFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """A closed, virtual module tree. Already imported modules stay in memory."""

    def __init__(self, guard, root, modules):
        self.guard, self.root, self.modules = guard, root, modules

    def find_spec(self, fullname, path=None, target=None):
        if fullname != self.root and not fullname.startswith(self.root + "."):
            return None
        self.guard.require()
        if fullname not in self.modules:
            # No fallback to a plaintext package on disk for this sealed tree.
            raise ModuleNotFoundError("加密包中没有此模块", name=fullname)
        _, package, filename = self.modules[fullname]
        spec = importlib.machinery.ModuleSpec(
            fullname, self, origin=filename, is_package=package
        )
        spec.has_location = True
        if package:
            spec.submodule_search_locations = [filename.rsplit("/", 1)[0]]
        return spec

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        code = self.get_code(module.__name__)
        if code is not None:
            exec(code, module.__dict__)

    def get_code(self, fullname):
        """Return the exact retained executable CodeType, not reconstructed pyc.

        Root co_consts can contain watermark strings even when module execution
        has returned and no function retains that root CodeType.
        """
        self.guard.require()
        with self.guard._lock:
            if fullname not in self.modules:
                raise ModuleNotFoundError("加密包中没有此模块", name=fullname)
            return self.modules[fullname][0]

    def get_resource_reader(self, fullname):
        raise ImportError(
            "加密包不支持 importlib.resources，请将数据文件放在加密包之外"
        )


def install_sealed(guard, name):
    """Install named Python content from /opt/authgo (AUTHGO_PAYLOAD_DIR)."""
    with _INSTALL_LOCK:
        return _install_sealed(guard, name)


def _install_sealed(guard, name):
    guard.require()
    if not isinstance(name, str) or not name.isidentifier():
        raise _invalid()
    # Paths locate public ciphertext only. Never use payload.config to select
    # the server or replace the Client's compiled-in connection configuration.
    directory = pathlib.Path(os.environ.get("AUTHGO_PAYLOAD_DIR", "/opt/authgo"))
    try:
        with (directory / "payload.json").open("rb") as source:
            payload = _coerce(source.read(65537))
        files = loads(unb64(payload.manifest))["files"]
        index, file = next((i, f) for i, f in enumerate(files) if f["name"] == name)
        if file["kind"] != "python":
            raise _invalid()
        version = f"{sys.version_info.major}.{sys.version_info.minor}"
        if (
            sys.implementation.name != "cpython"
            or file["python_version"] != version
            or _MAGICS.get(version)
            != int.from_bytes(importlib.util.MAGIC_NUMBER[:2], "little")
        ):
            raise Error(
                "PAYLOAD_INVALID",
                "加密包的 Python 版本与当前解释器主次版本不一致，请用相同版本重新打包",
            )
        if name in sys.modules or any(
            isinstance(f, SealedFinder) and f.root == name for f in sys.meta_path
        ):
            raise Error(
                "PAYLOAD_INVALID", "此包已加载或已安装，请在首次导入前安装加密包"
            )
        with (directory / file["path"]).open("rb") as source:
            total = payload_cipher_size(_integer(file["size"]))
            if os.fstat(source.fileno()).st_size != total:
                raise _invalid()
            ciphertext = source.read(total + 1)
        material = (
            guard._client._unlock_payload_material(payload)
        )
        if not isinstance(material, bytearray):
            material = bytearray(material)
        try:
            if len(material) != 64:
                raise _invalid()
            key = memoryview(material)[:32]
            private_index = None
            if payload.v == 2:
                meta_index, meta = next((i, f) for i, f in enumerate(files) if f["kind"] == "watermark")
                with (directory / meta["path"]).open("rb") as source:
                    total = payload_cipher_size(_integer(meta["size"]))
                    if os.fstat(source.fileno()).st_size != total:
                        raise _invalid()
                    encrypted = source.read(total + 1)
                raw = bytearray()
                try:
                    for block in decrypt_payload_file(payload, key, meta_index, encrypted):
                        raw.extend(block)
                    # No parsing until every encrypted index chunk authenticates.
                    private_index = parse_watermark_index(raw, files)
                finally:
                    raw[:] = b"\0" * len(raw)
            guard.require()
            modules = _archive(
                name, version, decrypt_payload_file(payload, key, index, ciphertext),
                private_index, index, memoryview(material)[32:],
            )
        finally:
            material[:] = b"\0" * len(material)
        guard.require()
        if name in sys.modules:
            raise Error("PAYLOAD_INVALID", "此包已加载，请在首次导入前安装加密包")
        finder = SealedFinder(guard, name, modules)
        # Registration and close/refusal cleanup share only the Guard lock;
        # never wait on the Client while holding that lock.
        with guard._lock:
            if guard._error or guard._stop.is_set() or guard._done.is_set():
                modules.clear()
                if guard._error:
                    raise guard._error
                raise Error("SDK_NOT_ACTIVATED", "授权守卫已关闭")
            if not hasattr(guard, "_sealed_loaders"):
                guard._sealed_loaders = []
            guard._sealed_loaders.append(finder)
            sys.meta_path.insert(0, finder)
        return finder
    except Error:
        raise
    except Exception:
        raise _invalid() from None
