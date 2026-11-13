"""Chunk-vector and in-memory import regression tests. Fixtures never write pyc."""

import builtins
import copy
import hashlib
import importlib
import importlib.util
import io
import json
import marshal
import os
import pathlib
import struct
import sys
import tarfile
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
import authgo as a
from authgo import sealed
from authgo.guard import Guard
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_payload import LICENSE, Server

VECTORS = pathlib.Path(__file__).parents[2] / "vectors"
ROOT = "authgo_sealed_test_core"
KEY = bytes(range(32))
VERSION = f"{sys.version_info.major}.{sys.version_info.minor}"


def encrypt(payload, plain, index=0):
    count = max(1, (len(plain) + (1 << 20) - 1) // (1 << 20))
    result = bytearray()
    for j in range(count):
        nonce = struct.pack(">IQ", index, j)
        aad = (
            b"authgo-payload-chunk-v1\0"
            + payload.payload_binding()
            + nonce
            + bytes([int(j == count - 1)])
        )
        result.extend(
            AESGCM(KEY).encrypt(nonce, plain[j * (1 << 20) : (j + 1) * (1 << 20)], aad)
        )
    return bytes(result)


def check_chunk_vectors():
    v = json.loads((VECTORS / "payload-envelope.json").read_text())
    payload = a.parse_payload(json.dumps(v["payload"]))
    assert payload.payload_binding().hex() == v["binding_hex"]
    cipherfiles = {}
    plainfiles = {}
    for chunk in v["chunks"]:
        index, j = chunk["file"], chunk["chunk"]
        plain = (
            bytes.fromhex(chunk["plain_hex"])
            if "plain_hex" in chunk
            else bytes.fromhex(chunk["plain_repeat_hex"]) * chunk["plain_repeat_count"]
        )
        nonce = struct.pack(">IQ", index, j)
        aad = (
            b"authgo-payload-chunk-v1\0"
            + payload.payload_binding()
            + nonce
            + bytes([int(chunk["last"])])
        )
        assert nonce.hex() == chunk["nonce_hex"]
        assert aad.hex() == chunk["aad_hex"]
        ct = AESGCM(bytes.fromhex(v["content_key_hex"])).encrypt(nonce, plain, aad)
        if "cipher_hex" in chunk:
            assert ct.hex() == chunk["cipher_hex"]
        else:
            assert ct[:32].hex() == chunk["cipher_first32_hex"]
            assert ct[-16:].hex() == chunk["tag_hex"]
            assert hashlib.sha256(ct).hexdigest() == chunk["cipher_sha256_hex"]
        cipherfiles.setdefault(index, bytearray()).extend(ct)
        plainfiles.setdefault(index, bytearray()).extend(plain)
    for index in cipherfiles:
        blocks = list(
            a.decrypt_payload_file(payload, KEY, index, memoryview(cipherfiles[index]))
        )
        assert all(len(block) <= 1 << 20 for block in blocks)
        assert b"".join(blocks) == plainfiles[index]
        assert a.payload_cipher_size(len(plainfiles[index])) == len(cipherfiles[index])


def pyc(source, *, magic=None, flags=0):
    header = (
        (magic or importlib.util.MAGIC_NUMBER) + struct.pack("<I", flags) + b"\0" * 8
    )
    return header + marshal.dumps(compile(source, "/private/build/secret.py", "exec"))


PRIVATE_CIPHERS = {}

def bundle(entries, *, version=VERSION, index=0, padding=0):
    tag = "0123456789abcdef0123456789abcdef"
    slot = tag + "0" * 64
    carrier = pyc("VALUES = " + repr(tuple(str(i) + slot for i in range(8))))
    entries = list(entries) + [("__authgo_carrier__.pyc", carrier)]
    offsets = [str(i) for i in range(len(carrier) - 95) if carrier[i:i+96] == slot.encode()]
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            if isinstance(data, tarfile.TarInfo):
                archive.addfile(data)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    plain = out.getvalue() + b"\0" * padding
    obj = json.loads((VECTORS / "payload-envelope.json").read_text())["payload"]
    files = [
        dict(
            name="ignored",
            kind="node",
            path=f"{i:08d}.agc",
            size=768,
            chunk_size=1 << 20,
            encoding="raw",
        )
        for i in range(index)
    ]
    files.append(
        dict(
            name=ROOT,
            kind="python",
            path=f"{index:08d}.agc",
            size=len(plain),
            chunk_size=1 << 20,
            encoding="tar",
            python_version=version,
        )
    )
    private = a.canonical(dict(v="1", tag=tag, files=[dict(index=str(i), entries=[dict(path=["__authgo_carrier__.pyc"] if i == index else [], offsets=offsets if i == index else [str(j*96) for j in range(8)])]) for i in range(len(files))])).encode()
    files.append(dict(name="__authgo_watermark", kind="watermark", path=f"{index+1:08d}.agc", size=len(private), chunk_size=1<<20, encoding="raw"))
    obj["manifest"] = a.b64(json.dumps({"files": files}, separators=(",", ":")).encode())
    payload = a.parse_payload(json.dumps(obj))
    PRIVATE_CIPHERS[payload.payload_binding()] = encrypt(payload, private, index+1)
    return payload, encrypt(payload, plain, index)


class FakeClient:
    def __init__(self, key=KEY):
        self.key, self.calls, self.error = key, 0, None
        self.cache_warning = None

    def validate(self, ticket):
        if self.error:
            raise self.error

    def _unlock_payload_material(self, payload):
        self.calls += 1
        if self.error:
            raise self.error
        return self.key + b"\x19" * 32


def guard_for(client):
    # Exercise the real Guard.require/install methods without starting its
    # scheduler; network/crypto integration below uses the actual Client.
    g = object.__new__(Guard)
    g._client, g._lock = client, threading.RLock()
    g._result = a.Result(client, {"features": {}}, "fixture-ticket", b"x" * 32)
    g._error = None
    g._stop, g._done = threading.Event(), threading.Event()
    return g


class SealedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.env = patch.dict(os.environ, AUTHGO_PAYLOAD_DIR=str(self.directory))
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = FakeClient()
        self.guard = guard_for(self.client)
        self.addCleanup(self.cleanup_imports)

    def cleanup_imports(self):
        for name in list(sys.modules):
            if name == ROOT or name.startswith(ROOT + "."):
                del sys.modules[name]
        sys.meta_path[:] = [
            f
            for f in sys.meta_path
            if not (isinstance(f, sealed.SealedFinder) and f.root == ROOT)
        ]

    def prepare(self, entries=None, **kwargs):
        if entries is None:
            entries = [
                ("__init__.pyc", pyc("VALUE = 42")),
                ("late.pyc", pyc("VALUE = 99")),
            ]
        payload, ct = bundle(entries, **kwargs)
        (self.directory / "payload.json").write_text(json.dumps(payload.to_dict()))
        files = a.loads(a.unb64(payload.manifest))["files"]
        (self.directory / files[-2]["path"]).write_bytes(ct)
        (self.directory / files[-1]["path"]).write_bytes(PRIVATE_CIPHERS[payload.payload_binding()])
        return payload, ct

    def error(self, code, action):
        with self.assertRaises(a.Error) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_go_chunk_vectors(self):
        check_chunk_vectors()

    def test_stream_chunk_bounds_and_auth_before_yield(self):
        payload, _ = self.prepare()
        # Use a manifest file with two chunks, independently constructed.
        obj = payload.to_dict()
        files = a.loads(a.unb64(payload.manifest))["files"]
        files[0]["size"] = (1 << 20) + 3
        obj["manifest"] = a.b64(a.canonical({"files": files}).encode())
        payload = a.parse_payload(json.dumps(obj))
        ct = bytearray(encrypt(payload, b"A" * (1 << 20) + b"end"))
        ct[-1] ^= 1
        blocks = a.decrypt_payload_file(payload, KEY, 0, ct)
        self.assertEqual(next(blocks), b"A" * (1 << 20))
        self.error("PAYLOAD_INVALID", lambda: next(blocks))

    def test_cipher_size_and_bad_inputs(self):
        for size in (0, 1, (1 << 20) - 1, 1 << 20, (1 << 20) + 1):
            self.assertEqual(
                a.payload_cipher_size(size),
                size + 16 * max(1, (size + (1 << 20) - 1) // (1 << 20)),
            )
        payload, ct = self.prepare()
        for index, key, cipher in (
            (-1, KEY, ct),
            (1, KEY, ct),
            (True, KEY, ct),
            (0, b"x", ct),
            (0, KEY, ct[:-1]),
            (0, KEY, ct + b"x"),
        ):
            self.error(
                "PAYLOAD_INVALID",
                lambda: list(a.decrypt_payload_file(payload, key, index, cipher)),
            )
        for size in (-1, True, 1.0, 2**63):
            self.error("PAYLOAD_INVALID", lambda: a.payload_cipher_size(size))

    def test_chunk_order_key_and_binding(self):
        payload, ct = self.prepare()
        wrong = copy.deepcopy(payload.to_dict())
        wrong["version"] = "2.0.0"
        for p, key in ((payload, b"x" * 32), (a.parse_payload(json.dumps(wrong)), KEY)):
            self.error(
                "PAYLOAD_INVALID", lambda: list(a.decrypt_payload_file(p, key, 0, ct))
            )

    def test_reordered_chunks_are_rejected(self):
        payload, ct = self.prepare([("__init__.pyc", pyc("VALUE=1"))], padding=3 << 20)
        stride = (1 << 20) + 16
        reordered = ct[stride : 2 * stride] + ct[:stride] + ct[2 * stride :]
        self.error(
            "PAYLOAD_INVALID",
            lambda: next(a.decrypt_payload_file(payload, KEY, 0, reordered)),
        )

    def test_parallel_installation_registers_one_finder(self):
        self.prepare()
        gate = threading.Barrier(3)
        results = []

        def install(g):
            gate.wait()
            try:
                results.append(g.install_sealed(ROOT))
            except a.Error as error:
                results.append(error)

        workers = [
            threading.Thread(target=install, args=(guard_for(self.client),))
            for _ in range(2)
        ]
        for worker in workers:
            worker.start()
        gate.wait()
        for worker in workers:
            worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sum(isinstance(r, sealed.SealedFinder) for r in results), 1)
        self.assertEqual(
            [r.code for r in results if isinstance(r, a.Error)], ["PAYLOAD_INVALID"]
        )
        self.assertEqual(self.client.calls, 1)

    def test_import_subpackage_and_relative_import(self):
        self.prepare(
            [
                ("__init__.pyc", pyc("from .sub.entry import VALUE")),
                ("sub/__init__.pyc", pyc("")),
                ("sub/entry.pyc", pyc("from ..helper import VALUE")),
                ("helper.pyc", pyc("VALUE = 314")),
            ]
        )
        self.guard.install_sealed(ROOT)
        module = importlib.import_module(ROOT)
        self.assertEqual(module.VALUE, 314)
        self.assertTrue(module.__file__.startswith("authgo-sealed://"))
        entry = sys.modules[ROOT + ".sub.entry"]
        self.assertEqual(entry.__package__, ROOT + ".sub")
        self.assertFalse(pathlib.Path(entry.__file__).exists())
        self.assertEqual(self.client.calls, 1)

    def test_standard_pycache_and_optimized_bytecode(self):
        tag = sys.implementation.cache_tag
        self.prepare(
            [
                (f"__pycache__/__init__.{tag}.pyc", pyc("from .sub import VALUE")),
                (f"sub/__pycache__/__init__.{tag}.opt-1.pyc", pyc("VALUE = 7")),
            ]
        )
        self.guard.install_sealed(ROOT)
        self.assertEqual(importlib.import_module(ROOT).VALUE, 7)

    def test_namespace_package(self):
        self.prepare([("nested/entry.pyc", pyc("VALUE = 8"))])
        self.guard.install_sealed(ROOT)
        self.assertEqual(importlib.import_module(ROOT + ".nested.entry").VALUE, 8)

    def test_file_index_not_always_zero(self):
        self.prepare(index=1)
        self.guard.install_sealed(ROOT)
        self.assertEqual(importlib.import_module(ROOT).VALUE, 42)

    def test_version_mismatch_before_unlock(self):
        self.prepare(version="3.8" if VERSION != "3.8" else "3.9")
        e = self.error("PAYLOAD_INVALID", lambda: self.guard.install_sealed(ROOT))
        self.assertIn("Python 版本", str(e))
        self.assertEqual(self.client.calls, 0)

    def test_invalid_pyc_headers_and_marshal(self):
        for raw in (
            b"short",
            pyc("", magic=b"xxxx"),
            pyc("", flags=4),
            pyc("")[:16] + marshal.dumps(42),
            pyc("") + b"extra",
        ):
            self.prepare([("__init__.pyc", raw)])
            self.error("PAYLOAD_INVALID", lambda: self.guard.install_sealed(ROOT))
            self.assertNotIn(ROOT, sys.modules)

    def test_unsafe_archive_entries(self):
        link = tarfile.TarInfo("linked.pyc")
        link.type, link.linkname = tarfile.SYMTYPE, "__init__.pyc"
        for name, data in (
            ("../evil.pyc", pyc("")),
            ("/evil.pyc", pyc("")),
            ("sub/./evil.pyc", pyc("")),
            ("source.py", pyc("")),
            ("bad-name.pyc", pyc("")),
            ("linked.pyc", link),
        ):
            self.prepare([(name, data)])
            self.error("PAYLOAD_INVALID", lambda: self.guard.install_sealed(ROOT))

    def test_duplicate_or_conflicting_modules(self):
        for entries in (
            [("__init__.pyc", pyc("")), ("__init__.pyc", pyc(""))],
            [("sub.pyc", pyc("")), ("sub/child.pyc", pyc(""))],
        ):
            self.prepare(entries)
            self.error("PAYLOAD_INVALID", lambda: self.guard.install_sealed(ROOT))

    def test_refusal_blocks_lazy_import_and_exec(self):
        self.prepare()
        finder = self.guard.install_sealed(ROOT)
        imported = importlib.import_module(ROOT)
        self.client.error = a.Error("LICENSE_REVOKED", authenticated=True)
        self.error("LICENSE_REVOKED", lambda: importlib.import_module(ROOT + ".late"))
        self.error("LICENSE_REVOKED", lambda: finder.exec_module(imported))
        self.assertNotIn(ROOT + ".late", sys.modules)
        # Existing modules are not unloaded; Guard remains responsible for exit.
        self.assertEqual(imported.VALUE, 42)

    def test_guard_notification_blocks_lazy_import(self):
        self.prepare()
        self.guard._on_change = None
        self.guard.install_sealed(ROOT)
        importlib.import_module(ROOT)
        self.guard._notify(error=a.Error("LICENSE_REVOKED", authenticated=True))
        self.assertTrue(self.guard.done.is_set())
        self.error("LICENSE_REVOKED", lambda: importlib.import_module(ROOT + ".late"))

    def test_closed_guard_and_expired_ticket(self):
        self.prepare()
        self.guard._stop.set()
        self.error("SDK_NOT_ACTIVATED", lambda: self.guard.install_sealed(ROOT))
        self.assertEqual(self.client.calls, 0)
        self.guard._stop.clear()
        self.client.error = a.Error("SDK_GRACE_EXPIRED")
        self.error("SDK_GRACE_EXPIRED", lambda: self.guard.install_sealed(ROOT))

    def test_install_failure_never_publishes_partial_archive(self):
        self.prepare([("__init__.pyc", pyc("VALUE=1")), ("bad.pyc", b"invalid")])
        self.error("PAYLOAD_INVALID", lambda: self.guard.install_sealed(ROOT))
        self.assertFalse(
            any(
                isinstance(f, sealed.SealedFinder) and f.root == ROOT
                for f in sys.meta_path
            )
        )

    def test_authenticates_trailing_tar_padding(self):
        # The tar end marker is early; corruption in the final chunk must still
        # fail installation instead of silently accepting a partial archive.
        payload, ct = self.prepare([("__init__.pyc", pyc("VALUE=1"))], padding=2 << 20)
        ct = bytearray(ct)
        ct[-1] ^= 1
        (self.directory / "00000000.agc").write_bytes(ct)
        self.error("PAYLOAD_INVALID", lambda: self.guard.install_sealed(ROOT))
        self.assertNotIn(ROOT, sys.modules)

    def test_no_plaintext_or_temporary_files(self):
        marker = "MEMORY_ONLY_CORE_MARKER"
        self.prepare([("__init__.pyc", pyc("VALUE=" + repr(marker)))])
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        real_open = builtins.open
        real_io_open = io.open

        def read_only(original):
            def checked(file, mode="r", *args, **kwargs):
                self.assertFalse(any(flag in mode for flag in "wax+"))
                return original(file, mode, *args, **kwargs)

            return checked

        with patch("builtins.open", read_only(real_open)), patch(
            "io.open", read_only(real_io_open)
        ), patch(
            "tempfile.TemporaryFile", side_effect=AssertionError("tempfile")
        ), patch(
            "tempfile.NamedTemporaryFile", side_effect=AssertionError("tempfile")
        ):
            self.guard.install_sealed(ROOT)
            self.assertEqual(importlib.import_module(ROOT).VALUE, marker)
        self.assertEqual(
            before, {p.name: p.read_bytes() for p in self.directory.iterdir()}
        )
        self.assertTrue(all(marker.encode() not in raw for raw in before.values()))

    def test_virtual_filename_nested_functions_and_resources(self):
        self.prepare([("__init__.pyc", pyc("def f():\n    return __file__"))])
        finder = self.guard.install_sealed(ROOT)
        module = importlib.import_module(ROOT)
        self.assertEqual(module.f.__code__.co_filename, module.__file__)
        self.assertTrue(module.f().startswith("authgo-sealed://"))
        with self.assertRaisesRegex(ImportError, "importlib.resources"):
            finder.get_resource_reader(ROOT)

    def test_virtual_filename_preserves_shared_code_and_constants_graph(self):
        namespace = {}
        exec("def f():\n    return 42\n", namespace)
        child = namespace["f"].__code__
        shared = []
        shared.append(shared)
        root = compile("", "/private/build.py", "exec")
        original = root.replace(co_consts=(None, child, child, (child,), shared, shared))
        uri = "authgo-sealed://core/__init__.pyc"
        actual = sealed._virtual_code(original, uri)
        self.assertEqual(actual.co_code, original.co_code)
        self.assertIs(actual.co_consts[1], actual.co_consts[2])
        self.assertIs(actual.co_consts[1], actual.co_consts[3][0])
        self.assertIs(actual.co_consts[4], actual.co_consts[5])
        self.assertIs(actual.co_consts[4][0], actual.co_consts[4])
        self.assertEqual(actual.co_consts[1].co_filename, uri)
        self.assertEqual(actual.co_filename, uri)
        self.assertEqual(types.FunctionType(actual.co_consts[1], {})(), 42)
        self.assertEqual(child.co_filename, "<string>")
        self.assertIs(original.co_consts[1], child)

    def test_no_plaintext_fallback_and_no_overriding_existing_module(self):
        self.prepare()
        self.guard.install_sealed(ROOT)
        importlib.import_module(ROOT)
        with self.assertRaises(ModuleNotFoundError):
            importlib.import_module(ROOT + ".absent")
        self.error("PAYLOAD_INVALID", lambda: self.guard.install_sealed(ROOT))

    def test_real_authenticated_client_and_refusal(self):
        payload, _ = self.prepare()
        server = Server()
        server.payload, server.dek = payload, KEY
        client = server.client(str(self.directory / "cache"))
        guard = guard_for(client)
        guard._result = client.check(LICENSE)
        guard.install_sealed(ROOT)
        self.assertEqual(importlib.import_module(ROOT).VALUE, 42)
        self.assertTrue(list(client.cache.glob("authgo-payload-v2-*.cache")))
        server.response_code = "LICENSE_REVOKED"
        self.error("LICENSE_REVOKED", client.verify)
        self.error("SDK_NOT_ACTIVATED", lambda: importlib.import_module(ROOT + ".late"))
        self.assertFalse(list(client.cache.glob("authgo-payload-v2-*.cache")))


if __name__ == "__main__":
    unittest.main()
