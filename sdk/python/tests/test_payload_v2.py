"""Current watermark schema, authentication and loader security tests."""

import copy
import builtins
import base64
import importlib
import marshal
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
import authgo as a
from authgo import payload as p
from authgo.watermark import parse_watermark_index, apply_watermark
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from test_payload import LICENSE, Server, vector
from test_sealed import ROOT, KEY, bundle, encrypt, pyc, guard_for

TAG = "0123456789abcdef0123456789abcdef"
WM = bytes(range(1, 33))
SLOT = TAG.encode() + b"0" * 64


def public_file(index=0, kind="node", name="core", size=2048):
    return dict(name=name, kind=kind, path=f"{index:08d}.agc", size=size,
                chunk_size=1048576, encoding="raw")


def meta_file(index=1, size=1):
    return public_file(index, "watermark", "__authgo_watermark", size)


def payload_with(files=None):
    value = copy.deepcopy(vector("payload-envelope.json")["payload"])
    value["v"] = 2
    value["manifest"] = a.b64(a.canonical({"files": files or [public_file(), meta_file()]}).encode())
    return value


def private_index(path=None):
    return dict(v="1", tag=TAG, files=[dict(index="0", entries=[dict(
        path=[] if path is None else path, offsets=[str(i * 96) for i in range(8)]
    )])])


def raw(value):
    return a.canonical(value).encode()


class WatermarkIndexTests(unittest.TestCase):
    def invalid(self, action):
        with self.assertRaises(a.Error) as raised:
            action()
        self.assertEqual(raised.exception.code, "PAYLOAD_INVALID")

    def parse(self, value, files=None):
        return parse_watermark_index(raw(value), files or [public_file(), meta_file()])

    def test_public_v2_exact_metadata_and_versioned_binding(self):
        value = payload_with()
        parsed = a.parse_payload(raw(value))
        self.assertEqual(parsed.v, 2)
        self.assertTrue(p._payload_aad(parsed).startswith(b"authgo-payload-envelope-v2\0"))
        self.assertTrue(p.payload_rewrap_aad(parsed, b"e" * 32, b"c" * 32).startswith(b"authgo-payload-rewrap-v2\0"))
        for change in (
            lambda f: f.pop(),
            lambda f: f[1].update(python_version=""),
            lambda f: f[1].update(main_class=""),
            lambda f: f[1].update(architecture=""),
            lambda f: f[1].update(size=0),
            lambda f: f[1].update(size=8388609),
            lambda f: f[1].update(encoding="tar"),
            lambda f: f[1].update(name="other"),
            lambda f: f[0].update(name="__authgo_watermark"),
            lambda f: f[1].update(path="00000000.agc"),
            lambda f: f.append(meta_file(2)),
        ):
            files = [public_file(), meta_file()]
            change(files)
            self.invalid(lambda: a.parse_payload(raw(payload_with(files))))
        self.invalid(lambda: a.parse_payload(raw(payload_with([meta_file(0)]))))
        text = raw(payload_with()).replace(b'"v":2', b'"v":2,"V":2')
        self.invalid(lambda: a.parse_payload(text))
        self.invalid(lambda: a.parse_payload(raw(payload_with()).replace(b'"v":2', b'"v":2,"v":2')))

    def test_private_schema_numbers_types_duplicates_aliases_paths_and_coverage(self):
        value = private_index()
        self.assertEqual(self.parse(value)["tag"], TAG)
        changes = [
            lambda x: x.update(v=1), lambda x: x.update(V="1"),
            lambda x: x.update(tag=TAG.upper()), lambda x: x.update(tag="a" * 31),
            lambda x: x["files"][0].update(index=0),
            lambda x: x["files"][0].update(index="00"),
            lambda x: x["files"][0].update(index="65535"),
            lambda x: x["files"][0].update(index="1"),
            lambda x: x["files"].append(copy.deepcopy(x["files"][0])),
            lambda x: x["files"][0]["entries"].append(copy.deepcopy(x["files"][0]["entries"][0])),
            lambda x: x["files"][0]["entries"][0].update(path=["code.pyc"]),
            lambda x: x["files"][0]["entries"][0].update(Path=[]),
            lambda x: x["files"][0]["entries"][0].update(offsets=["0"] * 8),
            lambda x: x["files"][0]["entries"][0].update(offsets=[str(i * 95) for i in range(8)]),
            lambda x: x["files"][0]["entries"][0].update(offsets=["0", "096"]),
            lambda x: x["files"][0]["entries"][0].update(offsets=[0] * 8),
            lambda x: x["files"][0]["entries"][0].update(offsets=["4611686018427387904"]),
            lambda x: x["files"][0]["entries"][0]["offsets"].pop(),
        ]
        for change in changes:
            bad = copy.deepcopy(value)
            change(bad)
            self.invalid(lambda: self.parse(bad))
        for text in (raw(value).replace(b'"v":"1"', b'"v":"1","v":"1"'),
                     raw(value).replace(b'"index":"0"', b'"index":"0","Index":"0"')):
            self.invalid(lambda: parse_watermark_index(text, [public_file(), meta_file()]))
        self.invalid(lambda: self.parse(value, [public_file(), public_file(1, name="second"), meta_file(2)]))
        for name in ("../x.pyc", "/x.pyc", "a//x.pyc", "a/./x.pyc", "x\\y.pyc", "x:y.pyc", "x\x00.pyc", "x\x7f.pyc"):
            self.invalid(lambda: self.parse(private_index([name]), [dict(public_file(), kind="python"), meta_file()]))
        aliases = private_index(["a.pyc"])
        aliases["files"][0]["entries"].append(dict(path=["A.pyc"], offsets=["0"]))
        self.invalid(lambda: self.parse(aliases, [dict(public_file(), kind="python"), meta_file()]))

    def test_private_bounds_before_tree_growth_and_atomic_slot_validation(self):
        self.invalid(lambda: parse_watermark_index(b" " * (8388608 + 1), [public_file()]))
        huge = b'{"v":"1","tag":"' + TAG.encode() + b'","files":[{"index":"0","entries":[{"path":[],"offsets":[' + b','.join([b'"0"'] * 65536) + b']}]}]}'
        self.invalid(lambda: parse_watermark_index(huge, [public_file(), meta_file()]))
        for huge in (
            dict(v="1", tag=TAG, files=[dict(index="0", entries=[])] * 65536),
            dict(v="1", tag=TAG, files=[dict(index="0", entries=[dict(path=[], offsets=[])] * 65536)]),
        ):
            self.invalid(lambda: parse_watermark_index(raw(huge), [public_file(), meta_file()]))
        for value in ("", "-1", "+1", "01", "1.0", "1e3", "١", "9223372036854775808"):
            bad = private_index()
            bad["files"][0]["entries"][0]["offsets"][0] = value
            self.invalid(lambda: self.parse(bad))
        paths = private_index(["a"] * 9)
        self.invalid(lambda: self.parse(paths, [dict(public_file(), kind="java"), meta_file()]))
        index = self.parse(private_index())
        target = bytearray(SLOT * 8)
        target[-1] = ord("1")
        before = bytes(target)
        self.invalid(lambda: apply_watermark({(): target}, index, 0, WM))
        self.assertEqual(target, before)
        target[-1] = ord("0")
        for wm in (b"", b"x" * 31, b"\0" * 32):
            self.invalid(lambda: apply_watermark({(): target}, index, 0, wm))
        self.invalid(lambda: apply_watermark({}, index, 0, WM))
        apply_watermark({(): target}, index, 0, WM)
        self.assertEqual(target, (TAG.encode() + WM.hex().encode()) * 8)
        self.invalid(lambda: apply_watermark({(): target}, index, 0, WM))
        self.invalid(lambda: self.parse(private_index(), [public_file(size=767), meta_file()]))
        archive_index = private_index(["a.pyc"])
        archive_index["files"][0]["entries"] = [
            dict(path=["a.pyc"], offsets=[str(i * 96) for i in range(4)]),
            dict(path=["b.pyc"], offsets=[str(i * 96) for i in range(4)]),
        ]
        archive_index = self.parse(archive_index, [dict(public_file(), kind="python"), meta_file()])
        first, second = bytearray(SLOT * 4), bytearray(SLOT * 4)
        second[-1] = ord("1")
        self.invalid(lambda: apply_watermark({("a.pyc",): first, ("b.pyc",): second}, archive_index, 0, WM))
        self.assertEqual(first, SLOT * 4)
        self.invalid(lambda: apply_watermark({("a.pyc",): first}, archive_index, 0, WM))
        self.assertEqual(first, SLOT * 4)
        archive_index["files"][0]["entries"][1]["offsets"][-1] = "10000"
        self.invalid(lambda: apply_watermark({("a.pyc",): first, ("b.pyc",): bytearray(SLOT * 4)}, archive_index, 0, WM))
        self.assertEqual(first, SLOT * 4)


class PayloadV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.server = Server()
        self.server.payload = a.parse_payload(raw(payload_with()))
        self.server.changes["watermark"] = WM.hex()
        self.client = self.server.client(self.temp.name)
        self.result = self.client.check(LICENSE)
        self.payload = self.server.payload

    def error(self, code, action):
        with self.assertRaises(a.Error) as raised:
            action()
        self.assertEqual(raised.exception.code, code)

    def caches(self):
        return sorted(self.directory.glob("authgo-payload-v*-*.cache"))

    def test_signed_material_public32_private64_cache_and_expiry(self):
        self.assertEqual(self.client.unlock_payload(self.payload), self.server.dek)
        self.assertEqual(self.client._unlock_payload_material(self.payload), self.server.dek + WM)
        cached = self.caches()[0]
        self.assertTrue(cached.name.startswith("authgo-payload-v2-"))
        self.assertTrue(cached.read_bytes().startswith(b"AUTHGO-PAYLOAD-CACHE-v2."))
        self.assertNotIn(self.server.dek + WM, cached.read_bytes())
        self.server.mode = "network"
        self.assertEqual(self.client._unlock_payload_material(self.payload), self.server.dek + WM)
        self.client.offline_ticket = self.result.ticket()
        self.client.online_until = 0
        before = len(self.server.calls)
        self.assertEqual(self.client._unlock_payload_material(self.payload), self.server.dek + WM)
        self.assertEqual(len(self.server.calls), before)
        self.client.offline_ticket = ""
        self.server.now += 120
        self.error("SDK_GRACE_EXPIRED", lambda: p.load_payload_key(self.client, self.payload, self.result))
        self.error("SDK_NETWORK_ERROR", lambda: self.client._unlock_payload_material(self.payload))

    def test_post_signature_valid_watermark_tamper_rejects_signature_without_payload_cache(self):
        self.assertFalse(self.caches())
        before = len(self.server.calls)
        self.server.mode = "watermark-tamper"
        self.error("SDK_RESPONSE_SIGNATURE_INVALID", lambda: self.client._unlock_payload_material(self.payload))
        self.assertFalse(self.caches())
        self.error("SDK_RESPONSE_SIGNATURE_INVALID", lambda: self.client.unlock_payload(self.payload))
        self.assertFalse(self.caches())
        self.assertEqual(self.server.calls[before:], ["payload.unlock", "payload.unlock"])
        self.server.mode = ""
        self.assertEqual(self.client._unlock_payload_material(self.payload), self.server.dek + WM)

    def test_fresh_malformed_watermark_is_terminal_after_validated_grant(self):
        self.client.unlock_payload(self.payload)
        before = self.caches()[0].read_bytes()
        for value in (None, "", WM.hex().upper(), "0" * 64, "x" * 64, WM.hex() + "\n", 42, {}):
            self.server.changes["watermark"] = value
            self.error("SDK_RESPONSE_INVALID", lambda: self.client.unlock_payload(self.payload))
            self.assertEqual(self.caches()[0].read_bytes(), before)
        del self.server.changes["watermark"]
        self.server.mode = "missing-watermark"
        self.error("SDK_RESPONSE_INVALID", lambda: self.client._unlock_payload_material(self.payload))
        self.assertEqual(self.caches()[0].read_bytes(), before)
        self.server.changes["watermark"] = WM.hex()
        self.server.mode = ""
        for mode in ("challenge", "license", "seed", "wrap"):
            self.server.mode = mode
            self.error("SDK_RESPONSE_INVALID", lambda: self.client.unlock_payload(self.payload))

    def test_cache_binding_material_length_trial_and_denial_cleanup(self):
        self.client.unlock_payload(self.payload)
        p.save_payload_key(self.client, self.payload, self.result, self.server.dek + WM)
        self.assertEqual(p.load_payload_key(self.client, self.payload, self.result), self.server.dek + WM)
        original = a.parse_payload(raw(vector("payload-cache-v2.json")["payload"]))
        p.save_payload_key(self.client, original, self.result, self.server.dek + WM)
        self.assertEqual(len(self.caches()), 2)
        changed = self.payload.to_dict()
        changed["envelope"]["n"] = a.b64(b"q" * 12)
        changed = a.parse_payload(raw(changed))
        destination, derived, aad = p._cache_material(self.client, changed, self.result)
        destination.write_bytes(next(f for f in self.caches() if f.name.startswith("authgo-payload-v2-")).read_bytes())
        destination.chmod(0o600)
        self.error("SDK_CACHE_INVALID", lambda: p.load_payload_key(self.client, changed, self.result))
        # The same encrypted file cannot authenticate under another signed UID.
        signed = self.client.grant(self.result.ticket())
        wrong_uid = dict(signed, license_id=43)
        with patch.object(self.client, "grant", return_value=wrong_uid):
            self.error("SDK_CACHE_INVALID", lambda: p.load_payload_key(self.client, self.payload, self.result))
        wrong_identity = dict(self.client.config, public_key=base64.b64encode(b"z" * 32).decode())
        with patch.object(self.client, "config", wrong_identity):
            self.error("SDK_CACHE_UNAVAILABLE", lambda: p.load_payload_key(self.client, self.payload, self.result))
        destination, derived, aad = p._cache_material(self.client, self.payload, self.result)
        nonce = b"z" * 12
        destination.write_bytes(b"AUTHGO-PAYLOAD-CACHE-v2." + a.b64(nonce + AESGCM(derived).encrypt(nonce, self.server.dek, aad)).encode())
        self.error("SDK_CACHE_INVALID", lambda: p.load_payload_key(self.client, self.payload, self.result))
        self.server.trial = True
        self.assertEqual(self.client._unlock_payload_material(self.payload), self.server.dek + WM)
        self.assertFalse(self.caches())
        self.server.changes.pop("watermark")
        self.server.mode = "missing-watermark"
        self.error("SDK_RESPONSE_INVALID", lambda: self.client.unlock_payload(self.payload))
        self.assertFalse(self.caches())
        self.server.changes["watermark"] = WM.hex()
        self.server.trial = False
        self.server.mode = ""
        self.client.check(LICENSE)
        self.client.unlock_payload(self.payload)
        p.save_payload_key(self.client, original, self.result, self.server.dek + WM)
        self.assertEqual(len(self.caches()), 2)
        self.server.response_code = "LICENSE_REVOKED"
        self.error("LICENSE_REVOKED", lambda: self.client.unlock_payload(self.payload))
        self.assertFalse(self.caches())

    def test_actual_loader_retains_root_code_constants_and_refuses_before_execution(self):
        original = pyc("VALUE = 42\n")
        module_code = marshal.loads(original[16:])
        constants = tuple("slot" + str(i) + ":" + SLOT.decode() for i in range(8))
        # Packer-style root co_consts, not function constants or a pyc trailer.
        module_code = module_code.replace(co_consts=module_code.co_consts + constants)
        bytecode = original[:16] + marshal.dumps(module_code)
        offsets, start = [], 0
        for _ in range(8):
            offset = bytecode.index(SLOT, start)
            offsets.append(str(offset))
            start = offset + 96
        old, _ = bundle([("__init__.pyc", bytecode)])
        files = a.loads(a.unb64(old.manifest))["files"][:1]
        index = private_index(["__init__.pyc"])
        index["files"][0]["entries"][0]["offsets"] = offsets
        private = raw(index) + b" " * 1048576
        files.append(meta_file(1, len(private)))
        value = old.to_dict()
        value.update(v=2, manifest=a.b64(raw({"files": files})))
        # bundle()'s tar framing, regenerated only when the parent runs tests.
        import io
        import tarfile
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("__init__.pyc")
            info.size = len(bytecode)
            archive.addfile(info, io.BytesIO(bytecode))
        files[0]["size"] = len(out.getvalue())
        value["manifest"] = a.b64(raw({"files": files}))
        payload = a.parse_payload(raw(value))
        ciphertext = encrypt(payload, out.getvalue())
        (self.directory / "payload.json").write_bytes(raw(payload.to_dict()))
        (self.directory / "00000000.agc").write_bytes(ciphertext)
        (self.directory / "00000001.agc").write_bytes(encrypt(payload, private, 1))
        self.server.payload, self.server.dek = payload, KEY
        guard = guard_for(self.client)
        guard._result = self.result
        finder = None
        try:
            with patch.dict(os.environ, AUTHGO_PAYLOAD_DIR=str(self.directory)):
                for material in (KEY, KEY + b"\0" * 32):
                    with patch.object(self.client, "_unlock_payload_material", return_value=material):
                        self.error("PAYLOAD_INVALID", lambda: guard.install_sealed(ROOT))
                bad = bytearray(encrypt(payload, private, 1))
                bad[-1] ^= 1
                (self.directory / "00000001.agc").write_bytes(bad)
                self.error("PAYLOAD_INVALID", lambda: guard.install_sealed(ROOT))
                self.assertNotIn(ROOT, sys.modules)
                (self.directory / "00000001.agc").write_bytes(encrypt(payload, private, 1))
                # Authenticated but invalid code slots must fail before marshal
                # or module execution, even though the key and index are valid.
                broken = bytearray(out.getvalue())
                broken[broken.index(SLOT) + 95] = ord("1")
                (self.directory / "00000000.agc").write_bytes(encrypt(payload, broken))
                self.error("PAYLOAD_INVALID", lambda: guard.install_sealed(ROOT))
                self.assertNotIn(ROOT, sys.modules)
                (self.directory / "00000000.agc").write_bytes(ciphertext)
                with patch.object(self.client, "unlock_payload", side_effect=AssertionError("public32 must not be used")):
                    finder = guard.install_sealed(ROOT)
                    retained = finder.get_code(ROOT)
                    executed = []
                    real_exec = builtins.exec

                    def record(code, *args, **kwargs):
                        if code is retained:
                            executed.append(code)
                        return real_exec(code, *args, **kwargs)

                    with patch.object(builtins, "exec", record):
                        module = importlib.import_module(ROOT)
                self.assertEqual(module.VALUE, 42)
                self.assertEqual(executed, [retained])
                self.assertIs(finder.get_code(ROOT), retained)
                self.assertEqual([v for v in retained.co_consts if type(v) is str and TAG in v],
                                 ["slot" + str(i) + ":" + TAG + WM.hex() for i in range(8)])
                self.assertEqual((self.directory / "00000000.agc").read_bytes(), ciphertext)
                self.assertFalse(any(f.suffix == ".pyc" for f in self.directory.iterdir()))
                # Observe refusal cleanup even if no further import is attempted.
                guard._on_change = None
                guard._notify(error=a.Error("LICENSE_REVOKED"))
                self.assertEqual(finder.modules, {})
                self.error("LICENSE_REVOKED", lambda: finder.get_code(ROOT))
        finally:
            sys.modules.pop(ROOT, None)
            if finder in sys.meta_path:
                sys.meta_path.remove(finder)

    def test_code_cache_is_released_on_close_and_get_code_stays_guarded(self):
        from authgo.guard import Guard
        from authgo.sealed import SealedFinder
        import threading

        class Client:
            cache_warning = None

            def validate(self, ticket):
                pass

            def release_seat(self):
                pass

        guard = guard_for(Client())
        guard._closing = False
        guard._close_error = None
        guard._closed = threading.Event()
        guard._stopped = threading.Event()
        guard._stopped.set()
        code = compile("VALUE = 42", "authgo-sealed://root/__init__.pyc", "exec")
        finder = SealedFinder(guard, "root", {"root": (code, True, "authgo-sealed://root")})
        guard._sealed_loaders = [finder]
        self.assertIs(finder.get_code("root"), code)
        Guard.close(guard)
        self.assertEqual(finder.modules, {})
        self.error("SDK_NOT_ACTIVATED", lambda: finder.get_code("root"))


if __name__ == "__main__":
    unittest.main()
