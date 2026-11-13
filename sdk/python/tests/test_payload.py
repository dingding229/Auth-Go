"""Native Python payload vectors and authenticated-channel/cache regression tests."""

import base64
import copy
import hashlib
import hmac
import json
import os
import pathlib
import stat
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
import authgo as a
from authgo import payload as p
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VECTORS = pathlib.Path(__file__).parents[2] / "vectors"
LICENSE = "AUTH-RNMSQ-VSQQA-4S4NH-JDGCM"


def vector(name):
    return json.loads((VECTORS / name).read_text())


def raw_public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def iso(when):
    return (
        a.datetime.datetime.fromtimestamp(when, a.datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def check_vectors():
    """Called both by pytest/unittest and the existing seven-language runner."""
    unlock = vector("payload-unlock-v2.json")
    payload = a.parse_payload(a.canonical(unlock["payload"]))
    private = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(unlock["client_private_hex"])
    )
    challenge = bytes.fromhex(unlock["challenge_hex"])
    aad = p.payload_rewrap_aad(payload, raw_public(private), challenge)
    assert aad.hex() == unlock["rewrap_aad_hex"]
    assert raw_public(private).hex() == unlock["client_public_hex"]
    shared = private.exchange(
        x25519.X25519PublicKey.from_public_bytes(
            bytes.fromhex(unlock["server_public_hex"])
        )
    )
    assert shared.hex() == unlock["shared_hex"]
    assert hashlib.sha256(aad).hexdigest() == unlock["salt_hex"]
    assert (
        a.hkdf(shared, hashlib.sha256(aad).digest(), b"authgo/payload/v1/rewrap").hex()
        == unlock["kek_hex"]
    )
    assert (
        p.unwrap_payload(payload, unlock["response"], private, challenge).hex()
        == unlock["content_key_hex"]
    )
    original = vector("payload-envelope.json")
    assert (
        a.parse_payload(a.canonical(original["payload"])).payload_binding().hex()
        == original["binding_hex"]
    )
    cache = vector("payload-cache-v2.json")
    payload = a.parse_payload(a.canonical(cache["payload"]))
    label = p.payload_cache_label(payload, cache["fingerprint"])
    assert label.hex() == cache["label_hex"]
    assert (b"authgo-unlock-v2\0" + label).hex() == cache["resource_info_hex"]
    derived = a.hkdf(
        bytes.fromhex(cache["unlock_hash_hex"]), b"", b"authgo-unlock-v2\0" + label
    )
    assert derived.hex() == cache["cache_key_hex"]
    aad = (
        b"authgo-payload-cache-file-v2\0"
        + hashlib.sha256(label).digest()
        + struct.pack(">Q", cache["license_id"])
    )
    assert aad.hex() == cache["aad_hex"]
    n = bytes.fromhex(cache["nonce_hex"])
    ciphertext = AESGCM(derived).encrypt(
        n, bytes.fromhex(cache["material_hex"]), aad
    )
    assert ciphertext.hex() == cache["ciphertext_hex"]
    assert (
        b"AUTHGO-PAYLOAD-CACHE-v2." + a.b64(n + ciphertext).encode()
    ).decode() == cache["file_utf8"]
    with tempfile.TemporaryDirectory() as directory:
        client = a.Client(
            payload.config,
            fingerprint=cache["fingerprint"],
            cache_dir=directory,
            clock=lambda: cache["proof_now"],
        )
        assert p.cache_identity(client) == cache["cache_identity_utf8"]
        result = a.Result(client, client.grant(cache["ticket"]), cache["ticket"])
        path, key, actual_aad = p._cache_material(client, payload, result)
        assert path.name == cache["filename"] and actual_aad == aad and key == derived
        with patch("authgo.payload.os.urandom", return_value=n):
            client.save_payload_key(
                payload, result, bytes.fromhex(cache["material_hex"])
            )
        assert path.read_text() == cache["file_utf8"]
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert (
            client.load_payload_key(payload, result).hex() == cache["material_hex"]
        )
        assert not list(pathlib.Path(directory).glob("*proof*"))


class Server:
    """Transport seam uses real v2 request/response AEAD, HMAC and Ed25519."""

    def __init__(self):
        cache = vector("payload-cache-v2.json")
        self.now = cache["proof_now"]
        self.signer = ed25519.Ed25519PrivateKey.from_private_bytes(b"\x45" * 32)
        self.gateway = x25519.X25519PrivateKey.generate()
        self.payload = a.parse_payload(a.canonical(cache["payload"]))
        self.dek = bytes.fromhex(cache["content_key_hex"])
        self.material = self.dek + b"\x19" * 32
        self.seed = b"\x27" * 32
        self.config = a.loads(a.unb64(self.payload.config[8:]))
        self.config["gateway_key"] = a.b64(raw_public(self.gateway))
        self.config["url"] = "https://PAYLOAD.EXAMPLE.TEST"
        self.calls = []
        self.mode = ""
        self.response_code = ""
        self.trial = False
        self.grace = 120
        self.floating = False
        self.license_id = 42
        self.expires = None
        self.changes = {}

    def client(self, directory, fingerprint=None):
        return a.Client(
            "authgo2." + a.b64(a.canonical(self.config).encode()),
            cache_dir=directory,
            fingerprint=fingerprint or vector("payload-cache-v2.json")["fingerprint"],
            clock=lambda: self.now,
            transport=self.transport,
        )

    def ticket(self, body):
        return dict(
            v=2,
            app_key=self.config["app_key"],
            challenge=body["challenge"],
            license_id=self.license_id,
            license_ref="synthetic-public-license-ref",
            device_hash=a.sha(body["device_fingerprint"].encode()),
            status="active",
            issued_at=iso(self.now),
            starts_at=None,
            expires_at=self.expires,
            features={"export": True},
            next_check_in=10,
            grace_until=iso(self.now + self.grace),
            lease_expires_at=iso(self.now + 20) if self.floating else None,
            floating=self.floating,
            is_trial=self.trial,
            unlock_hash=a.sha(self.seed),
        )

    def transport(self, url, packet, headers, timeout, limit):
        assert url == "https://PAYLOAD.EXAMPLE.TEST/api/v1/client/gateway"
        assert headers == {"Content-Type": "application/json"} and timeout == 10
        outer = a.loads(packet)
        self.calls.append("transport")
        if self.mode == "network":
            raise a.Error("SDK_NETWORK_ERROR", "fixture unreachable")
        if self.mode == "status":
            return 502, {}, b"<html>not a signed refusal</html>"
        if self.mode == "html":
            return 200, {}, b"<html>not a signed response</html>"
        aad = b"authgo-gateway-v2\0" + outer["k"].encode() + b"\0" + outer["e"].encode()
        shared = self.gateway.exchange(
            x25519.X25519PublicKey.from_public_bytes(a.unb64(outer["e"]))
        )
        salt = hashlib.sha256(aad).digest()
        plain = a.unpad(
            AESGCM(a.hkdf(shared, salt, b"authgo/v2/request")).decrypt(
                a.unb64(outer["n"]), a.unb64(outer["c"]), aad
            )
        )
        inner = a.loads(plain)
        body, op, nonce = inner["body"], inner["op"], inner["nonce"]
        assert (
            inner["signature"]
            == hmac.digest(
                self.config["app_secret"].encode(),
                (
                    op + inner["timestamp"] + nonce + a.sha(a.canonical(body).encode())
                ).encode(),
                "sha256",
            ).hex()
        )
        assert len(a.unb64(body["challenge"])) == 32
        self.calls[-1] = op
        grant = self.ticket(body)
        data = dict(
            grant,
            unlock_seed=a.b64(self.seed),
            request_nonce=nonce,
            heartbeat_interval=5,
            satisfied_methods=["KEY", "FLOATING"] if self.floating else ["KEY"],
        )
        if op == "activate":
            data["activation_token"] = "act_" + a.b64(b"\x42" * 32)
        if op == "deactivate":
            data["deactivated"] = True
        if op == "release-seat":
            data["released"] = True
        if op == "payload.unlock":
            assert set(body) == {
                "license_key",
                "activation_token",
                "device_fingerprint",
                        "instance_session",
                "payload",
                "ephemeral_public_key",
                "challenge",
            }
            assert body["license_key"] == LICENSE
            assert body["activation_token"].startswith("act_")
            assert (
                a.parse_payload(a.canonical(body["payload"])).payload_binding()
                == self.payload.payload_binding()
            )
            ephemeral = a.unb64(body["ephemeral_public_key"])
            private = x25519.X25519PrivateKey.generate()
            rewrap_aad = p.payload_rewrap_aad(
                self.payload, ephemeral, a.unb64(body["challenge"])
            )
            content_shared = private.exchange(
                x25519.X25519PublicKey.from_public_bytes(ephemeral)
            )
            kek = a.hkdf(
                content_shared,
                hashlib.sha256(rewrap_aad).digest(),
                b"authgo/payload/v1/rewrap",
            )
            n = os.urandom(12)
            data["watermark"] = "19" * 32
            data.update(
                e=a.b64(raw_public(private)),
                n=a.b64(n),
                c=a.b64(AESGCM(kek).encrypt(n, self.dek, rewrap_aad)),
            )
            if self.mode == "challenge":
                grant["challenge"] = a.b64(b"\x01" * 32)
            if self.mode == "license":
                grant["license_id"] = data["license_id"] = 41
            if self.mode == "seed":
                data["unlock_seed"] = a.b64(b"x" * 32)
            if self.mode == "issued":
                grant["issued_at"] = iso(self.now + 301)
                grant["grace_until"] = iso(self.now + 500)
            if self.mode == "wrap":
                data["c"] = a.b64(b"x" * 48)
            if self.mode == "missing-wrap":
                del data["e"]
            if self.mode == "trial":
                grant["is_trial"] = True
            if self.mode == "zero":
                grant["grace_until"] = grant["issued_at"]
        raw_grant = a.canonical(grant).encode()
        data["ticket"] = (
            a.b64(raw_grant)
            + "."
            + a.b64(self.signer.sign(b"authgo-ticket-v2\0" + raw_grant))
        )
        data.update(self.changes)
        if self.mode == "missing-watermark" and op == "payload.unlock":
            data.pop("watermark", None)
        env = dict(
            code=self.response_code or "OK", data=data, ts=int(self.now), nonce=nonce
        )
        env["signature"] = base64.b64encode(
            self.signer.sign(
                a.canonical({k: env[k] for k in ("code", "data", "ts")}).encode()
            )
        ).decode()
        if self.mode == "signature":
            env["signature"] = base64.b64encode(b"x" * 64).decode()
        if self.mode == "watermark-tamper" and op == "payload.unlock":
            # Keep the signature; replace only the valid watermark before encryption.
            data["watermark"] = "2a" * 32
        if self.mode == "nonce":
            env["nonce"] = "wrong"
        n = os.urandom(12)
        response_aad = (
            aad + b"\0" + a.sha((outer["n"] + "." + outer["c"]).encode()).encode()
        )
        cipher = AESGCM(a.hkdf(shared, salt, b"authgo/v2/response")).encrypt(
            n, a.pad(a.canonical(env).encode()), response_aad
        )
        return 200, {}, a.canonical(dict(n=a.b64(n), c=a.b64(cipher))).encode()


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.server = Server()
        self.client = self.server.client(self.temp.name)
        self.payload = self.server.payload

    def cache_files(self, client=None):
        return sorted((client or self.client).cache.glob("authgo-payload-v2-*.cache"))

    def check(self):
        return self.client.check(LICENSE)

    def unlock(self):
        self.assertEqual(self.client.unlock_payload(self.payload), self.server.dek)

    def assert_error(self, code, fn):
        with self.assertRaises(a.Error) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_cross_language_vectors(self):
        check_vectors()

    def test_not_activated_no_implicit_request_and_restored_proof_is_not_ready(self):
        self.assert_error("SDK_NOT_ACTIVATED", self.unlock)
        self.assertEqual(self.server.calls, [])
        self.check()
        restored = self.server.client(self.temp.name)
        self.assertTrue(restored.state.get("ticket"))
        calls = list(self.server.calls)
        self.assert_error(
            "SDK_NOT_ACTIVATED", lambda: restored.unlock_payload(self.payload)
        )
        self.assertEqual(calls, self.server.calls)
        self.client.state["refused"] = True
        self.assert_error("SDK_NOT_ACTIVATED", self.unlock)

    def test_authenticated_unlock_roundtrip_without_plaintext_or_proof(self):
        self.check()
        self.unlock()
        self.assertEqual(self.server.calls, ["activate", "payload.unlock"])
        files = self.cache_files()
        self.assertEqual(len(files), 1)
        raw = files[0].read_bytes()
        self.assertTrue(raw.startswith(b"AUTHGO-PAYLOAD-CACHE-v2."))
        self.assertNotIn(self.server.dek, raw)
        self.assertNotIn(a.b64(self.server.dek).encode(), raw)
        self.assertNotIn(LICENSE, files[0].name)
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        self.assertFalse(list(self.client.cache.glob("*proof*")))
        self.assertFalse(list(self.client.cache.glob("*.tmp")))
        self.server.mode = "network"
        self.unlock()

    def test_offline_check_hits_cache_without_repeating_network_timeout(self):
        self.server.floating = True
        self.check()
        self.unlock()
        self.server.now += 30  # lease has expired, but accepted signed grace remains
        self.server.mode = "network"
        self.assertEqual(self.client.verify().status, "grace")
        before = len(self.server.calls)
        self.unlock()
        self.assertEqual(before, len(self.server.calls))
        # A fresh Client must successfully check/fallback before using the cache.
        restored = self.server.client(self.temp.name)
        self.assertEqual(restored.check(LICENSE).status, "grace")
        calls = len(self.server.calls)
        self.assertEqual(restored.unlock_payload(self.payload), self.server.dek)
        self.assertEqual(calls, len(self.server.calls))

    def test_key_tamper_wrong_permissions_symlink_and_size_rejected(self):
        result = self.check()
        self.unlock()
        path = self.cache_files()[0]
        control = path.read_bytes()
        variants = [
            b"garbage",
            control[:-1],
            control + b"!",
            b"x" * 257,
            control[:-1] + (b"A" if control[-1:] != b"A" else b"B"),
        ]
        for raw in variants:
            with self.subTest(raw_size=len(raw)):
                path.write_bytes(raw)
                with self.assertRaises(a.Error):
                    self.client.load_payload_key(self.payload, result)
        path.write_bytes(control)
        path.chmod(0o644)
        self.assert_error(
            "SDK_CACHE_UNAVAILABLE",
            lambda: self.client.load_payload_key(self.payload, result),
        )
        path.chmod(0o600)
        target = self.client.cache / "outside"
        target.write_bytes(b"outside-data")
        path.unlink()
        path.symlink_to(target)
        self.client.save_payload_key(self.payload, result, self.server.material)
        self.assertEqual(target.read_bytes(), b"outside-data")
        self.assert_error(
            "SDK_CACHE_UNAVAILABLE",
            lambda: self.client.load_payload_key(self.payload, result),
        )

    def test_atomic_write_failure_keeps_old_cache_and_online_success(self):
        self.check()
        self.unlock()
        path = self.cache_files()[0]
        raw = path.read_bytes()
        for target in (
            "authgo.payload.os.replace",
            "authgo.payload.os.fsync",
            "authgo.payload.tempfile.mkstemp",
        ):
            with self.subTest(target=target), patch(
                target, side_effect=OSError("disk")
            ):
                self.unlock()
            self.assertEqual(path.read_bytes(), raw)
            self.assertFalse(list(self.client.cache.glob("*.tmp")))
        with patch("authgo.payload.os.replace") as replace:
            self.server.mode = "wrap"
            self.assert_error("SDK_RESPONSE_INVALID", self.unlock)
            replace.assert_not_called()

    def test_cache_platform_write_failure_is_best_effort_and_bad_seed_is_typed(self):
        self.check()
        with patch(
            "authgo.payload.os.fchmod", side_effect=AttributeError("unsupported")
        ):
            self.unlock()
        self.assertFalse(self.cache_files())
        self.assertFalse(list(self.client.cache.glob("*.tmp")))
        self.client.state["seed"] = "bad!"
        self.assert_error("SDK_RESPONSE_INVALID", self.unlock)
        self.client.state["seed"] = a.b64(b"z" * 32)
        self.assert_error("SDK_RESPONSE_SIGNATURE_INVALID", self.unlock)

    def test_unwritable_and_memory_cache_do_not_block_online_unlock(self):
        self.check()
        self.client.cache = pathlib.Path("/proc/authgo-cannot-create")
        self.unlock()
        memory = self.server.client("")
        memory.check(LICENSE)
        self.assertEqual(memory.unlock_payload(self.payload), self.server.dek)
        self.assertTrue(memory.memory_cache)
        self.assertEqual(self.cache_files(), [])

    def test_trial_and_zero_grace_never_cache_and_delete_existing(self):
        for kind in ("trial", "zero"):
            with self.subTest(kind=kind):
                self.server.mode = ""
                self.check()
                self.unlock()
                self.assertEqual(len(self.cache_files()), 1)
                self.server.mode = kind
                self.unlock()
                self.assertEqual(self.cache_files(), [])
                self.assertTrue(self.client.payload_no_cache)
                self.server.mode = "network"
                self.assert_error("SDK_NETWORK_ERROR", self.unlock)
                self.server.mode = ""
                self.client.verify()
        self.server.trial = True
        self.client.verify()
        self.unlock()
        self.assertFalse(self.cache_files())
        self.server.mode = "network"
        self.assert_error("SDK_GRACE_EXPIRED", self.client.verify)

    def test_normal_checks_apply_no_cache_and_deactivate_cleans(self):
        self.check()
        self.unlock()
        self.server.trial = True
        self.client.verify()
        self.assertFalse(self.cache_files())
        self.server.trial = False
        self.client.verify()
        self.unlock()
        self.server.grace = 0
        self.client.heartbeat()
        self.assertFalse(self.cache_files())
        self.server.grace = 120
        self.client.verify()
        self.unlock()
        self.client.deactivate()
        self.assertFalse(self.cache_files())
        self.assertFalse(self.client.payload_ready)
        self.assert_error("SDK_NOT_ACTIVATED", self.unlock)

    def test_cache_scope_cleanup_and_license_binding(self):
        result = self.check()
        self.unlock()
        path = self.cache_files()[0]
        same = self.client.cache / (path.name[:-6] + "-second.cache")
        same.write_bytes(path.read_bytes())
        unrelated = self.client.cache / "authgo-payload-v2-another-context-abc.cache"
        unrelated.write_bytes(b"unrelated")
        proof = self.client.cache / "AUTHGO-PAYLOAD-PROOF-v1-untouched.cache"
        proof.write_bytes(b"not-owned-by-python")
        # A different valid signed license cannot open the old file even under
        # the same app/instance/manifest path: uint64 license_id is in GCM AAD.
        self.server.license_id = 43
        other = self.client.verify()
        self.assert_error(
            "SDK_CACHE_INVALID",
            lambda: self.client.load_payload_key(self.payload, other),
        )
        self.assertEqual(
            self.client.load_payload_key(self.payload, result), self.server.material
        )
        self.client.clear_payload_keys()
        self.assertFalse(path.exists())
        self.assertFalse(same.exists())
        self.assertEqual(unrelated.read_bytes(), b"unrelated")
        self.assertEqual(proof.read_bytes(), b"not-owned-by-python")

    def test_cache_rejects_expired_future_or_not_started_proof(self):
        result = self.check()
        self.unlock()
        grant = dict(result.data)

        def signed(data):
            raw = a.canonical(data).encode()
            ticket = (
                a.b64(raw)
                + "."
                + a.b64(self.server.signer.sign(b"authgo-ticket-v2\0" + raw))
            )
            return a.Result(self.client, data, ticket)

        future = dict(
            grant,
            issued_at=iso(self.server.now + 301),
            grace_until=iso(self.server.now + 600),
        )
        self.assert_error(
            "SDK_GRACE_EXPIRED",
            lambda: self.client.load_payload_key(self.payload, signed(future)),
        )
        pending = dict(grant, starts_at=iso(self.server.now + 1))
        self.assert_error(
            "LICENSE_NOT_STARTED",
            lambda: self.client.load_payload_key(self.payload, signed(pending)),
        )
        result.source = "offline"
        self.assert_error(
            "SDK_CACHE_UNAVAILABLE",
            lambda: self.client.load_payload_key(self.payload, result),
        )
        result.source = "cache"
        result.status = "grace"
        self.server.now += self.server.grace
        self.assert_error(
            "SDK_GRACE_EXPIRED",
            lambda: self.client.load_payload_key(self.payload, result),
        )
        count = len(self.cache_files())
        self.client.save_payload_key(self.payload, result, self.server.material)
        self.assertEqual(count, len(self.cache_files()))

    def test_grace_exact_expiry_start_expiry_and_clock_rollback(self):
        result = self.check()
        self.unlock()
        self.server.now += self.server.grace
        self.assert_error(
            "SDK_GRACE_EXPIRED",
            lambda: self.client.load_payload_key(self.payload, result),
        )
        self.server.mode = "network"
        self.assert_error("SDK_NETWORK_ERROR", self.unlock)
        self.server.mode = ""
        self.client.verify()
        calls = len(self.server.calls)
        self.client.state["observed"] = self.server.now + 301
        self.assert_error("SDK_CLOCK_ROLLBACK", self.unlock)
        self.assertEqual(calls, len(self.server.calls))
        self.client.state["observed"] = self.server.now + 300
        self.unlock()  # equality accepted
        self.server.expires = iso(self.server.now + 1)
        result = self.client.verify()
        self.server.now += 1
        self.assert_error("LICENSE_EXPIRED", self.unlock)
        self.assert_error(
            "LICENSE_EXPIRED",
            lambda: self.client.load_payload_key(self.payload, result),
        )

    def test_authenticated_refusal_clears_keys_on_unlock_and_normal_verify(self):
        for code in (
            "LICENSE_REVOKED",
            "VERSION_DISABLED",
            "MAINTENANCE_EXPIRED",
            "UNRECOGNIZED_DENIAL",
        ):
            for op in (self.unlock, self.client.verify, self.client.heartbeat):
                with self.subTest(code=code, operation=op.__name__):
                    self.server.response_code = ""
                    self.check()
                    self.unlock()
                    self.server.response_code = code
                    error = self.assert_error(code, op)
                    self.assertTrue(error.refusal)
                    self.assertFalse(self.client.payload_ready)
                    self.assertTrue(self.client.state["refused"])
                    self.assertFalse(self.cache_files())
                    self.assert_error("SDK_NOT_ACTIVATED", self.unlock)

    def test_instance_replaced_clears_content_but_preserves_license_proof(self):
        self.check()
        self.unlock()
        ticket = self.client.state["ticket"]
        self.server.response_code = "INSTANCE_REPLACED"
        try:
            self.assert_error("INSTANCE_REPLACED", self.unlock)
            self.assertEqual(self.client.state["ticket"], ticket)
            self.assertFalse(self.cache_files())
            self.assert_error("SDK_NOT_ACTIVATED", self.unlock)
        finally:
            a._replaced.discard(self.client.instance_key())

    def test_payload_invalid_and_unauthenticated_network_errors_preserve_cache(self):
        self.check()
        self.unlock()
        path = self.cache_files()[0]
        raw, ticket = path.read_bytes(), self.client.state["ticket"]
        for mode in ("network", "status", "html", "signature", "nonce"):
            self.server.mode = mode
            self.unlock()
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(self.client.state["ticket"], ticket)
        self.server.mode = ""
        self.server.response_code = "PAYLOAD_INVALID"
        self.unlock()  # authenticated temporary error: use verified cached key
        self.assertEqual(path.read_bytes(), raw)
        self.client.clear_payload_keys()
        error = self.assert_error("PAYLOAD_INVALID", self.unlock)
        self.assertTrue(error.authenticated)
        self.assertFalse(error.refusal)
        self.assertEqual(self.client.state["ticket"], ticket)

    def test_unmarshal_errors_recover_but_bad_wrapped_strings_do_not(self):
        self.check()
        self.unlock()
        raw = self.cache_files()[0].read_bytes()
        self.server.mode = "missing-wrap"
        self.unlock()
        self.server.mode = ""
        for value in (17, True, {}, []):
            self.server.changes = {"e": value}
            self.unlock()
        self.server.changes = {"e": None}
        self.assert_error("SDK_RESPONSE_INVALID", self.unlock)
        self.server.changes = {"e": "bad"}
        self.assert_error("SDK_RESPONSE_INVALID", self.unlock)
        self.server.changes = {}
        self.assertEqual(raw, self.cache_files()[0].read_bytes())
        with patch.object(
            self.client,
            "request",
            side_effect=ValueError("not an authenticated denial"),
        ):
            self.unlock()
        self.assertFalse(self.client.state.get("refused"))

    def test_invalid_fresh_ticket_or_unwrap_never_uses_cache(self):
        self.check()
        self.unlock()
        path = self.cache_files()[0]
        original = path.read_bytes()
        for mode in ("challenge", "license", "seed", "issued", "wrap"):
            self.server.mode = mode
            with self.subTest(mode=mode), self.assertRaises(a.Error):
                self.unlock()
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse(self.client.state.get("refused"))
        self.server.mode = ""
        self.unlock()

    def test_cross_instance_copy_cannot_open_even_if_renamed(self):
        self.check()
        self.unlock()
        original = self.cache_files()[0].read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            other = self.server.client(
                directory, a.instance_fingerprint("different-instance")
            )
            result = other.check(LICENSE)
            path, _, _ = p._cache_material(other, self.payload, result)
            path.write_bytes(original)
            path.chmod(0o600)
            self.assert_error(
                "SDK_CACHE_INVALID",
                lambda: other.load_payload_key(self.payload, result),
            )

    def test_payload_parser_rejects_schema_duplicate_bounds_and_config_changes_binding(
        self,
    ):
        base = self.payload.to_dict()
        invalid = [b"{" * 66000, b"{}", b"null", b"[]", b'{"v":2,"v":2}']
        for field in base:
            wrong = copy.deepcopy(base)
            del wrong[field]
            invalid.append(a.canonical(wrong))
        for field, value in (
            ("v", True),
            ("v", "1"),
            ("v", 1.0),
            ("v", None),
            ("key_id", "bad.key"),
            ("version", "1.2"),
            ("version", "1.2.3-01"),
            ("built_at", "2026-11-07T00:00:00+00:00"),
            ("built_at", "2026-02-30T00:00:00Z"),
            ("app_key", "a" * 257),
            ("manifest", "__=="),
            ("App_Key", "wrong"),
            ("config", "authgo2.bad"),
        ):
            wrong = copy.deepcopy(base)
            wrong[field] = value
            invalid.append(a.canonical(wrong))
        for raw in invalid:
            with self.subTest(raw=raw[:60]):
                self.assert_error("PAYLOAD_INVALID", lambda: a.parse_payload(raw))
        # Envelope field names are exact; e/n/c lengths and canonical B64U enforced.
        for field in ("e", "n", "c"):
            wrong = copy.deepcopy(base)
            wrong["envelope"][field] = "AA"
            self.assert_error(
                "PAYLOAD_INVALID", lambda: a.parse_payload(a.canonical(wrong))
            )
        manifest = json.loads(a.unb64(base["manifest"]))
        for field, value in (
            ("size", -1),
            ("size", 2**62),
            ("size", "0"),
            ("chunk_size", 1),
            ("path", "../escape"),
            ("kind", "invalid"),
            ("encoding", "tar"),
            ("name", "bad.name"),
        ):
            wrong = copy.deepcopy(manifest)
            wrong["files"][0][field] = value
            changed = dict(base, manifest=a.b64(a.canonical(wrong).encode()))
            self.assert_error(
                "PAYLOAD_INVALID", lambda: a.parse_payload(a.canonical(changed))
            )
        changed = copy.deepcopy(base)
        config = a.loads(a.unb64(changed["config"][8:]))
        config["url"] = "https://another.example.test"
        changed["config"] = "authgo2." + a.b64(a.canonical(config).encode())
        self.assertNotEqual(
            self.payload.payload_binding(),
            a.parse_payload(a.canonical(changed)).payload_binding(),
        )
        self.check()
        self.assert_error(
            "PAYLOAD_INVALID",
            lambda: self.client.unlock_payload(dict(base, app_key="wrong")),
        )

    def test_payload_json_exact_size_integer_and_optional_field_types(self):
        base = self.payload.to_dict()
        raw = a.canonical(base).encode()
        self.assertLess(len(raw), 65536)
        self.assertEqual(a.parse_payload(raw + b" " * (65536 - len(raw))), self.payload)
        self.assert_error(
            "PAYLOAD_INVALID", lambda: a.parse_payload(raw + b" " * (65537 - len(raw)))
        )
        self.assert_error(
            "PAYLOAD_INVALID", lambda: a.parse_payload(raw[:-1] + b',"v":2}')
        )
        for spelling in ("2.0", "2e0", "true", '"2"'):
            changed = raw.replace(b'"v":2,', b'"v":' + spelling.encode() + b",")
            self.assertNotEqual(raw, changed)
            self.assert_error("PAYLOAD_INVALID", lambda: a.parse_payload(changed))
        for field in ("python_version", "main_class", "architecture"):
            manifest = json.loads(a.unb64(base["manifest"]))
            manifest["files"][0][field] = None
            changed = dict(base, manifest=a.b64(a.canonical(manifest).encode()))
            self.assert_error(
                "PAYLOAD_INVALID", lambda: a.parse_payload(a.canonical(changed))
            )

    def test_go_url_parser_rules_do_not_inherit_python_urlsplit_relaxations(self):
        base = self.payload.to_dict()
        config = a.loads(a.unb64(base["config"][8:]))
        for url in (
            "https://host:xxx",
            "https://ho st",
            "https://ho\\st",
            "https://host/\npath",
            "https://host/%ZZ",
            "https://h%6fst",
            "https://ho[st",
            "https://ho^st",
            "https://ho`st",
            "https://ho{st",
            "https://ho|st",
            "https://ho}st",
        ):
            for field in ("url",):
                c = dict(config, **{field: url if field == "url" else [url]})
                data = dict(base, config="authgo2." + a.b64(a.canonical(c).encode()))
                with self.subTest(url=url, field=field):
                    self.assert_error(
                        "PAYLOAD_INVALID", lambda: a.parse_payload(a.canonical(data))
                    )
        for url in (
            "HTTPS://host",
            "https://ho]st",
            "https://[syntactic-host]",
            "https://host:65536",
            "https://host:",
            "https://host/path space",
            "https://host/path?",
            "https://host#",
        ):
            c = dict(config, url=url)
            data = dict(base, config="authgo2." + a.b64(a.canonical(c).encode()))
            self.assertIsInstance(a.parse_payload(a.canonical(data)), a.Payload)

    def test_unwrap_rejects_changed_binding_low_order_and_challenge(self):
        v = vector("payload-unlock-v2.json")
        payload = a.parse_payload(a.canonical(v["payload"]))
        private = x25519.X25519PrivateKey.from_private_bytes(
            bytes.fromhex(v["client_private_hex"])
        )
        challenge = bytes.fromhex(v["challenge_hex"])
        for field in ("e", "n", "c"):
            wrong = dict(v["response"])
            wrong[field] = a.b64(
                b"\0" * (32 if field == "e" else 12 if field == "n" else 48)
            )
            self.assert_error(
                "SDK_RESPONSE_INVALID",
                lambda: p.unwrap_payload(payload, wrong, private, challenge),
            )
        self.assert_error(
            "SDK_RESPONSE_INVALID",
            lambda: p.unwrap_payload(payload, v["response"], private, b"x" * 32),
        )

    def test_concurrent_unlock_and_cache_replace_are_serialized(self):
        self.check()
        failures = []

        def worker():
            try:
                self.unlock()
            except Exception as error:
                failures.append(error)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertFalse(failures)
        self.assertEqual(len(self.cache_files()), 1)
        self.assertFalse(list(self.client.cache.glob("*.tmp")))


if __name__ == "__main__":
    unittest.main()
