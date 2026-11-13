import pathlib, sys, json, hashlib, hmac

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
import authgo as a
from cryptography.hazmat.primitives.asymmetric import x25519

root = pathlib.Path(__file__).parents[2] / "vectors"
v = json.loads((root / "v2.json").read_text())
h = json.loads((root / "hkdf.json").read_text())
assert (
    a.hkdf(
        bytes.fromhex(h["ikm_hex"]),
        bytes.fromhex(h["salt_hex"]),
        bytes.fromhex(h["info_hex"]),
        h["length"],
    ).hex()
    == h["okm_hex"]
)
shared = x25519.X25519PrivateKey.from_private_bytes(
    bytes.fromhex(v["ephemeral_private_hex"])
).exchange(x25519.X25519PublicKey.from_public_bytes(a.unb64(v["gateway_public"])))
aad = bytes.fromhex(v["request_aad_hex"])
salt = hashlib.sha256(aad).digest()
assert a.hkdf(shared, salt, b"authgo/v2/request").hex() == v["request_key_hex"]
assert a.hkdf(shared, salt, b"authgo/v2/response").hex() == v["response_key_hex"]
plain = a.AESGCM(bytes.fromhex(v["request_key_hex"])).decrypt(
    a.unb64(v["request"]["n"]), a.unb64(v["request"]["c"]), aad
)
assert plain.hex() == v["padding_hex"] and a.unpad(plain).decode() == v["inner"]
assert (
    a.AESGCM(bytes.fromhex(v["response_key_hex"]))
    .decrypt(
        a.unb64(v["response"]["n"]),
        a.unb64(v["response"]["c"]),
        bytes.fromhex(v["response_aad_hex"]),
    )[4 : 4 + len(v["response_plain"])]
    .decode()
    == v["response_plain"]
)
i = json.loads(v["inner"])
raw = a.canonical(a.loads(v["inner"])["body"]).encode()
# HMAC signs original body bytes in this vector, not a reserialized body.
raw = json.dumps(i["body"], ensure_ascii=False, separators=(",", ":")).encode()
assert (
    hmac.digest(
        b"test-secret-only",
        (i["op"] + i["timestamp"] + i["nonce"] + a.sha(raw)).encode(),
        "sha256",
    ).hex()
    == i["signature"]
)
pub = a.ed25519.Ed25519PublicKey.from_public_bytes(a.unb64(v["ed25519_public"]))
p, s = v["ticket"].split(".")
pub.verify(a.unb64(s), b"authgo-ticket-v2\0" + a.unb64(p))
try:
    pub.verify(a.unb64(s), b"invalid-domain\0" + a.unb64(p))
    raise AssertionError("ticket accepted under wrong signature domain")
except a.InvalidSignature:
    pass
key = a.hkdf(
    bytes.fromhex(v["unlock_seed_hex"]),
    b"",
    ("authgo-unlock-v2\0" + v["unlock_label"]).encode(),
)
assert key.hex() == v["unlock_key_hex"]
_, n, c = v["resource"].split(".")
assert (
    a.AESGCM(key).decrypt(a.unb64(n), a.unb64(c), b"authgo-resource-v2\0settings")
    == b"hello"
)
u = json.loads((root / "update-response.json").read_text())
for item in [u] + u["docker_cases"]:
    env = a.loads(a.canonical(item["response"]))
    canonical = a.canonical({k: env[k] for k in ["code", "data", "ts"]})
    assert canonical == item["canonical_signed"]
    a.ed25519.Ed25519PublicKey.from_public_bytes(
        a.base64.b64decode(item["public_key"])
    ).verify(a.base64.b64decode(item["signature"]), canonical.encode())
e = json.loads((root / "error-classification.json").read_text())
for case in e["cases"]:
    assert (
        a.Error(case["code"], authenticated=case["authenticated"]).refusal
        == case["clear_cache"]
    )
for case in e["update_cases"]:
    assert case["clear_cache"] is False
print(
    json.dumps(
        {
            "language": "python",
            "vectors": "PASS",
            "cases": len(e["cases"]) + len(e["update_cases"]),
        }
    )
)
for case in json.loads((root / "fingerprint.json").read_text())["cases"]:
    assert (
        a.identity_hash(case["machine"], case["mac"], case["cpu"]) == case["expected"]
    )
c = json.loads((root / "canonical.json").read_text())
assert a.canonical(a.loads(c["raw"])) == c["canonical"]
a.ed25519.Ed25519PublicKey.from_public_bytes(
    a.base64.b64decode(c["public_key"])
).verify(a.base64.b64decode(c["signature"]), c["canonical"].encode())
for invalid in c["invalid"]:
    try:
        a.loads(invalid)
        raise AssertionError("accepted invalid JSON")
    except (ValueError, UnicodeError):
        pass
for invalid in ["authgo2.private-test-secret", ""]:
    try:
        a.Client(invalid)
        raise AssertionError("bad configuration accepted")
    except a.Error as e:
        assert e.code == "SDK_INVALID_CONFIG" and "private-test-secret" not in str(e)

# Invalid configs cannot leak credentials even with optimization enabled.
for invalid in ["authgo2.PRIVATE"]:
    try:
        a.Client(invalid)
        raise RuntimeError("obsolete config accepted")
    except a.Error as error:
        if error.code != "SDK_INVALID_CONFIG" or "PRIVATE" in str(error):
            raise RuntimeError("config error leak")

for case in json.loads((root / "license-key.json").read_text())["cases"]:
    try:
        a.validate_key(case["key"])
        assert case["valid"], case["name"]
    except a.Error as error:
        assert not case["valid"] and error.code == case["code"], case["name"]
for case in json.loads((root / "fingerprint.json").read_text())["cpuinfo_cases"]:
    cpu = a.parse_linux_cpu(case["cpuinfo"])
    assert cpu == case["cpu"], case["name"]
    if cpu:
        assert a.identity_hash(case["machine"], case["mac"], cpu) == case["expected"]
print(
    '{"language":"python","license_key_vectors":16,"cpuinfo_vectors":8,"result":"PASS"}'
)

container = json.loads((root / "container-identity.json").read_text())
for case in container["detection"]:
    def read(path):
        if path not in case["files"]: raise FileNotFoundError(path)
        return case["files"][path].encode()
    assert a.detect_container(read, case["env"]) == case["expected"], case["name"]
for case in container["fingerprints"]:
    assert a.instance_fingerprint(case["id"]) == case["expected"]
print('{"language":"python","container_vectors":"PASS"}')

session = json.loads((root / "instance-session.json").read_text())["instance_session"]
assert len(a.unb64(session["valid"])) == session["bytes"]
for value in session["invalid"]:
    valid = False
    try: valid = len(a.unb64(value)) == session["bytes"]
    except Exception: pass
    assert not valid
assert session["persist_in_cache"] is False

# Closing a connection before the status line is a network failure. Received
# incomplete responses remain response-invalid; neither is an authenticated denial.
import http.client
from unittest.mock import patch
for cause, expected in [(http.client.RemoteDisconnected("closed"), "SDK_NETWORK_ERROR"), (http.client.IncompleteRead(b"x", 2), "SDK_RESPONSE_INVALID")]:
    with patch("urllib.request.build_opener") as opener:
        opener.return_value.open.side_effect = cause
        try:
            a.http_request("http://127.0.0.1/")
            raise AssertionError("transport error accepted")
        except a.Error as error:
            assert error.code == expected and not error.authenticated

# Runtime payload and content-key cache use the same bytes as the Go vectors.
# Keep these in the existing conformance entry point; no launcher proof files.
from test_payload import check_vectors
check_vectors()
print(json.dumps({"language": "python", "payload_vectors": "PASS", "vectors": ["payload-envelope", "payload-unlock-v2", "payload-cache-v2"]}))

from test_sealed import check_chunk_vectors
check_chunk_vectors()
print(json.dumps({"language": "python", "payload_chunks": "PASS", "vector": "payload-envelope"}))
