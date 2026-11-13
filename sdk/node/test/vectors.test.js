import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import * as a from "../index.js";
const root = new URL("../../vectors/", import.meta.url),
  read = (name) => JSON.parse(fs.readFileSync(new URL(name, root), "utf8"));
test("all fixed protocol vectors", () => {
  const v = read("v2.json"),
    h = read("hkdf.json"),
    hex = (s) => Buffer.from(s, "hex");
  assert.equal(
    a
      .hkdf(hex(h.ikm_hex), hex(h.salt_hex), hex(h.info_hex), h.length)
      .toString("hex"),
    h.okm_hex,
  );
  const shared = a.sharedSecret(
      hex(v.ephemeral_private_hex),
      a.unb64(v.gateway_public),
    ),
    aad = hex(v.request_aad_hex),
    salt = Buffer.from(a.sha(aad), "hex");
  assert.equal(
    a.hkdf(shared, salt, Buffer.from("authgo/v2/request")).toString("hex"),
    v.request_key_hex,
  );
  assert.equal(
    a.hkdf(shared, salt, Buffer.from("authgo/v2/response")).toString("hex"),
    v.response_key_hex,
  );
  const padding = a.open(
    hex(v.request_key_hex),
    a.unb64(v.request.n),
    a.unb64(v.request.c),
    aad,
  );
  assert.equal(padding.toString("hex"), v.padding_hex);
  assert.equal(a.unpad(padding).toString(), v.inner);
  assert.equal(
    a
      .unpad(
        a.open(
          hex(v.response_key_hex),
          a.unb64(v.response.n),
          a.unb64(v.response.c),
          hex(v.response_aad_hex),
        ),
      )
      .toString(),
    v.response_plain,
  );
  const inner = JSON.parse(v.inner);
  assert.equal(
    crypto
      .createHmac("sha256", "test-secret-only")
      .update(
        inner.op +
          inner.timestamp +
          inner.nonce +
          a.sha(JSON.stringify(inner.body)),
      )
      .digest("hex"),
    inner.signature,
  );
  const [p, s] = v.ticket.split(".");
  assert(
    a.verifySignature(
      a.unb64(v.ed25519_public),
      Buffer.concat([Buffer.from("authgo-ticket-v2\0"), a.unb64(p)]),
      a.unb64(s),
    ),
  );
  assert(!a.verifySignature(a.unb64(v.ed25519_public), Buffer.concat([Buffer.from("invalid-domain\0"), a.unb64(p)]), a.unb64(s)));
  const key = a.hkdf(
    hex(v.unlock_seed_hex),
    Buffer.alloc(0),
    Buffer.from("authgo-unlock-v2\0" + v.unlock_label),
  );
  assert.equal(key.toString("hex"), v.unlock_key_hex);
  const [, n, c] = v.resource.split(".");
  assert.equal(
    a
      .open(
        key,
        a.unb64(n),
        a.unb64(c),
        Buffer.from("authgo-resource-v2\0settings"),
      )
      .toString(),
    "hello",
  );
  const u = read("update-response.json");
  for (const v of [u, ...u.docker_cases]) {
    const env = a.parse(JSON.stringify(v.response)),
      canonical = a.canonical({ code: env.code, data: env.data, ts: env.ts });
    assert.equal(canonical, v.canonical_signed);
    assert(
      a.verifySignature(
        Buffer.from(v.public_key, "base64"),
        Buffer.from(canonical),
        Buffer.from(v.signature, "base64"),
      ),
    );
  }
  const errors = read("error-classification.json");
  for (const c of errors.cases)
    assert.equal(
      new a.AuthGoError(c.code, "", c.authenticated).refusal,
      c.clear_cache,
    );
  for (const c of errors.update_cases) assert.equal(c.clear_cache, false);
  assert.throws(() => a.parse('{"x":1,"x":2}'));
  assert.equal(
    a.canonical(a.parse('{"n":18446744073709551615}')),
    '{"n":18446744073709551615}',
  );
});
test("fingerprint raw hardware vectors", () => {
  for (const c of read("fingerprint.json").cases)
    assert.equal(a.identityHash(c.machine, c.mac, c.cpu), c.expected);
});
test("lossless canonical JSON and malformed input", () => {
  const c = read("canonical.json");
  assert.equal(a.canonical(a.parse(c.raw)), c.canonical);
  assert(
    a.verifySignature(
      Buffer.from(c.public_key, "base64"),
      Buffer.from(c.canonical),
      Buffer.from(c.signature, "base64"),
    ),
  );
  for (const s of c.invalid) assert.throws(() => a.parse(s));
});
test("config rejects obsolete and malformed secrets without leaking", () => {
  for (const c of [
    "authgo2.private-test-secret",
    "",
  ])
    assert.throws(
      () => new a.Client(c),
      (e) =>
        e.code === "SDK_INVALID_CONFIG" &&
        !e.message.includes("private-test-secret"),
    );
});
test("result serialization never discloses credentials, seed or ticket", () => {
  const client = {
    now: () => 0,
    config: { app_secret: "DO_NOT_LOG_SECRET" },
    state: { token: "DO_NOT_LOG_TOKEN" },
  };
  const result = new a.Result(
    client,
    { features: {} },
    "DO_NOT_LOG_TICKET",
    Buffer.from("DO_NOT_LOG_SEED".padEnd(32, "x")),
  );
  const text = JSON.stringify(result);
  for (const secret of [
    "DO_NOT_LOG_SECRET",
    "DO_NOT_LOG_TOKEN",
    "DO_NOT_LOG_TICKET",
    "DO_NOT_LOG_SEED",
  ])
    assert(!text.includes(secret));
  assert.equal(result.ticket(), "DO_NOT_LOG_TICKET");
});

test("license key shared vectors", () => {
  for (const c of read("license-key.json").cases) {
    if (c.valid) assert.doesNotThrow(() => a.validateKey(c.key));
    else
      assert.throws(
        () => a.validateKey(c.key),
        (e) => e.code === c.code,
        c.name,
      );
  }
});
test("Linux CPU parsing shared vectors", () => {
  for (const c of read("fingerprint.json").cpuinfo_cases) {
    const cpu = a.parseLinuxCPU(c.cpuinfo);
    assert.equal(cpu, c.cpu, c.name);
    if (cpu) assert.equal(a.identityHash(c.machine, c.mac, cpu), c.expected);
  }
});

test("container detection and instance fingerprint vectors",()=>{
  const vectors=read("container-identity.json");
  for(const v of vectors.detection)assert.equal(a.detectContainer(p=>{if(!(p in v.files))throw Error();return Buffer.from(v.files[p]);},v.env),v.expected,v.name);
  for(const v of vectors.fingerprints)assert.equal(a.instanceFingerprint(v.id),v.expected);
});

test("instance session encoding vectors",()=>{
  const v=read("instance-session.json").instance_session;
  assert.equal(a.unb64(v.valid).length,v.bytes);
  for(const value of v.invalid){let valid=false;try{valid=a.unb64(value).length===v.bytes;}catch{}assert.equal(valid,false);}
  assert.equal(v.persist_in_cache,false);
  assert.equal(a.Codes.INSTANCE_REPLACED,"INSTANCE_REPLACED");
  assert.equal(a.Codes.VERSION_DISABLED,"VERSION_DISABLED");
});

test("payload-envelope / payload-unlock-v2 / payload-cache-v2 fixed vectors", async () => {
  const { checkPayloadVectors } = await import("./payload-vectors.js");
  checkPayloadVectors();
  console.log(JSON.stringify({language: "node", payload_vectors: "PASS", vectors: ["payload-envelope", "payload-unlock-v2", "payload-cache-v2"]}));
});

test("payload-envelope chunk decryption matches Go byte for byte", async () => {
  const { checkChunkVectors } = await import("./sealed-vectors.js");
  checkChunkVectors();
  console.log(JSON.stringify({language: "node", payload_chunks: "PASS", vector: "payload-envelope"}));
});
