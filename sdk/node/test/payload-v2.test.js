// Current watermark and loader security tests with authenticated synthetic fixtures.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import * as a from "../index.js";
import * as p from "../payload.js";
import { parseWatermarkIndex, applyWatermark } from "../watermark.js";
import { vector, rawPublic } from "./payload-vectors.js";

const TAG = "0123456789abcdef0123456789abcdef";
const WM = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));
const SLOT = TAG + "0".repeat(64);
const LICENSE = "AUTH-RNMSQ-VSQQA-4S4NH-JDGCM";
const raw = (value) => Buffer.from(JSON.stringify(value));
const clone = (value) => JSON.parse(JSON.stringify(value));
const digest = (value) => Buffer.from(a.sha(value), "hex");
const iso = (time) => new Date(time * 1000).toISOString().replace(".000Z", "Z");
const code = (expected) => (error) => { assert.equal(error.code, expected); return true; };
const file = (i = 0, kind = "node", name = "core", size = 2048) => ({
  name, kind, path: String(i).padStart(8, "0") + ".agc", size,
  chunk_size: 1048576, encoding: "raw",
});
const meta = (i = 1, size = 1) => file(i, "watermark", "__authgo_watermark", size);
function payloadObject(files = [file(), meta()]) {
  return { ...vector("payload-envelope.json").payload, v: 2, manifest: a.b64(raw({ files })) };
}
const privateIndex = (entryPath = []) => ({ v: "1", tag: TAG, files: [{ index: "0", entries: [{
  path: entryPath, offsets: Array.from({ length: 8 }, (_, i) => String(i * 96)),
}] }] });

// Real channel AEAD, nonce, HMAC, signed response and signed ticket; not a mock
// of unlockPayloadMaterial or request. It intentionally uses v1 HKDF rewrap info.
class SignedServer {
  constructor() {
    const v = vector("payload-cache-v2.json");
    this.now = v.proof_now;
    this.payload = a.parsePayload(raw(payloadObject()));
    this.dek = Buffer.from(v.content_key_hex, "hex");
    this.seed = Buffer.alloc(32, 0x27);
    this.signer = crypto.generateKeyPairSync("ed25519").privateKey;
    this.gateway = crypto.generateKeyPairSync("x25519");
    this.config = JSON.parse(a.unb64(this.payload.config.slice(8)));
    this.config.url = "https://PAYLOAD.EXAMPLE.TEST";
    this.config.public_key = rawPublic(crypto.createPublicKey(this.signer)).toString("base64");
    this.config.gateway_key = a.b64(rawPublic(this.gateway.publicKey));
    this.watermark = WM.toString("hex");
    this.mode = "";
    this.trial = false;
    this.refusal = "";
    this.calls = [];
  }
  options(dir) {
    return { cacheDir: dir, fingerprint: vector("payload-cache-v2.json").fingerprint,
      clock: () => this.now, transport: this.transport.bind(this) };
  }
  encodedConfig() { return "authgo2." + a.b64(raw(this.config)); }
  async transport(url, packet) {
    assert.equal(url, "https://PAYLOAD.EXAMPLE.TEST/api/v1/client/gateway");
    if (this.mode === "network") throw new a.AuthGoError("SDK_NETWORK_ERROR");
    const outer = a.parse(packet);
    const aad = Buffer.from("authgo-gateway-v2\0" + outer.k + "\0" + outer.e);
    const shared = a.sharedSecret(this.gateway.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32), a.unb64(outer.e));
    const salt = digest(aad);
    const inner = a.parse(a.unpad(a.open(a.hkdf(shared, salt, Buffer.from("authgo/v2/request")), a.unb64(outer.n), a.unb64(outer.c), aad)));
    const { op, body, nonce } = inner;
    assert.equal(inner.signature, crypto.createHmac("sha256", this.config.app_secret)
      .update(op + inner.timestamp + nonce + a.sha(a.canonical(body))).digest("hex"));
    assert.equal(a.unb64(body.challenge).length, 32);
    this.calls.push(op);
    const grant = {
      v: 2, app_key: this.config.app_key, challenge: body.challenge,
      license_id: 42, license_ref: "synthetic-v2", device_hash: a.sha(body.device_fingerprint),
      status: "active", issued_at: iso(this.now), starts_at: null, expires_at: null,
      features: { export: true }, next_check_in: 10, grace_until: iso(this.now + 120),
      lease_expires_at: null,
      floating: false, is_trial: this.trial, unlock_hash: a.sha(this.seed),
    };
    const data = { ...grant, unlock_seed: a.b64(this.seed), request_nonce: nonce,
      heartbeat_interval: 5, satisfied_methods: ["KEY"] };
    if (op === "activate") data.activation_token = "act_" + a.b64(Buffer.alloc(32, 0x42));
    if (op === "release-seat") data.released = true;
    if (op === "payload.unlock") {
      assert.deepEqual(a.parsePayload(a.canonical(body.payload)).payloadBinding(), this.payload.payloadBinding());
      const pair = crypto.generateKeyPairSync("x25519");
      const ep = a.unb64(body.ephemeral_public_key);
      const wrapAAD = p.payloadRewrapAAD(this.payload, ep, a.unb64(body.challenge));
      const secret = a.sharedSecret(pair.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32), ep);
      const kek = a.hkdf(secret, digest(wrapAAD), Buffer.from("authgo/payload/v1/rewrap"));
      const n = crypto.randomBytes(12);
      Object.assign(data, { e: a.b64(rawPublic(pair.publicKey)), n: a.b64(n), c: a.b64(a.seal(kek, n, this.dek, wrapAAD)) });
      if (this.mode !== "missing-watermark") data.watermark = this.watermark;
      if (this.mode === "challenge") grant.challenge = a.b64(Buffer.alloc(32, 1));
      if (this.mode === "license") grant.license_id = data.license_id = 41;
      if (this.mode === "wrap") data.c = a.b64(Buffer.alloc(48, 1));
    }
    const ticket = Buffer.from(a.canonical(grant));
    data.ticket = a.b64(ticket) + "." + a.b64(crypto.sign(null, Buffer.concat([Buffer.from("authgo-ticket-v2\0"), ticket]), this.signer));
    const envelope = { code: this.refusal || "OK", data, ts: this.now, nonce };
    envelope.signature = crypto.sign(null, Buffer.from(a.canonical({ code: envelope.code, data, ts: envelope.ts })), this.signer).toString("base64");
    if (this.mode === "signature") envelope.signature = Buffer.alloc(64).toString("base64");
    if (this.mode === "watermark-tamper" && op === "payload.unlock") {
      // Keep the signature; replace only the valid watermark before encryption.
      data.watermark = "2a".repeat(32);
    }
    if (this.mode === "nonce") envelope.nonce = "wrong";
    const n = crypto.randomBytes(12);
    const responseAAD = Buffer.concat([aad, Buffer.from("\0" + a.sha(outer.n + "." + outer.c))]);
    return { status: 200, body: raw({ n: a.b64(n), c: a.b64(a.seal(a.hkdf(shared, salt, Buffer.from("authgo/v2/response")), n, a.pad(Buffer.from(a.canonical(envelope))), responseAAD)) }) };
  }
}
async function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "authgo-v2-"));
  t.after(() => fs.rmSync(dir, { force: true, recursive: true }));
  const server = new SignedServer();
  const client = new a.Client(server.encodedConfig(), server.options(dir));
  const result = await client.check(LICENSE);
  return { dir, server, client, result, payload: server.payload };
}
const cacheFiles = (dir) => fs.readdirSync(dir).filter((name) => /^authgo-payload-v[12]-.*\.cache$/.test(name));

test("v2 public exact metadata, version AAD and required watermark metadata", () => {
  const value = payloadObject(), parsed = a.parsePayload(raw(value));
  assert.equal(parsed.v, 2);
  assert.ok(p.payloadAAD(parsed).subarray(0, 27).toString().startsWith("authgo-payload-envelope-v2"));
  assert.ok(p.payloadRewrapAAD(parsed, Buffer.alloc(32), Buffer.alloc(32)).toString().startsWith("authgo-payload-rewrap-v2\0"));
  const changes = [
    (f) => f.pop(), (f) => f[1].python_version = "", (f) => f[1].main_class = "",
    (f) => f[1].architecture = "", (f) => f[1].size = 0, (f) => f[1].size = 8388609,
    (f) => f[1].encoding = "tar", (f) => f[1].name = "wrong",
    (f) => f[0].name = "__authgo_watermark", (f) => f[1].path = "00000000.agc",
    (f) => f.push(meta(2)),
  ];
  for (const change of changes) {
    const files = [file(), meta()]; change(files);
    assert.throws(() => a.parsePayload(raw(payloadObject(files))), code("PAYLOAD_INVALID"));
  }
  assert.throws(() => a.parsePayload(raw(payloadObject([meta(0)]))), code("PAYLOAD_INVALID"));
  for (const insertion of ['"v":2,"v":2', '"v":2,"V":2'])
    assert.throws(() => a.parsePayload(raw(payloadObject()).toString().replace('"v":2', insertion)), code("PAYLOAD_INVALID"));
});

test("v2 bounded private schema, duplicate/case aliases, decimals, paths and coverage", () => {
  const files = [file(), meta()];
  const parse = (value, publicFiles = files) => parseWatermarkIndex(raw(value), publicFiles);
  assert.equal(parse(privateIndex()).tag, TAG);
  const changes = [
    (x) => x.v = 1, (x) => x.V = "1", (x) => x.tag = TAG.toUpperCase(),
    (x) => x.files[0].index = 0, (x) => x.files[0].index = "00",
    (x) => x.files[0].index = "65535", (x) => x.files[0].index = "1",
    (x) => x.files.push(clone(x.files[0])),
    (x) => x.files[0].entries.push(clone(x.files[0].entries[0])),
    (x) => x.files[0].entries[0].path = ["a.pyc"],
    (x) => x.files[0].entries[0].Path = [],
    (x) => x.files[0].entries[0].offsets = Array(8).fill("0"),
    (x) => x.files[0].entries[0].offsets = Array.from({ length: 8 }, (_, i) => String(i * 95)),
    (x) => x.files[0].entries[0].offsets[1] = "096",
    (x) => x.files[0].entries[0].offsets[1] = "4611686018427387904",
    (x) => x.files[0].entries[0].offsets[1] = 96,
    (x) => x.files[0].entries[0].offsets.pop(),
  ];
  for (const change of changes) { const value = privateIndex(); change(value); assert.throws(() => parse(value), code("PAYLOAD_INVALID")); }
  for (const text of [raw(privateIndex()).toString().replace('"v":"1"', '"v":"1","v":"1"'),
    raw(privateIndex()).toString().replace('"index":"0"', '"index":"0","Index":"0"')])
    assert.throws(() => parseWatermarkIndex(Buffer.from(text), files), code("PAYLOAD_INVALID"));
  assert.throws(() => parse(privateIndex(), [file(), file(1, "node", "second"), meta(2)]), code("PAYLOAD_INVALID"));
  for (const name of ["../a", "/a", "a//b", "a/./b", "a\\b", "a:b", "a\0b", "a\x7fb"])
    assert.throws(() => parse(privateIndex([name]), [{ ...file(), kind: "python" }, meta()]), code("PAYLOAD_INVALID"));
  const aliases = privateIndex(["a.pyc"]);
  aliases.files[0].entries.push({ path: ["A.pyc"], offsets: ["0"] });
  assert.throws(() => parse(aliases, [{ ...file(), kind: "python" }, meta()]), code("PAYLOAD_INVALID"));
  assert.throws(() => parse(privateIndex(Array(9).fill("a")), [{ ...file(), kind: "java" }, meta()]), code("PAYLOAD_INVALID"));
  assert.throws(() => parseWatermarkIndex(Buffer.alloc(8388609, 32), files), code("PAYLOAD_INVALID"));
  const huge = privateIndex(); huge.files[0].entries[0].offsets = Array(65536).fill("0");
  assert.throws(() => parse(huge), code("PAYLOAD_INVALID"));
  for (const value of [
    { v: "1", tag: TAG, files: Array(65536).fill({ index: "0", entries: [] }) },
    { v: "1", tag: TAG, files: [{ index: "0", entries: Array(65536).fill({ path: [], offsets: [] }) }] },
  ]) assert.throws(() => parse(value), code("PAYLOAD_INVALID"));
  for (const decimal of ["", "-1", "+1", "01", "1.0", "1e3", "١", "9223372036854775808"]) {
    const value = privateIndex(); value.files[0].entries[0].offsets[0] = decimal;
    assert.throws(() => parse(value), code("PAYLOAD_INVALID"));
  }
  assert.throws(() => parse(privateIndex(), [file(0, "node", "core", 767), meta()]), code("PAYLOAD_INVALID"));
});

test("v2 slots validate all before rewrite; only the 64-byte tail changes", () => {
  const index = parseWatermarkIndex(raw(privateIndex()), [file(), meta()]);
  const target = Buffer.from(SLOT.repeat(8)); target[target.length - 1] = 49;
  const before = Buffer.from(target);
  assert.throws(() => applyWatermark(new Map([["[]", target]]), index, 0, WM), code("PAYLOAD_INVALID"));
  assert.deepEqual(target, before);
  target[target.length - 1] = 48;
  for (const wm of [Buffer.alloc(0), Buffer.alloc(31, 1), Buffer.alloc(32)])
    assert.throws(() => applyWatermark(new Map([["[]", target]]), index, 0, wm), code("PAYLOAD_INVALID"));
  assert.throws(() => applyWatermark(new Map(), index, 0, WM), code("PAYLOAD_INVALID"));
  applyWatermark(new Map([["[]", target]]), index, 0, WM);
  assert.equal(target.toString(), (TAG + WM.toString("hex")).repeat(8));
  assert.throws(() => applyWatermark(new Map([["[]", target]]), index, 0, WM), code("PAYLOAD_INVALID"));
});

test("v2 signed public32/private64 and versioned cache offline/expiry", async (t) => {
  const f = await fixture(t);
  assert.deepEqual(await f.client.unlockPayload(f.payload), f.server.dek);
  assert.deepEqual(await f.client._unlockPayloadMaterial(f.payload), Buffer.concat([f.server.dek, WM]));
  const name = cacheFiles(f.dir)[0];
  assert.ok(name.startsWith("authgo-payload-v2-"));
  assert.ok(fs.readFileSync(path.join(f.dir, name)).toString().startsWith("AUTHGO-PAYLOAD-CACHE-v2."));
  f.server.mode = "network";
  assert.deepEqual(await f.client._unlockPayloadMaterial(f.payload), Buffer.concat([f.server.dek, WM]));
  f.client.offlineTicket = f.result.ticket(); f.client.onlineUntil = 0;
  const before = f.server.calls.length;
  assert.deepEqual(await f.client._unlockPayloadMaterial(f.payload), Buffer.concat([f.server.dek, WM]));
  assert.equal(f.server.calls.length, before);
  f.client.offlineTicket = "";
  f.server.now += 120;
  assert.throws(() => p.loadPayloadKey(f.client, f.payload, f.result), code("SDK_GRACE_EXPIRED"));
  await assert.rejects(f.client.unlockPayload(f.payload), code("SDK_NETWORK_ERROR"));
});

test("v2 post-signature valid watermark tamper rejects signature without payload cache", async (t) => {
  const f = await fixture(t);
  assert.deepEqual(cacheFiles(f.dir), []);
  const before = f.server.calls.length;
  f.server.mode = "watermark-tamper";
  await assert.rejects(f.client._unlockPayloadMaterial(f.payload), code("SDK_RESPONSE_SIGNATURE_INVALID"));
  assert.deepEqual(cacheFiles(f.dir), []);
  await assert.rejects(f.client.unlockPayload(f.payload), code("SDK_RESPONSE_SIGNATURE_INVALID"));
  assert.deepEqual(cacheFiles(f.dir), []);
  assert.deepEqual(f.server.calls.slice(before), ["payload.unlock", "payload.unlock"]);
  f.server.mode = "";
  assert.deepEqual(await f.client._unlockPayloadMaterial(f.payload), Buffer.concat([f.server.dek, WM]));
});

test("v2 freshly signed malformed/missing watermark never falls back or erases evidence", async (t) => {
  const f = await fixture(t);
  await f.client.unlockPayload(f.payload);
  const cached = path.join(f.dir, cacheFiles(f.dir)[0]), before = fs.readFileSync(cached);
  for (const value of [null, "", WM.toString("hex").toUpperCase(), "0".repeat(64), "x".repeat(64), WM.toString("hex") + "\n", 42, {}]) {
    f.server.watermark = value;
    await assert.rejects(f.client.unlockPayload(f.payload), code("SDK_RESPONSE_INVALID"));
    assert.deepEqual(fs.readFileSync(cached), before);
  }
  f.server.mode = "missing-watermark";
  await assert.rejects(f.client._unlockPayloadMaterial(f.payload), code("SDK_RESPONSE_INVALID"));
  assert.deepEqual(fs.readFileSync(cached), before);
  f.server.watermark = WM.toString("hex");
  for (const mode of ["challenge", "license", "wrap"]) {
    f.server.mode = mode;
    await assert.rejects(f.client.unlockPayload(f.payload), code("SDK_RESPONSE_INVALID"));
  }
  for (const mode of ["nonce", "signature"]) {
    f.server.mode = mode;
    // Unauthenticated replies cannot inject a watermark, only reuse old grant.
    assert.deepEqual(await f.client._unlockPayloadMaterial(f.payload), Buffer.concat([f.server.dek, WM]));
  }
});

test("cache binding, material length, trials and explicit denial cleanup", async (t) => {
  const f = await fixture(t);
  await f.client.unlockPayload(f.payload);
  p.savePayloadKey(f.client, f.payload, f.result, Buffer.concat([f.server.dek, WM]));
  assert.deepEqual(p.loadPayloadKey(f.client, f.payload, f.result), Buffer.concat([f.server.dek, WM]));
  const control = a.parsePayload(raw(vector("payload-cache-v2.json").payload));
  p.savePayloadKey(f.client, control, f.result, Buffer.concat([f.server.dek, WM]));
  assert.equal(cacheFiles(f.dir).length, 2);
  const changed = clone(f.payload); changed.envelope.n = a.b64(Buffer.alloc(12, 7));
  const replacement = a.parsePayload(raw(changed));
  const target = p.cacheMaterial(f.client, replacement, f.result);
  fs.copyFileSync(path.join(f.dir, cacheFiles(f.dir).find((name) => name.startsWith("authgo-payload-v2-"))), target.file);
  fs.chmodSync(target.file, 0o600); target.key.fill(0);
  assert.throws(() => p.loadPayloadKey(f.client, replacement, f.result), code("SDK_CACHE_INVALID"));
  const grant = f.client.grant.bind(f.client), signed = grant(f.result.ticket());
  f.client.grant = () => ({ ...signed, license_id: 43 });
  try { assert.throws(() => p.loadPayloadKey(f.client, f.payload, f.result), code("SDK_CACHE_INVALID")); }
  finally { f.client.grant = grant; }
  const publicKey = f.client.public;
  f.client.public = Buffer.alloc(32, 8);
  f.client.grant = () => signed;
  try { assert.throws(() => p.loadPayloadKey(f.client, f.payload, f.result), code("SDK_CACHE_UNAVAILABLE")); }
  finally { f.client.public = publicKey; f.client.grant = grant; }
  const material = p.cacheMaterial(f.client, f.payload, f.result), nonce = Buffer.alloc(12, 9);
  fs.writeFileSync(material.file, "AUTHGO-PAYLOAD-CACHE-v2." + a.b64(Buffer.concat([nonce, a.seal(material.key, nonce, f.server.dek, material.aad)])));
  material.key.fill(0);
  assert.throws(() => p.loadPayloadKey(f.client, f.payload, f.result), code("SDK_CACHE_INVALID"));
  f.server.trial = true;
  assert.deepEqual(await f.client._unlockPayloadMaterial(f.payload), Buffer.concat([f.server.dek, WM]));
  assert.equal(cacheFiles(f.dir).length, 0);
  f.server.mode = "missing-watermark";
  await assert.rejects(f.client.unlockPayload(f.payload), code("SDK_RESPONSE_INVALID"));
  assert.equal(cacheFiles(f.dir).length, 0);
  f.server.mode = "";
  f.server.trial = false;
  await f.client.check(LICENSE);
  await f.client.unlockPayload(f.payload);
  p.savePayloadKey(f.client, control, f.result, Buffer.concat([f.server.dek, WM]));
  assert.equal(cacheFiles(f.dir).length, 2);
  f.server.refusal = "LICENSE_REVOKED";
  await assert.rejects(f.client.unlockPayload(f.payload), code("LICENSE_REVOKED"));
  assert.equal(cacheFiles(f.dir).length, 0);
});

function encrypt(payload, key, index, plain) {
  const chunks = Math.max(1, Math.ceil(plain.length / 1048576)), out = [];
  for (let j = 0; j < chunks; j++) {
    const nonce = Buffer.alloc(12); nonce.writeUInt32BE(index); nonce.writeBigUInt64BE(BigInt(j), 4);
    const aad = Buffer.concat([Buffer.from("authgo-payload-chunk-v1\0"), payload.payloadBinding(), nonce, Buffer.from([Number(j === chunks - 1)])]);
    out.push(a.seal(key, nonce, plain.subarray(j * 1048576, (j + 1) * 1048576), aad));
  }
  return Buffer.concat(out);
}

test("v2 actual Guard/CommonJS loader uses private64 and patches real strings before compile", async (t) => {
  const f = await fixture(t);
  const prior = process.env.AUTHGO_PAYLOAD_DIR;
  process.env.AUTHGO_PAYLOAD_DIR = f.dir;
  t.after(() => { if (prior === undefined) delete process.env.AUTHGO_PAYLOAD_DIR; else process.env.AUTHGO_PAYLOAD_DIR = prior; });
  // Packer-style real literals on the original CommonJS this/exports, after
  // Directive Prologue; never a synthetic external resource or script suffix.
  const source = Buffer.from("'use strict'; Object.defineProperty(this, '__pack_slots', {enumerable:false,value:" +
    JSON.stringify(Array.from({ length: 8 }, (_, i) => "slot" + i + ":" + SLOT)) + "}); this.value = 42;");
  const index = privateIndex();
  let start = 0;
  index.files[0].entries[0].offsets = Array.from({ length: 8 }, () => {
    const offset = source.indexOf(SLOT, start); assert.ok(offset >= 0); start = offset + 96; return String(offset);
  });
  // Force a second metadata chunk. Authentication of the last chunk is mandatory.
  const privateBytes = Buffer.concat([raw(index), Buffer.alloc(1048576, 32)]);
  const payload = a.parsePayload(raw(payloadObject([file(0, "node", "core", source.length), meta(1, privateBytes.length)])));
  f.server.payload = payload;
  const ciphertext = encrypt(payload, f.server.dek, 0, source);
  const metadata = encrypt(payload, f.server.dek, 1, privateBytes);
  fs.writeFileSync(path.join(f.dir, "payload.json"), raw(payload));
  fs.writeFileSync(path.join(f.dir, "00000000.agc"), ciphertext);
  const metadataPath = path.join(f.dir, "00000001.agc");
  fs.writeFileSync(metadataPath, metadata);
  const guard = await a.startGuard({ config: f.server.encodedConfig(), license: LICENSE, ...f.server.options(f.dir) });
  t.after(() => guard.close());
  const bad = Buffer.from(metadata); bad[bad.length - 1] ^= 1;
  fs.writeFileSync(metadataPath, bad);
  await assert.rejects(guard.requireSealed("core"), code("PAYLOAD_INVALID"));
  fs.unlinkSync(metadataPath);
  await assert.rejects(guard.requireSealed("core"), code("PAYLOAD_INVALID"));
  fs.writeFileSync(metadataPath, metadata);
  f.server.mode = "missing-watermark";
  await assert.rejects(guard.requireSealed("core"), code("SDK_RESPONSE_INVALID"));
  f.server.mode = "";
  const badSource = Buffer.from(source);
  badSource[badSource.indexOf(SLOT) + 95] = 49;
  fs.writeFileSync(path.join(f.dir, "00000000.agc"), encrypt(payload, f.server.dek, 0, badSource));
  await assert.rejects(guard.requireSealed("core"), code("PAYLOAD_INVALID"));
  fs.writeFileSync(path.join(f.dir, "00000000.agc"), ciphertext);
  const value = await guard.requireSealed("core");
  assert.equal(value.value, 42);
  assert.deepEqual(Object.keys(value), ["value"]);
  assert.deepEqual(value.__pack_slots, Array.from({ length: 8 }, (_, i) => "slot" + i + ":" + TAG + WM.toString("hex")));
  assert.equal(await guard.requireSealed("core"), value);
  assert.deepEqual(fs.readFileSync(path.join(f.dir, "00000000.agc")), ciphertext);
  assert.equal(fs.existsSync(path.join(f.dir, ".authgo-sealed-core.cjs")), false);
  await guard.close();
  await assert.rejects(guard.requireSealed("core"), code("SDK_NOT_ACTIVATED"));
});
