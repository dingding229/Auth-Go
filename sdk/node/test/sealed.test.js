import { test, mock } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Module from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as a from "../index.js";
import { vector } from "./payload-vectors.js";
import { checkChunkVectors } from "./sealed-vectors.js";

const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const code = (expected) => (error) => {
  assert.equal(error.code, expected);
  return true;
};
function encrypt(payload, index, plain) {
  const count = Math.max(1, Math.ceil(plain.length / (1 << 20))),
    blocks = [];
  for (let j = 0; j < count; j++) {
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(index);
    nonce.writeBigUInt64BE(BigInt(j), 4);
    const aad = Buffer.concat([
      Buffer.from("authgo-payload-chunk-v1\0"),
      payload.payloadBinding(),
      nonce,
      Buffer.from([Number(j === count - 1)]),
    ]);
    const cipher = crypto.createCipheriv("aes-256-gcm", KEY, nonce);
    cipher.setAAD(aad);
    blocks.push(
      cipher.update(plain.subarray(j * (1 << 20), (j + 1) * (1 << 20))),
      cipher.final(),
      cipher.getAuthTag(),
    );
  }
  return Buffer.concat(blocks);
}
function bundle(
  source,
  { index = 0, version = "1.2.3", kind = "node", name = "core", config } = {},
) {
  const original = Buffer.isBuffer(source) ? source : Buffer.from(source);
  const tag = "0123456789abcdef0123456789abcdef", slot = tag + "0".repeat(64);
  const plain = Buffer.concat([original, Buffer.from("\n/*" + slot.repeat(8) + "*/")]);
  const obj = vector("payload-envelope.json").payload;
  obj.version = version;
  if (config) obj.config = config;
  const files = Array.from({ length: index }, (_, i) => ({
    name: "ignored" + i,
    kind: "node",
    path: String(i).padStart(8, "0") + ".agc",
    size: 768,
    chunk_size: 1 << 20,
    encoding: "raw",
  }));
  files.push({
    name,
    kind,
    path: String(index).padStart(8, "0") + ".agc",
    size: plain.length,
    chunk_size: 1 << 20,
    encoding: "raw",
  });
  const privateIndex = Buffer.from(JSON.stringify({v:"1",tag,files:files.map((f,i)=>({index:String(i),entries:[{path:[],offsets:Array.from({length:8},(_,j)=>String((i===index?original.length+3:0)+j*96))}]}))}));
  files.push({name:"__authgo_watermark",kind:"watermark",path:String(index+1).padStart(8,"0")+".agc",size:privateIndex.length,chunk_size:1<<20,encoding:"raw"});
  obj.manifest = a.b64(Buffer.from(JSON.stringify({ files })));
  const payload = a.parsePayload(JSON.stringify(obj));
  return { payload, ciphertext: encrypt(payload, index, plain), privateCiphertext: encrypt(payload, index+1, privateIndex), index };
}
async function setup(
  t,
  source = "module.exports = { answer: 42 };",
  options = {},
) {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "authgo-node-sealed-"),
  );
  const env = process.env.AUTHGO_PAYLOAD_DIR;
  process.env.AUTHGO_PAYLOAD_DIR = directory;
  const state = {
    unlocks: 0,
    checks: 0,
    validations: 0,
    keys: [],
    error: null,
    gate: null,
  };
  const value = (c) =>
    new a.Result(
      c,
      { features: {}, next_check_in: 3600, floating: false },
      "proof",
      Buffer.alloc(32),
      "online",
      c.now() + 3600,
    );
  mock.method(a.Client.prototype, "check", async function () {
    state.checks++;
    state.client = this;
    return value(this);
  });
  mock.method(a.Client.prototype, "verify", async function () {
    if (state.error) throw state.error;
    return value(this);
  });
  mock.method(a.Client.prototype, "validate", function (ticket) {
    state.validations++;
    assert.equal(ticket, "proof");
    if (state.error) throw state.error;
  });
  mock.method(a.Client.prototype, "releaseSeat", async () => {});
  mock.method(a.Client.prototype, "_unlockPayloadMaterial", async function (payload) {
    state.unlocks++;
    state.lastPayload = payload;
    if (state.gate) await state.gate;
    if (state.unlockError) throw state.unlockError;
    const key = Buffer.concat([KEY, Buffer.alloc(32, 0x19)]);
    state.keys.push(key);
    return key;
  });
  const v = vector("v2.json");
  const config =
    "authgo2." +
    a.b64(
      Buffer.from(
        JSON.stringify({
          url: "https://auth.example.test",
          app_key: "app_test",
          app_secret: "test-secret",
          public_key: Buffer.from(v.ed25519_public, "base64url").toString(
            "base64",
          ),
          gateway_key: v.gateway_public,
        }),
      ),
    );
  const guard = await a.startGuard({
    config,
    license: "customer",
    cacheDir: directory,
    fingerprint: "a".repeat(64),
  });
  t.after(async () => {
    await guard.close();
    mock.restoreAll();
    if (env === undefined) delete process.env.AUTHGO_PAYLOAD_DIR;
    else process.env.AUTHGO_PAYLOAD_DIR = env;
    fs.rmSync(directory, { recursive: true, force: true });
  });
  function write(content = source, changes = options) {
    const b = bundle(content, changes);
    fs.writeFileSync(
      path.join(directory, "payload.json"),
      JSON.stringify(b.payload),
    );
    fs.writeFileSync(
      path.join(directory, String(b.index).padStart(8, "0") + ".agc"),
      b.ciphertext,
    );
    fs.writeFileSync(path.join(directory, String(b.index+1).padStart(8, "0") + ".agc"), b.privateCiphertext);
    return b;
  }
  const b = write();
  return { directory, state, guard, write, ...b };
}

test("sealed: original chunk vectors", checkChunkVectors);
test("sealed: Node 22 _compile experiment in ESM and CJS hosts", () => {
  const cwd = fileURLToPath(new URL("../", import.meta.url));
  for (const args of [
    ["test/sealed-runtime.mjs"],
    ["--input-type=commonjs", "-e", 'import("./test/sealed-runtime.mjs")'],
  ]) {
    const run = spawnSync(process.execPath, args, { cwd, encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    const report = JSON.parse(run.stdout);
    assert.equal(report.commonjs_exports, "PASS");
    assert.equal(report.require_resolution, "PASS");
  }
});
test("sealed: CommonJS exports, module.exports replacement and falsy exports", async (t) => {
  const f = await setup(t);
  const first = await f.guard.requireSealed("core");
  assert.equal(first.answer, 42);
  assert.strictEqual(await f.guard.requireSealed("core"), first);
  assert.equal(f.state.unlocks, 1);
  assert.equal(f.state.checks, 1);
  assert.ok(f.state.keys.every((key) => key.every((byte) => byte === 0)));
});
test("sealed: CommonJS hashbang and BOM preserve Node loading behavior", async (t) => {
  const f = await setup(t, "\uFEFF#!/usr/bin/env node\nmodule.exports = 17;");
  assert.equal(await f.guard.requireSealed("core"), 17);
});
test("sealed: public payload config cannot replace Client connection config", async (t) => {
  const f = await setup(t);
  const obj = JSON.parse(JSON.stringify(f.payload));
  const config = JSON.parse(a.unb64(obj.config.slice(8)));
  config.url = "https://untrusted.example.test";
  obj.config = "authgo2." + a.b64(Buffer.from(JSON.stringify(config)));
  const changed = bundle("module.exports = { answer: 42 };", { config: obj.config });
  fs.writeFileSync(path.join(f.directory, "payload.json"), JSON.stringify(changed.payload));
  fs.writeFileSync(path.join(f.directory, "00000000.agc"), changed.ciphertext);
  fs.writeFileSync(path.join(f.directory, "00000001.agc"), changed.privateCiphertext);
  assert.equal((await f.guard.requireSealed("core")).answer, 42);
  assert.equal(f.state.client.config.url, "https://auth.example.test");
  assert.equal(
    JSON.parse(a.unb64(f.state.lastPayload.config.slice(8))).url,
    config.url,
  );
});
test("sealed: replacement function exports and builtins", async (t) => {
  const f = await setup(
    t,
    'module.exports = x => require("node:path").basename(x);',
  );
  const core = await f.guard.requireSealed("core");
  assert.equal(core("/dir/value"), "value");
});
test("sealed: primitive falsy exports cached without reevaluation", async (t) => {
  const f = await setup(t, "module.exports = 0;");
  assert.equal(await f.guard.requireSealed("core"), 0);
  assert.equal(await f.guard.requireSealed("core"), 0);
  assert.equal(f.state.unlocks, 1);
});
test("sealed: external relative dependency and node_modules resolution", async (t) => {
  const f = await setup(
    t,
    'module.exports = [require("./helper.cjs"), require("public-dep")];',
  );
  fs.writeFileSync(
    path.join(f.directory, "helper.cjs"),
    'module.exports = "relative";',
  );
  const dep = path.join(f.directory, "node_modules", "public-dep");
  fs.mkdirSync(dep, { recursive: true });
  fs.writeFileSync(
    path.join(dep, "index.js"),
    'module.exports = "dependency";',
  );
  assert.deepEqual(await f.guard.requireSealed("core"), [
    "relative",
    "dependency",
  ]);
  delete Module._cache[path.join(f.directory, "helper.cjs")];
  delete Module._cache[path.join(dep, "index.js")];
});
test("sealed: module exceptions propagate and failed loads can retry", async (t) => {
  const f = await setup(t, 'throw new TypeError("sealed failure");');
  await assert.rejects(f.guard.requireSealed("core"), {
    name: "TypeError",
    message: "sealed failure",
  });
  f.write("module.exports = 7;");
  assert.equal(await f.guard.requireSealed("core"), 7);
  assert.ok(f.state.keys.every((key) => key.every((byte) => byte === 0)));
});
test("sealed: syntax errors propagate without substituting cached exports", async (t) => {
  const f = await setup(t, "module.exports = {;");
  await assert.rejects(f.guard.requireSealed("core"), { name: "SyntaxError" });
});
test("sealed: authenticated refusal blocks cached and new loads", async (t) => {
  const f = await setup(t);
  await f.guard.requireSealed("core");
  f.state.error = new a.AuthGoError("LICENSE_REVOKED", "", true);
  await assert.rejects(f.guard.requireSealed("core"), code("LICENSE_REVOKED"));
  assert.equal(f.state.unlocks, 1);
});
test("sealed: refusal during unlock blocks module evaluation and zeros key", async (t) => {
  const f = await setup(t, "process.__authgoSealedShouldNotRun = true;");
  let release;
  f.state.gate = new Promise((r) => {
    release = r;
  });
  const loading = f.guard.requireSealed("core");
  while (!f.state.unlocks) await new Promise((r) => setTimeout(r, 1));
  f.state.error = new a.AuthGoError("LICENSE_REVOKED", "", true);
  release();
  await assert.rejects(loading, code("LICENSE_REVOKED"));
  assert.equal(process.__authgoSealedShouldNotRun, undefined);
  assert.ok(f.state.keys[0].every((byte) => byte === 0));
});
test("sealed: closed guard and expired ticket cannot load", async (t) => {
  const f = await setup(t);
  f.state.error = new a.AuthGoError("SDK_GRACE_EXPIRED");
  await assert.rejects(
    f.guard.requireSealed("core"),
    code("SDK_GRACE_EXPIRED"),
  );
  f.state.error = null;
  await f.guard.close();
  await assert.rejects(
    f.guard.requireSealed("core"),
    code("SDK_NOT_ACTIVATED"),
  );
  assert.equal(f.state.unlocks, 0);
});
test("sealed: lazy external require is guard gated after refusal", async (t) => {
  const f = await setup(t, 'module.exports = () => require("node:path");');
  const core = await f.guard.requireSealed("core");
  f.state.error = new a.AuthGoError("LICENSE_REVOKED", "", true);
  assert.throws(core, code("LICENSE_REVOKED"));
});
test("sealed: ESM import, export, dynamic import and import.meta statically rejected", async (t) => {
  const f = await setup(t);
  for (const source of [
    'import fs from "node:fs";',
    "export default 1;",
    'module.exports = () => import("node:fs");',
    "module.exports = import.meta.url;",
  ]) {
    f.write(source);
    await assert.rejects(f.guard.requireSealed("core"), (error) => {
      assert.equal(error.code, "PAYLOAD_INVALID");
      assert.match(error.message, /CommonJS/);
      return true;
    });
  }
  assert.ok(f.state.keys.every((key) => key.every((byte) => byte === 0)));
});
test("sealed: native .node and dlopen statically rejected", async (t) => {
  const f = await setup(t);
  for (const source of [
    'module.exports = require("./native.node");',
    'process.dlopen(module, "native");',
  ]) {
    f.write(source);
    await assert.rejects(f.guard.requireSealed("core"), (error) => {
      assert.equal(error.code, "PAYLOAD_INVALID");
      assert.match(error.message, /原生插件/);
      return true;
    });
  }
});
test("sealed: computed native filename cannot evade runtime require gate", async (t) => {
  const f = await setup(
    t,
    'module.exports = () => require("./native" + String.fromCharCode(46) + "node");',
  );
  fs.writeFileSync(
    path.join(f.directory, "native.node"),
    "not a shared library",
  );
  const core = await f.guard.requireSealed("core");
  assert.throws(core, code("PAYLOAD_INVALID"));
});
test("sealed: concurrent callers share one unlock and evaluation", async (t) => {
  const f = await setup(
    t,
    "process.__authgoSealedEvaluations = (process.__authgoSealedEvaluations || 0) + 1; module.exports = {};",
  );
  t.after(() => {
    delete process.__authgoSealedEvaluations;
  });
  const values = await Promise.all(
    Array.from({ length: 12 }, () => f.guard.requireSealed("core")),
  );
  assert.ok(values.every((v) => v === values[0]));
  assert.equal(process.__authgoSealedEvaluations, 1);
  assert.equal(f.state.unlocks, 1);
});
test("sealed: concurrent failures do not cache partial exports", async (t) => {
  const f = await setup(
    t,
    'exports.partial = true; throw new Error("not ready");',
  );
  const values = await Promise.allSettled(
    Array.from({ length: 8 }, () => f.guard.requireSealed("core")),
  );
  assert.ok(
    values.every(
      (v) => v.status === "rejected" && v.reason.message === "not ready",
    ),
  );
  f.write('module.exports = "ready";');
  assert.equal(await f.guard.requireSealed("core"), "ready");
});
test("sealed: conflicting payload version is rejected instead of using stale exports", async (t) => {
  const f = await setup(t);
  await f.guard.requireSealed("core");
  f.write("module.exports = 99;", { version: "2.0.0" });
  await assert.rejects(f.guard.requireSealed("core"), code("PAYLOAD_INVALID"));
  assert.equal(f.state.unlocks, 1);
});
test("sealed: duplicate names, non-node content and unknown name rejected", async (t) => {
  const f = await setup(t);
  let obj = JSON.parse(JSON.stringify(f.payload));
  const files = JSON.parse(a.unb64(obj.manifest));
  files.files.push({ ...files.files[0], path: "00000001.agc" });
  obj.manifest = a.b64(Buffer.from(JSON.stringify(files)));
  fs.writeFileSync(path.join(f.directory, "payload.json"), JSON.stringify(obj));
  await assert.rejects(f.guard.requireSealed("core"), code("PAYLOAD_INVALID"));
  f.write("", { kind: "java" });
  await assert.rejects(f.guard.requireSealed("core"), code("PAYLOAD_INVALID"));
  f.write();
  await assert.rejects(
    f.guard.requireSealed("missing"),
    code("PAYLOAD_INVALID"),
  );
  assert.equal(f.state.unlocks, 0);
});
test("sealed: virtual filename conflict never loads plaintext", async (t) => {
  const f = await setup(t);
  fs.writeFileSync(
    path.join(f.directory, ".authgo-sealed-core.cjs"),
    "process.__authgoSealedShouldNotRun = true;",
  );
  await assert.rejects(f.guard.requireSealed("core"), code("PAYLOAD_INVALID"));
  assert.equal(f.state.unlocks, 0);
  assert.equal(process.__authgoSealedShouldNotRun, undefined);
});
test("sealed: UTF-8 must be valid and metadata bounded", async (t) => {
  const f = await setup(t, Buffer.from([0xff]));
  await assert.rejects(f.guard.requireSealed("core"), code("PAYLOAD_INVALID"));
  fs.writeFileSync(path.join(f.directory, "payload.json"), " ".repeat(65537));
  await assert.rejects(f.guard.requireSealed("core"), code("PAYLOAD_INVALID"));
});
test("sealed: ciphertext length, tampering and wrong key are rejected", async (t) => {
  const f = await setup(t);
  for (const ct of [
    f.ciphertext.subarray(1),
    Buffer.concat([f.ciphertext, Buffer.from([0])]),
    Buffer.alloc(f.ciphertext.length),
  ]) {
    fs.writeFileSync(path.join(f.directory, "00000000.agc"), ct);
    await assert.rejects(
      f.guard.requireSealed("core"),
      code("PAYLOAD_INVALID"),
    );
  }
  assert.ok(f.state.keys.every((key) => key.every((byte) => byte === 0)));
});
test("sealed: no plaintext writes, temp files or global require cache registration", async (t) => {
  const marker = "AUTHGO_CORE_MEMORY_ONLY_9FA";
  const f = await setup(t, "module.exports = " + JSON.stringify(marker) + ";");
  const before = new Map(
    fs
      .readdirSync(f.directory)
      .map((name) => [name, fs.readFileSync(path.join(f.directory, name))]),
  );
  for (const method of [
    "writeFileSync",
    "writeFile",
    "mkdtempSync",
    "mkdirSync",
    "appendFileSync",
    "renameSync",
  ])
    mock.method(fs, method, () => {
      throw new Error("loader attempted a write");
    });
  for (const method of [
    "writeFile",
    "mkdtemp",
    "mkdir",
    "appendFile",
    "rename",
  ])
    mock.method(fs.promises, method, () => {
      throw new Error("loader attempted a write");
    });
  const opened = fs.promises.open.bind(fs.promises);
  mock.method(fs.promises, "open", async function (file, flags, ...args) {
    assert.equal(
      flags &
        (fs.constants.O_WRONLY |
          fs.constants.O_RDWR |
          fs.constants.O_CREAT |
          fs.constants.O_TRUNC |
          fs.constants.O_APPEND),
      0,
    );
    return opened(file, flags, ...args);
  });
  assert.equal(await f.guard.requireSealed("core"), marker);
  for (const [name, bytes] of before) {
    assert.deepEqual(fs.readFileSync(path.join(f.directory, name)), bytes);
    assert.equal(bytes.includes(Buffer.from(marker)), false);
  }
  assert.deepEqual(
    fs.readdirSync(f.directory).sort(),
    [...before.keys()].sort(),
  );
  assert.equal(
    Module._cache[path.join(f.directory, ".authgo-sealed-core.cjs")],
    undefined,
  );
});
test("sealed: index other than zero and multi-chunk source", async (t) => {
  const f = await setup(
    t,
    "/*" + "x".repeat((1 << 20) + 7) + "*/ module.exports = 73;",
    { index: 1 },
  );
  assert.equal(await f.guard.requireSealed("core"), 73);
});
test("sealed: chunk size arithmetic remains exact and malformed inputs fail", () => {
  for (const size of [0n, 1n, 1048576n, 1048577n, 9007199254740993n])
    assert.equal(
      a.payloadCipherSize(size),
      size + 16n * ((size + 1048575n) / 1048576n || 1n),
    );
  for (const size of [-1, 1.5, true, undefined, 2 ** 53, 2n ** 63n])
    assert.throws(() => a.payloadCipherSize(size), code("PAYLOAD_INVALID"));
  const { payload, ciphertext } = bundle("abc");
  for (const [key, index, ct] of [
    [KEY, -1, ciphertext],
    [KEY, 1, ciphertext],
    [Buffer.alloc(1), 0, ciphertext],
    [KEY, 0, ciphertext.subarray(1)],
  ])
    assert.throws(
      () => [...a.decryptPayloadFile(payload, key, index, ct)],
      code("PAYLOAD_INVALID"),
    );
});
test("sealed: no unauthenticated bytes, reordering and binding substitution", () => {
  const { payload, ciphertext } = bundle(Buffer.alloc((1 << 20) + 3, 65));
  const broken = Buffer.from(ciphertext);
  broken[broken.length - 1] ^= 1;
  const iterator = a.decryptPayloadFile(payload, KEY, 0, broken);
  assert.equal(iterator.next().value.length, 1 << 20);
  assert.throws(() => iterator.next(), code("PAYLOAD_INVALID"));
  const stride = (1 << 20) + 16;
  const multi = bundle(Buffer.alloc(3 << 20, 65));
  const reordered = Buffer.concat([
    multi.ciphertext.subarray(stride, 2 * stride),
    multi.ciphertext.subarray(0, stride),
    multi.ciphertext.subarray(2 * stride),
  ]);
  assert.throws(
    () => [...a.decryptPayloadFile(multi.payload, KEY, 0, reordered)],
    code("PAYLOAD_INVALID"),
  );
  const changed = JSON.parse(JSON.stringify(payload));
  changed.version = "2.0.0";
  assert.throws(
    () => [
      ...a.decryptPayloadFile(
        a.parsePayload(JSON.stringify(changed)),
        KEY,
        0,
        ciphertext,
      ),
    ],
    code("PAYLOAD_INVALID"),
  );
});
