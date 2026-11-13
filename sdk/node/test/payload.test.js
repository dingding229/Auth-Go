import { test, mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import * as a from "../index.js";
import * as p from "../payload.js";
import {
  vector,
  hex,
  rawPublic,
  checkPayloadVectors,
} from "./payload-vectors.js";
const iso = (time) => new Date(time * 1000).toISOString().replace(".000Z", "Z");
const LICENSE = "AUTH-RNMSQ-VSQQA-4S4NH-JDGCM";
const code = (expected) => (error) => {
  assert.equal(error.code, expected);
  return true;
};
const clone = (value) => JSON.parse(JSON.stringify(value));
class Server {
  constructor() {
    const v = vector("payload-cache-v2.json");
    this.now = v.proof_now;
    this.signer = crypto.generateKeyPairSync("ed25519").privateKey;
    this.gateway = crypto.generateKeyPairSync("x25519");
    this.payload = a.parsePayload(a.canonical(v.payload));
    this.dek = hex(v.content_key_hex);
    this.material = Buffer.concat([this.dek, Buffer.alloc(32, 0x19)]);
    this.seed = Buffer.alloc(32, 0x27);
    this.config = JSON.parse(a.unb64(this.payload.config.slice(8)));
    this.config.public_key = rawPublic(
      crypto.createPublicKey(this.signer),
    ).toString("base64");
    this.config.gateway_key = a.b64(rawPublic(this.gateway.publicKey));
    this.config.url = "https://PAYLOAD.EXAMPLE.TEST";
    this.calls = [];
    this.mode = "";
    this.responseCode = "";
    this.trial = false;
    this.grace = 120;
    this.floating = false;
    this.licenseId = 42;
    this.expires = null;
    this.changes = {};
    this.grantChanges = {};
    this.inFlight = 0;
    this.maxInFlight = 0;
  }
  client(dir, fp = vector("payload-cache-v2.json").fingerprint) {
    return new a.Client(
      "authgo2." + a.b64(Buffer.from(a.canonical(this.config))),
      {
        cacheDir: dir,
        fingerprint: fp,
        clock: () => this.now,
        transport: this.transport.bind(this),
      },
    );
  }
  ticket(body) {
    return {
      v: 2,
      app_key: this.config.app_key,
      challenge: body.challenge,
      license_id: this.licenseId,
      license_ref: "public-synthetic-ref",
      device_hash: a.sha(body.device_fingerprint),
      status: "active",
      issued_at: iso(this.now),
      starts_at: null,
      expires_at: this.expires,
      features: { export: true },
      next_check_in: 10,
      grace_until: iso(this.now + this.grace),
      lease_expires_at: this.floating ? iso(this.now + 20) : null,
      floating: this.floating,
      is_trial: this.trial,
      unlock_hash: a.sha(this.seed),
    };
  }
  signed(grant) {
    const raw = Buffer.from(a.canonical(grant));
    return (
      a.b64(raw) +
      "." +
      a.b64(
        crypto.sign(
          null,
          Buffer.concat([Buffer.from("authgo-ticket-v2\0"), raw]),
          this.signer,
        ),
      )
    );
  }
  async transport(url, packet, headers, timeout, limit) {
    assert.equal(url, "https://PAYLOAD.EXAMPLE.TEST/api/v1/client/gateway");
    assert.deepEqual(headers, { "Content-Type": "application/json" });
    assert.equal(timeout, 10000);
    assert.equal(limit, 2 * 1024 * 1024);
    this.inFlight++;
    this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
    try {
      await Promise.resolve();
      this.calls.push("transport");
      if (this.mode === "network") throw new a.AuthGoError("SDK_NETWORK_ERROR");
      if (this.mode === "status")
        return { status: 502, body: Buffer.from("<html>not signed</html>") };
      if (this.mode === "html")
        return { status: 200, body: Buffer.from("<html>not signed</html>") };
      const outer = a.parse(packet),
        aad = Buffer.from("authgo-gateway-v2\0" + outer.k + "\0" + outer.e);
      const shared = a.sharedSecret(
          this.gateway.privateKey
            .export({ format: "der", type: "pkcs8" })
            .subarray(-32),
          a.unb64(outer.e),
        ),
        salt = hex(a.sha(aad));
      const inner = a.parse(
        a.unpad(
          a.open(
            a.hkdf(shared, salt, Buffer.from("authgo/v2/request")),
            a.unb64(outer.n),
            a.unb64(outer.c),
            aad,
          ),
        ),
      );
      const { body, op, nonce } = inner;
      assert.equal(
        inner.signature,
        crypto
          .createHmac("sha256", this.config.app_secret)
          .update(op + inner.timestamp + nonce + a.sha(a.canonical(body)))
          .digest("hex"),
      );
      assert.equal(a.unb64(body.challenge).length, 32);
      this.calls[this.calls.length - 1] = op;
      const grant = this.ticket(body),
        data = {
          ...grant,
          unlock_seed: a.b64(this.seed),
          request_nonce: nonce,
          heartbeat_interval: 5,
          satisfied_methods: this.floating ? ["KEY", "FLOATING"] : ["KEY"],
        };
      if (op === "activate")
        data.activation_token = "act_" + a.b64(Buffer.alloc(32, 0x42));
      if (op === "deactivate") data.deactivated = true;
      if (op === "release-seat") data.released = true;
      if (op === "payload.unlock") {
        assert.deepEqual(
          Object.keys(body).sort(),
          [
            "license_key",
            "activation_token",
            "device_fingerprint",
                "instance_session",
            "payload",
            "ephemeral_public_key",
            "challenge",
          ].sort(),
        );
        assert.equal(body.license_key, LICENSE);
        assert(data.activation_token === undefined);
        assert.deepEqual(
          a.parsePayload(a.canonical(body.payload)).payloadBinding(),
          this.payload.payloadBinding(),
        );
        const ephemeral = a.unb64(body.ephemeral_public_key),
          pair = crypto.generateKeyPairSync("x25519");
        const wrapAAD = p.payloadRewrapAAD(
          this.payload,
          ephemeral,
          a.unb64(body.challenge),
        );
        const secret = a.sharedSecret(
          pair.privateKey
            .export({ format: "der", type: "pkcs8" })
            .subarray(-32),
          ephemeral,
        );
        const kek = a.hkdf(
            secret,
            hex(a.sha(wrapAAD)),
            Buffer.from("authgo/payload/v1/rewrap"),
          ),
          n = crypto.randomBytes(12);
        Object.assign(data, {
          watermark: "19".repeat(32),
          e: a.b64(rawPublic(pair.publicKey)),
          n: a.b64(n),
          c: a.b64(a.seal(kek, n, this.dek, wrapAAD)),
        });
        if (this.mode === "challenge")
          grant.challenge = a.b64(Buffer.alloc(32, 1));
        if (this.mode === "license") grant.license_id = data.license_id = 41;
        if (this.mode === "seed") data.unlock_seed = a.b64(Buffer.alloc(32, 1));
        if (this.mode === "issued") {
          grant.issued_at = iso(this.now + 301);
          grant.grace_until = iso(this.now + 500);
        }
        if (this.mode === "wrap") data.c = a.b64(Buffer.alloc(48, 1));
        if (this.mode === "missing-wrap") delete data.e;
        if (this.mode === "trial") grant.is_trial = true;
        if (this.mode === "zero") grant.grace_until = grant.issued_at;
      }
      Object.assign(grant, this.grantChanges);
      data.ticket = this.signed(grant);
      Object.assign(data, this.changes);
      const env = {
        code: this.responseCode || "OK",
        data,
        ts: Math.floor(this.now),
        nonce,
      };
      env.signature = crypto
        .sign(
          null,
          Buffer.from(a.canonical({ code: env.code, data, ts: env.ts })),
          this.signer,
        )
        .toString("base64");
      if (this.mode === "signature")
        env.signature = Buffer.alloc(64, 1).toString("base64");
      if (this.mode === "nonce") env.nonce = "wrong";
      const n = crypto.randomBytes(12),
        responseAAD = Buffer.concat([
          aad,
          Buffer.from("\0" + a.sha(outer.n + "." + outer.c)),
        ]);
      const c = a.seal(
        a.hkdf(shared, salt, Buffer.from("authgo/v2/response")),
        n,
        a.pad(Buffer.from(a.canonical(env))),
        responseAAD,
      );
      return {
        status: 200,
        body: Buffer.from(a.canonical({ n: a.b64(n), c: a.b64(c) })),
      };
    } finally {
      this.inFlight--;
    }
  }
}
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "authgo-payload-"));
  t.after(() => {
    mock.restoreAll();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const server = new Server(),
    client = server.client(dir);
  return { dir, server, client, payload: server.payload };
}
const cacheFiles = (dir) =>
  fs.readdirSync(dir).filter((name) => name.startsWith("authgo-payload-v2-"));
async function primed(t) {
  const f = fixture(t);
  f.result = await f.client.check(LICENSE);
  assert.deepEqual(await f.client.unlockPayload(f.payload), f.server.dek);
  return f;
}

test("payload: cross-language vectors", checkPayloadVectors);
test("payload: not activated or restored cache cannot implicitly activate", async (t) => {
  const { client, server, payload, dir } = fixture(t);
  await assert.rejects(
    client.unlockPayload(payload),
    code("SDK_NOT_ACTIVATED"),
  );
  assert.equal(server.calls.length, 0);
  await client.check(LICENSE);
  const restored = server.client(dir);
  await assert.rejects(
    restored.unlockPayload(payload),
    code("SDK_NOT_ACTIVATED"),
  );
});
test("payload: authenticated unlock roundtrip only writes encrypted key, no proof", async (t) => {
  const { client, server, payload, dir } = await primed(t);
  assert.equal(cacheFiles(dir).length, 1);
  assert.equal(client.payloadReady, true);
  assert(!fs.readdirSync(dir).some((n) => n.includes("proof")));
  for (const name of cacheFiles(dir))
    assert(!fs.readFileSync(path.join(dir, name)).includes(server.dek));
  assert.equal(server.calls.filter((op) => op === "payload.unlock").length, 1);
  assert.equal(payload.v, 2);
  const offline = new a.Result(client, {}, "", Buffer.alloc(0), "offline");
  await assert.rejects(
    client.loadPayloadKey(payload, offline),
    code("SDK_CACHE_UNAVAILABLE"),
  );
  const before = server.calls.length;
  const config = JSON.parse(a.unb64(payload.config.slice(8)));
  config.app_key = "different-app";
  const wrong = {
    ...payload,
    app_key: config.app_key,
    config: "authgo2." + a.b64(Buffer.from(a.canonical(config))),
  };
  await assert.rejects(client.unlockPayload(wrong), code("PAYLOAD_INVALID"));
  assert.equal(server.calls.length, before);
});
test("payload: offline check uses key cache without another timeout, expired lease allowed", async (t) => {
  const f = fixture(t);
  f.server.floating = true;
  await f.client.check(LICENSE);
  await f.client.unlockPayload(f.payload);
  f.server.now += 25;
  f.server.mode = "network";
  const result = await f.client.check(LICENSE);
  assert.equal(result.status, "grace");
  const calls = f.server.calls.length;
  assert.deepEqual(await f.client.unlockPayload(f.payload), f.server.dek);
  assert.equal(f.server.calls.length, calls);
  const restored = f.server.client(f.dir);
  assert.equal((await restored.check(LICENSE)).status, "grace");
  const afterRestore = f.server.calls.length;
  assert.deepEqual(await restored.unlockPayload(f.payload), f.server.dek);
  assert.equal(f.server.calls.length, afterRestore);
});
test("payload: cache tamper, permissions, symlink and size rejected", async (t) => {
  const { client, payload, result, dir } = await primed(t),
    file = path.join(dir, cacheFiles(dir)[0]),
    raw = fs.readFileSync(file);
  fs.writeFileSync(file, "AUTHGO-PAYLOAD-CACHE-v2." + a.b64(Buffer.alloc(60)));
  assert.throws(
    () => p.loadPayloadKey(client, payload, result),
    code("SDK_CACHE_INVALID"),
  );
  fs.writeFileSync(file, raw);
  fs.chmodSync(file, 0o644);
  assert.throws(
    () => p.loadPayloadKey(client, payload, result),
    code("SDK_CACHE_UNAVAILABLE"),
  );
  fs.chmodSync(file, 0o600);
  fs.writeFileSync(file, Buffer.alloc(257));
  assert.throws(
    () => p.loadPayloadKey(client, payload, result),
    code("SDK_CACHE_UNAVAILABLE"),
  );
  fs.unlinkSync(file);
  const target = path.join(dir, "target");
  fs.writeFileSync(target, raw, { mode: 0o600 });
  fs.symlinkSync(target, file);
  assert.throws(
    () => p.loadPayloadKey(client, payload, result),
    code("SDK_CACHE_UNAVAILABLE"),
  );
  p.savePayloadKey(client, payload, result, Buffer.concat([Buffer.alloc(32), Buffer.alloc(32, 0x19)]));
  assert(fs.lstatSync(file).isSymbolicLink());
  assert.deepEqual(fs.readFileSync(target), raw);
});
test("payload: atomic rename failure preserves old cache and online success", async (t) => {
  const { client, server, payload, result, dir } = await primed(t),
    file = path.join(dir, cacheFiles(dir)[0]),
    raw = fs.readFileSync(file);
  const rename = fs.renameSync;
  mock.method(fs, "renameSync", (from, to) => {
    if (to === file) throw Error("read only");
    return rename(from, to);
  });
  assert.deepEqual(await client.unlockPayload(payload), server.dek);
  assert.deepEqual(fs.readFileSync(file), raw);
  assert.deepEqual(p.loadPayloadKey(client, payload, result), server.material);
  assert(!fs.readdirSync(dir).some((n) => n.endsWith(".tmp")));
});
test("payload: unwritable storage best effort and invalid seed typed", async (t) => {
  const { client, payload, result } = await primed(t);
  mock.method(fs, "openSync", () => {
    throw Error("read only");
  });
  assert.doesNotThrow(() =>
    p.savePayloadKey(client, payload, result, Buffer.alloc(32)),
  );
  client.state.seed = "bad=";
  await assert.rejects(
    client.unlockPayload(payload),
    code("SDK_RESPONSE_INVALID"),
  );
});
test("payload: memory cache and file-as-directory do not block online unlock", async (t) => {
  const { server, payload, dir } = fixture(t);
  for (const cache of ["", path.join(dir, "not-directory")]) {
    if (cache) fs.writeFileSync(cache, "x");
    const client = server.client(cache);
    await client.check(LICENSE);
    assert.deepEqual(await client.unlockPayload(payload), server.dek);
  }
});
test("payload: trial and zero grace never cache, delete old content keys", async (t) => {
  const { client, server, payload, dir } = await primed(t);
  for (const mode of ["trial", "zero"]) {
    client.payloadNoCache = false;
    server.mode = mode;
    assert.deepEqual(await client.unlockPayload(payload), server.dek);
    assert.equal(cacheFiles(dir).length, 0);
    assert.equal(client.payloadNoCache, true);
  }
});
test("payload: ordinary authorization refresh applies no-cache and deactivate clears", async (t) => {
  const { client, server, payload, dir } = await primed(t);
  server.trial = true;
  await client.verify();
  assert.equal(cacheFiles(dir).length, 0);
  assert.equal(client.payloadNoCache, true);
  server.trial = false;
  await client.verify();
  await client.unlockPayload(payload);
  assert.equal(cacheFiles(dir).length, 1);
  await client.deactivate();
  assert.equal(cacheFiles(dir).length, 0);
  assert.equal(client.payloadReady, false);
});
test("payload: cleanup stays in context, ignores proof, license id binds cache", async (t) => {
  const { client, server, payload, dir, result } = await primed(t);
  const other = server.client(dir, "ab".repeat(32));
  await other.check(LICENSE);
  await other.unlockPayload(payload);
  const proof = path.join(dir, "authgo-payload-proof-v1-untouched.cache");
  fs.writeFileSync(proof, "untouched");
  const grant = client.grant(result.ticket());
  grant.license_id = 43;
  assert.throws(
    () =>
      p.loadPayloadKey(
        client,
        payload,
        new a.Result(client, grant, server.signed(grant)),
      ),
    code("SDK_CACHE_INVALID"),
  );
  await client.clearPayloadKeys();
  assert.equal(cacheFiles(dir).length, 1);
  assert.deepEqual(await other.unlockPayload(payload), server.dek);
  assert.equal(fs.readFileSync(proof, "utf8"), "untouched");
});
test("payload: cache expiry, future or not-started grants", async (t) => {
  const { client, server, payload, result } = await primed(t);
  const grant = client.grant(result.ticket());
  grant.grace_until = iso(server.now);
  assert.throws(
    () =>
      p.loadPayloadKey(
        client,
        payload,
        new a.Result(client, grant, server.signed(grant)),
      ),
    code("SDK_GRACE_EXPIRED"),
  );
  grant.issued_at = iso(server.now + 301);
  grant.grace_until = iso(server.now + 500);
  assert.throws(
    () =>
      p.loadPayloadKey(
        client,
        payload,
        new a.Result(client, grant, server.signed(grant)),
      ),
    code("SDK_GRACE_EXPIRED"),
  );
  grant.issued_at = iso(server.now);
  grant.starts_at = iso(server.now + 1);
  assert.throws(
    () =>
      p.loadPayloadKey(
        client,
        payload,
        new a.Result(client, grant, server.signed(grant)),
      ),
    code("LICENSE_NOT_STARTED"),
  );
});
test("payload: grace exact expiry, license expiry and clock rollback", async (t) => {
  const { client, server, payload, result } = await primed(t),
    initial = server.now;
  server.now += 120;
  assert.throws(
    () => p.loadPayloadKey(client, payload, result),
    code("SDK_GRACE_EXPIRED"),
  );
  server.now = initial - 301;
  await assert.rejects(
    client.unlockPayload(payload),
    code("SDK_CLOCK_ROLLBACK"),
  );
  server.now = initial;
  const grant = client.grant(result.ticket());
  grant.expires_at = iso(initial);
  assert.throws(
    () =>
      p.loadPayloadKey(
        client,
        payload,
        new a.Result(client, grant, server.signed(grant)),
      ),
    code("LICENSE_EXPIRED"),
  );
});
test("payload: authenticated refusal clears keys on unlock and normal verify", async (t) => {
  const { client, server, payload, dir } = await primed(t);
  server.responseCode = "LICENSE_REVOKED";
  await assert.rejects(client.unlockPayload(payload), code("LICENSE_REVOKED"));
  assert.equal(cacheFiles(dir).length, 0);
  assert.equal(client.payloadReady, false);
  assert.equal(client.state.refused, true);
  server.responseCode = "";
  await client.check(LICENSE);
  await client.unlockPayload(payload);
  server.responseCode = "UNKNOWN_NEW_REFUSAL";
  await assert.rejects(client.verify(), code("UNKNOWN_NEW_REFUSAL"));
  assert.equal(cacheFiles(dir).length, 0);
});
test("payload: instance replacement clears content but preserves authorization proof", async (t) => {
  const { client, server, payload, dir } = await primed(t),
    ticket = client.state.ticket;
  server.responseCode = "INSTANCE_REPLACED";
  await assert.rejects(
    client.unlockPayload(payload),
    code("INSTANCE_REPLACED"),
  );
  assert.equal(cacheFiles(dir).length, 0);
  assert.equal(client.state.ticket, ticket);
  assert.equal(client.payloadReady, false);
  await assert.rejects(
    client.unlockPayload(payload),
    code("SDK_NOT_ACTIVATED"),
  );
  await assert.rejects(client.verify(), code("INSTANCE_REPLACED"));
});
test("payload: PAYLOAD_INVALID and unauthenticated channel errors preserve cache", async (t) => {
  const { client, server, payload, dir } = await primed(t);
  for (const mode of ["network", "status", "html", "signature", "nonce", ""]) {
    server.mode = mode;
    server.responseCode = mode ? "" : "PAYLOAD_INVALID";
    assert.deepEqual(await client.unlockPayload(payload), server.dek);
    assert.equal(cacheFiles(dir).length, 1);
    assert.equal(client.payloadReady, true);
  }
});
test("payload: wrap schema errors recover, malformed string/null never fallback", async (t) => {
  const { client, server, payload } = await primed(t);
  for (const changes of [{ e: 1 }, { n: [] }, { c: true }]) {
    server.changes = changes;
    assert.deepEqual(await client.unlockPayload(payload), server.dek);
  }
  server.changes = {};
  server.mode = "missing-wrap";
  assert.deepEqual(await client.unlockPayload(payload), server.dek);
  server.mode = "";
  for (const changes of [
    { e: null },
    { n: "=" },
    { c: a.b64(Buffer.alloc(48)) },
  ]) {
    server.changes = changes;
    await assert.rejects(
      client.unlockPayload(payload),
      code("SDK_RESPONSE_INVALID"),
    );
  }
});
test("payload: invalid fresh ticket/context or unwrap never uses cached key", async (t) => {
  const { client, server, payload, dir } = await primed(t);
  for (const mode of ["challenge", "license", "seed", "issued", "wrap"]) {
    server.mode = mode;
    await assert.rejects(
      client.unlockPayload(payload),
      code(
        mode === "issued"
          ? "SDK_RESPONSE_TIMESTAMP_INVALID"
          : "SDK_RESPONSE_INVALID",
      ),
    );
    assert.equal(cacheFiles(dir).length, 1);
    assert.equal(client.state.refused, false);
  }
  server.mode = "";
  server.changes = { ticket: "invalid" };
  await assert.rejects(
    client.unlockPayload(payload),
    code("SDK_RESPONSE_SIGNATURE_INVALID"),
  );
});
test("payload: copied cache cannot open under another instance even renamed", async (t) => {
  const { client, server, payload, result, dir } = await primed(t),
    other = server.client(dir, "cd".repeat(32));
  const otherResult = await other.check(LICENSE),
    material = p.cacheMaterial(other, payload, otherResult);
  fs.copyFileSync(p.cacheMaterial(client, payload, result).file, material.file);
  assert.throws(
    () => p.loadPayloadKey(other, payload, otherResult),
    code("SDK_CACHE_INVALID"),
  );
});
test("payload: strict schemas, duplicate/alias keys, bounds and config binding", (t) => {
  const { payload } = fixture(t),
    base = clone(payload);
  const bad = ["{".repeat(66000), "{}", "null", "[]", '{"v":2,"v":2}'];
  for (const key of Object.keys(base)) {
    const wrong = clone(base);
    delete wrong[key];
    bad.push(a.canonical(wrong));
  }
  for (const [key, value] of [
    ["v", { source: "1" }],
    ["v", true],
    ["v", "1"],
    ["v", null],
    ["key_id", "bad.key"],
    ["key_id", "key\n"],
    ["version", "1.2"],
    ["version", "1.2.3-01"],
    ["built_at", "2026-02-30T00:00:00Z"],
    ["built_at", "2026-11-07T00:00:00+00:00"],
    ["app_key", "a".repeat(257)],
    ["manifest", "__=="],
    ["App_Key", "wrong"],
    ["config", "authgo2.bad"],
  ])
    bad.push(a.canonical({ ...base, [key]: value }));
  for (const raw of bad)
    assert.throws(() => a.parsePayload(raw), code("PAYLOAD_INVALID"));
  const changed = clone(base),
    config = JSON.parse(a.unb64(base.config.slice(8)));
  config.app_secret += "changed";
  changed.config = "authgo2." + a.b64(Buffer.from(a.canonical(config)));
  assert.notDeepEqual(
    a.parsePayload(a.canonical(changed)).payloadBinding(),
    payload.payloadBinding(),
  );
});
test("payload: exact JSON size, integer spelling and optional manifest types", (t) => {
  const { payload } = fixture(t),
    raw = a.canonical(payload);
  assert(a.parsePayload(raw + " ".repeat(65536 - Buffer.byteLength(raw))));
  assert.throws(
    () => a.parsePayload(raw + " ".repeat(65537 - Buffer.byteLength(raw))),
    code("PAYLOAD_INVALID"),
  );
  assert.throws(
    () => a.parsePayload(raw.replace('"v":2', '"v":2.0')),
    code("PAYLOAD_INVALID"),
  );
  const base = clone(payload),
    m = JSON.parse(a.unb64(base.manifest));
  for (const file of [
    { ...m.files[0], size: { source: "0" } },
    { ...m.files[0], size: "0" },
    { ...m.files[0], size: -1 },
    { ...m.files[0], chunk_size: 1 },
    { ...m.files[0], python_version: null },
    { ...m.files[0], name: "__\n" },
  ]) {
    base.manifest = a.b64(Buffer.from(a.canonical({ files: [file] })));
    assert.throws(
      () => a.parsePayload(a.canonical(base)),
      code("PAYLOAD_INVALID"),
    );
  }
});
test("payload: Go URL predicate rejects WHATWG relaxations and accepts Go forms", (t) => {
  const { payload } = fixture(t),
    base = clone(payload),
    config = JSON.parse(a.unb64(base.config.slice(8)));
  for (const url of [
    "http://host",
    "https:host",
    "https:///host",
    "https://host\n",
    " https://host",
    "https://user@host",
    "https://host?x=1",
    "https://host#x",
    "https://host:abc",
    "https://ho%41st",
    "https://ho{st",
    "https://ho|st",
    "https://ho}st",
    "https://host/path%zz",
  ]) {
    for (const field of ["url"]) {
      const c = { ...config, [field]: field === "url" ? url : [url] };
      assert.throws(
        () =>
          a.parsePayload(
            a.canonical({
              ...base,
              config: "authgo2." + a.b64(Buffer.from(a.canonical(c))),
            }),
          ),
        code("PAYLOAD_INVALID"),
      );
    }
  }
  for (const url of [
    "HTTPS://host",
    "https://ho]st",
    "https://[syntactic-host]",
    "https://host:65536",
    "https://host:",
    "https://host/path space",
    "https://host/path?",
    "https://host#",
  ]) {
    assert(
      a.parsePayload(
        a.canonical({
          ...base,
          config:
            "authgo2." + a.b64(Buffer.from(a.canonical({ ...config, url }))),
        }),
      ),
    );
  }
});
test("payload: unwrap rejects changed binding, low order point and challenge", () => {
  const v = vector("payload-unlock-v2.json"),
    payload = a.parsePayload(a.canonical(v.payload));
  assert.throws(
    () =>
      p.unwrapPayload(
        { ...payload, version: "2.0.0" },
        v.response,
        hex(v.client_private_hex),
        hex(v.challenge_hex),
      ),
    code("SDK_RESPONSE_INVALID"),
  );
  assert.throws(
    () =>
      p.unwrapPayload(
        payload,
        { ...v.response, e: a.b64(Buffer.alloc(32)) },
        hex(v.client_private_hex),
        hex(v.challenge_hex),
      ),
    code("SDK_RESPONSE_INVALID"),
  );
  assert.throws(
    () =>
      p.unwrapPayload(
        payload,
        v.response,
        hex(v.client_private_hex),
        Buffer.alloc(32),
      ),
    code("SDK_RESPONSE_INVALID"),
  );
});
test("payload: concurrent unlock, verify and cache replace are serialized", async (t) => {
  const { client, server, payload, dir } = await primed(t);
  const result = await client.verify();
  const results = await Promise.all(
    Array.from({ length: 12 }, (_, i) => {
      if (i % 4 === 0)
        return client.savePayloadKey(payload, result, server.material);
      if (i % 4 === 1) return client.loadPayloadKey(payload, result);
      if (i % 4 === 2) return client.unlockPayload(payload);
      return client.verify();
    }),
  );
  results.forEach((result, i) => {
    if (i % 4 === 1) assert.deepEqual(result, server.material);
    if (i % 4 === 2) assert.deepEqual(result, server.dek);
  });
  assert.equal(server.maxInFlight, 1);
  assert.equal(cacheFiles(dir).length, 1);
  assert(!fs.readdirSync(dir).some((n) => n.endsWith(".tmp")));
  // Clearing queued after an in-flight unlock must run after its atomic save.
  await Promise.all([client.unlockPayload(payload), client.clearPayloadKeys()]);
  assert.equal(cacheFiles(dir).length, 0);
  await client.savePayloadKey(payload, result, server.material);
  assert.deepEqual(await client.loadPayloadKey(payload, result), server.material);
});
test("payload: release-seat authenticated refusal clears content keys", async (t) => {
  const { client, server, payload, dir } = fixture(t);
  server.floating = true;
  await client.check(LICENSE);
  await client.unlockPayload(payload);
  server.responseCode = "LICENSE_REVOKED";
  await assert.rejects(client.releaseSeat(), code("LICENSE_REVOKED"));
  assert.equal(cacheFiles(dir).length, 0);
  assert.equal(client.payloadReady, false);
});
