// Payload v2 and authenticated material cache. No launcher proof files.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  AuthGoError,
  Result,
  b64,
  unb64,
  sha,
  hkdf,
  parse,
  canonical,
  sharedSecret,
  open,
  seal,
} from "./index.js";

const invalid = () => new AuthGoError("PAYLOAD_INVALID", "加密载荷无效");
const failure = (code, message = "") => new AuthGoError(code, message);
const digest = (value) => Buffer.from(sha(value), "hex");
const stamp = (value) => (value == null ? Infinity : Date.parse(value) / 1000);
const fields = [
  "v",
  "app_key",
  "version",
  "built_at",
  "key_id",
  "config",
  "manifest",
  "envelope",
];
const namePattern = /^[a-z0-9_-]+$(?![\s\S])/;
const versionPattern =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/;
function object(value, required, optional = []) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    required.some((k) => !Object.hasOwn(value, k)) ||
    Object.keys(value).some(
      (k) => !required.includes(k) && !optional.includes(k),
    )
  )
    throw Error("schema");
}
function text(value) {
  if (typeof value !== "string" || !value.isWellFormed()) throw Error("string");
  return value;
}
function integer(value) {
  // parse preserves the original numeric token, including unsafe integers.
  const token = canonical(value);
  if (typeof token !== "string" || !/^-?(0|[1-9][0-9]*)$/.test(token))
    throw Error("integer");
  return BigInt(token);
}
function lp(value) {
  const raw = Buffer.from(value),
    length = Buffer.alloc(4);
  length.writeUInt32BE(raw.length);
  return Buffer.concat([length, raw]);
}
export function payloadHTTPS(value) {
  // Go net/url.Parse HTTPS predicate: deliberately not WHATWG URL normalization.
  text(value);
  if (/[\x00-\x1f\x7f]/.test(value)) throw Error("https");
  const match =
    /^(?:https):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/i.exec(value);
  if (!match) throw Error("https");
  const [, authority, pathname, query, fragment] = match;
  if (!authority || authority.includes("@") || query || fragment)
    throw Error("https");
  if (authority.includes("[") && !authority.startsWith("["))
    throw Error("host");
  let host = authority;
  if (host.startsWith("[")) {
    const end = host.lastIndexOf("]");
    if (end < 0 || !host.slice(1, end)) throw Error("host");
    const suffix = host.slice(end + 1);
    if (suffix && !/^:[0-9]*$/.test(suffix)) throw Error("port");
  } else if (host.includes(":")) {
    const end = host.lastIndexOf(":");
    if (!host.slice(0, end) || !/^[0-9]*$/.test(host.slice(end + 1)))
      throw Error("port");
  }
  if (/[^a-zA-Z0-9_.~!$&'()*+,;=:\[\]<>"%\u0080-\u{10ffff}-]/u.test(authority))
    throw Error("host");
  if (/%(?![0-9a-fA-F]{2})/.test(authority + pathname)) throw Error("escape");
  for (const escaped of authority.matchAll(/%([0-9a-fA-F]{2})/g)) {
    const code = parseInt(escaped[1], 16);
    if (code < 128 && code !== 37) throw Error("host escape");
  }
}
function config(value, appKey) {
  if (Buffer.byteLength(value) > 32768 || !value.startsWith("authgo2."))
    throw Error("config");
  const c = parse(unb64(value.slice(8)));
  object(
    c,
    ["url", "app_key", "app_secret", "public_key", "gateway_key"],
    [],
  );
  for (const field of [
    "url",
    "app_key",
    "app_secret",
    "public_key",
    "gateway_key",
  ])
    text(c[field]);
  if (c.app_key !== appKey || !c.app_secret) throw Error("config");
  payloadHTTPS(c.url);
  const publicKey = Buffer.from(c.public_key, "base64");
  if (
    publicKey.length !== 32 ||
    publicKey.toString("base64") !== c.public_key ||
    unb64(c.gateway_key).length !== 32
  )
    throw Error("keys");
}
function manifest(value, version = 2) {
  const raw = unb64(value);
  if (raw.length > 8 << 20) throw Error("manifest size");
  const m = parse(raw);
  object(m, ["files"]);
  if (!Array.isArray(m.files) || m.files.length < 1 || m.files.length > 65535)
    throw Error("files");
  const names = new Set();
  let metadata = 0;
  m.files.forEach((file, index) => {
    object(
      file,
      ["name", "kind", "path", "size", "chunk_size", "encoding"],
      ["python_version", "main_class", "architecture"],
    );
    for (const key of Object.keys(file))
      if (!["size", "chunk_size"].includes(key)) text(file[key]);
    if (
      !namePattern.test(file.name) ||
      Buffer.byteLength(file.name) > 128 ||
      names.has(file.name)
    )
      throw Error("name");
    names.add(file.name);
    if (
      file.path !== String(index).padStart(8, "0") + ".agc" ||
      integer(file.size) < 0n ||
      integer(file.size) > (2n ** 63n - 1n) / 2n ||
      integer(file.chunk_size) !== 1048576n
    )
      throw Error("file bounds");
    if (version === 2 && file.name === "__authgo_watermark" && file.kind !== "watermark")
      throw Error("reserved name");
    if (file.kind === "watermark") {
      if (version !== 2 || file.name !== "__authgo_watermark" ||
          Object.keys(file).length !== 6 || file.encoding !== "raw" ||
          integer(file.size) < 1n || integer(file.size) > 8388608n)
        throw Error("watermark metadata");
      metadata++;
      return;
    }
    const encoding = {
      python: "tar",
      php: "tar",
      dotnet: "tar",
      node: "raw",
      java: "raw",
      protect: "raw",
    }[file.kind];
    if (
      !encoding ||
      file.encoding !== encoding ||
      (file.kind === "python" && !file.python_version) ||
      (file.kind === "protect" &&
        !["amd64", "arm64"].includes(file.architecture))
    )
      throw Error("file metadata");
  });
  if (version !== 2 || (version === 2 && (metadata !== 1 || m.files.length < 2)))
    throw Error("watermark count");
  return raw;
}
export class Payload {
  constructor(value) {
    Object.assign(this, value);
  }
  payloadBinding() {
    return payloadBinding(this);
  }
}
export function payloadAAD(p) {
  if (p.v !== 2) throw Error("version");
  for (const field of fields.filter((k) => !["v", "envelope"].includes(k)))
    text(p[field]);
  if (
    !p.app_key ||
    Buffer.byteLength(p.app_key) > 256 ||
    Buffer.byteLength(p.key_id) > 128 ||
    !namePattern.test(p.key_id) ||
    Buffer.byteLength(p.version) > 256 ||
    versionPattern.exec(p.version)?.[0] !== p.version
  )
    throw Error("metadata");
  const pre = p.version.split("+")[0].split("-").slice(1).join("-");
  if (pre.split(".").some((v) => /^0[0-9]+$/.test(v))) throw Error("semver");
  if (
    !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(
      p.built_at,
    ) ||
    !Number.isFinite(Date.parse(p.built_at)) ||
    new Date(p.built_at).toISOString() !== p.built_at.slice(0, -1) + ".000Z"
  )
    throw Error("built_at");
  config(p.config, p.app_key);
  return Buffer.concat([
    Buffer.from(`authgo-payload-envelope-v${p.v}\0`),
    ...[p.app_key, p.version, p.built_at, p.key_id, p.config].map(lp),
    digest(manifest(p.manifest, p.v)),
  ]);
}
export function payloadBinding(p) {
  try {
    const aad = payloadAAD(p);
    object(p.envelope, ["e", "n", "c"]);
    const parts = ["e", "n", "c"].map((k) => unb64(p.envelope[k]));
    if (parts.some((v, i) => v.length !== [32, 12, 48][i]))
      throw Error("envelope lengths");
    return digest(Buffer.concat([aad, ...parts]));
  } catch {
    throw invalid();
  }
}
export function parsePayload(raw) {
  try {
    if (typeof raw === "string") {
      text(raw);
      raw = Buffer.from(raw);
    }
    if (!Buffer.isBuffer(raw) || raw.length > 65536)
      throw Error("payload size");
    const obj = parse(raw);
    object(obj, fields);
    const version = integer(obj.v);
    if (version !== 2n) throw Error("version");
    const p = new Payload({ ...obj, v: Number(version) });
    payloadBinding(p);
    return p;
  } catch {
    throw invalid();
  }
}
export function coercePayload(value) {
  try {
    return parsePayload(
      typeof value === "object" && !Buffer.isBuffer(value)
        ? canonical(value)
        : value,
    );
  } catch {
    throw invalid();
  }
}
export function payloadRewrapAAD(p, ephemeral, challenge) {
  if (p.v !== 2 || ephemeral.length !== 32 || challenge.length !== 32) throw invalid();
  return Buffer.concat([
    Buffer.from(`authgo-payload-rewrap-v${p.v}\0`),
    ...[p.app_key, p.version, p.built_at, p.key_id].map(lp),
    digest(unb64(p.manifest)),
    ephemeral,
    challenge,
  ]);
}
export function unwrapPayload(p, wrapped, privateKey, challenge) {
  let shared, kek;
  try {
    const [e, n, c] = ["e", "n", "c"].map((k) => unb64(wrapped[k]));
    if (e.length !== 32 || n.length !== 12 || c.length !== 48)
      throw Error("rewrap lengths");
    shared = sharedSecret(privateKey, e);
    const privateObject = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from("302e020100300506032b656e04220420", "hex"),
        privateKey,
      ]),
      format: "der",
      type: "pkcs8",
    });
    const ephemeral = crypto
      .createPublicKey(privateObject)
      .export({ format: "der", type: "spki" })
      .subarray(-32);
    const aad = payloadRewrapAAD(p, ephemeral, challenge);
    kek = hkdf(shared, digest(aad), Buffer.from("authgo/payload/v1/rewrap"));
    const key = open(kek, n, c, aad);
    if (key.length !== 32) throw Error("key length");
    return key;
  } catch {
    throw failure("SDK_RESPONSE_INVALID", "内容密钥响应认证失败");
  } finally {
    shared?.fill(0);
    kek?.fill(0);
  }
}
export function payloadCacheLabel(p, fingerprint) {
  return Buffer.concat([
    Buffer.from(`authgo-payload-cache-v${p.v}\0`),
    ...[p.app_key, fingerprint, p.key_id, p.version].map(lp),
    digest(unb64(p.manifest)),
    payloadBinding(p),
  ]);
}
export function cacheIdentity(client) {
  // Preserve endpoint path/query spelling; Go normalizes only the host's case.
  const endpoint = client.endpoint.replace(
    /^(https?:\/\/)([^/\?#]*)/i,
    (_, scheme, host) => scheme.toLowerCase() + host.toLowerCase(),
  );
  return [endpoint, client.config.app_key, client.fp, sha(client.public)].join(
    "\0",
  );
}
function cacheBase(client, version = 2) {
  return `authgo-payload-v${version}-` + sha(Buffer.from(cacheIdentity(client))) + "-";
}
function materialSize(p) {
  if (p.v !== 2) throw invalid();
  return 64;
}
function validMaterial(p, material) {
  return material.length === materialSize(p) &&
    material.subarray(32).some((byte) => byte !== 0);
}
function cachePrefix(p) { return `AUTHGO-PAYLOAD-CACHE-v${p.v}.`; }
function period(client, grant) {
  const now = client.now();
  if (
    grant.is_trial ||
    stamp(grant.grace_until) <= stamp(grant.issued_at) ||
    now >= stamp(grant.grace_until) ||
    stamp(grant.issued_at) > now + 300
  )
    throw failure("SDK_GRACE_EXPIRED", "内容密钥宽限期已结束");
  if (grant.starts_at && now < stamp(grant.starts_at))
    throw failure("LICENSE_NOT_STARTED");
  if (now >= stamp(grant.expires_at)) throw failure("LICENSE_EXPIRED");
}
export function cacheMaterial(client, p, result) {
  if (
    client.payloadNoCache ||
    !result ||
    result.isTrial ||
    client.memoryCache ||
    result.status === "offline"
  )
    throw failure("SDK_CACHE_UNAVAILABLE", "此授权不允许内容密钥缓存");
  const grant = client.grant(result.ticket());
  period(client, grant);
  if (
    typeof grant.unlock_hash !== "string" ||
    !/^[0-9a-fA-F]{64}$/.test(grant.unlock_hash)
  )
    throw failure("SDK_CACHE_INVALID");
  const label = payloadCacheLabel(p, client.fp),
    hash = digest(label),
    id = integer(grant.license_id),
    license = Buffer.alloc(8);
  if (id <= 0n || id >= 2n ** 64n) throw failure("SDK_CACHE_INVALID");
  license.writeBigUInt64BE(id);
  return {
    file: path.join(
      client.cache,
      cacheBase(client, p.v) + hash.toString("hex") + ".cache",
    ),
    key: hkdf(
      Buffer.from(grant.unlock_hash, "hex"),
      Buffer.alloc(0),
      Buffer.concat([Buffer.from("authgo-unlock-v2\0"), label]),
    ),
    aad: Buffer.concat([
      Buffer.from(`authgo-payload-cache-file-v${p.v}\0`),
      hash,
      license,
    ]),
  };
}
export function savePayloadKey(client, p, result, key) {
  if (!validMaterial(p, key)) return;
  let temp, material;
  try {
    material = cacheMaterial(client, p, result);
    const n = crypto.randomBytes(12),
      raw =
        cachePrefix(p) +
        b64(Buffer.concat([n, seal(material.key, n, key, material.aad)]));
    fs.mkdirSync(client.cache, { mode: 0o700, recursive: true });
    try {
      if (!fs.lstatSync(material.file).isFile()) return;
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
    temp = path.join(
      client.cache,
      ".authgo-payload-" + b64(crypto.randomBytes(12)) + ".tmp",
    );
    const fd = fs.openSync(temp, "wx", 0o600);
    try {
      fs.fchmodSync(fd, 0o600);
      fs.writeFileSync(fd, raw);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temp, material.file);
  } catch {
    /* Best effort: unwritable storage never revokes online success. */
  } finally {
    material?.key.fill(0);
    if (temp) {
      try {
        fs.unlinkSync(temp);
      } catch {
        /* already renamed */
      }
    }
  }
}
export function loadPayloadKey(client, p, result) {
  const material = cacheMaterial(client, p, result);
  const prefix = cachePrefix(p);
  try {
    let raw;
    try {
      const before = fs.lstatSync(material.file);
      if (
        !before.isFile() ||
        (before.mode & 0o7777) !== 0o600 ||
        before.size > 256
      )
        throw Error("cache");
      const fd = fs.openSync(
        material.file,
        fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
      );
      try {
        const after = fs.fstatSync(fd);
        if (before.dev !== after.dev || before.ino !== after.ino)
          throw failure("SDK_CACHE_INVALID", "内容密钥缓存已变化");
        const buffer = Buffer.alloc(257),
          size = fs.readSync(fd, buffer, 0, 257, 0);
        raw = buffer.subarray(0, size);
      } finally {
        fs.closeSync(fd);
      }
    } catch (error) {
      if (error instanceof AuthGoError) throw error;
      throw failure("SDK_CACHE_UNAVAILABLE", "没有可用的内容密钥缓存");
    }
    try {
      if (
        raw.length > 256 ||
        !raw.subarray(0, prefix.length).equals(Buffer.from(prefix))
      )
        throw Error("cache format");
      const encrypted = unb64(raw.subarray(prefix.length).toString("utf8"));
      if (encrypted.length !== 12 + materialSize(p) + 16) throw Error("cache size");
      const key = open(
        material.key,
        encrypted.subarray(0, 12),
        encrypted.subarray(12),
        material.aad,
      );
      if (!validMaterial(p, key)) {
        key.fill(0);
        throw Error("key");
      }
      return key;
    } catch {
      throw failure("SDK_CACHE_INVALID", "内容密钥缓存认证失败");
    }
  } finally {
    material.key.fill(0);
  }
}
export function clearPayloadKeys(client) {
  if (client.memoryCache || !client.fp || !client.endpoint) return;
  try {
    const base = cacheBase(client);
    for (const name of fs.readdirSync(client.cache))
      if (name.startsWith(base) && name.endsWith(".cache")) {
        try {
          fs.unlinkSync(path.join(client.cache, name));
        } catch {
          /* best effort */
        }
      }
  } catch {
    /* No persistent cache. */
  }
}
export function recordPayloadResult(client, result) {
  if (!result) return;
  client.payloadReady = true;
  const grant = client.grant(result.ticket());
  client.payloadNoCache =
    !!grant.is_trial || stamp(grant.grace_until) <= stamp(grant.issued_at);
  if (client.payloadNoCache) clearPayloadKeys(client);
}
function cachedResult(client) {
  const ticket = client.state.ticket,
    grant = client.grant(ticket);
  let seed;
  try {
    seed = unb64(client.state.seed || "");
  } catch {
    throw failure("SDK_RESPONSE_INVALID");
  }
  if (seed.length !== 32 || sha(seed) !== grant.unlock_hash)
    throw failure("SDK_RESPONSE_SIGNATURE_INVALID");
  if (grant.starts_at && client.now() < stamp(grant.starts_at))
    throw failure("LICENSE_NOT_STARTED");
  if (client.now() >= stamp(grant.expires_at)) throw failure("LICENSE_EXPIRED");
  return new Result(client, grant, ticket, seed);
}
function freshResult(client, data, challenge, previous) {
  try {
    const required = [
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
    ];
    if (!data || required.some((k) => !Object.hasOwn(data, k)))
      throw Error("fields");
    const grant = client.grant(data.ticket),
      id = integer(data.license_id),
      methods = data.satisfied_methods;
    if (
      id !== integer(grant.license_id) ||
      id <= 0n ||
      id >= 2n ** 63n ||
      data.status !== "active" ||
      !data.features ||
      typeof data.features !== "object" ||
      Array.isArray(data.features) ||
      integer(data.next_check_in) !== integer(grant.next_check_in) ||
      integer(data.heartbeat_interval) < 1n ||
      integer(data.heartbeat_interval) > 3600n ||
      !Array.isArray(methods) ||
      methods.some(
        (m) =>
          typeof m !== "string" ||
          !["KEY", "FLOATING"].includes(m),
      ) ||
      new Set(methods).size !== methods.length ||
      !methods.includes("KEY") ||
      (methods.includes("FLOATING") && !data.lease_expires_at) ||
      !data.grace_until ||
      !Number.isFinite(stamp(data.grace_until))
    )
      throw Error("grant");
    client.validGrantTime({ ...data, floating: methods.includes("FLOATING") });
    if (Math.abs(stamp(grant.issued_at) - client.now()) > 300)
      throw failure("SDK_RESPONSE_TIMESTAMP_INVALID");
    const seed = unb64(data.unlock_seed);
    if (
      seed.length !== 32 ||
      sha(seed) !== grant.unlock_hash ||
      grant.challenge !== challenge ||
      id !== integer(previous.data.license_id)
    )
      throw Error("context");
    return new Result(client, grant, data.ticket, seed);
  } catch (error) {
    if (error instanceof AuthGoError) throw error;
    throw failure("SDK_RESPONSE_INVALID", "解锁票据上下文不符");
  }
}
function unlockFailure(client, p, result, error) {
  if (error.refusal) {
    client.payloadReady = false;
    clearPayloadKeys(client);
    if (error.code === "INSTANCE_REPLACED") client.rememberPayloadReplacement();
    else client.revokeCache();
    throw error;
  }
  try {
    return loadPayloadKey(client, p, result);
  } catch {
    throw error;
  }
}
// Called only inside Client.exclusive, shared with authorization and releaseSeat.
export async function unlockPayload(client, payload) {
  const material = await unlockPayloadMaterial(client, payload);
  try { return Buffer.from(material.subarray(0, 32)); }
  finally { material.fill(0); }
}
// Loader-only material; called under Client.exclusive just like public unlock.
export async function unlockPayloadMaterial(client, payload) {
  let replaced = false;
  let watermark;
  try {
    client.ensureInstance();
  } catch {
    replaced = true;
  }
  if (
    !client.payloadReady ||
    client.state.refused ||
    !client.state.ticket ||
    replaced
  )
    throw failure("SDK_NOT_ACTIVATED", "请先完成授权校验");
  const p = coercePayload(payload);
  if (p.app_key !== client.config.app_key) throw invalid();
  const result = cachedResult(client);
  if (client.now() + 300 < Number(client.state.observed || 0))
    throw failure("SDK_CLOCK_ROLLBACK");
  if (client.offlineTicket === result.ticket() && !client.onlineUntil)
    return loadPayloadKey(client, p, result);
  const pair = crypto.generateKeyPairSync("x25519"),
    privateKey = pair.privateKey
      .export({ format: "der", type: "pkcs8" })
      .subarray(-32);
  try {
    const ephemeral = pair.publicKey
        .export({ format: "der", type: "spki" })
        .subarray(-32),
      base = client.body();
    const body = Object.fromEntries(
      [
        "license_key",
        "activation_token",
        "device_fingerprint",
        "instance_session",
      ].map((k) => [k, base[k]]),
    );
    Object.assign(body, { payload: p, ephemeral_public_key: b64(ephemeral) });
    let data, challenge;
    try {
      [data, challenge] = await client.request("payload.unlock", body);
    } catch (error) {
      return unlockFailure(
        client,
        p,
        result,
        error instanceof AuthGoError ? error : failure("SDK_RESPONSE_INVALID"),
      );
    }
    // Malformed fresh grants and failed unwraps never fall back to cached keys.
    const fresh = freshResult(client, data, challenge, result),
      grant = fresh.data;
    if (grant.is_trial || stamp(grant.grace_until) <= stamp(grant.issued_at)) {
      client.payloadNoCache = true;
      clearPayloadKeys(client);
    }
    if (p.v === 2) {
      if (typeof data.watermark !== "string" || !/^[0-9a-f]{64}$(?![\s\S])/.test(data.watermark))
        throw failure("SDK_RESPONSE_INVALID", "内容水印响应无效");
      watermark = Buffer.from(data.watermark, "hex");
      if (!watermark.some((byte) => byte !== 0))
        throw failure("SDK_RESPONSE_INVALID", "内容水印响应无效");
    }
    const wrapped = {};
    for (const field of ["e", "n", "c"]) {
      if (
        !Object.hasOwn(data, field) ||
        (data[field] !== null && typeof data[field] !== "string")
      )
        return unlockFailure(
          client,
          p,
          result,
          failure("SDK_RESPONSE_INVALID", "内容密钥响应无效"),
        );
      wrapped[field] = data[field] ?? "";
    }
    let key = unwrapPayload(p, wrapped, privateKey, unb64(challenge));
    if (p.v === 2) {
      const material = Buffer.concat([key, watermark]);
      key.fill(0);
      key = material;
    }
    savePayloadKey(client, p, fresh, key);
    return key;
  } finally {
    privateKey.fill(0);
    watermark?.fill(0);
  }
}
