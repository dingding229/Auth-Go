// Authenticated payload chunks and in-memory CommonJS. No plaintext files.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Module from "node:module";
import vm from "node:vm";
import { constants as bufferConstants, isUtf8 } from "node:buffer";
import { AuthGoError, canonical, parse, unb64 } from "./index.js";
import { coercePayload } from "./payload.js";
import { parseWatermarkIndex, applyWatermark } from "./watermark.js";

export const PAYLOAD_CHUNK_SIZE = 1 << 20;
const states = new WeakMap();
export function clearSealed(guard) {
  const modules = states.get(guard);
  if (modules) {
    for (const entry of modules.values()) entry.executedSource = undefined;
    modules.clear();
  }
  states.delete(guard);
}
const invalid = (message = "加密载荷无效") =>
  new AuthGoError("PAYLOAD_INVALID", message);
const integer = (value) => {
  try {
    if (typeof value === "bigint") return value;
    if (typeof value === "number" && !Number.isSafeInteger(value))
      throw invalid();
    const token = canonical(value);
    if (!/^(0|[1-9][0-9]*)$/.test(token)) throw invalid();
    return BigInt(token);
  } catch {
    throw invalid();
  }
};
export function payloadCipherSize(size) {
  size = integer(size);
  if (size < 0n || size > (2n ** 63n - 1n) / 2n) throw invalid();
  const chunks =
    (size + BigInt(PAYLOAD_CHUNK_SIZE) - 1n) / BigInt(PAYLOAD_CHUNK_SIZE);
  return size + 16n * (chunks || 1n);
}

export function* decryptPayloadFile(payload, key, index, ciphertext) {
  try {
    const p = coercePayload(payload),
      files = parse(unb64(p.manifest)).files;
    if (
      !Number.isInteger(index) ||
      index < 0 ||
      index >= files.length ||
      !(key instanceof Uint8Array) ||
      key.length !== 32 ||
      !(ciphertext instanceof Uint8Array)
    )
      throw invalid();
    const input = Buffer.from(
      ciphertext.buffer,
      ciphertext.byteOffset,
      ciphertext.byteLength,
    );
    const size = integer(files[index].size);
    if (BigInt(input.length) !== payloadCipherSize(size)) throw invalid();
    const binding = p.payloadBinding();
    const count = Math.max(1, Math.ceil(Number(size) / PAYLOAD_CHUNK_SIZE));
    for (let j = 0; j < count; j++) {
      const n = Math.min(
        PAYLOAD_CHUNK_SIZE,
        Number(size) - j * PAYLOAD_CHUNK_SIZE,
      );
      const nonce = Buffer.alloc(12);
      nonce.writeUInt32BE(index);
      nonce.writeBigUInt64BE(BigInt(j), 4);
      const aad = Buffer.concat([
        Buffer.from("authgo-payload-chunk-v1\0"),
        binding,
        nonce,
        Buffer.from([Number(j === count - 1)]),
      ]);
      const offset = j * (PAYLOAD_CHUNK_SIZE + 16);
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
      decipher.setAAD(aad);
      decipher.setAuthTag(input.subarray(offset + n, offset + n + 16));
      const pending = decipher.update(input.subarray(offset, offset + n));
      // GCM update alone is unauthenticated: never yield before final succeeds.
      try {
        const tail = decipher.final();
        yield tail.length ? Buffer.concat([pending, tail]) : pending;
      } catch {
        pending.fill(0);
        throw invalid();
      }
    }
  } catch {
    throw invalid();
  }
}

async function readBounded(filename, limit, exact = false) {
  const flags =
    fs.constants.O_RDONLY |
    (fs.constants.O_NOFOLLOW || 0) |
    (fs.constants.O_NONBLOCK || 0);
  const handle = await fs.promises.open(filename, flags);
  try {
    const info = await handle.stat({ bigint: true });
    if (
      !info.isFile() ||
      info.size > limit ||
      (exact && info.size !== limit) ||
      info.size > BigInt(bufferConstants.MAX_LENGTH)
    )
      throw invalid();
    const output = Buffer.alloc(Number(info.size));
    let offset = 0;
    while (offset < output.length) {
      const { bytesRead } = await handle.read(
        output,
        offset,
        output.length - offset,
        offset,
      );
      if (!bytesRead) throw invalid();
      offset += bytesRead;
    }
    if ((await handle.read(Buffer.alloc(1), 0, 1, offset)).bytesRead)
      throw invalid();
    return output;
  } finally {
    await handle.close();
  }
}

function sourceCheck(source) {
  // Like pack's conservative lexical check, this intentionally also rejects
  // keyword occurrences in comments/strings. It is not a JavaScript sandbox.
  if (/\b(?:import|export)\b/.test(source))
    throw invalid(
      "加密包只支持 CommonJS，不支持 ESM（import/export），请先打包为单文件 CommonJS",
    );
  if (/\.node\b/i.test(source) || /\bdlopen\b/.test(source))
    throw invalid("加密包不支持原生插件（.node），请使用纯 JavaScript 核心包");
}

async function evaluate(
  guard,
  client,
  payload,
  file,
  index,
  directory,
  filename,
  retainExecutedSource,
) {
  let ciphertext;
  try {
    ciphertext = await readBounded(
      path.join(directory, file.path),
      payloadCipherSize(file.size),
      true,
    );
  } catch {
    throw invalid();
  }
  guard.require();
  const material = await client._unlockPayloadMaterial(payload);
  let plain;
  try {
    if (!Buffer.isBuffer(material) || material.length !== 64)
      throw invalid();
    const key = material.subarray(0, 32);
    let privateIndex;
    if (payload.v === 2) {
      const files = parse(unb64(payload.manifest)).files;
      const metaIndex = files.findIndex((f) => f.kind === "watermark");
      const meta = files[metaIndex];
      const encrypted = await readBounded(
        path.join(directory, meta.path), payloadCipherSize(meta.size), true,
      );
      const raw = Buffer.alloc(Number(integer(meta.size)));
      try {
        let position = 0;
        for (const block of decryptPayloadFile(payload, key, metaIndex, encrypted)) {
          block.copy(raw, position);
          position += block.length;
          block.fill(0);
        }
        // All metadata chunks authenticate before parsing any private offsets.
        privateIndex = parseWatermarkIndex(raw, files);
      } finally { raw.fill(0); }
    }
    guard.require();
    const size = Number(integer(file.size));
    plain = Buffer.alloc(size);
    let offset = 0;
    for (const block of decryptPayloadFile(payload, key, index, ciphertext)) {
      block.copy(plain, offset);
      offset += block.length;
      block.fill(0);
    }
    if (payload.v === 2)
      applyWatermark(new Map([["[]", plain]]), privateIndex, index, material.subarray(32));
  } catch (error) {
    plain?.fill(0);
    throw error instanceof AuthGoError ? error : invalid();
  } finally {
    if (material instanceof Uint8Array) material.fill(0);
  }
  let source;
  try {
    if (!isUtf8(plain)) throw invalid("加密包不是有效的 UTF-8 CommonJS 代码");
    // Match CommonJS file loading: BOM and a leading executable hashbang
    // are not part of the wrapped function body.
    source = plain
      .toString("utf8")
      .replace(/^\uFEFF/, "")
      .replace(/^#![^\r\n]*/, "");
    sourceCheck(source);
  } finally {
    plain.fill(0);
  }
  const instance = new Module(filename);
  instance.filename = filename;
  instance.paths = Module._nodeModulePaths(directory);
  const originalRequire = instance.require.bind(instance);
  instance.require = function (request) {
    guard.require();
    const resolved = Module._resolveFilename(request, instance);
    if (/\.(?:node|mjs)$/i.test(resolved))
      throw invalid("加密包不支持 ESM 文件或原生插件（.node）");
    return originalRequire(request);
  };
  // Node 22 accepts _compile(source, filename); a .cjs virtual filename keeps
  // the module CommonJS even when the host application's package is ESM.
  guard.require();
  // Force CommonJS grammar before _compile: do not let Node syntax detection
  // reinterpret top-level await or other ESM-only syntax. This does not run it.
  new vm.Script(Module.wrap(source), { filename });
  instance._compile(source, filename);
  instance.loaded = true;
  guard.require();
  // Retain only the SAME source passed to successful _compile above, never an
  // unexecuted metadata/resource copy. V8 may collect no-op literal bytecode.
  // Private Guard state keeps it alive without changing public module objects.
  // JavaScript strings cannot be wiped; clearSealed releases our reference,
  // not compiled code or references already held by the host application.
  retainExecutedSource(source);
  return instance.exports;
}

export async function requireSealed(guard, client, name) {
  guard.require();
  if (
    typeof name !== "string" ||
    !/^[a-z0-9_-]+$/.test(name) ||
    name.length > 128
  )
    throw invalid();
  const directory = path.resolve(
    process.env.AUTHGO_PAYLOAD_DIR || "/opt/authgo",
  );
  let payload, file, index;
  try {
    payload = coercePayload(
      await readBounded(path.join(directory, "payload.json"), 65536n),
    );
    const files = parse(unb64(payload.manifest)).files;
    index = files.findIndex((f) => f.name === name);
    file = files[index];
    if (!file || file.kind !== "node") throw invalid();
  } catch {
    throw invalid();
  }
  const identity =
    directory + "\0" + payload.payloadBinding().toString("hex") + ":" + index;
  const filename = path.join(directory, ".authgo-sealed-" + name + ".cjs");
  if (fs.existsSync(filename) || Module._cache[filename])
    throw invalid("内存模块路径与现有文件冲突，请移除同名明文文件");
  let modules = states.get(guard);
  if (!modules) {
    modules = new Map();
    states.set(guard, modules);
  }
  const existing = modules.get(name);
  if (existing) {
    if (existing.identity !== identity)
      throw invalid("此名称已绑定其他加密包，请重启程序后加载新版本");
    const result = await existing.promise;
    guard.require();
    return result;
  }
  guard.require();
  const entry = { identity };
  // Reserve before the first async read/unlock, so concurrent callers share
  // one evaluation and cannot replace the entry with a conflicting payload.
  entry.promise = evaluate(
    guard,
    client,
    payload,
    file,
    index,
    directory,
    filename,
    (source) => {
      if (states.get(guard) !== modules || modules.get(name) !== entry)
        throw invalid("Guard 状态已清理，拒绝保留已失效模块");
      entry.executedSource = source;
    },
  );
  modules.set(name, entry);
  try {
    const result = await entry.promise;
    guard.require();
    return result;
  } catch (error) {
    entry.executedSource = undefined;
    if (modules.get(name) === entry) modules.delete(name);
    throw error;
  }
}
