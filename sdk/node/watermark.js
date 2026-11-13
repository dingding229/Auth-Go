// Private v2 schema parser. Bounds are enforced before allocating array items.
import { AuthGoError, canonical } from "./index.js";
const invalid = () => new AuthGoError("PAYLOAD_INVALID", "加密载荷无效");
const LIMIT = 65535;
const MAX = (2n ** 63n - 1n) / 2n;
const exact = (pattern, text) => typeof text === "string" && pattern.exec(text)?.[0] === text;
function decimal(value, limit = MAX) {
  if (!exact(/^(?:0|[1-9][0-9]{0,18})/, value)) throw invalid();
  const n = BigInt(value);
  if (n > limit) throw invalid();
  return n;
}
function safeEntry(value) {
  if (typeof value !== "string" || !value.isWellFormed() || !value ||
      /[\\\x00-\x1f\x7f:]/.test(value) ||
      value.split("/").some((part) => ["", ".", ".."].includes(part))) throw invalid();
}
function readIndex(raw) {
  if (!(raw instanceof Uint8Array) || raw.length < 1 || raw.length > 8 << 20) throw invalid();
  const bytes = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  const source = bytes.toString("utf8");
  if (!Buffer.from(source).equals(bytes)) throw invalid();
  let at = 0;
  const counts = { files: 0, entries: 0, offsets: 0 };
  const ws = () => { while (at < source.length && /[ \r\n\t]/.test(source[at])) at++; };
  function take(char) {
    ws();
    if (source[at++] !== char) throw invalid();
  }
  function text() {
    ws();
    if (source[at] !== '"') throw invalid();
    const begin = at++;
    while (at < source.length) {
      const char = source[at++];
      if (char === "\\") { at++; continue; }
      if (char === '"') {
        const value = JSON.parse(source.slice(begin, at));
        if (!value.isWellFormed()) throw invalid();
        return value;
      }
    }
    throw invalid();
  }
  function array(name, read) {
    take("[");
    const out = [];
    ws();
    if (source[at] === "]") { take("]"); return out; }
    for (;;) {
      if (name === "path") { if (out.length >= 8) throw invalid(); }
      else { if (counts[name] >= LIMIT) throw invalid(); counts[name]++; }
      out.push(read());
      ws();
      if (source[at] === "]") { take("]"); return out; }
      take(",");
    }
  }
  function object(schema) {
    take("{");
    const out = Object.create(null);
    for (;;) {
      const key = text();
      if (!Object.hasOwn(schema, key) || Object.hasOwn(out, key)) throw invalid();
      take(":");
      out[key] = schema[key]();
      ws();
      if (source[at] === "}") {
        take("}");
        if (Object.keys(out).length !== Object.keys(schema).length) throw invalid();
        return out;
      }
      take(",");
    }
  }
  const entry = () => object({ path: () => array("path", text), offsets: () => array("offsets", text) });
  const file = () => object({ index: text, entries: () => array("entries", entry) });
  const out = object({ v: text, tag: text, files: () => array("files", file) });
  ws();
  if (at !== source.length) throw invalid();
  return out;
}
export function parseWatermarkIndex(raw, files) {
  try {
    const out = readIndex(raw);
    if (out.v !== "1" || !exact(/^[0-9a-f]{32}/, out.tag) || !out.files.length ||
        !Array.isArray(files) || !files.length || files.length > LIMIT) throw invalid();
    const seen = new Set();
    for (const file of out.files) {
      const i = Number(decimal(file.index, BigInt(LIMIT - 1)));
      if (i >= files.length || seen.has(i) || files[i].kind === "watermark" || !file.entries.length) throw invalid();
      seen.add(i);
      const publicFile = files[i], paths = new Set();
      let count = 0;
      for (const entry of file.entries) {
        entry.path.forEach(safeEntry);
        const kind = publicFile.kind;
        if ((["node", "protect"].includes(kind) && entry.path.length !== 0) ||
            (["python", "php", "dotnet"].includes(kind) && entry.path.length !== 1) ||
            (kind === "java" && !entry.path.length) ||
            !["node", "protect", "python", "php", "dotnet", "java"].includes(kind) ||
            (kind === "dotnet" && (entry.path[0].includes("/") || !entry.path[0].toLowerCase().endsWith(".dll")))) throw invalid();
        const identity = JSON.stringify(entry.path.map((p) => p.toLowerCase()));
        if (paths.has(identity) || !entry.offsets.length) throw invalid();
        paths.add(identity);
        let last = -96n;
        for (const value of entry.offsets) {
          const n = decimal(value);
          if (n < last + 96n || (!entry.path.length && n + 96n > BigInt(canonical(publicFile.size)))) throw invalid();
          last = n;
        }
        count += entry.offsets.length;
      }
      if (count < 8) throw invalid();
    }
    files.forEach((file, i) => { if (file.kind !== "watermark" && !seen.has(i)) throw invalid(); });
    return out;
  } catch { throw invalid(); }
}
export function applyWatermark(targets, index, fileIndex, watermark) {
  // targets is keyed by JSON.stringify(path); all validation precedes mutation.
  try {
    if (!(watermark instanceof Uint8Array) || watermark.length !== 32 ||
        !watermark.some((byte) => byte !== 0) || !exact(/^[0-9a-f]{32}/, index.tag)) throw invalid();
    const selected = index.files.find((f) => Number(decimal(f.index, BigInt(LIMIT - 1))) === fileIndex);
    if (!selected) throw invalid();
    const expected = Buffer.from(index.tag + "0".repeat(64)), pending = [];
    for (const entry of selected.entries) {
      const target = targets.get(JSON.stringify(entry.path));
      if (!Buffer.isBuffer(target)) throw invalid();
      let last = -96n;
      for (const value of entry.offsets) {
        const n = decimal(value);
        if (n < last + 96n || n + 96n > BigInt(target.length) ||
            !target.subarray(Number(n), Number(n) + 96).equals(expected)) throw invalid();
        pending.push([target, Number(n) + 32]);
        last = n;
      }
    }
    if (pending.length < 8) throw invalid();
    const encoded = Buffer.from(Buffer.from(watermark.buffer, watermark.byteOffset, watermark.byteLength).toString("hex"));
    try { for (const [target, n] of pending) encoded.copy(target, n); }
    finally { encoded.fill(0); }
  } catch { throw invalid(); }
}
