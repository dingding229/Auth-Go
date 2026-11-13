/** Browser-only local inspection. No file data (including names) belongs in HTTP. */
export interface WatermarkCandidate {
  watermark: string;
  count: number;
}
export interface WatermarkResult {
  status: "found" | "zero" | "none" | "ambiguous" | "partial" | "cancelled";
  watermark?: string;
  count: number;
  slots: number;
  zeros: number;
  complete: boolean;
  candidates: WatermarkCandidate[];
  warnings: string[];
}
export interface WatermarkProgress {
  bytes: number;
  total: number;
  entries: number;
  expanded: number;
}
export interface ScanOptions {
  signal?: AbortSignal;
  onProgress?: (progress: WatermarkProgress) => void;
}
export const WATERMARK_LIMITS = Object.freeze({
  totalExpanded: 512 * 1024 * 1024,
  entryExpanded: 128 * 1024 * 1024,
  depth: 4,
  entries: 4096,
  candidates: 4096,
});
export type WatermarkWorkerRequest =
  | { type: "scan"; id: number; file: File; tags: string[] }
  | { type: "cancel"; id: number };
export type WatermarkWorkerResponse =
  | { type: "progress"; id: number; progress: WatermarkProgress }
  | { type: "result"; id: number; result: WatermarkResult };

const ZERO = "0".repeat(64);
const hex = (b: number) => (b >= 48 && b <= 57) || (b >= 97 && b <= 102);
const u16 = (b: Uint8Array, o: number) => b[o]! | (b[o + 1]! << 8);
const u32 = (b: Uint8Array, o: number) =>
  (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;
const zipMagic = (b: Uint8Array) =>
  b.length >= 4 &&
  b[0] === 80 &&
  b[1] === 75 &&
  ((b[2] === 3 && b[3] === 4) ||
    (b[2] === 5 && b[3] === 6) ||
    (b[2] === 7 && b[3] === 8) ||
    (b[2] === 6 && b[3] === 6));
const join = (a: Uint8Array, b: Uint8Array) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

/** 95 carried bytes ensure each 96-byte occurrence is counted exactly once. */
export class WatermarkSlots {
  private carry = new Uint8Array();
  private tags = new Map<number, Uint8Array[]>();
  private counts = new Map<string, number>();
  private overflowed = false;
  slots = 0;
  zeros = 0;
  constructor(tags: readonly string[]) {
    for (const tag of new Set(tags)) {
      if (!/^[0-9a-f]{32}$/.test(tag)) continue;
      const bytes = Uint8Array.from(tag, (c) => c.charCodeAt(0));
      const key = u32(bytes, 0);
      this.tags.set(key, [...(this.tags.get(key) ?? []), bytes]);
    }
  }
  /** Call between independent archive entries, never between stream chunks. */
  boundary() {
    this.carry = new Uint8Array();
  }
  push(chunk: Uint8Array) {
    const bytes = join(this.carry, chunk);
    for (let offset = 0; offset + 96 <= bytes.length; offset++) {
      const tags = this.tags.get(u32(bytes, offset));
      if (!tags?.some((tag) => tag.every((b, i) => b === bytes[offset + i])))
        continue;
      let valid = true;
      for (let i = offset + 32; i < offset + 96; i++) {
        if (!hex(bytes[i]!)) {
          valid = false;
          break;
        }
      }
      if (!valid) continue;
      let value = "";
      for (let i = offset + 32; i < offset + 96; i++)
        value += String.fromCharCode(bytes[i]!);
      if (
        value !== ZERO &&
        !this.counts.has(value) &&
        this.counts.size >= WATERMARK_LIMITS.candidates
      ) {
        this.overflowed = true;
        throw new StopScan();
      }
      this.slots++;
      if (value === ZERO) this.zeros++;
      else this.counts.set(value, (this.counts.get(value) ?? 0) + 1);
    }
    this.carry = bytes.slice(Math.max(0, bytes.length - 95));
  }
  result(warnings: string[] = [], cancelled = false): WatermarkResult {
    warnings = [...warnings];
    if (this.overflowed)
      warnings.push("不同非零候选水印超过 4096 个，已停止检查。");
    const candidates = [...this.counts]
      .map(([watermark, count]) => ({ watermark, count }))
      .sort(
        (a, b) =>
          b.count - a.count ||
          (a.watermark < b.watermark ? -1 : a.watermark > b.watermark ? 1 : 0),
      );
    const first = candidates[0];
    const tied = !!first && candidates[1]?.count === first.count;
    const complete = !cancelled && !warnings.length;
    const status = cancelled
      ? "cancelled"
      : !complete
        ? "partial"
        : tied
          ? "ambiguous"
          : first
            ? "found"
            : this.zeros
              ? "zero"
              : "none";
    return {
      status,
      ...(status === "found" && first ? { watermark: first.watermark } : {}),
      count: first?.count ?? 0,
      slots: this.slots,
      zeros: this.zeros,
      complete,
      candidates,
      warnings: [...warnings],
    };
  }
}
class StopScan extends Error {}
class CancelScan extends Error {}
const crcTable = Uint32Array.from({ length: 256 }, (_, i) => {
  let value = i;
  for (let bit = 0; bit < 8; bit++)
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});

/** ZIP/JAR uses the central directory (also supports data descriptors). Only
 * expanded entries are searched, never compressed parent bytes or ZIP names.
 * Each bounded entry is validated before any of its bytes are searched. */
export async function scanWatermark(
  file: Blob,
  tags: readonly string[],
  options: ScanOptions = {},
): Promise<WatermarkResult> {
  const slots = new WatermarkSlots(tags);
  const warnings = new Set<string>();
  let expanded = 0,
    entries = 0,
    bytes = 0,
    sinceYield = 0,
    lastProgress = 0;
  const warn = (message: string) => warnings.add(message);
  const check = () => {
    if (options.signal?.aborted) throw new CancelScan();
  };
  const progress = (force = false) => {
    const now = Date.now();
    if (force || now - lastProgress >= 80) {
      lastProgress = now;
      options.onProgress?.({
        bytes: Math.min(bytes, file.size),
        total: file.size,
        entries,
        expanded,
      });
    }
  };
  const yieldUI = async (length: number) => {
    sinceYield += length;
    if (sinceYield >= 1024 * 1024) {
      sinceYield = 0;
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
    check();
    progress();
  };
  const read = async (blob: Blob, offset: number, length: number) => {
    check();
    if (offset < 0 || length < 0 || offset + length > blob.size)
      throw new Error("bounds");
    const data = new Uint8Array(
      await blob.slice(offset, offset + length).arrayBuffer(),
    );
    check();
    return data;
  };
  async function consume(
    stream: ReadableStream<Uint8Array>,
    visit: (chunk: Uint8Array) => Promise<void>,
  ) {
    const reader = stream.getReader();
    const abort = () => {
      void reader.cancel().catch(() => {});
    };
    options.signal?.addEventListener("abort", abort, { once: true });
    try {
      check();
      while (true) {
        const part = await reader.read();
        check();
        if (part.done) break;
        // Bound synchronous work even for a custom stream returning giant chunks.
        for (let offset = 0; offset < part.value.length; offset += 64 * 1024) {
          const chunk = part.value.subarray(offset, offset + 64 * 1024);
          await visit(chunk);
          await yieldUI(chunk.length);
        }
      }
    } finally {
      options.signal?.removeEventListener("abort", abort);
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }
  async function archive(blob: Blob, depth: number): Promise<void> {
    if (depth > WATERMARK_LIMITS.depth) {
      warn("嵌套 ZIP/JAR 超过 4 层，未继续检查。");
      throw new StopScan();
    }
    const tail = await read(
      blob,
      Math.max(0, blob.size - 65557),
      Math.min(blob.size, 65557),
    );
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (
        u32(tail, i) === 0x06054b50 &&
        i + 22 + u16(tail, i + 20) === tail.length
      ) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) {
      warn("ZIP/JAR 目录缺失或损坏，未扫描压缩容器原始字节。");
      throw new StopScan();
    }
    const count = u16(tail, eocd + 10),
      size = u32(tail, eocd + 12),
      start = u32(tail, eocd + 16);
    const eocdOffset = blob.size - tail.length + eocd;
    const locator =
      eocdOffset >= 20
        ? await read(blob, eocdOffset - 20, 4)
        : new Uint8Array();
    if (
      count === 0xffff ||
      size === 0xffffffff ||
      start === 0xffffffff ||
      (locator.length === 4 && u32(locator, 0) === 0x07064b50)
    ) {
      warn("ZIP64 暂不支持，结果不完整。");
      throw new StopScan();
    }
    if (
      u16(tail, eocd + 4) ||
      u16(tail, eocd + 6) ||
      u16(tail, eocd + 8) !== count
    ) {
      warn("分卷 ZIP 暂不支持，结果不完整。");
      throw new StopScan();
    }
    const end = start + size;
    if (end !== eocdOffset || start > blob.size) {
      warn("ZIP/JAR 目录范围异常。");
      throw new StopScan();
    }
    let cursor = start;
    const ranges: [number, number][] = [];
    for (let index = 0; index < count; index++) {
      check();
      if (entries >= WATERMARK_LIMITS.entries) {
        warn("归档条目超过 4096 个，已停止检查。");
        throw new StopScan();
      }
      entries++;
      // Even thousands of empty entries must yield to cancel messages; byte-
      // based yielding alone would never run for a metadata-only archive.
      if (entries % 64 === 0) {
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
        check();
        progress(true);
      }
      if (cursor + 46 > end) {
        warn("ZIP/JAR 条目目录损坏。");
        throw new StopScan();
      }
      const header = await read(blob, cursor, 46);
      if (u32(header, 0) !== 0x02014b50) {
        warn("ZIP/JAR 条目目录损坏。");
        throw new StopScan();
      }
      const flags = u16(header, 8),
        method = u16(header, 10),
        crc = u32(header, 16);
      const compressed = u32(header, 20),
        length = u32(header, 24),
        local = u32(header, 42);
      const nameLength = u16(header, 28),
        extraLength = u16(header, 30),
        commentLength = u16(header, 32);
      const next = cursor + 46 + nameLength + extraLength + commentLength;
      if (next > end) {
        warn("ZIP/JAR 条目目录越界。");
        throw new StopScan();
      }
      const extra = await read(blob, cursor + 46 + nameLength, extraLength);
      cursor = next;
      let zip64 =
        compressed === 0xffffffff ||
        length === 0xffffffff ||
        local === 0xffffffff;
      for (let p = 0; p < extra.length;) {
        if (p + 4 > extra.length || p + 4 + u16(extra, p + 2) > extra.length) {
          warn("ZIP 扩展字段损坏。");
          throw new StopScan();
        }
        if (u16(extra, p) === 1) zip64 = true;
        p += 4 + u16(extra, p + 2);
      }
      if (zip64 || u16(header, 34) || u16(header, 6) >= 45) {
        warn("ZIP64 或分卷条目暂不支持。");
        throw new StopScan();
      }
      if (flags & (1 | 64 | 8192)) {
        warn("加密 ZIP 条目无法检查。");
        throw new StopScan();
      }
      if (flags & ~(2 | 4 | 8 | 2048) || (method !== 0 && method !== 8)) {
        warn("ZIP 包含不支持的压缩方式或特性。");
        throw new StopScan();
      }
      if (length > WATERMARK_LIMITS.entryExpanded) {
        warn("单条目展开超过 128 MiB，已跳过。");
        throw new StopScan();
      }
      if (expanded + length > WATERMARK_LIMITS.totalExpanded) {
        warn("归档累计展开超过 512 MiB，已停止检查。");
        throw new StopScan();
      }
      try {
        if (local + 30 > start) throw new Error("local bounds");
        const lh = await read(blob, local, 30);
        if (
          u32(lh, 0) !== 0x04034b50 ||
          u16(lh, 6) !== flags ||
          u16(lh, 8) !== method
        )
          throw new Error("local header");
        const localExtraStart = local + 30 + u16(lh, 26);
        const localExtra = await read(blob, localExtraStart, u16(lh, 28));
        if (
          u16(lh, 4) >= 45 ||
          u32(lh, 18) === 0xffffffff ||
          u32(lh, 22) === 0xffffffff
        ) {
          warn("ZIP64 条目暂不支持。");
          throw new StopScan();
        }
        let localZip64 = false;
        for (let p = 0; p < localExtra.length;) {
          if (
            p + 4 > localExtra.length ||
            p + 4 + u16(localExtra, p + 2) > localExtra.length
          )
            throw new Error("local extra");
          if (u16(localExtra, p) === 1) localZip64 = true;
          p += 4 + u16(localExtra, p + 2);
        }
        if (localZip64) {
          warn("ZIP64 条目暂不支持。");
          throw new StopScan();
        }
        if (
          !(flags & 8) &&
          (u32(lh, 14) !== crc ||
            u32(lh, 18) !== compressed ||
            u32(lh, 22) !== length)
        )
          throw new Error("local size or CRC");
        const dataStart = localExtraStart + localExtra.length,
          dataEnd = dataStart + compressed;
        if (
          dataEnd > start ||
          dataStart > start ||
          ranges.some(([a, b]) => local < b && dataEnd > a)
        )
          throw new Error("entry bounds");
        ranges.push([local, dataEnd]);
        let stream = blob.slice(dataStart, dataEnd).stream();
        if (method === 8) {
          try {
            stream = stream.pipeThrough(new DecompressionStream("deflate-raw"));
          } catch {
            warn("当前浏览器不支持 deflate-raw 解压，请换用支持的浏览器重试。");
            throw new StopScan();
          }
        }
        let actual = 0,
          checksum = 0xffffffff,
          prefixLength = 0;
        const prefix = new Uint8Array(4),
          parts: ArrayBuffer[] = [];
        slots.boundary();
        await consume(stream, async (chunk) => {
          actual += chunk.length;
          expanded += chunk.length;
          if (expanded > WATERMARK_LIMITS.totalExpanded) {
            warn("归档累计展开超过 512 MiB，已停止检查。");
            throw new StopScan();
          }
          if (actual > WATERMARK_LIMITS.entryExpanded || actual > length)
            throw new Error("expanded bounds");
          for (const b of chunk)
            checksum = crcTable[(checksum ^ b) & 255]! ^ (checksum >>> 8);
          const prefixBytes = chunk.subarray(0, 4 - prefixLength);
          prefix.set(prefixBytes, prefixLength);
          prefixLength += prefixBytes.length;
          parts.push(chunk.slice().buffer);
        });
        // Do not attribute slots from corrupt/lying entries, even when their
        // unverified output happens to contain a syntactically valid watermark.
        if (actual !== length || (checksum ^ 0xffffffff) >>> 0 !== crc)
          throw new Error("size or CRC");
        if (zipMagic(prefix.subarray(0, prefixLength)))
          await archive(new Blob(parts), depth + 1);
        else
          for (const part of parts) {
            check();
            slots.push(new Uint8Array(part));
            await yieldUI(part.byteLength);
          }
        slots.boundary();
      } catch (error) {
        if (error instanceof CancelScan || error instanceof StopScan)
          throw error;
        warn("部分 ZIP/JAR 条目损坏、超出边界或无法解压，结果不完整。");
        slots.boundary();
        throw new StopScan();
      }
      if (depth === 0) bytes += compressed;
      progress();
    }
    if (cursor !== end) warn("ZIP/JAR 目录包含无法识别的数据。");
  }
  try {
    check();
    progress(true);
    if (!tags.length || tags.some((tag) => !/^[0-9a-f]{32}$/.test(tag)))
      warn("软件标记缺失或格式无效，请重新读取标记。");
    if (!tags.some((tag) => /^[0-9a-f]{32}$/.test(tag)))
      return slots.result([...warnings]);
    if (zipMagic(await read(file, 0, Math.min(4, file.size))))
      await archive(file, 0);
    else
      await consume(file.stream(), async (chunk) => {
        slots.push(chunk);
        bytes += chunk.length;
      });
    check();
    if (!warnings.size) bytes = file.size;
    progress(true);
    return slots.result([...warnings]);
  } catch (error) {
    if (error instanceof CancelScan || options.signal?.aborted)
      return slots.result([...warnings], true);
    if (!(error instanceof StopScan))
      warn("本地文件读取失败，结果不完整；请重新选择文件重试。");
    progress(true);
    return slots.result([...warnings]);
  }
}
