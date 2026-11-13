import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Blob as NativeBlob } from "node:buffer";
import { readFileSync } from "node:fs";
import { deflateRawSync } from "node:zlib";
import {
  scanWatermark,
  WatermarkSlots,
  WATERMARK_LIMITS,
} from "../src/lib/watermark-scan";

beforeEach(() => vi.stubGlobal("Blob", NativeBlob));
afterEach(() => vi.unstubAllGlobals());

const tag = "0123456789abcdef".repeat(2),
  oldTag = "fedcba9876543210".repeat(2);
const a = "a".repeat(64),
  b = "b".repeat(64),
  zero = "0".repeat(64);
const encode = (value: string) => new TextEncoder().encode(value);
function blob(bytes: Uint8Array, chunkSize?: number): Blob {
  const file = new NativeBlob([bytes]);
  if (chunkSize)
    Object.defineProperty(file, "stream", {
      configurable: true,
      value: () => {
        let offset = 0;
        return new ReadableStream<Uint8Array>({
          pull(controller) {
            if (offset === bytes.length) {
              controller.close();
              return;
            }
            controller.enqueue(bytes.slice(offset, offset + chunkSize));
            offset = Math.min(bytes.length, offset + chunkSize);
          },
        });
      },
    });
  return file as unknown as Blob;
}
function crc32(bytes: Uint8Array) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++)
      crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
interface Entry {
  data: Uint8Array;
  name?: string;
  method?: number;
  flags?: number;
  size?: number;
  crc?: number;
  extra?: Uint8Array;
}
/** Build fixtures in tests, without production dependencies or shared-vector writes. */
function zip(items: Entry[], comment = ""): Uint8Array {
  const files: Buffer[] = [],
    directory: Buffer[] = [];
  let offset = 0;
  for (const [index, item] of items.entries()) {
    const method = item.method ?? 0,
      flags = item.flags ?? 0;
    const name = Buffer.from(item.name ?? `${index}.class`),
      extra = Buffer.from(item.extra ?? []);
    const data =
      method === 8 ? deflateRawSync(item.data) : Buffer.from(item.data);
    const crc = item.crc ?? crc32(item.data),
      size = item.size ?? item.data.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    if (!(flags & 8)) {
      local.writeUInt32LE(crc, 14);
      local.writeUInt32LE(data.length, 18);
      local.writeUInt32LE(size, 22);
    }
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(extra.length, 28);
    const descriptor = Buffer.alloc(flags & 8 ? 16 : 0);
    if (flags & 8) {
      descriptor.writeUInt32LE(0x08074b50);
      descriptor.writeUInt32LE(crc, 4);
      descriptor.writeUInt32LE(data.length, 8);
      descriptor.writeUInt32LE(size, 12);
    }
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(extra.length, 30);
    central.writeUInt32LE(offset, 42);
    files.push(local, name, extra, data, descriptor);
    directory.push(central, name, extra);
    offset +=
      local.length +
      name.length +
      extra.length +
      data.length +
      descriptor.length;
  }
  const cd = Buffer.concat(directory),
    end = Buffer.alloc(22),
    notes = Buffer.from(comment);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(items.length, 8);
  end.writeUInt16LE(items.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(notes.length, 20);
  return Buffer.concat([...files, cd, end, notes]);
}

it("matches across every slot split, deduplicates tags and counts each overlap only once", () => {
  for (let split = 1; split < 96; split++) {
    const slots = new WatermarkSlots([tag, oldTag, tag]);
    const bytes = encode(`!${tag}${a}!${oldTag}${a}!${tag}${zero}!`);
    for (let i = 0; i < bytes.length; i += split)
      slots.push(bytes.subarray(i, i + split));
    expect(slots.result()).toEqual({
      status: "found",
      watermark: a,
      count: 2,
      slots: 3,
      zeros: 1,
      complete: true,
      candidates: [{ watermark: a, count: 2 }],
      warnings: [],
    });
  }
});
it("does not count uppercase or damaged slots, nor join separate entries", () => {
  const slots = new WatermarkSlots([tag]);
  slots.push(encode(tag + a.slice(0, 30)));
  slots.boundary();
  slots.push(encode(a.slice(30)));
  slots.push(
    encode(
      `!${tag.toUpperCase()}${a}!${tag}${"A".repeat(64)}!${tag}${a.slice(0, 63)}z`,
    ),
  );
  expect(slots.result()).toMatchObject({ status: "none", slots: 0, count: 0 });
});
it("zeros cannot win or break a tie; ambiguous values are lexically sorted", () => {
  const slots = new WatermarkSlots([tag]);
  slots.push(encode([zero, zero, zero, b, a].map((v) => tag + v).join("!")));
  expect(slots.result()).toEqual({
    status: "ambiguous",
    count: 1,
    slots: 5,
    zeros: 3,
    complete: true,
    candidates: [
      { watermark: a, count: 1 },
      { watermark: b, count: 1 },
    ],
    warnings: [],
  });
  expect(slots.result()).not.toHaveProperty("watermark");
  slots.push(encode("!" + tag + b));
  expect(slots.result()).toMatchObject({
    status: "found",
    watermark: b,
    count: 2,
    slots: 6,
    zeros: 3,
  });
});
it("allzero has count zero, empty has none, partial and cancellation preserve candidates", () => {
  const slots = new WatermarkSlots([tag]);
  expect(slots.result()).toMatchObject({
    status: "none",
    complete: true,
    slots: 0,
    count: 0,
  });
  slots.push(encode(tag + zero));
  expect(slots.result()).toMatchObject({
    status: "zero",
    count: 0,
    slots: 1,
    zeros: 1,
  });
  slots.push(encode("!" + tag + a));
  expect(slots.result(["incomplete"])).toMatchObject({
    status: "partial",
    complete: false,
    count: 1,
    candidates: [{ watermark: a, count: 1 }],
  });
  expect(slots.result([], true)).toMatchObject({
    status: "cancelled",
    complete: false,
    count: 1,
  });
});
it("streams raw non-ZIP formats without reading the complete Blob into an ArrayBuffer", async () => {
  const file = blob(encode(`gzip-like!${oldTag}${a}!`), 3);
  Object.defineProperty(file, "arrayBuffer", {
    value: () => {
      throw new Error("whole-file read forbidden");
    },
  });
  const progress = vi.fn();
  expect(
    await scanWatermark(file, [tag, oldTag], { onProgress: progress }),
  ).toMatchObject({ status: "found", watermark: a, count: 1, complete: true });
  expect(progress.mock.calls.at(-1)?.[0]).toMatchObject({
    bytes: file.size,
    total: file.size,
  });
});
it("handles empty files and missing/invalid tags conservatively", async () => {
  expect(await scanWatermark(blob(new Uint8Array()), [tag])).toMatchObject({
    status: "none",
    complete: true,
  });
  for (const tags of [[], [tag.toUpperCase()], [tag, "invalid"]]) {
    expect(await scanWatermark(blob(encode(tag + a)), tags)).toMatchObject({
      status: "partial",
      complete: false,
    });
  }
});
it("reads stored, deflated, descriptor entries and nested JARs, never ZIP names/comments or compressed parents", async () => {
  const nested = zip([{ data: encode(tag + b), method: 8 }]);
  const file = zip(
    [
      { data: encode(tag + a), method: 0 },
      { data: encode(oldTag + a), method: 8, flags: 8 },
      { data: nested, name: "lib/nested.jar", method: 8 },
      { data: encode("no slots"), name: tag + a },
    ],
    tag + a,
  );
  expect(await scanWatermark(blob(file), [tag, oldTag])).toEqual({
    status: "found",
    watermark: a,
    count: 2,
    slots: 3,
    zeros: 0,
    complete: true,
    candidates: [
      { watermark: a, count: 2 },
      { watermark: b, count: 1 },
    ],
    warnings: [],
  });
});
it("does not stitch slots across independent ZIP entries", async () => {
  expect(
    await scanWatermark(
      blob(
        zip([
          { data: encode(tag + a.slice(0, 25)) },
          { data: encode(a.slice(25)) },
        ]),
      ),
      [tag],
    ),
  ).toMatchObject({ status: "none", slots: 0, complete: true });
});
it("unsupported and corrupt ZIPs are partial and retain earlier candidates", async () => {
  for (const item of [
    { data: encode("encrypted"), flags: 1 },
    { data: encode("unsupported"), method: 99 },
    { data: encode("bad CRC"), crc: 1234 },
    { data: encode("wrong declared size"), size: 30 },
    { data: encode("ZIP64"), extra: new Uint8Array([1, 0, 0, 0]) },
    { data: encode("oversized"), size: WATERMARK_LIMITS.entryExpanded + 1 },
  ]) {
    const result = await scanWatermark(
      blob(zip([{ data: encode(tag + a) }, item])),
      [tag],
    );
    expect(result).toMatchObject({
      status: "partial",
      complete: false,
      count: 1,
      slots: 1,
      candidates: [{ watermark: a, count: 1 }],
    });
    expect(result.warnings.length).toBeGreaterThan(0);
  }
  const truncated = zip([{ data: encode(tag + a) }]).slice(0, -10);
  expect(await scanWatermark(blob(truncated), [tag])).toMatchObject({
    status: "partial",
    complete: false,
    slots: 0,
  });
});
it("never counts unverified bytes from a bad-CRC or wrong-size entry", async () => {
  for (const entry of [
    { data: encode(tag + a), crc: 1234 },
    { data: encode(tag + a), size: 97 },
  ]) {
    expect(await scanWatermark(blob(zip([entry])), [tag])).toMatchObject({
      status: "partial",
      slots: 0,
      count: 0,
      candidates: [],
      complete: false,
    });
  }
});
it("bounds distinct nonzero candidates and returns partial without an identified watermark", async () => {
  const values = Array.from(
    { length: 4097 },
    (_, index) => tag + (index + 1).toString(16).padStart(64, "0"),
  );
  const result = await scanWatermark(blob(encode(values.join("!")), 65536), [
    tag,
  ]);
  expect(result).toMatchObject({
    status: "partial",
    slots: 4096,
    count: 1,
    complete: false,
  });
  expect(result.candidates).toHaveLength(4096);
  expect(result).not.toHaveProperty("watermark");
});
it("enforces actual expanded size even when an archive lies about its size", async () => {
  const file = zip([
    { data: encode(tag + a) },
    { data: new Uint8Array(131072), method: 8, size: 1 },
  ]);
  expect(await scanWatermark(blob(file), [tag])).toMatchObject({
    status: "partial",
    complete: false,
    count: 1,
    slots: 1,
  });
});
it("keeps fixed resource limits and rejects oversized declarations without allocating them", async () => {
  const items = [
    { data: new Uint8Array(), size: WATERMARK_LIMITS.entryExpanded + 1 },
  ];
  expect(
    await scanWatermark(blob(zip([{ data: encode(tag + a) }, ...items])), [
      tag,
    ]),
  ).toMatchObject({ status: "partial", complete: false, count: 1 });
  expect(WATERMARK_LIMITS).toEqual({
    totalExpanded: 536870912,
    entryExpanded: 134217728,
    depth: 4,
    entries: 4096,
    candidates: 4096,
  });
});
it("allows depth four, refuses depth five, and caps aggregate entry count", async () => {
  let nested = zip([{ data: encode(tag + a) }]);
  for (let depth = 0; depth < 4; depth++) nested = zip([{ data: nested }]);
  expect(await scanWatermark(blob(nested), [tag])).toMatchObject({
    status: "found",
    count: 1,
    complete: true,
  });
  nested = zip([{ data: nested }]);
  expect(await scanWatermark(blob(nested), [tag])).toMatchObject({
    status: "partial",
    complete: false,
    slots: 0,
  });
  const many = zip(
    Array.from({ length: 4097 }, (_, index) => ({
      data: index === 0 ? encode(tag + a) : new Uint8Array(),
    })),
  );
  expect(await scanWatermark(blob(many), [tag])).toMatchObject({
    status: "partial",
    count: 1,
    complete: false,
  });
});
it("a browser without deflate-raw support gets partial, never a misleading none", async () => {
  const original = globalThis.DecompressionStream;
  vi.stubGlobal(
    "DecompressionStream",
    class {
      constructor() {
        throw new Error("unsupported");
      }
    },
  );
  try {
    const result = await scanWatermark(
      blob(
        zip([{ data: encode(tag + a) }, { data: encode(tag + b), method: 8 }]),
      ),
      [tag],
    );
    expect(result).toMatchObject({
      status: "partial",
      complete: false,
      count: 1,
    });
    expect(result.warnings.join(" ")).toContain("deflate-raw");
  } finally {
    vi.stubGlobal("DecompressionStream", original);
  }
});
it("cancels an active read and leaves an incomplete result", async () => {
  const controller = new AbortController();
  const file = blob(encode(`${tag}${a}!${tag}${b}`), 97);
  const originalStream = file.stream.bind(file);
  Object.defineProperty(file, "stream", {
    value: () =>
      originalStream().pipeThrough(
        new TransformStream({
          transform(chunk, stream) {
            stream.enqueue(chunk);
            controller.abort();
          },
        }),
      ),
  });
  expect(
    await scanWatermark(file, [tag], { signal: controller.signal }),
  ).toMatchObject({ status: "cancelled", complete: false });
  expect(
    await scanWatermark(blob(encode(tag + a)), [tag], {
      signal: controller.signal,
    }),
  ).toMatchObject({ status: "cancelled", complete: false, slots: 0 });
});

// Parent owns this common schema and the Go/browser vectors. Register the cases
// unconditionally; a missing shared vector file is a test failure.
const vectorPath = "../sdk/vectors/watermark.json";
{
  const vectors = JSON.parse(readFileSync(vectorPath, "utf8")) as {
    v: number;
    scan: {
      name: string;
      tags: string[];
      bytes_b64: string;
      chunk_size?: number;
      cancel_before?: boolean;
      expected: {
        status: string;
        watermark?: string;
        count: number;
        slots: number;
        zeros: number;
        complete: boolean;
      };
    }[];
  };
  describe("shared sdk/vectors/watermark.json", () => {
    it("uses the common v1 scan schema", () => {
      expect(vectors.v).toBe(1);
      expect(vectors.scan.length).toBeGreaterThan(0);
    });
    for (const vector of vectors.scan)
      it(vector.name, async () => {
        const controller = new AbortController();
        if (vector.cancel_before) controller.abort();
        const result = await scanWatermark(
          blob(Buffer.from(vector.bytes_b64, "base64"), vector.chunk_size),
          vector.tags,
          { signal: controller.signal },
        );
        const { status, watermark, count, slots, zeros, complete } = result;
        expect({
          status,
          ...(watermark === undefined ? {} : { watermark }),
          count,
          slots,
          zeros,
          complete,
        }).toEqual(vector.expected);
      });
  });
}
