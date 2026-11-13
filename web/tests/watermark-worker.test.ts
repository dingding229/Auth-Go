import { afterEach, expect, it, vi } from "vitest";
import { scanWatermark } from "../src/lib/watermark-scan";
import type {
  ScanOptions,
  WatermarkResult,
  WatermarkWorkerRequest,
  WatermarkWorkerResponse,
} from "../src/lib/watermark-scan";
vi.mock("../src/lib/watermark-scan", () => ({ scanWatermark: vi.fn() }));
afterEach(() => {
  vi.resetAllMocks();
  vi.unstubAllGlobals();
  vi.resetModules();
});
const result: WatermarkResult = {
  status: "none",
  count: 0,
  slots: 0,
  zeros: 0,
  complete: true,
  candidates: [],
  warnings: [],
};
async function setup() {
  const scope: {
    onmessage?: (event: MessageEvent<WatermarkWorkerRequest>) => void;
    postMessage: ReturnType<typeof vi.fn>;
  } = { postMessage: vi.fn() };
  vi.stubGlobal("self", scope);
  await import("../src/lib/watermark-worker");
  return {
    scope,
    send(message: WatermarkWorkerRequest) {
      scope.onmessage!({
        data: message,
      } as MessageEvent<WatermarkWorkerRequest>);
    },
  };
}
it("passes the File and all supplied tags to scanner, relays progress and result", async () => {
  vi.mocked(scanWatermark).mockImplementation(async (_file, _tags, options) => {
    options?.onProgress?.({ bytes: 8, total: 10, entries: 0, expanded: 0 });
    return result;
  });
  const { scope, send } = await setup(),
    file = new File(["local"], "private.bin"),
    tags = ["a".repeat(32), "b".repeat(32)];
  send({ type: "scan", id: 1, file, tags });
  await Promise.resolve();
  await Promise.resolve();
  expect(scanWatermark).toHaveBeenCalledWith(
    file,
    tags,
    expect.objectContaining({ signal: expect.any(AbortSignal) }),
  );
  expect(scope.postMessage).toHaveBeenCalledWith({
    type: "progress",
    id: 1,
    progress: { bytes: 8, total: 10, entries: 0, expanded: 0 },
  });
  expect(scope.postMessage).toHaveBeenCalledWith({
    type: "result",
    id: 1,
    result,
  });
});
it("cancels only the current job and never emits late progress/results from replaced jobs", async () => {
  const runs: {
    options?: ScanOptions;
    resolve: (value: WatermarkResult) => void;
  }[] = [];
  vi.mocked(scanWatermark).mockImplementation(
    (_file, _tags, options) =>
      new Promise((resolve) => {
        runs.push({ options, resolve });
      }),
  );
  const { scope, send } = await setup(),
    file = new File(["local"], "private.bin"),
    tags = ["a".repeat(32)];
  send({ type: "scan", id: 1, file, tags });
  send({ type: "scan", id: 2, file, tags });
  expect(runs[0]!.options!.signal!.aborted).toBe(true);
  send({ type: "cancel", id: 1 });
  expect(runs[1]!.options!.signal!.aborted).toBe(false);
  runs[0]!.options!.onProgress?.({
    bytes: 1,
    total: 1,
    entries: 0,
    expanded: 0,
  });
  runs[0]!.resolve(result);
  await Promise.resolve();
  await Promise.resolve();
  expect(scope.postMessage).not.toHaveBeenCalled();
  send({ type: "cancel", id: 2 });
  expect(runs[1]!.options!.signal!.aborted).toBe(true);
  const cancelled = {
    ...result,
    status: "cancelled",
    complete: false,
  } as WatermarkResult;
  runs[1]!.resolve(cancelled);
  await Promise.resolve();
  await Promise.resolve();
  expect(scope.postMessage).toHaveBeenCalledExactlyOnceWith({
    type: "result",
    id: 2,
    result: cancelled,
  } satisfies WatermarkWorkerResponse);
});
