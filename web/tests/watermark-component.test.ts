import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, ref, type App } from "vue";
import { createMemoryHistory, createRouter } from "vue-router";
import ElementPlus from "element-plus";
import WatermarkTrace from "../src/components/WatermarkTrace.vue";
import type {
  WatermarkResult,
  WatermarkWorkerRequest,
  WatermarkWorkerResponse,
} from "../src/lib/watermark-scan";
import { get, post } from "../src/lib/http";
import { readFileSync } from "node:fs";

vi.mock("../src/lib/http", () => ({ get: vi.fn(), post: vi.fn() }));
const tag = "0123456789abcdef".repeat(2),
  oldTag = "fedcba9876543210".repeat(2),
  value = "a".repeat(64);
class FakeWorker {
  static all: FakeWorker[] = [];
  sent: WatermarkWorkerRequest[] = [];
  terminated = false;
  onmessage?: (event: MessageEvent<WatermarkWorkerResponse>) => void;
  onerror?: (event: ErrorEvent) => void;
  onmessageerror?: () => void;
  constructor() {
    FakeWorker.all.push(this);
  }
  postMessage(message: WatermarkWorkerRequest) {
    this.sent.push(message);
  }
  terminate() {
    this.terminated = true;
  }
  emit(message: WatermarkWorkerResponse) {
    this.onmessage?.({
      data: message,
    } as MessageEvent<WatermarkWorkerResponse>);
  }
  finish(result: WatermarkResult) {
    const start = this.sent.find((message) => message.type === "scan")!;
    this.emit({ type: "result", id: start.id, result });
  }
}
function found(): WatermarkResult {
  return {
    status: "found",
    watermark: value,
    count: 2,
    slots: 3,
    zeros: 1,
    complete: true,
    candidates: [{ watermark: value, count: 2 }],
    warnings: [],
  };
}
let app: App | undefined, root: HTMLElement;
const id = ref("7");
async function flush() {
  for (let index = 0; index < 6; index++) {
    await nextTick();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}
async function mount(setup?: () => void) {
  id.value = "7";
  FakeWorker.all = [];
  vi.stubGlobal("Worker", FakeWorker);
  vi.mocked(get).mockResolvedValue({
    items: [
      { key_id: "old", tag: oldTag },
      { key_id: "new", tag },
      { key_id: "duplicate", tag },
    ],
  });
  vi.mocked(post).mockResolvedValue({
    found: true,
    license_id: "91",
    user_id: "23",
    user_name: "客户甲",
  });
  setup?.();
  root = document.createElement("div");
  document.body.append(root);
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", component: { render: () => null } },
      { path: "/admin/:resource/:id", component: { render: () => null } },
    ],
  });
  await router.push("/");
  app = createApp({ render: () => h(WatermarkTrace, { id: id.value }) })
    .use(ElementPlus)
    .use(router);
  app.mount(root);
  await flush();
}
afterEach(() => {
  app?.unmount();
  root?.remove();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
  document
    .querySelectorAll(".el-overlay, .el-message")
    .forEach((element) => element.remove());
});
async function select(name = "private-leaked-file.jar") {
  const input = root.querySelector<HTMLInputElement>('input[type="file"]')!;
  const file = new File(["never send this content"], name);
  Object.defineProperty(input, "files", { configurable: true, value: [file] });
  input.dispatchEvent(new Event("change", { bubbles: true }));
  await flush();
  return FakeWorker.all.at(-1)!;
}
function button(text: string) {
  return [...root.querySelectorAll<HTMLButtonElement>("button")].find((item) =>
    item.textContent?.includes(text),
  )!;
}
function manual(text: string) {
  const input = root.querySelector<HTMLInputElement>(".trace-manual input")!;
  input.value = text;
  input.dispatchEvent(new Event("input", { bubbles: true }));
}
function submit() {
  root
    .querySelector("form")!
    .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}
function pending<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
it("integrates below PayloadKeys without adding a switch or changing existing tab routing", () => {
  const source = readFileSync(
    "src/views/admin/ApplicationDetailView.vue",
    "utf8",
  );
  expect(source).toContain('<watermark-trace :id="id" :key="id" />');
  expect(source.indexOf("<watermark-trace")).toBeGreaterThan(
    source.indexOf("<payload-keys"),
  );
  expect(source).toContain('label="打包密钥"');
});
it("sends all distinct historical tags to a local worker and only watermark to REST", async () => {
  await mount();
  const job = await select();
  expect(get).toHaveBeenCalledWith(
    "/applications/7/watermark-tags",
    undefined,
    { quiet: true },
  );
  expect(job.sent[0]).toMatchObject({ type: "scan", tags: [oldTag, tag] });
  expect(post).not.toHaveBeenCalled();
  job.finish(found());
  await flush();
  expect(post).toHaveBeenCalledExactlyOnceWith(
    "/applications/7/watermark-trace",
    { watermark: value },
  );
  expect(root.textContent).toContain("一致非零槽位 2 / 全部槽位 3");
  expect(root.querySelector('a[href="/admin/licenses/91"]')).not.toBeNull();
  expect(
    root.querySelector('a[href="/admin/users/23"]')?.textContent,
  ).toContain("客户甲");
  expect(root.textContent).not.toContain("private-leaked-file.jar");
  expect(JSON.stringify(vi.mocked(post).mock.calls)).not.toContain(
    "never send this content",
  );
});
it("shows trial source records without exposing any real license key", async () => {
  await mount(() =>
    vi.mocked(post).mockResolvedValue({
      found: true,
      license_id: "91",
      is_trial: true,
      source_ip: "192.0.2.1",
      created_at: "2026-11-09T00:00:00Z",
      key_id: "old",
      sources: [
        {
          ip: "192.0.2.1",
          instance_id: "instance-one",
          created_at: "2026-11-09T00:00:00Z",
        },
        {
          ip: "192.0.2.2",
          instance_id: "instance-two",
          created_at: "2026-11-09T01:00:00Z",
        },
      ],
      license_key: "MUST-NOT-DISPLAY",
    }),
  );
  (await select()).finish(found());
  await flush();
  expect(root.textContent).toContain("自助试用");
  expect(root.textContent).toContain("试用来源记录");
  expect(root.textContent).toContain("192.0.2.2");
  expect(root.textContent).toContain("instance-two");
  expect(root.textContent).not.toContain("MUST-NOT-DISPLAY");
});
it.each([
  ["zero", "没有水印，可能是用密钥直接解出的"],
  ["none", "文件里没有水印"],
  ["ambiguous", "来源有歧义"],
  ["partial", "文件未扫描完"],
  ["cancelled", "扫描已取消"],
] as const)(
  "%s never auto-queries, even with a supplied watermark",
  async (status, message) => {
    await mount();
    const job = await select();
    job.finish({
      ...found(),
      status,
      complete:
        status === "zero" || status === "none" || status === "ambiguous",
      warnings: status === "partial" ? ["unsupported ZIP"] : [],
    });
    await flush();
    expect(root.textContent).toContain(message);
    expect(post).not.toHaveBeenCalled();
  },
);
it("distinguishes a complete scan with an unknown/deleted authorization", async () => {
  await mount(() => vi.mocked(post).mockResolvedValue({ found: false }));
  (await select()).finish(found());
  await flush();
  expect(root.textContent).toContain("不属于这个软件的授权，或授权已删除");
});
it("cancels a scan, ignores a racing found result and keeps incomplete counts", async () => {
  await mount();
  const job = await select();
  job.emit({
    type: "progress",
    id: job.sent[0]!.id,
    progress: { bytes: 5, total: 10, expanded: 0, entries: 0 },
  });
  await flush();
  expect(root.textContent).toContain("50%");
  button("取消扫描").click();
  await flush();
  expect(job.sent.at(-1)).toEqual({ type: "cancel", id: job.sent[0]!.id });
  job.finish(found());
  await flush();
  expect(root.textContent).toContain("扫描已取消");
  expect(root.textContent).toContain("扫描不完整");
  expect(post).not.toHaveBeenCalled();
  expect(job.terminated).toBe(true);
});
it("ignores old-file callbacks and old HTTP completions after a newer selection", async () => {
  const old = pending<{ found: boolean; license_id: string }>();
  await mount(() => vi.mocked(post).mockReturnValueOnce(old.promise));
  const first = await select("old.bin");
  first.finish(found());
  await flush();
  const second = await select("new.bin");
  first.finish({ ...found(), watermark: "b".repeat(64) });
  old.resolve({ found: true, license_id: "stale" });
  await flush();
  expect(post).toHaveBeenCalledTimes(1);
  expect(root.textContent).not.toContain("stale");
  second.finish({ ...found(), status: "none", watermark: undefined });
  await flush();
  expect(post).toHaveBeenCalledTimes(1);
  expect(root.textContent).toContain("文件里没有水印");
});
it("synchronous app-id changes invalidate workers, queries, manual text and tag requests", async () => {
  const old = pending<{ items: { key_id: string; tag: string }[] }>();
  await mount(() => vi.mocked(get).mockReturnValueOnce(old.promise));
  id.value = "8";
  await flush();
  old.resolve({ items: [{ key_id: "stale-tags", tag }] });
  await flush();
  expect(root.textContent).not.toContain("stale-tags");
  const first = await select();
  const query = pending<{ found: boolean; license_id: string }>();
  vi.mocked(post).mockReturnValueOnce(query.promise);
  first.finish(found());
  await flush();
  id.value = "9";
  await flush();
  first.finish(found());
  query.resolve({ found: true, license_id: "stale-license" });
  await flush();
  expect(root.textContent).not.toContain("stale-license");
  expect(post).toHaveBeenCalledTimes(1);
  expect(post).toHaveBeenCalledWith("/applications/8/watermark-trace", {
    watermark: value,
  });
  const second = await select();
  id.value = "10";
  await flush();
  second.finish(found());
  await flush();
  expect(second.terminated).toBe(true);
  expect(post).toHaveBeenCalledTimes(1);
});
it("manual keyboard form validates nonzero lowercase hex, invalidates old scan and retries only current value", async () => {
  await mount();
  const first = await select();
  manual("0".repeat(64));
  await flush();
  submit();
  await flush();
  expect(root.textContent).toContain("全 0 水印无法识别");
  expect(post).not.toHaveBeenCalled();
  manual("A".repeat(64));
  await flush();
  submit();
  await flush();
  expect(root.textContent).toContain("小写十六进制");
  expect(post).not.toHaveBeenCalled();
  vi.mocked(post).mockRejectedValueOnce(new Error("offline"));
  manual(value);
  await flush();
  submit();
  await flush();
  expect(root.textContent).toContain("查询授权来源失败");
  first.finish(found());
  await flush();
  expect(post).toHaveBeenCalledTimes(1);
  button("重试").click();
  await flush();
  expect(post).toHaveBeenCalledTimes(2);
  expect(post).toHaveBeenLastCalledWith("/applications/7/watermark-trace", {
    watermark: value,
  });
  manual("b".repeat(64));
  await flush();
  expect(root.textContent).not.toContain("已找到授权来源");
});
it("offers retry on tag/worker failure, handles drop and releases worker on unmount", async () => {
  await mount(() => vi.mocked(get).mockRejectedValueOnce(new Error("offline")));
  expect(
    root.querySelector<HTMLInputElement>('input[type="file"]')!.disabled,
  ).toBe(true);
  expect(root.textContent).toContain("读取软件标记失败");
  button("重试").click();
  await flush();
  const drop = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(drop, "dataTransfer", {
    value: { files: [new File(["local only"], "private.bin")] },
  });
  root.querySelector(".trace-drop")!.dispatchEvent(drop);
  await flush();
  const first = FakeWorker.all.at(-1)!;
  first.onerror?.({ preventDefault() {} } as ErrorEvent);
  await flush();
  expect(root.textContent).toContain("本地扫描失败");
  button("重试").click();
  await flush();
  const second = FakeWorker.all.at(-1)!;
  expect(second).not.toBe(first);
  app!.unmount();
  app = undefined;
  second.finish(found());
  await flush();
  expect(second.terminated).toBe(true);
  expect(post).not.toHaveBeenCalled();
});
it("uses labelled native input/progress, shared tokens and wrapping narrow-screen layout", async () => {
  await mount();
  const input = root.querySelector<HTMLInputElement>('input[type="file"]')!;
  expect(root.querySelector(`label[for="${input.id}"]`)).not.toBeNull();
  expect(root.querySelector('input[type="checkbox"]')).toBeNull();
  expect(root.textContent).toContain("不上传文件、文件名或内容片段");
  const source = readFileSync("src/components/WatermarkTrace.vue", "utf8");
  expect(source).toContain("overflow-wrap: anywhere");
  expect(source).toContain("min-width: 0");
  expect(source).toContain("var(--line)");
  expect(source).not.toMatch(/#[0-9a-f]{6}\b/i);
});

it("refreshes newly rotated tags at file selection before sending a worker job", async () => {
  await mount();
  const newer = "3".repeat(32);
  vi.mocked(get).mockResolvedValueOnce({
    items: [
      { key_id: "newest", tag: newer },
      { key_id: "old", tag },
    ],
  });
  const job = await select();
  expect(job.sent[0]).toMatchObject({ type: "scan", tags: [newer, tag] });
  expect(post).not.toHaveBeenCalled();
});
it("late tag refresh for a selected file cannot start scanning a different software", async () => {
  await mount();
  const response = pending<{ items: { key_id: string; tag: string }[] }>();
  vi.mocked(get).mockReturnValueOnce(response.promise);
  await select();
  expect(FakeWorker.all).toHaveLength(0);
  id.value = "8";
  await flush();
  response.resolve({ items: [{ key_id: "old-target", tag }] });
  await flush();
  expect(FakeWorker.all).toHaveLength(0);
  expect(post).not.toHaveBeenCalled();
  expect(root.textContent).not.toContain("old-target");
});
