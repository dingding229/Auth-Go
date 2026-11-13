import "./admin-bootstrap";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, nextTick, type App } from "vue";
import ElementPlus, { ElMessageBox } from "element-plus";
import { AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import IpDatabaseSettings from "../src/components/IpDatabaseSettings.vue";
import { http, ipDatabaseTimeout } from "../src/lib/http";
import { setAdmin } from "../src/lib/session";
let app: App | undefined;
let root: HTMLElement;
const previous = http.defaults.adapter;
const db = {
  source: "db-ip",
  database_type: "DBIP-City-Lite",
  data_date: "2026-11-01T00:00:00Z",
  size: 123456789,
  updated_at: "2026-11-07T00:00:00Z",
};
let state: Record<string, unknown>;
let calls: InternalAxiosRequestConfig[];
let failUpload = false;
let holdUpload = false;
let pending: (() => void) | undefined;
beforeEach(() => {
  root = document.createElement("div");
  document.body.append(root);
  setAdmin("test-admin", "test-refresh");
  state = { enabled: false, last_error: "" };
  calls = [];
  failUpload = false;
  holdUpload = false;
  pending = undefined;
  http.defaults.adapter = async (config) => {
    calls.push(config);
    if (
      config.method === "post" &&
      ["/system/ip-info/city", "/system/ip-info/asn"].includes(config.url || "")
    ) {
      expect(config.data).toBeInstanceOf(FormData);
      expect(config.timeout).toBe(ipDatabaseTimeout);
      config.onUploadProgress?.({
        loaded: 50,
        total: 100,
        bytes: 50,
        lengthComputable: true,
      });
      if (holdUpload)
        await new Promise<void>((resolve) => {
          pending = resolve;
        });
      if (failUpload)
        return {
          config,
          status: 200,
          statusText: "OK",
          headers: new AxiosHeaders(),
          data: {
            code: "INVALID_REQUEST",
            message: "MMDB 库类型不匹配，请上传对应的 City 或 ASN 库",
          },
        };
      state = {
        ...state,
        enabled: true,
        [config.url!.endsWith("city") ? "city" : "asn"]: {
          ...db,
          source: "upload",
        },
      };
    }
    if (config.method === "post" && config.url === "/system/ip-info/enable") {
      await new Promise<void>((resolve) => {
        pending = resolve;
      });
      state = { enabled: true, city: db, asn: db, last_error: "" };
    }
    if (config.method === "delete") state = { enabled: false, last_error: "" };
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data: state },
    };
  };
});
afterEach(() => {
  pending?.();
  app?.unmount();
  app = undefined;
  root.remove();
  http.defaults.adapter = previous;
  vi.restoreAllMocks();
});
async function mount() {
  app = createApp(IpDatabaseSettings);
  app.use(ElementPlus);
  app.mount(root);
  await vi.waitFor(() => expect(root.textContent).toContain("未启用"));
}
function button(label: string) {
  const b = [...root.querySelectorAll("button")].find(
    (node) => node.textContent?.trim() === label,
  );
  expect(b, label).toBeTruthy();
  return b!;
}
async function upload(kind: string, filename = `${kind}.mmdb`) {
  const input = root.querySelector<HTMLInputElement>(
    `input[aria-label="选择 ${kind} MMDB 文件"]`,
  )!;
  expect(input.accept).toBe(".mmdb");
  Object.defineProperty(input, "files", {
    configurable: true,
    value: [new File(["fake-db"], filename)],
  });
  input.dispatchEvent(new Event("change"));
  await nextTick();
}
it("启用和立即更新使用长超时、进行中状态及互斥按钮；状态分别展示 City 与 ASN", async () => {
  await mount();
  button("启用并下载").click();
  await vi.waitFor(() => expect(pending).toBeDefined());
  expect(root.textContent).toContain("可能需要数分钟");
  expect(button("启用并下载").disabled).toBe(true);
  expect(button("上传 City 库").disabled).toBe(true);
  const enable = calls.find((c) => c.url?.endsWith("/enable"))!;
  expect(enable.timeout).toBeGreaterThanOrEqual(4 * 60 * 1000);
  pending!();
  pending = undefined;
  await vi.waitFor(() => expect(root.textContent).toContain("已启用"));
  expect(root.querySelectorAll(".ipdb-file")).toHaveLength(2);
  expect(root.textContent).toContain("117.7 MiB");
  expect(root.textContent).toContain("2026-11-01");
  expect(root.textContent).toContain("IP 地理位置数据由 DB-IP.com 提供");
  button("立即更新").click();
  await vi.waitFor(() =>
    expect(calls.some((c) => c.url?.endsWith("/update"))).toBe(true),
  );
  expect(calls.find((c) => c.url?.endsWith("/update"))?.timeout).toBe(
    ipDatabaseTimeout,
  );
});
it("City 与 ASN 分别上传，上传库不显示 DB-IP 署名", async () => {
  await mount();
  for (const kind of ["City", "ASN"]) {
    await upload(kind);
    await vi.waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.url === `/system/ip-info/${kind.toLowerCase()}` &&
            c.method === "post",
        ),
      ).toBe(true),
    );
    await vi.waitFor(() =>
      expect(button(`上传 ${kind} 库`).disabled).toBe(false),
    );
  }
  expect(root.textContent).toContain("管理员上传");
  expect(root.querySelector(".ip-attribution")).toBeNull();
});
it("错误文件扩展名本地拒绝，选错库展示服务端中文原因并保留旧状态", async () => {
  await mount();
  await upload("City", "database.gz");
  expect(root.textContent).toContain("请选择 .mmdb 文件");
  expect(calls.filter((c) => c.method === "post")).toHaveLength(0);
  failUpload = true;
  await upload("City");
  await vi.waitFor(() =>
    expect(root.textContent).toContain(
      "MMDB 库类型不匹配，请上传对应的 City 或 ASN 库",
    ),
  );
  expect(root.textContent).toContain("未启用");
});
it("停用删除需要明确确认，取消不发请求，确认后才删除", async () => {
  await mount();
  const confirm = vi
    .spyOn(ElMessageBox, "confirm")
    .mockRejectedValueOnce("cancel")
    .mockResolvedValueOnce("confirm");
  button("停用并删除").click();
  await vi.waitFor(() => expect(confirm).toHaveBeenCalledTimes(1));
  expect(confirm.mock.calls[0]![0]).toContain(
    "删除服务器上的 City、ASN 数据库文件",
  );
  await vi.waitFor(() => expect(button("停用并删除").disabled).toBe(false));
  expect(calls.some((c) => c.method === "delete")).toBe(false);
  button("停用并删除").click();
  await vi.waitFor(() =>
    expect(calls.some((c) => c.method === "delete")).toBe(true),
  );
  expect(calls.find((c) => c.method === "delete")?.url).toBe("/system/ip-info");
});
it("错误状态保留可恢复操作且显示安全文案", async () => {
  state = {
    enabled: false,
    last_error: "IP 库状态文件损坏，请重新启用、上传或删除恢复",
  };
  await mount();
  expect(root.textContent?.split(String(state.last_error))).toHaveLength(2);
  expect(root.querySelectorAll(".ipdb-error")).toHaveLength(1);
  expect(root.querySelector(".ipdb-files")?.textContent).not.toContain(
    String(state.last_error),
  );
  expect(root.querySelector(".ipdb-files")?.textContent).not.toContain(
    "最近错误",
  );
  expect(button("上传 City 库").disabled).toBe(false);
  expect(button("启用并下载").disabled).toBe(false);
});

it("上传显示进度且操作互斥，完成后恢复按钮", async () => {
  await mount();
  holdUpload = true;
  await upload("City");
  await vi.waitFor(() => expect(pending).toBeDefined());
  expect(root.textContent).toContain("正在上传数据库");
  expect(
    root.querySelector('[role="progressbar"]')?.getAttribute("aria-valuenow"),
  ).toBe("50");
  expect(button("上传 City 库").disabled).toBe(true);
  expect(button("上传 ASN 库").disabled).toBe(true);
  pending!();
  pending = undefined;
  await vi.waitFor(() => expect(button("上传 City 库").disabled).toBe(false));
  expect(root.querySelector('[role="progressbar"]')).toBeNull();
});
it("超大文件在发送前拒绝，不分配大文件或执行上传", async () => {
  await mount();
  const input = root.querySelector<HTMLInputElement>(
    'input[aria-label="选择 City MMDB 文件"]',
  )!;
  const file = new File(["small"], "large.mmdb");
  Object.defineProperty(file, "size", { value: 512 * 1024 * 1024 + 1 });
  Object.defineProperty(input, "files", { configurable: true, value: [file] });
  input.dispatchEvent(new Event("change"));
  await nextTick();
  expect(root.textContent).toContain("MMDB 超过 512 MiB 上限");
  expect(calls.filter((c) => c.method === "post")).toHaveLength(0);
});
