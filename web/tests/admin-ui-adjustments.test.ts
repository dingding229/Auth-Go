import "./admin-bootstrap";
vi.mock("../src/lib/files", () => ({ saveBlob: vi.fn() }));
import { saveBlob } from "../src/lib/files";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, nextTick, type App, type Component } from "vue";
import { createPinia } from "pinia";
import { createRouter, createMemoryHistory } from "vue-router";
import ElementPlus, { ElMessage } from "element-plus";
import { AxiosHeaders } from "axios";
import { http } from "../src/lib/http";
import { clearAdmin, setAdmin } from "../src/lib/session";
import ConnectionConfig from "../src/components/ConnectionConfig.vue";
import FeatureTemplates from "../src/components/FeatureTemplates.vue";
import IpDatabaseSettings from "../src/components/IpDatabaseSettings.vue";
import IpInfo from "../src/components/IpInfo.vue";
import SettingsView from "../src/views/admin/SettingsView.vue";
import AdminLayout from "../src/layouts/AdminLayout.vue";
import SDKExamples from "../src/components/SDKExamples.vue";
import { announcementExamples, sdkLanguages } from "../src/lib/sdk-examples";
import { internalIP } from "../src/lib/ip";
import {
  INTERNAL_TRUSTED_PROXIES,
  CLOUDFLARE_TRUSTED_PROXIES,
} from "../src/lib/trusted-proxies";
const adapter = http.defaults.adapter;
let app: App | undefined, root: HTMLElement;
const clipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
afterEach(() => {
  app?.unmount();
  app = undefined;
  root?.remove();
  http.defaults.adapter = adapter;
  clearAdmin();
  vi.restoreAllMocks();
  ElMessage.closeAll();
  if (!clipboard) Reflect.deleteProperty(navigator, "clipboard");
  if (clipboard) Object.defineProperty(navigator, "clipboard", clipboard);
});
function respond(
  handler: (
    url: string,
    method: string,
    body: unknown,
  ) => unknown | Promise<unknown>,
) {
  http.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
    data: {
      code: "OK",
      data: await handler(
        String(config.url),
        String(config.method),
        config.data ? JSON.parse(String(config.data)) : undefined,
      ),
    },
  });
}
async function mount(
  component: Component,
  props: Record<string, unknown> = {},
) {
  root = document.createElement("div");
  document.body.append(root);
  setAdmin("access", "refresh");
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/:pathMatch(.*)*", component }],
  });
  await router.push("/admin/applications/7");
  app = createApp(component, props);
  app.use(createPinia()).use(ElementPlus).use(router);
  app.mount(root);
}
function buttons(name: string) {
  return [...root.querySelectorAll<HTMLButtonElement>("button")].filter(
    (n) => n.textContent?.trim() === name,
  );
}
it("接入配置只保留一组按钮，等待地址加载后可以显示并复制", async () => {
  let release: ((v: unknown) => void) | undefined;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  let reveals = 0;
  respond(async (url, method) => {
    if (url === "/system/settings") return pending;
    if (url.endsWith("/connection") && method === "post") {
      reveals++;
      return { config: "authgo2.visible-configuration" };
    }
    if (url === "/applications/7")
      return { docker_image: "example/app", app_key: "app" };
    if (url.endsWith("/publishing"))
      return {
        repository: "",
        branch: "main",
        language: "Go",
        mode: "cli",
        encrypted: false,
      };
    return { items: [] };
  });
  const writeText = vi.fn(async () => {});
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
  await mount(ConnectionConfig, {
    id: "7",
    application: { docker_image: "org/repo", app_key: "app_test" },
  });
  await nextTick();
  expect(buttons("显示接入配置")).toHaveLength(1);
  expect(buttons("显示接入配置")[0]?.disabled).toBe(true);
  if (!release) throw new Error("地址请求未初始化");
  release({ public_url: "https://license.example" });
  await vi.waitFor(() =>
    expect(buttons("显示接入配置")[0]?.disabled).toBe(false),
  );
  buttons("显示接入配置")[0]?.click();
  await vi.waitFor(() =>
    expect(root.querySelector(".connection-value")?.textContent).toBe(
      "authgo2.visible-configuration",
    ),
  );
  expect(reveals).toBe(1);
  expect(buttons("复制接入配置")).toHaveLength(1);
  expect(root.querySelector(".copy-field")).toBeNull();
  buttons("复制接入配置")[0]?.click();
  await vi.waitFor(() =>
    expect(writeText).toHaveBeenCalledWith("authgo2.visible-configuration"),
  );
});
it("功能模板空列表只有标题行的新建入口，排序在筛选行", async () => {
  respond(() => ({ items: [], total: 0 }));
  await mount(FeatureTemplates, { id: "7" });
  await vi.waitFor(() =>
    expect(root.querySelector(".table-empty")?.textContent).toContain(
      "还没有功能模板",
    ),
  );
  expect(buttons("新建功能模板")).toHaveLength(1);
  expect(root.querySelector(".table-empty button")).toBeNull();
  expect(root.querySelector(".filter-bar")?.textContent).toContain("排序字段");
  expect(root.querySelector(".panel-heading")?.textContent).not.toContain(
    "排序字段",
  );
});
it("IP 库计划展示默认月度UTC时刻，并只提交可编辑设置", async () => {
  const writes: unknown[] = [];
  const initial = {
    enabled: false,
    last_error: "",
    schedule: {
      enabled: false,
      cron: "0 3 1 * *",
      last_result: "尚未同步",
      failures: 0,
    },
  };
  respond((url, method, body) => {
    if (method === "patch") {
      expect(url).toBe("/system/ip-info/schedule");
      writes.push(body);
      return {
        ...initial,
        schedule: {
          ...initial.schedule,
          ...(body as object),
          next_run_at: "2026-12-01T03:00:00Z",
        },
      };
    }
    return initial;
  });
  await mount(IpDatabaseSettings);
  await vi.waitFor(() =>
    expect(root.querySelector(".ipdb-schedule")).not.toBeNull(),
  );
  expect(root.textContent).toContain("UTC");
  expect(root.textContent).toContain("替换管理员上传");
  (root.querySelector(".ipdb-schedule .el-switch") as HTMLElement).click();
  await nextTick();
  root
    .querySelector(".ipdb-schedule")
    ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() =>
    expect(writes).toEqual([
      {
        enabled: true,
        cron: "0 3 1 * *",
      },
    ]),
  );
  expect(root.textContent).toContain("2026-12-01T03:00:00.000Z");
  expect(root.textContent).toContain("本地：");
  for (const [label, cron] of [
    ["每天", "0 3 * * *"],
    ["每周一", "0 3 * * 1"],
    ["每月", "0 3 1 * *"],
  ]) {
    buttons(`${label} ${cron}`)[0]!.click();
    await nextTick();
    expect(
      root.querySelector<HTMLInputElement>(
        '.ipdb-schedule input[placeholder="0 3 1 * *"]',
      )?.value,
    ).toBe(cron);
  }
});
it("IP 库未启用时也标注内网，七语言提供公告示例", async () => {
  for (const ip of [
    "10.1.1.1",
    "10.*.*.*",
    "172.19.*.*",
    "192.168.*.*",
    "172.19.1.2",
    "192.168.1.1",
    "127.0.0.1",
    "169.254.0.1",
    "::1",
    "fd12::1",
    "fe80::1",
    "::ffff:192.168.1.1",
  ])
    expect(internalIP(ip), ip).toBe(true);
  for (const ip of ["8.8.8.8", "198.51.100.7", "2001:4860::8888", "bad"])
    expect(internalIP(ip), ip).toBe(false);
  await mount(IpInfo, { ip: "172.19.1.2" });
  await nextTick();
  expect(root.textContent).toContain("内网");
  app?.unmount();
  app = undefined;
  root.remove();
  for (const language of sdkLanguages.filter((v) => v !== "其他语言"))
    expect(announcementExamples[language]).toMatch(/[Aa]nnouncements\(/);
  await mount(SDKExamples);
  await nextTick();
  for (const title of [
    "1. 选择语言",
    "2. 安装 SDK",
    "3. 接入代码",
    "4. 构建与发布",
    "获取并显示公告",
  ])
    expect(root.textContent).toContain(title);
  expect(
    root.querySelectorAll(".json-block button").length,
  ).toBeGreaterThanOrEqual(3);
});

it("设置响应缺少站点名时保留已有名称，不显示 undefined", async () => {
  let read = false;
  respond(() => ({
    get site_name() {
      read = true;
      return undefined;
    },
  }));
  await mount(AdminLayout);
  await vi.waitFor(() => expect(read).toBe(true));
  expect(root.textContent).toContain("Auth Go");
  expect(root.textContent).not.toContain("undefined");
});

it("限流提示不阻止超出推荐范围的值，突发小于速率时禁止保存", async () => {
  const writes: unknown[] = [];
  let settings = {
    trial_days: 14,
    public_url: "",
    site_name: "Auth Go",
    trusted_proxies: [],
    client_ip_rate: 10,
    client_ip_burst: 60,
    client_license_rate: 5,
    client_license_burst: 30,
    log_retention_days: 90,
    notification_retention_days: 30,
    admin_notification_emails: [],
    smtp: {},
  };
  respond((url, method, body) => {
    if (url === "/system/settings") {
      if (method === "patch") {
        writes.push(body);
        settings = { ...settings, ...(body as object) };
      }
      return settings;
    }
    if (url === "/applications/gateway") return { public_key: "" };
    if (url === "/system/updates") return { poll_minutes: 10 };
    return { items: [] };
  });
  await mount(SettingsView);
  await vi.waitFor(() =>
    expect(root.querySelector('[data-field="client_ip_rate"]')).not.toBeNull(),
  );
  const field = (key: string) =>
    root.querySelector<HTMLElement>(`[data-field="${key}"]`)!;
  const change = async (key: string, value: string) => {
    const input = field(key).querySelector<HTMLInputElement>("input")!;
    input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    input.dispatchEvent(new Event("blur", { bubbles: true }));
    await nextTick();
  };
  const submit = () =>
    field("client_ip_rate")
      .closest("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  for (const [key, hint] of [
    ["client_ip_rate", "默认 10，推荐 5–50"],
    ["client_ip_burst", "默认 60，推荐 30–300"],
    ["client_license_rate", "默认 5，推荐 1–20"],
    ["client_license_burst", "默认 30，推荐 10–100"],
  ])
    expect(field(key).textContent).toContain(hint);
  await change("client_ip_rate", "51");
  expect(field("client_ip_rate").textContent).toContain("超出推荐范围");
  submit();
  await vi.waitFor(() => expect(writes).toEqual([{ client_ip_rate: 51 }]));
  await vi.waitFor(() =>
    expect(
      field("client_ip_rate").querySelector<HTMLInputElement>("input")
        ?.disabled,
    ).toBe(false),
  );
  await change("client_ip_burst", "50");
  submit();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("突发容量不能小于对应的速率"),
  );
  expect(writes).toHaveLength(1);
  await change("client_ip_burst", "60");
  await change("client_license_burst", "4");
  submit();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("突发容量不能小于对应的速率"),
  );
  expect(writes).toHaveLength(1);
});

it("受信代理按钮合并当前草稿，不自动保存且不重置其他字段", async () => {
  const writes: unknown[] = [];
  let settingsReads = 0;
  let settings = {
    trial_days: 14,
    public_url: "",
    site_name: "Auth Go",
    trusted_proxies: ["203.0.113.8"],
    client_ip_rate: 10,
    client_ip_burst: 60,
    client_license_rate: 5,
    client_license_burst: 30,
    log_retention_days: 90,
    notification_retention_days: 30,
    admin_notification_emails: [],
    smtp: {},
  };
  respond((url, method, body) => {
    if (url === "/system/settings") {
      if (method === "patch") {
        writes.push(body);
        settings = { ...settings, ...(body as object) };
      } else settingsReads++;
      return settings;
    }
    if (url === "/applications/gateway") return { public_key: "" };
    if (url === "/system/updates") return { poll_minutes: 10 };
    return { items: [] };
  });
  const message = vi.spyOn(ElMessage, "success");
  await mount(SettingsView);
  await vi.waitFor(() =>
    expect(
      root.querySelector('[data-field="trusted_proxies"] textarea'),
    ).not.toBeNull(),
  );
  const textarea = root.querySelector<HTMLTextAreaElement>(
    '[data-field="trusted_proxies"] textarea',
  )!;
  textarea.value = `203.0.113.8\n 198.51.100.42 \n ${INTERNAL_TRUSTED_PROXIES[0]} \n\n${INTERNAL_TRUSTED_PROXIES[0]}`;
  textarea.dispatchEvent(new Event("input", { bubbles: true }));
  const siteName = root.querySelector<HTMLInputElement>(
    '[data-field="site_name"] input',
  )!;
  siteName.value = "尚未保存的站点";
  siteName.dispatchEvent(new Event("input", { bubbles: true }));
  await nextTick();
  buttons("填入内网默认")[0]!.click();
  await nextTick();
  const internal = [
    "203.0.113.8",
    "198.51.100.42",
    ...INTERNAL_TRUSTED_PROXIES,
  ];
  expect(textarea.value.split("\n")).toEqual(internal);
  expect(writes).toEqual([]);
  expect(siteName.value).toBe("尚未保存的站点");
  buttons("填入 Cloudflare")[0]!.click();
  await nextTick();
  const expected = [...internal, ...CLOUDFLARE_TRUSTED_PROXIES];
  expect(textarea.value.split("\n")).toEqual(expected);
  buttons("填入 Cloudflare")[0]!.click();
  await nextTick();
  expect(textarea.value.split("\n")).toEqual(expected);
  expect(writes).toEqual([]);
  expect(settingsReads).toBe(1);
  expect(siteName.value).toBe("尚未保存的站点");
  expect(message).toHaveBeenCalledWith(
    "已填入，保存后生效。Cloudflare 网段偶有调整，请定期对照官网。",
  );
  textarea
    .closest("form")!
    .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() =>
    expect(writes).toEqual([
      { trusted_proxies: expected, site_name: "尚未保存的站点" },
    ]),
  );
});

it("Cloudflare 检测提示仅在网段未填全时显示", async () => {
  respond((url) => {
    if (url === "/system/settings")
      return {
        cloudflare_ip_seen: true,
        site_name: "Auth Go",
        trusted_proxies: [],
        client_ip_rate: 10,
        client_ip_burst: 60,
        client_license_rate: 5,
        client_license_burst: 30,
        smtp: {},
      };
    return { items: [] };
  });
  await mount(SettingsView);
  const warning =
    "最近记录到的客户端 IP 属于 Cloudflare 节点，请点击“填入 Cloudflare”并保存。";
  await vi.waitFor(() => expect(root.textContent).toContain(warning));
  buttons("填入 Cloudflare")[0]!.click();
  await nextTick();
  expect(root.textContent).not.toContain(warning);
});
it("备份密码只放请求体，填写下载加密包，留空沿用 ZIP 下载", async () => {
  const exports: { method: string; url: string; body?: unknown }[] = [];
  const name = "authgo-20261116T030000Z-test.db";
  http.defaults.adapter = async (config) => {
    let data: unknown = { items: [] };
    let headers = new AxiosHeaders();
    if (config.url === "/system/settings")
      data = { site_name: "Auth Go", trusted_proxies: [], smtp: {} };
    if (config.url === "/system/backups")
      data = {
        items: [{ name, size: 100, created_at: "2026-11-16T03:00:00Z" }],
      };
    if (String(config.url).startsWith("/system/backups/")) {
      const encrypted = config.method === "post";
      exports.push({
        method: String(config.method),
        url: String(config.url),
        body: config.data ? JSON.parse(String(config.data)) : undefined,
      });
      data = new Blob(["backup bytes"]);
      headers = new AxiosHeaders({
        "content-type": encrypted
          ? "application/octet-stream"
          : "application/zip",
        "content-disposition": `attachment; filename="${name}.zip${encrypted ? ".enc" : ""}"`,
      });
      return { config, status: 200, statusText: "", headers, data };
    }
    return {
      config,
      status: 200,
      statusText: "",
      headers,
      data: { code: "OK", data },
    };
  };
  await mount(SettingsView);
  const desktopDownload = () =>
    buttons("下载完整包").filter((button) => button.closest(".table-scroll"));
  await vi.waitFor(() => {
    expect(desktopDownload()).toHaveLength(1);
    expect(
      buttons("下载完整包").filter((button) => button.closest(".table-cards")),
    ).toHaveLength(1);
  });
  const tab = [...root.querySelectorAll<HTMLElement>('[role="tab"]')].find(
    (node) => node.textContent === "数据库备份",
  )!;
  tab.click();
  await vi.waitFor(() =>
    expect(
      root.querySelector('[role="tab"][aria-selected="true"]')?.textContent,
    ).toBe("数据库备份"),
  );
  const input = root.querySelector<HTMLInputElement>(
    'input[aria-label="备份下载密码"]',
  )!;
  input.value = "private backup password";
  input.dispatchEvent(new Event("input", { bubbles: true }));
  await nextTick();
  desktopDownload()[0]!.click();
  await vi.waitFor(() => expect(exports).toHaveLength(1));
  await vi.waitFor(() => expect(input.value).toBe(""));
  expect(exports[0]).toEqual({
    method: "post",
    url: `/system/backups/${name}/export`,
    body: { password: "private backup password" },
  });
  expect(root.textContent).not.toContain("private backup password");
  expect(saveBlob).toHaveBeenCalledWith(expect.any(Blob), name + ".zip.enc");
  await vi.waitFor(() =>
    expect(desktopDownload()[0]?.disabled).toBe(false),
  );
  desktopDownload()[0]!.click();
  await vi.waitFor(() => expect(exports).toHaveLength(2));
  expect(exports[1]).toEqual({
    method: "get",
    url: `/system/backups/${name}`,
    body: undefined,
  });
});
