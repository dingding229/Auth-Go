import "./admin-bootstrap";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App, type Component } from "vue";
import { createPinia } from "pinia";
import { createRouter, createMemoryHistory, RouterView } from "vue-router";
import ElementPlus, { ElMessageBox } from "element-plus";
import { AxiosHeaders, AxiosError, type AxiosAdapter } from "axios";
import LicenseSharing from "../src/components/LicenseSharing.vue";
import SharingCount from "../src/components/SharingCount.vue";
import LicensesView from "../src/views/admin/LicensesView.vue";
import { http } from "../src/lib/http";
import { setAdmin } from "../src/lib/session";
let app: App | undefined,
  root: HTMLElement,
  state: Record<string, unknown>,
  calls: { url: string; method: string; params: unknown }[];
const previous = http.defaults.adapter;
beforeEach(() => {
  root = document.createElement("div");
  document.body.append(root);
  setAdmin("synthetic-admin", "synthetic-refresh");
  calls = [];
  state = {
    available: true,
    flagged: true,
    ignored: false,
    instance_count: 4,
    countries: [
      { code: "CN", count: 2 },
      { code: "US", count: 2 },
    ],
    asns: [{ asn: 4134, org: "Synthetic Telecom", count: 4 }],
    updated_at: "2026-11-07T00:00:00Z",
    last_seen_at: "2026-11-07T00:00:00Z",
  };
  http.defaults.adapter = async (config) => {
    calls.push({
      url: config.url || "",
      method: config.method || "get",
      params: config.params,
    });
    let data: unknown = { items: [], total: 0 };
    if (config.url?.endsWith("/sharing")) data = state;
    else if (config.url?.endsWith("/sharing/ignore")) {
      state = {
        ...state,
        flagged: false,
        ignored: true,
        ignored_until: "2030-01-01T00:00:00Z",
      };
      data = state;
    } else if (config.url === "/licenses")
      data = {
        items: [
          {
            id: 42,
            key: "AUTH-TESTA-TESTB-TESTC-TESTD",
            status: "active",
            app_name: "软件",
            type: "trial",
            suspected_sharing: true,
            verify_methods: ["KEY", "FLOATING"],
            online_instances: 1,
            max_activations: 2,
          },
        ],
        total: 1,
      };
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data },
    };
  };
});
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.remove();
  http.defaults.adapter = previous;
  vi.restoreAllMocks();
});
async function mount(
  component: Component,
  props: Record<string, unknown> = {},
  path = "/",
) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: path.split("?")[0]!, component, props: () => props },
      { path: "/:pathMatch(.*)*", component: { render: () => null } },
    ],
  });
  await router.push(path);
  app = createApp({ render: () => h(RouterView) });
  app.use(createPinia()).use(ElementPlus).use(router);
  app.mount(root);
  return router;
}
it("详情复用表格显示国家和ASN实例分布、更新时间和误报说明", async () => {
  await mount(LicenseSharing, { licenseId: 42 });
  await vi.waitFor(() =>
    expect(root.textContent).toContain("Synthetic Telecom"),
  );
  expect(root.textContent).toContain("疑似共享");
  expect(root.textContent).toContain("中国 (CN)");
  expect(root.textContent).toContain("AS4134");
  expect(root.textContent).toContain("最近更新时间");
  expect(root.textContent).toContain("不会影响授权");
  expect(root.textContent).toContain("去重公网 IP");
  expect(root.querySelectorAll(".data-table")).toHaveLength(2);
  expect(root.querySelector(".table-cards")).not.toBeNull();
  expect(calls[0]?.url).toBe("/licenses/42/sharing");
});
it("无标记显示明确空状态，不提供忽略按钮", async () => {
  state = {
    ...state,
    flagged: false,
    countries: [],
    asns: [],
    instance_count: 0,
  };
  await mount(LicenseSharing, { licenseId: 42 });
  await vi.waitFor(() =>
    expect(root.textContent).toContain("最近 24 小时未发现异常"),
  );
  expect(root.textContent).not.toContain("忽略此次提示");
});
it("库未启用时显示原因和系统设置链接，不展示旧标记或旧分布", async () => {
  state = { ...state, available: false };
  await mount(LicenseSharing, { licenseId: 42 });
  await vi.waitFor(() =>
    expect(root.textContent).toContain("需要先在系统设置启用 IP 库"),
  );
  expect(root.querySelector("a")?.getAttribute("href")).toBe("/admin/settings");
  expect(root.querySelector(".data-table")).toBeNull();
  expect(root.textContent).not.toContain("疑似共享");
  expect(root.textContent).not.toContain("Synthetic Telecom");
});
it("忽略需要二次确认，取消不提交，确认后显示忽略期限", async () => {
  await mount(LicenseSharing, { licenseId: 42 });
  await vi.waitFor(() => expect(root.textContent).toContain("忽略此次提示"));
  const confirm = vi
    .spyOn(ElMessageBox, "confirm")
    .mockRejectedValueOnce("cancel")
    .mockResolvedValueOnce("confirm");
  const button = () =>
    [...root.querySelectorAll<HTMLButtonElement>("button")].find(
      (v) => v.textContent?.trim() === "忽略此次提示",
    )!;
  button().click();
  await vi.waitFor(() => expect(confirm).toHaveBeenCalledTimes(1));
  await vi.waitFor(() => expect(button().disabled).toBe(false));
  expect(calls.some((v) => v.method === "post")).toBe(false);
  expect(confirm.mock.calls[0]![0]).toContain("未来30天");
  button().click();
  await vi.waitFor(() => expect(root.textContent).toContain("已忽略至"));
  expect(calls.filter((v) => v.method === "post")).toHaveLength(1);
  expect(calls.find((v) => v.method === "post")?.url).toBe(
    "/licenses/42/sharing/ignore",
  );
  expect(root.textContent).not.toContain("忽略此次提示");
});
it("已忽略状态不显示疑似共享标记", async () => {
  state = {
    ...state,
    flagged: false,
    ignored: true,
    ignored_until: "2030-01-01T00:00:00Z",
  };
  await mount(LicenseSharing, { licenseId: 42 });
  await vi.waitFor(() => expect(root.textContent).toContain("已忽略至"));
  expect(root.querySelector(".status-badge")).toBeNull();
});
it.each([0, 3])("概览数量%s只在非零时显示小型筛选链接", async (count) => {
  await mount(SharingCount, { count });
  if (count === 0) expect(root.querySelector("a")).toBeNull();
  else {
    expect(root.textContent).toContain("疑似共享 3 个授权");
    expect(root.querySelector("a")?.getAttribute("href")).toBe(
      "/admin/licenses?suspected_sharing=true",
    );
  }
});
it("授权列表与手机卡片都有小标记，URL筛选发送到服务端", async () => {
  await mount(LicensesView, {}, "/admin/licenses?suspected_sharing=true");
  await vi.waitFor(() =>
    expect(
      root.querySelector(".table-scroll [aria-label='疑似共享']"),
    ).not.toBeNull(),
  );
  expect(
    root.querySelector(".table-cards [aria-label='疑似共享']"),
  ).not.toBeNull();
  expect(
    calls.some(
      (v) =>
        v.url === "/licenses" &&
        (v.params as Record<string, unknown>)?.suspected_sharing === "true",
    ),
  ).toBe(true);
  expect(root.querySelector(".advanced-filters")?.textContent).toContain(
    "疑似共享",
  );
  const advanced = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
    (v) => v.textContent?.includes("更多筛选"),
  )!;
  advanced.click();
  await nextTick();
  expect(root.querySelector(".advanced-filters")).toBeNull();
  advanced.click();
  await nextTick();
  expect(root.querySelector(".advanced-filters")?.textContent).toContain(
    "疑似共享",
  );
});
it("读取失败显示错误和重试，不误报没有异常", async () => {
  const original = http.defaults.adapter as AxiosAdapter;
  http.defaults.adapter = async (config) => {
    if (config.url?.endsWith("/sharing"))
      throw new AxiosError("failed", "ERR_BAD_RESPONSE", config, undefined, {
        config,
        status: 500,
        statusText: "Error",
        headers: new AxiosHeaders(),
        data: { code: "INTERNAL_ERROR", message: "共享检测暂时不可用" },
      });
    return original(config);
  };
  await mount(LicenseSharing, { licenseId: 42 });
  await vi.waitFor(() =>
    expect(root.textContent).toContain("共享检测暂时不可用"),
  );
  expect(root.textContent).not.toContain("未发现异常");
  expect(root.querySelector(".request-notice button")).not.toBeNull();
});
