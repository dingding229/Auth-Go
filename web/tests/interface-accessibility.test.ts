import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import { createRouter, createMemoryHistory } from "vue-router";
import ElementPlus from "element-plus";
import { AxiosHeaders } from "axios";
import { http } from "../src/lib/http";
import LicenseDetailView from "../src/views/admin/LicenseDetailView.vue";
import {
  activationQuota,
  deviceUsage,
  effectiveDays,
  keyTail,
} from "../src/lib/presentation";
import { label } from "../src/lib/labels";
import StatusBadge from "../src/components/StatusBadge.vue";
import { readFileSync } from "node:fs";
let app: App | undefined, root: HTMLElement | undefined;
const adapter = http.defaults.adapter;
afterEach(() => {
  app?.unmount();
  app = undefined;
  root?.remove();
  http.defaults.adapter = adapter;
  vi.restoreAllMocks();
});
it("KEY绑定文案是授权码；永久授权天数为空；KEY没有绑定额度，浮动席位仍有额度", () => {
  expect(label("key")).toBe("授权码");
  expect(label("KEY")).toBe("授权码");
  expect(effectiveDays({ validity_rule: "perpetual", duration_days: 0 })).toBe(
    "—",
  );
  expect(
    effectiveDays({ validity_rule: "after_activation", duration_days: 30 }),
  ).toBe("30");
  expect(
    activationQuota({ verify_methods: ["KEY"], max_activations: 2 }, true),
  ).toBe("不限（仅授权码）");
  expect(
    deviceUsage({
      verify_methods: ["KEY"],
      active_activations: 3,
      max_activations: 2,
    }),
  ).toBe("3/不限");
  expect(
    deviceUsage({
      verify_methods: ["KEY", "DEVICE"],
      active_activations: 1,
      max_activations: 5,
    }),
  ).toBe("1/5");
  expect(
    activationQuota({
      verify_methods: ["KEY", "FLOATING"],
      max_activations: 5,
    }),
  ).toBe("5");
  expect(keyTail("AUTH-ABCDE-FGHIJ-KLMNP-QRSTU")).toBe("QRSTU");
});
it("授权详情显示软件名称链接、不显示永久天数0；头部复制和状态位于标题行", async () => {
  const license = {
    id: 11,
    app_id: 7,
    app_name: "记账软件",
    key: "AUTH-ABCDE-FGHIJ-KLMNP-QRSTU",
    status: "active",
    type: "standard",
    verify_methods: ["KEY"],
    validity_rule: "perpetual",
    duration_days: 0,
    max_activations: 2,
    active_activations: 3,
    features: {},
    metadata: {},
  };
  http.defaults.adapter = async (config) => ({
    config,
    headers: new AxiosHeaders(),
    status: 200,
    statusText: "OK",
    data: {
      code: "OK",
      data: config.url === "/licenses/11" ? license : { items: [], total: 0 },
    },
  });
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/admin/licenses/:id", component: LicenseDetailView },
      { path: "/admin/applications/:id", component: { template: "<div/>" } },
    ],
  });
  await router.push("/admin/licenses/11");
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(LicenseDetailView);
  app.use(ElementPlus).use(router);
  app.mount(root);
  await vi.waitFor(() => expect(root!.textContent).toContain("记账软件"));
  const item = (name: string) =>
    [...root!.querySelectorAll(".key-value-item")].find(
      (el) => el.querySelector("dt")?.textContent?.trim() === name,
    )!;
  expect(item("软件").querySelector("a")?.getAttribute("href")).toBe(
    "/admin/applications/7",
  );
  expect(item("软件").querySelector("dd")?.textContent?.trim()).toBe(
    "记账软件",
  );
  expect(item("有效天数").querySelector("dd")?.textContent?.trim()).toBe("—");
  expect(item("最大激活数").textContent).toContain("不限（仅授权码）");
  expect(
    root.querySelector(".page-title-line .copy-field")?.textContent,
  ).toContain(license.key);
  expect(root.querySelector(".page-title-line .status-badge")).not.toBeNull();
  expect(root.querySelector(".license-banner")).toBeNull();
  expect(root.querySelector(".page-heading")?.textContent).not.toContain(
    "返回列表",
  );
  expect(root.querySelector(".page-heading")?.textContent).not.toContain(
    "复制授权码",
  );
});
it("错误日志和审计结果使用显式语义徽标；未知普通状态仍neutral", async () => {
  root = document.createElement("div");
  document.body.append(root);
  app = createApp({
    render: () =>
      h("div", [
        h(StatusBadge, { value: "LICENSE_EXPIRED", kind: "danger" }),
        h(StatusBadge, { value: "403 失败", kind: "danger" }),
        h(StatusBadge, { value: "unknown" }),
      ]),
  });
  app.use(ElementPlus);
  app.mount(root);
  await nextTick();
  expect(root.querySelectorAll(".status-danger")).toHaveLength(2);
  expect(root.querySelector(".status-neutral")?.textContent).toBe("unknown");
});
it("手机表格为标题状态加两列资料，语言不换行，登录按钮全宽，测试超时统一配置", () => {
  const css = readFileSync("src/styles/base.css", "utf8"),
    overrides = readFileSync("src/styles/element-overrides.css", "utf8");
  expect(css).toContain(".table-card-title");
  expect(css).toContain(".table-card-fields");
  expect(overrides).toMatch(
    /\.el-segmented__group\s*\{[^}]*flex-wrap:\s*nowrap/,
  );
  expect(overrides).toContain("text-align: left");
  expect(overrides).toContain(".login-panel .el-button");
  expect(readFileSync("vitest.config.ts", "utf8")).toMatch(
    /testTimeout:\s*20000/,
  );
});

it.each([0, 3])(
  "授权详情有%d条KEY激活：无设备不显示矛盾空态，全部为空时显示指引",
  async (count) => {
    const items = Array.from({ length: count }, (_, i) => ({
      id: i + 1,
      kind: "key",
      hostname: `激活${i + 1}`,
      value: `binding-${i}`,
      status: "active",
    }));
    const license = {
      id: 11,
      app_id: 7,
      app_name: "软件",
      key: "AUTH-ABCDE-FGHIJ-KLMNP-QRSTU",
      status: "active",
      type: "standard",
      user_id: null,
      verify_methods: ["KEY"],
      validity_rule: "perpetual",
      features: {},
      metadata: {},
    };
    http.defaults.adapter = async (config) => ({
      config,
      headers: new AxiosHeaders(),
      status: 200,
      statusText: "OK",
      data: {
        code: "OK",
        data:
          config.url === "/licenses/11"
            ? license
            : config.url === "/licenses/11/activations"
              ? { items, total: items.length }
              : { items: [], total: 0 },
      },
    });
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: "/admin/licenses/:id", component: LicenseDetailView },
        { path: "/admin/applications/:id", component: { template: "<div/>" } },
        { path: "/portal/login", component: { template: "<div/>" } },
      ],
    });
    await router.push("/admin/licenses/11");
    root = document.createElement("div");
    document.body.append(root);
    app = createApp(LicenseDetailView);
    app.use(ElementPlus).use(router);
    app.mount(root);
    if (count) {
      await vi.waitFor(() => expect(root!.textContent).toContain("激活3"));
      expect(root.textContent).not.toContain("还没有运行实例");
      const details = root.querySelector("details.activation-section")!;
      expect(details.querySelector(".list-pager")).not.toBeNull();
      const headers = [...details.querySelectorAll("th .cell")].map((el) =>
        el.textContent?.trim(),
      );
      expect(headers).not.toContain("编号");
      expect(headers).not.toContain("授权码");
    } else {
      await vi.waitFor(() =>
        expect(root!.textContent).toContain("还没有运行实例"),
      );
      expect(root.querySelector(".activation-section .list-pager")).toBeNull();
    }
  },
);

it("设备页完整授权码通过既有授权查询解析，并保留URL license_id筛选", async () => {
  const { default: ActivationsView } =
    await import("../src/views/admin/ActivationsView.vue");
  const calls: { url?: string; params?: Record<string, unknown> }[] = [];
  const key = "AUTH-ABCDE-FGHIJ-KLMNP-QRSTU";
  http.defaults.adapter = async (config) => {
    calls.push({ url: config.url, params: config.params });
    return {
      config,
      headers: new AxiosHeaders(),
      status: 200,
      statusText: "OK",
      data: {
        code: "OK",
        data:
          config.url === "/licenses"
            ? { items: [{ id: 42, key }], total: 1 }
            : { items: [], total: 0 },
      },
    };
  };
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/admin/activations", component: ActivationsView }],
  });
  await router.push("/admin/activations?license_id=42");
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(ActivationsView);
  app.use(ElementPlus).use(router);
  app.mount(root);
  await vi.waitFor(() =>
    expect(
      calls.some(
        (c) =>
          c.url === "/activations" && String(c.params?.license_id) === "42",
      ),
    ).toBe(true),
  );
  expect(root.querySelector('[data-filter="license_id"]')).toBeNull();
  const input = root.querySelector<HTMLInputElement>(".filter-bar input")!;
  input.value = key;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  await nextTick();
  root
    .querySelector<HTMLFormElement>(".filter-bar")!
    .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() =>
    expect(
      calls.some((c) => c.url === "/licenses" && c.params?.q === key),
    ).toBe(true),
  );
  await vi.waitFor(() =>
    expect(
      calls.filter((c) => c.url === "/activations").length,
    ).toBeGreaterThanOrEqual(2),
  );
  await vi.waitFor(() =>
    expect(
      calls.filter((c) => c.url === "/activations").at(-1)?.params,
    ).toMatchObject({ license_id: 42 }),
  );
  expect(
    calls.filter((c) => c.url === "/activations").at(-1)?.params?.q,
  ).toBeUndefined();
});
