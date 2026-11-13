import "./admin-bootstrap";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createApp,
  defineComponent,
  h,
  nextTick,
  ref,
  type App,
  type Component,
} from "vue";
import {
  createMemoryHistory,
  createRouter,
  RouterView,
  type RouteRecordRaw,
} from "vue-router";
import ElementPlus from "element-plus";
import { AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import { http } from "../src/lib/http";
import { clearAdmin, setAdmin } from "../src/lib/session";
import { field, specs } from "../src/lib/schema";
import type { Row } from "../src/lib/json";
import ValidityControl from "../src/components/ValidityControl.vue";
import FilterBar from "../src/components/FilterBar.vue";
import CrudPanel from "../src/components/CrudPanel.vue";
import ConnectionConfig from "../src/components/ConnectionConfig.vue";
import UserDetailView from "../src/views/admin/UserDetailView.vue";
import LicensesView from "../src/views/admin/LicensesView.vue";
import DashboardView from "../src/views/admin/DashboardView.vue";
import CrudView from "../src/views/admin/CrudView.vue";
import ApplicationDetailView from "../src/views/admin/ApplicationDetailView.vue";

vi.mock("../src/components/ChartPanel.vue", () => ({
  default: { template: "<div />" },
}));
let app: App | undefined, root: HTMLElement;
let requests: InternalAxiosRequestConfig[];
const appRow = {
  id: 7,
  name: "应用甲",
  allowed_client_versions: "",
  status: "active",
};
beforeEach(() => {
  root = document.createElement("div");
  document.body.append(root);
  clearAdmin();
  setAdmin("access", "refresh", { username: "owner" });
  requests = [];
  http.defaults.adapter = async (config) => {
    requests.push(config);
    let data: Row = { items: [], total: 0 };
    if (config.url === "/applications")
      data = { items: [appRow, { id: 8, name: "应用乙" }], total: 2 };
    else if (config.url === "/users")
      data = { items: [{ id: 9, name: "用户甲" }], total: 1 };
    else if (config.url === "/applications/7") data = appRow;
    else if (config.url === "/system/settings")
      data = { public_url: "https://auth.example.com" };
    else if (config.url === "/stats/overview")
      data = {
        counts: { applications_total: 2, users_total: 1, licenses_total: 0 },
        expiring: [],
      };
    else if (config.url === "/licenses")
      data = {
        items: [
          {
            id: 11,
            app_id: 7,
            app_name: "应用甲",
            active_activations: 1,
            max_activations: 5,
            verify_methods: ["KEY", "DEVICE"],
            key: "AUTH-XXXXX-XXXXX-XXXXX-XXXXX",
            status: "unused",
            expires_at: null,
          },
        ],
        total: 1,
      };
    return {
      config,
      data: { code: "OK", data },
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
    };
  };
});
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.remove();
});
function mount(component: Component) {
  app = createApp(component);
  app.use(ElementPlus);
  return app.mount(root);
}
async function mountRoute(
  path: string,
  initial: Component,
  extra: RouteRecordRaw[] = [],
) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", component: initial },
      { path: "/admin/licenses", component: LicensesView },
      ...extra,
    ],
  });
  await router.push(path);
  await router.isReady();
  app = createApp({ render: () => h(RouterView) });
  app.use(ElementPlus).use(router);
  app.mount(root);
  return router;
}
function button(label: string) {
  const value = [...root.querySelectorAll("button")].find((b) => {
    const content = b.cloneNode(true) as HTMLElement;
    content
      .querySelectorAll('[aria-hidden="true"]')
      .forEach((node) => node.remove());
    return content.textContent?.trim() === label;
  });
  expect(value, `button ${label}`).toBeDefined();
  return value!;
}

describe("有效期控件宽度与分支", () => {
  it("根容器和下拉占满宽度，永久值可见，天数和日期附加控件保持完整", async () => {
    const rule = ref("perpetual");
    mount(
      defineComponent({
        setup: () => () =>
          h(ValidityControl, {
            rule: rule.value,
            days: 30,
            expiry: "2030-01-01T00:00:00Z",
            "onUpdate:rule": (v) => {
              rule.value = v;
            },
          }),
      }),
    );
    await nextTick();
    const control = root.querySelector<HTMLElement>(".validity-control")!;
    expect(control.style.width).toBe("100%");
    expect(parseFloat(control.style.minWidth)).toBe(0);
    expect(control.querySelector<HTMLElement>(".el-select")!.style.width).toBe(
      "100%",
    );
    expect(control.textContent).toContain("永久有效");
    expect(control.querySelector(".el-input-number")).toBeNull();
    rule.value = "fixed_days";
    await nextTick();
    expect(
      control.querySelector<HTMLInputElement>(".el-input-number input")?.value,
    ).toBe("30");
    expect(control.querySelector(".el-date-editor")).toBeNull();
    rule.value = "fixed_expiry";
    await nextTick();
    expect(control.querySelector(".el-input-number")).toBeNull();
    expect(control.querySelector(".el-date-editor")).not.toBeNull();
    expect(control.textContent).toContain("指定到期日期");
  });
});

describe("直接发放与上手引导", () => {
  it("应用弹窗的立即发放直接打开表单并选中该应用，不把create发给API", async () => {
    const router = await mountRoute(
      "/",
      defineComponent({ setup: () => () => h(ConnectionConfig, { id: "7" }) }),
    );
    button("立即发放授权").click();
    await vi.waitFor(() =>
      expect(root.querySelector(".el-drawer")).not.toBeNull(),
    );
    expect(router.currentRoute.value.path).toBe("/admin/licenses");
    expect(router.currentRoute.value.query).toEqual({ app_id: "7" });
    expect(root.querySelector(".el-drawer")?.textContent).toContain(
      "应用甲（7）",
    );
    expect(
      requests
        .filter((r) => r.url === "/licenses")
        .every((r) => !("create" in (r.params || {}))),
    ).toBe(true);
    root.querySelector<HTMLButtonElement>(".el-drawer__close-btn")!.click();
    await nextTick();

    await router.replace({
      path: "/admin/licenses",
      query: { app_id: "7", status: "active" },
    });
    await nextTick();

    expect(
      requests.filter(
        (r) => r.url === "/applications" && r.params?.page_size === 2,
      ),
    ).toHaveLength(1);
  });
  it("概览只保留一套三步引导，发放直接开表单并选应用", async () => {
    const router = await mountRoute("/", DashboardView);
    await vi.waitFor(() =>
      expect(root.querySelectorAll(".onboarding-step")).toHaveLength(4),
    );
    await vi.waitFor(() => expect(button("接入程序").disabled).toBe(false));
    expect(root.querySelectorAll(".el-steps")).toHaveLength(0);
    expect(
      root.querySelector(".onboarding-step.is-complete")?.textContent,
    ).toContain("✓");
    button("发放授权").click();
    await vi.waitFor(() =>
      expect(root.querySelector(".el-drawer")).not.toBeNull(),
    );
    expect(router.currentRoute.value.query.app_id).toBe("7");
    expect(router.currentRoute.value.query.user_id).toBe("9");
  });
  it("接入程序进入指定应用的接入标签", async () => {
    const router = await mountRoute("/", DashboardView, [
      { path: "/admin/applications/:id", component: ApplicationDetailView },
    ]);
    await vi.waitFor(() => expect(button("接入程序").disabled).toBe(false));
    button("接入程序").click();
    await vi.waitFor(() =>
      expect(
        root.querySelector('[role="tab"][aria-selected="true"]')?.textContent,
      ).toContain("接入程序"),
    );
    expect(router.currentRoute.value.path).toBe("/admin/applications/7");
    expect(router.currentRoute.value.query.tab).toBe("integration");
  });
});

describe("筛选渐进展示与URL", () => {
  it("默认只显示搜索和状态，更多筛选可展开，生效值自动展开且能重置", async () => {
    const model = ref<Row>({});
    const fields = [
      field("status", "状态", { type: "select", options: [] }),
      field("app_id", "应用", { advanced: true }),
      field("batch_id", "批次号", { advanced: true }),
    ];
    mount(
      defineComponent({
        setup: () => () =>
          h(FilterBar, {
            modelValue: model.value,
            fields,
            "onUpdate:modelValue": (v) => {
              model.value = v;
            },
          }),
      }),
    );
    await nextTick();
    expect(root.querySelector(".advanced-filters")).toBeNull();
    expect(root.querySelectorAll(".query-field")).toHaveLength(2);
    button("更多筛选").click();
    await nextTick();
    expect(root.querySelector('[data-filter="app_id"]')).not.toBeNull();
    button("收起更多筛选").click();
    await nextTick();
    model.value = { app_id: "7", batch_id: "batch_甲" };
    await nextTick();
    expect(root.querySelector(".advanced-filters")).not.toBeNull();
    expect(
      root.querySelector<HTMLInputElement>('[data-filter="app_id"] input')
        ?.value,
    ).toBe("7");
    expect(button("收起更多筛选（2）").getAttribute("aria-expanded")).toBe(
      "true",
    );
    button("清除筛选").click();
    await nextTick();
    expect(model.value).toEqual({});
    expect(root.querySelector(".advanced-filters")).toBeNull();
  });
  it("URL带入高级筛选立即展开且API继续筛选，重置同时清除URL", async () => {
    const router = await mountRoute(
      "/admin/licenses?app_id=7&batch_id=batch_url",
      LicensesView,
    );
    await vi.waitFor(() =>
      expect(root.querySelector(".advanced-filters")?.textContent).toContain(
        "批次号",
      ),
    );
    expect(
      root.querySelector<HTMLInputElement>('[data-filter="batch_id"] input')
        ?.value,
    ).toBe("batch_url");
    await vi.waitFor(() =>
      expect(
        root.querySelector('[data-filter="app_id"]')?.textContent,
      ).toContain("应用甲（7）"),
    );
    expect(
      requests.some(
        (r) =>
          r.url === "/licenses" &&
          r.params.app_id === "7" &&
          r.params.batch_id === "batch_url",
      ),
    ).toBe(true);
    button("清除筛选").click();
    await vi.waitFor(() => expect(router.currentRoute.value.query).toEqual({}));
    await vi.waitFor(() =>
      expect(
        requests.filter((r) => r.url === "/licenses").at(-1)?.params.app_id,
      ).toBeUndefined(),
    );
    expect(root.querySelector(".advanced-filters")).toBeNull();
  });
  it("应用列表只保留搜索，不显示排序与运行状态筛选", async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/", component: { template: "<div />" } }],
    });
    app = createApp(CrudPanel, { spec: specs.applications });
    app.use(ElementPlus).use(router);
    app.mount(root);
    await nextTick();
    expect(root.textContent).not.toContain("排序字段");
    expect(root.textContent).not.toContain("方向");
    expect(root.textContent).not.toContain("运行状态");
    expect(root.querySelectorAll(".filter-bar .query-field")).toHaveLength(1);
  });
  it("授权列表显示账本列和软件名称，操作列不固定遮挡状态", async () => {
    await mountRoute("/admin/licenses", LicensesView);
    await vi.waitFor(() =>
      expect(
        root.querySelector(".el-table__body-wrapper")?.textContent,
      ).toContain("应用甲"),
    );
    const headers = [
      ...root.querySelectorAll(".el-table__header-wrapper th .cell"),
    ].map((node) => node.textContent?.trim());
    expect(headers).toEqual([
      "授权码",
      "用户",
      "软件名称",
      "状态",
      "到期时间",
      "实例数",
    ]);
    expect(root.querySelector(".el-table-fixed-column--right")).toBeNull();
    // At 1024px the 216px sidebar, 48px content padding and 32px panel padding leave 728px.
    const widths = [
      ...root.querySelectorAll(".el-table__header colgroup col"),
    ].map((col) => Number(col.getAttribute("width")));
    expect(widths.every((width) => width > 0)).toBe(true);
    expect(widths.reduce((sum, width) => sum + width, 0)).toBeLessThanOrEqual(
      728,
    );
  });
});

it("只有一个软件时自动选中并隐藏软件选择，但继续提交软件编号", async () => {
  const previous = http.defaults.adapter;
  http.defaults.adapter = async (config) =>
    config.url === "/applications"
      ? {
          config,
          data: { code: "OK", data: { items: [appRow], total: 1 } },
          status: 200,
          statusText: "",
          headers: new AxiosHeaders(),
        }
      : ((previous as (c: InternalAxiosRequestConfig) => Promise<unknown>)(
          config,
        ) as never);
  await mountRoute("/admin/licenses?create=1&user_id=9", LicensesView);
  await vi.waitFor(() =>
    expect(
      root.querySelector('.el-drawer [data-field="app_id"]'),
    ).not.toBeNull(),
  );
  expect(
    root.querySelector<HTMLElement>('.el-drawer [data-field="app_id"]')!.style
      .display,
  ).toBe("none");
  expect(
    root.querySelector('.el-drawer [data-field="user_id"]'),
  ).not.toBeNull();
});

it("用户列表只留搜索，新建按钮在页面标题，操作列不固定", async () => {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/", component: CrudView, meta: { resource: "users" } }],
  });
  await router.push("/");
  app = createApp(CrudView);
  app.use(ElementPlus).use(router);
  app.mount(root);
  await nextTick();
  expect(root.textContent).not.toContain("排序字段");
  expect(root.textContent).not.toContain("方向");
  expect(root.querySelector(".page-heading")?.textContent).toContain(
    "新建用户",
  );
  expect(root.querySelector(".filter-bar")?.textContent).not.toContain(
    "新建用户",
  );
  expect(root.querySelectorAll(".filter-bar .query-field")).toHaveLength(1);
  expect(root.querySelector(".el-table-fixed-column--right")).toBeNull();
  expect(
    specs.users!.columns.reduce((sum, col) => sum + (col.width || 130), 172),
  ).toBeLessThanOrEqual(680);
});

it("用户详情的授权、设备和记录使用精简列，默认列宽均适合1024px", async () => {
  http.defaults.adapter = async (config) => {
    let data: unknown = { items: [], total: 0 };
    if (config.url === "/users/9")
      data = {
        id: 9,
        name: "用户甲",
        email: "user@example.com",
        status: "active",
      };
    if (config.url === "/licenses")
      data = {
        items: [{ id: 11, key: "AUTH-DETAIL", status: "active" }],
        total: 1,
      };
    if (config.url === "/activations")
      data = {
        items: [
          {
            id: 22,
            license_key: "AUTH-DETAIL",
            hostname: "笔记本",
            kind: "device",
            os: "Linux",
            status: "active",
          },
        ],
        total: 1,
      };
    if (config.url === "/verify-logs")
      data = {
        items: [
          {
            id: 33,
            license_key: "AUTH-DETAIL",
            action: "verify",
            code: "OK",
            ip: "192.0.2.1",
          },
        ],
        total: 1,
      };
    return {
      config,
      data: { code: "OK", data },
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
    };
  };
  await mountRoute("/admin/users/9", UserDetailView, [
    { path: "/admin/users/:id", component: UserDetailView },
  ]);
  await vi.waitFor(() => expect(root.textContent).toContain("笔记本"));
  const tables = [...root.querySelectorAll(".el-table")];
  expect(tables).toHaveLength(3);
  const headers = tables.map((table) =>
    [...table.querySelectorAll(".el-table__header-wrapper th .cell")].map(
      (cell) => cell.textContent?.trim(),
    ),
  );
  expect(headers).toEqual([
    ["授权码", "状态", "到期时间"],
    ["实例名称", "授权码", "实例 ID", "系统", "状态", "最近在线"],
    ["时间", "授权码", "操作", "结果", "来源IP"],
  ]);
  for (const table of tables) {
    expect(table.querySelector(".el-table-fixed-column--right")).toBeNull();
    const widths = [
      ...table.querySelectorAll(".el-table__header colgroup col"),
    ].map((col) => Number(col.getAttribute("width")));
    expect(widths.length).toBeGreaterThan(0);
    expect(widths.reduce((sum, width) => sum + width, 0)).toBeLessThanOrEqual(
      728,
    );
  }
});
