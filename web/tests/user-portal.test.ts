import "./admin-bootstrap";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App, type Component } from "vue";
import { createPinia } from "pinia";
import { createMemoryHistory, createRouter, RouterView } from "vue-router";
import ElementPlus from "element-plus";
import {
  AxiosError,
  AxiosHeaders,
  type AxiosResponse,
  type AxiosAdapter,
  type InternalAxiosRequestConfig,
} from "axios";
import { readFileSync } from "node:fs";
import PortalLayout from "../src/layouts/PortalLayout.vue";
import PortalAttention from "../src/components/PortalAttention.vue";
import PortalDeployment from "../src/components/PortalDeployment.vue";
import PortalLicenseFacts from "../src/components/PortalLicenseFacts.vue";
import SupportContactSettings from "../src/components/SupportContactSettings.vue";
import PortalLicenseDetailView from "../src/views/portal/PortalLicenseDetailView.vue";
import PortalRecords from "../src/components/PortalRecords.vue";
import PortalInstancesView from "../src/views/portal/PortalInstancesView.vue";
import PortalAccountView from "../src/views/portal/PortalAccountView.vue";
import UserCenterView from "../src/views/portal/UserCenterView.vue";
import PortalLicensesView from "../src/views/portal/PortalLicensesView.vue";
import PortalView from "../src/views/portal/PortalView.vue";
import PortalUpdate from "../src/components/PortalUpdate.vue";
import { http, portalHttp } from "../src/lib/http";
import {
  clearPortal,
  setPortal,
  portalSession,
  setAdmin,
} from "../src/lib/session";
import {
  portalPages,
  userPortalPages,
} from "../src/lib/portal-navigation";
let app: App | undefined, root: HTMLElement;
let calls: { url: string; data?: unknown; params?: unknown }[];
let owned: Record<string, unknown>;
const oldPortalAdapter = portalHttp.defaults.adapter,
  oldAdminAdapter = http.defaults.adapter;
beforeEach(() => {
  root = document.createElement("div");
  document.body.append(root);
  clearPortal();
  setPortal("email-token", "user");
  calls = [];
  owned = {
    id: 42,
    app_name: "软件",
    key: "OWN-LICENSE",
    status: "active",
    type: "standard",
    verify_methods: ["KEY", "FLOATING"],
    features: {},
    online_instances: 1,
    max_activations: 3,
    maintenance_until: "2030-01-01T00:00:00Z",
    latest_entitled_version: "2.0.0",
    deployment: {
      available: true,
      compose:
        "services:\n  app:\n    restart: unless-stopped\n    AUTHGO_LICENSE: OWN-LICENSE",
      ports_hint: "如程序需要对外提供服务，请按软件文档添加 ports",
      steps: ["docker compose up -d"],
      guide: "### 席位\n每个实例使用独立缓存卷。",
    },
  };
  portalHttp.defaults.adapter = async (config) => {
    calls.push({
      url: config.url || "",
      data: config.data,
      params: config.params,
    });
    let data: unknown = { items: [], total: 0 };
    if (config.url === "/licenses/42") data = owned;
    if (config.url === "/switch")
      data = {
        portal_token: "selected-token",
        license: {
          id: 42,
          app_name: "软件",
          verify_methods: owned.verify_methods,
          has_announcements: owned.has_announcements !== false,
          status: "active",
          remaining_unbinds: 2,
        },
      };
    if (config.url === "/user")
      data = {
        id: 3,
        name: "用户",
        email: "user@example.com",
        license_count: 1,
        instances_total: 1,
      };
    if (config.url === "/login/options") data = { smtp_configured: false };
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
  clearPortal();
  portalHttp.defaults.adapter = oldPortalAdapter;
  http.defaults.adapter = oldAdminAdapter;
  vi.restoreAllMocks();
});
async function mount(
  component: Component,
  path = "/",
  props: Record<string, unknown> = {},
) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      {
        path: path.includes("/licenses/")
          ? "/portal/licenses/:id"
          : path.split("?")[0]!,
        component,
        props: () => props,
      },
      { path: "/portal/login", component: { render: () => null } },
      {
        path: "/portal/licenses",
        component: { render: () => h("p", "授权列表") },
      },
      { path: "/:pathMatch(.*)*", component: { render: () => null } },
    ],
  });
  await router.push(path);
  app = createApp({ render: () => h(RouterView) });
  app.use(createPinia()).use(ElementPlus).use(router);
  app.mount(root);
  return router;
}
it("邮箱登录始终显示六个入口，空公告/更新仍保留；授权码登录保留原导航", async () => {
  await mount(PortalLayout);
  await nextTick();
  expect(
    [...root.querySelectorAll(".portal-nav a")].map((a) =>
      a.textContent?.trim(),
    ),
  ).toEqual(userPortalPages.map((p) => p.title));
  portalSession.scope = "license";
  portalSession.license = {
    id: 42,
    verify_methods: ["KEY"],
    has_announcements: false,
  };
  await nextTick();
  expect(
    [...root.querySelectorAll(".portal-nav a")].map((a) =>
      a.textContent?.trim(),
    ),
  ).toEqual(
    portalPages
      .filter(
        (p) =>
          ![
            "/portal/home",
            "/portal/domains",
            "/portal/announcements",
          ].includes(p.path),
      )
      .map((p) => p.title),
  );
  portalSession.license = {
    ...portalSession.license,
    verify_methods: ["KEY", "DOMAIN"],
    has_announcements: true,
  };
  await nextTick();
  expect(root.textContent).not.toContain("域名验证");
  expect(root.textContent).toContain("软件公告");
});
it("待处理空状态明确，无需选中授权", async () => {
  await mount(PortalAttention, "/", { items: [] });
  expect(root.textContent).toContain("目前没有需要处理的事项");
});
it.each([
  "expired",
  "expiring",
  "suspended",
  "unbind_exhausted",
  "update_available",
  "maintenance_expiring",
  "version_disabled",
])("待处理 %s 显示严重程度和安全跳转", async (type) => {
  await mount(PortalAttention, "/", {
    items: [
      {
        type,
        license_id: 42,
        app_name: "软件",
        severity: type === "update_available" ? "info" : "danger",
        support_contact: "联系 support@example.com",
        href: "javascript:alert(1)",
      },
    ],
  });
  const titleByType: Record<string, string> = {
    expired: "授权已过期",
    expiring: "授权将在 30 天内到期",
    suspended: "授权已暂停",
    unbind_exhausted: "解绑次数已用完",
    update_available: "有可用的新版本",
    maintenance_expiring: "维护期将在 30 天内到期",
    version_disabled: "正在运行的版本已被禁用",
  };
  expect(root.textContent).toContain(titleByType[type]);
  expect(root.querySelector(".status-badge")?.textContent).toBe(
    type === "update_available" ? "有更新" : "需尽快处理",
  );
  expect(root.querySelector("a")?.getAttribute("href")).toMatch(
    /^\/portal\/licenses\/42\?tab=/,
  );
  expect(root.innerHTML).not.toContain("javascript:");
  expect(root.textContent?.includes("support@example.com")).toBe(
    ["expired", "expiring", "maintenance_expiring"].includes(type),
  );
});
it("伪造id的404显示友好提示和返回列表，不调用switch或显示旧compose", async () => {
  const original = portalHttp.defaults.adapter;
  // APIError.status is the HTTP status, so emulate an actual rejected 404 response.
  portalHttp.defaults.adapter = async (config) => {
    calls.push({ url: config.url || "" });
    const error = new Error("404") as Error & {
      isAxiosError: boolean;
      config: typeof config;
      response: unknown;
    };
    error.isAxiosError = true;
    error.config = config;
    error.response = {
      status: 404,
      data: { code: "NOT_FOUND", message: "资源不存在" },
      headers: {},
      config,
    };
    throw error;
  };
  await mount(PortalLicenseDetailView, "/portal/licenses/999");
  await vi.waitFor(() =>
    expect(root.textContent).toContain("该授权不存在，或不属于当前账号"),
  );
  expect(root.querySelector('a[href="/portal/licenses"]')).not.toBeNull();
  expect(calls.some((c) => c.url === "/switch")).toBe(false);
  expect(root.textContent).not.toContain("OWN-LICENSE");
  portalHttp.defaults.adapter = original;
});
it("部署可用时可显式显示和复制完整compose，指南安全渲染，无效状态不显示compose", async () => {
  const compose =
    "services:\n  app:\n    restart: unless-stopped\n    AUTHGO_LICENSE: PRIVATE-OWN-KEY";
  const value = {
    available: true,
    compose,
    ports_hint: "如程序需要对外提供服务，请按软件文档添加 ports",
    steps: ["docker compose up -d"],
    guide:
      "# 常见问题\n<img src=x onerror=alert(1)>\n[坏链接](javascript:alert(1))\n\n```sh\ndocker compose logs\n```",
  };
  await mount(PortalDeployment, "/", { value });
  await nextTick();
  expect(root.textContent).toContain("请妥善保管");
  expect(root.textContent).toContain(value.ports_hint);
  expect(
    root.querySelector(".protocol-markdown img, .protocol-markdown script"),
  ).toBeNull();
  expect(root.querySelector('a[href^="javascript:"]')).toBeNull();
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
  root
    .querySelector<HTMLButtonElement>(
      'button[aria-label="显示docker-compose.yml"]',
    )!
    .click();
  await nextTick();
  root
    .querySelector<HTMLButtonElement>(
      'button[aria-label="复制docker-compose.yml"]',
    )!
    .click();
  await vi.waitFor(() => expect(writeText).toHaveBeenCalledWith(compose));
  expect(calls).toHaveLength(0); // Guide rendering never calls the admin document API.
});
it("部署不可用时只显示原因，不显示或复制compose", async () => {
  await mount(PortalDeployment, "/", {
    value: {
      available: false,
      reason: "维护期外版本需要续期",
      compose: "PRIVATE-OWN-KEY",
    },
  });
  await nextTick();
  expect(root.textContent).toContain("维护期外版本需要续期");
  expect(root.textContent).not.toContain("PRIVATE-OWN-KEY");
  expect(root.querySelector(".copy-field")).toBeNull();
});
it("试用、维护期、最高授权版本和续期提示完整显示", async () => {
  await mount(PortalLicenseFacts, "/", {
    license: {
      type: "trial",
      trial_remaining_days: 3,
      remaining_days: 3,
      maintenance_until: "2030-01-01",
      latest_entitled_version: "2.0.0",
      renewal_required: true,
      online_instances: 1,
      max_activations: 3,
    },
  });
  expect(root.textContent).toContain("剩余 3 天");
  expect(root.textContent).toContain("联系提供方转正");
  expect(root.textContent).toContain("可用版本到 2.0.0");
  expect(root.textContent).toContain("需要续期");
  expect(root.textContent).toContain("1/3");
});
it("页脚同时显示数据署名和纯文本联系方式，退出后不残留", async () => {
  portalSession.ipInfoDBIP = true;
  portalSession.supportContact = "邮箱 support@example.com <b>支持</b>";
  await mount(PortalLayout);
  await nextTick();
  expect(root.querySelector("footer")?.textContent).toContain("DB-IP.com");
  expect(root.querySelector("footer")?.textContent).toContain("<b>支持</b>");
  expect(root.querySelector("footer b")).toBeNull();
  clearPortal();
  await nextTick();
  expect(root.querySelector("footer")?.textContent).not.toContain(
    "support@example.com",
  );
});
it("支持联系方式读取、200字限制、保存与清除均走现有管理封装", async () => {
  setAdmin("admin", "refresh");
  let saved = "support@example.com";
  const adminCalls: string[] = [];
  http.defaults.adapter = async (config) => {
    adminCalls.push(`${config.method} ${config.url}`);
    if (config.method === "patch")
      saved = JSON.parse(String(config.data)).support_contact;
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data: { support_contact: saved } },
    };
  };
  await mount(SupportContactSettings);
  await vi.waitFor(() =>
    expect(root.querySelector("textarea")?.value).toBe(saved),
  );
  const input = root.querySelector<HTMLTextAreaElement>("textarea")!;
  expect(input.maxLength).toBe(200);
  input.value = "新的支持联系方式";
  input.dispatchEvent(new Event("input"));
  await nextTick();
  root
    .querySelector<HTMLFormElement>("form")!
    .dispatchEvent(new Event("submit", { cancelable: true }));
  await vi.waitFor(() => expect(saved).toBe("新的支持联系方式"));
  await vi.waitFor(() =>
    expect(
      root.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled,
    ).toBe(false),
  );
  input.value = "";
  input.dispatchEvent(new Event("input"));
  await nextTick();
  root
    .querySelector<HTMLFormElement>("form")!
    .dispatchEvent(new Event("submit", { cancelable: true }));
  await vi.waitFor(() => expect(saved).toBe(""));
  expect(adminCalls).toContain("get /system/support");
  expect(adminCalls.filter((c) => c === "patch /system/support")).toHaveLength(
    2,
  );
});
it("用户日志首次请求为10条，软件实例筛选不调用管理接口", async () => {
  await mount(PortalRecords, "/", { kind: "logs" });
  await vi.waitFor(() =>
    expect(calls.some((c) => c.url === "/user/logs")).toBe(true),
  );
  expect(calls.find((c) => c.url === "/user/logs")?.params).toMatchObject({
    page_size: 10,
  });
});
it("账号资料只读，密码入口仍然存在", async () => {
  await mount(PortalAccountView);
  await vi.waitFor(() =>
    expect(root.textContent).toContain("user@example.com"),
  );
  expect(root.textContent).toContain("由管理员维护");
  expect(root.querySelector('input[type="email"]')).toBeNull();
  expect(root.textContent).toContain("保存密码并重新登录");
});
it("实例展示脱敏IP和本地位置，软件筛选通过app_id发送", async () => {
  portalHttp.defaults.adapter = async (config) => {
    calls.push({ url: config.url || "", params: config.params });
    const data =
      config.url === "/user/updates"
        ? { items: [{ app_id: 7, app_name: "软件" }], total: 1 }
        : {
            items: [
              {
                id: 1,
                app_name: "软件",
                hostname: "实例甲",
                last_ip: "8.8.*.*",
                ip_info: {
                  country_code: "US",
                  city: "Mountain View",
                  asn: 15169,
                  as_org: "Google LLC",
                },
                remaining_unbinds: 0,
                status: "active",
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
  await mount(PortalInstancesView, "/portal/instances?app_id=7");
  await vi.waitFor(() => expect(root.textContent).toContain("实例甲"));
  for (const selector of [".el-table__body .ip-info", ".table-card .ip-info"]) {
    const info = root.querySelector(selector);
    expect(info?.querySelector(".ip-info-address")?.textContent).toBe(
      "8.8.*.*",
    );
    expect(info?.querySelector(".ip-info-details")?.textContent).toContain(
      "美国 Mountain View",
    );
    expect(info?.querySelector(".ip-info-asn")?.textContent).toBe("AS15169");
  }
  expect(calls.find((c) => c.url === "/user/instances")?.params).toMatchObject({
    app_id: "7",
  });
  expect(calls.some((c) => c.url.startsWith("/applications"))).toBe(false);
});

it("没有公告时不显示公告标签，指定公告tab回退概览", async () => {
  owned.has_announcements = false;
  await mount(PortalLicenseDetailView, "/portal/licenses/42?tab=announcements");
  await vi.waitFor(() =>
    expect(root.querySelector('[role="tab"]')).not.toBeNull(),
  );
  expect(
    [...root.querySelectorAll('[role="tab"]')].map((el) =>
      el.textContent?.trim(),
    ),
  ).not.toContain("公告");
  expect(
    root.querySelector('[role="tab"][aria-selected="true"]')?.textContent,
  ).toContain("概览");
});
it("快速切换详情时忽略迟到响应，不覆盖当前授权或显示旧部署配置", async () => {
  let resolveOld!: (value: AxiosResponse) => void;
  // Keep the first ownership request pending while navigating to another ID.
  portalHttp.defaults.adapter = async (config) => {
    if (config.url === "/licenses/42")
      return await new Promise((resolve) => {
        resolveOld = resolve;
      });
    calls.push({ url: config.url || "", data: config.data });
    const data =
      config.url === "/licenses/43"
        ? {
            ...owned,
            id: 43,
            app_name: "当前软件",
            deployment: { available: false, reason: "当前授权不可部署" },
          }
        : {
            portal_token: "current-token",
            license: { id: 43, has_announcements: false },
          };
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data },
    };
  };
  const router = await mount(
    PortalLicenseDetailView,
    "/portal/licenses/42?tab=deployment",
  );
  await vi.waitFor(() => expect(resolveOld).toBeTypeOf("function"));
  await router.push("/portal/licenses/43?tab=deployment");
  await vi.waitFor(() =>
    expect(root.textContent).toContain("当前授权不可部署"),
  );
  resolveOld({
    config: { headers: new AxiosHeaders() },
    status: 200,
    statusText: "OK",
    headers: new AxiosHeaders(),
    data: { code: "OK", data: owned },
  });
  await nextTick();
  await nextTick();
  expect(portalSession.license.id).toBe(43);
  expect(portalSession.token).toBe("current-token");
  expect(root.textContent).not.toContain("OWN-LICENSE");
  expect(calls.filter((c) => c.url === "/switch")).toHaveLength(1);
});

it("部署代码使用独立整行，手机复制控件不挤占代码宽度", () => {
  const css = readFileSync("src/styles/base.css", "utf8");
  expect(css).toMatch(
    /\.portal-deployment > \.copy-field \.copy-field-value\s*\{[^}]*width: 100%/,
  );
  expect(css).toMatch(
    /\.portal-deployment > \.copy-field \.copy-controls\s*\{[^}]*order: -1/,
  );
});

it("待处理事项超过100条时仍可翻页，单次请求不突破页大小上限", async () => {
  const original = portalHttp.defaults.adapter as (
    config: import("axios").InternalAxiosRequestConfig,
  ) => Promise<AxiosResponse>;
  portalHttp.defaults.adapter = async (config) => {
    if (config.url !== "/user/attention") return original(config);
    calls.push({ url: config.url, params: config.params });
    const page = Number(config.params.page);
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: {
          items: [
            {
              type: "expired",
              license_id: 42,
              severity: "danger",
              app_name: `第${page}页事项`,
            },
          ],
          total: 201,
        },
      },
    };
  };
  await mount(UserCenterView, "/portal/home");
  await vi.waitFor(() => expect(root.textContent).toContain("第1页事项"));
  const panel = root
    .querySelector(".portal-attention-list")!
    .closest("section")!;
  panel.querySelector<HTMLButtonElement>(".el-pagination .btn-next")!.click();
  await vi.waitFor(() => expect(root.textContent).toContain("第2页事项"));
  expect(
    calls.filter((c) => c.url === "/user/attention").at(-1)?.params,
  ).toMatchObject({ page: 2, page_size: 20 });
});

function rateFailure(config: InternalAxiosRequestConfig): never {
  throw new AxiosError("429", "ERR_BAD_RESPONSE", config, undefined, {
    config,
    status: 429,
    statusText: "Too Many Requests",
    headers: new AxiosHeaders(),
    data: { code: "RATE_LIMITED", message: "用户中心请求过于频繁" },
  });
}
it.each([
  {
    name: "我的授权",
    component: PortalLicensesView,
    path: "/portal/licenses",
    props: {},
    url: "/licenses",
    empty: "还没有授权，请联系管理员发放",
  },
  {
    name: "我的实例",
    component: PortalInstancesView,
    path: "/portal/instances",
    props: {},
    url: "/user/instances",
    empty: "还没有实例绑定",
  },
  {
    name: "验证记录",
    component: PortalRecords,
    path: "/records",
    props: { kind: "logs" },
    url: "/user/logs",
    empty: "还没有验证记录",
  },
  {
    name: "软件更新",
    component: PortalRecords,
    path: "/records",
    props: { kind: "updates" },
    url: "/user/updates",
    empty: "软件尚未发布更新",
  },
  {
    name: "公告",
    component: PortalRecords,
    path: "/records",
    props: { kind: "announcements" },
    url: "/user/announcements",
    empty: "软件尚未发布公告",
  },
  {
    name: "概览待处理",
    component: UserCenterView,
    path: "/portal/home",
    props: {},
    url: "/user/attention",
    empty: "目前没有需要处理的事项",
  },
  {
    name: "账号汇总",
    component: UserCenterView,
    path: "/portal/home",
    props: {},
    url: "/user",
    empty: "还没有授权，请联系管理员发放",
  },
  {
    name: "原验证记录页",
    component: PortalView,
    path: "/portal/logs",
    props: {},
    url: "/logs",
    empty: "还没有可显示的记录",
  },
  {
    name: "授权更新标签",
    component: PortalUpdate,
    path: "/update",
    props: { license: { id: 42, status: "active" } },
    url: "/update",
    empty: "暂无适合当前平台的更新",
  },
])(
  "$name 加载失败只显示错误，不伪装为空数据",
  async ({ component, path, props, url, empty }) => {
    const original = portalHttp.defaults.adapter as AxiosAdapter;
    portalSession.user = { license_count: 0, instances_total: 0 };
    portalHttp.defaults.adapter = async (config) =>
      config.url === url ? rateFailure(config) : original(config);
    await mount(component, path, props);
    await vi.waitFor(() =>
      expect(root.textContent).toContain("用户中心请求过于频繁"),
    );
    expect(root.textContent).not.toContain(empty);
    if (url === "/user")
      expect(root.textContent).not.toContain("还没有实例绑定");
    expect(
      [...root.querySelectorAll("button")].some(
        (b) => b.textContent?.trim() === "重试",
      ),
    ).toBe(true);
  },
);
it("授权列表错误后可以重试，只有成功返回空数据才显示空状态", async () => {
  let failed = true;
  const original = portalHttp.defaults.adapter as AxiosAdapter;
  portalHttp.defaults.adapter = async (config) =>
    config.url === "/licenses" && failed
      ? rateFailure(config)
      : original(config);
  await mount(PortalLicensesView, "/portal/licenses");
  await vi.waitFor(() =>
    expect(root.querySelector(".request-notice")).not.toBeNull(),
  );
  expect(root.querySelector(".table-empty")).toBeNull();
  failed = false;
  root.querySelector<HTMLButtonElement>(".request-notice button")!.click();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("还没有授权，请联系管理员发放"),
  );
  expect(root.querySelector(".request-notice")).toBeNull();
});
it("无在线实例时软件更新仍显示当前最新版本和可用拉取命令", async () => {
  portalHttp.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "OK",
    headers: new AxiosHeaders(),
    data: {
      code: "OK",
      data: {
        items: [
          {
            app_id: 7,
            license_id: 42,
            app_name: "容器软件",
            version: "2.0.0",
            latest_entitled_version: "2.0.0",
            has_update: false,
            current_versions: [],
            docker_pull: "docker pull example/software:2.0.0",
          },
        ],
        total: 1,
      },
    },
  });
  await mount(PortalRecords, "/updates", { kind: "updates" });
  await vi.waitFor(() =>
    expect(root.textContent).toContain("docker pull example/software:2.0.0"),
  );
  expect(root.textContent).toMatch(/当前最新版本\s*2\.0\.0/);
  expect(root.textContent).not.toContain("有可用的新版本");
});
it("授权卡片和详情的授权码换行而非裁切，复制按钮保持独立宽度", () => {
  const css = readFileSync("src/styles/base.css", "utf8");
  const layout = readFileSync("src/styles/layout.css", "utf8");
  expect(layout).toMatch(
    /\.user-license-list\s*\{[^}]*grid-template-columns: minmax\(0, 1fr\)/,
  );
  expect(layout).toMatch(/\.user-license-card\s*\{[^}]*min-width: 0/);
  expect(css).toMatch(
    /\.copy-field\.portal-license-key \.copy-field-value\s*\{[^}]*overflow: visible;[^}]*overflow-wrap: anywhere/,
  );
  for (const file of [
    "PortalLicensesView.vue",
    "PortalLicenseDetailView.vue",
    "PortalView.vue",
  ])
    expect(readFileSync(`src/views/portal/${file}`, "utf8")).toContain(
      'class="portal-license-key"',
    );
});
it("实例页的软件选项读取失败也不显示空实例，重试会重新读取选项", async () => {
  let failed = true;
  const original = portalHttp.defaults.adapter as AxiosAdapter;
  portalHttp.defaults.adapter = async (config) =>
    config.url === "/user/updates" && failed
      ? rateFailure(config)
      : original(config);
  await mount(PortalInstancesView, "/portal/instances");
  await vi.waitFor(() =>
    expect(root.textContent).toContain("用户中心请求过于频繁"),
  );
  expect(root.textContent).not.toContain("还没有实例绑定");
  failed = false;
  root.querySelector<HTMLButtonElement>(".request-notice button")!.click();
  await vi.waitFor(() => expect(root.textContent).toContain("还没有实例绑定"));
  expect(root.querySelector(".request-notice")).toBeNull();
});

it("软件没有版本时使用清晰标题，不显示空发布时间和空更新说明", async () => {
  portalHttp.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "OK",
    headers: new AxiosHeaders(),
    data: {
      code: "OK",
      data: {
        items: [
          {
            app_id: 7,
            license_id: 42,
            app_name: "星河图床",
            version: "",
            published_at: null,
            changelog: "",
            has_update: false,
          },
        ],
        total: 1,
      },
    },
  });
  await mount(PortalRecords, "/portal/updates", { kind: "updates" });
  await vi.waitFor(() =>
    expect(
      root
        .querySelector(".portal-record h2")
        ?.textContent?.replace(/\s+/g, " ")
        .trim(),
    ).toBe("星河图床 · 暂无可用版本"),
  );
  expect(root.textContent).not.toContain("当前最新版本");
  expect(root.textContent).not.toContain("发布时间");
  expect(root.textContent).not.toContain("暂无更新说明");
  expect(root.querySelector(".announcement-body")).toBeNull();
});
