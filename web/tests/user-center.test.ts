import "./admin-bootstrap";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import { createPinia } from "pinia";
import { createMemoryHistory, createRouter, RouterView } from "vue-router";
import { AxiosHeaders } from "axios";
import ElementPlus from "element-plus";
import PortalLicensesView from "../src/views/portal/PortalLicensesView.vue";
import PortalAccountView from "../src/views/portal/PortalAccountView.vue";
import PortalLicenseDetailView from "../src/views/portal/PortalLicenseDetailView.vue";
import UserCenterView from "../src/views/portal/UserCenterView.vue";
import ApplicationDetailView from "../src/views/admin/ApplicationDetailView.vue";
import { http, portalHttp } from "../src/lib/http";
import {
  clearPortal,
  portalSession,
  setPortal,
  setAdmin,
} from "../src/lib/session";
let root: HTMLElement, app: App | undefined;
beforeEach(() => {
  root = document.createElement("div");
  document.body.append(root);
  clearPortal();
});
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.remove();
});
it("用户中心展示汇总并用服务端切换结果更新当前授权", async () => {
  setPortal("user-token", "user");
  portalSession.user = {
    id: 3,
    name: "张三",
    license_count: 2,
    instances_total: 1,
    next_expires_at: "2030-01-01T00:00:00Z",
  };
  const requests: string[] = [];
  portalHttp.defaults.adapter = async (config) => {
    requests.push(config.url!);
    let data: unknown = { items: [], total: 0 };
    if (config.url === "/user")
      data = {
        id: 3,
        name: "张三",
        license_count: 2,
        instances_total: 1,
        next_expires_at: "2030-01-01T00:00:00Z",
      };
    if (config.url === "/licenses/11")
      data = {
        id: 11,
        app_name: "软件一",
        status: "active",
        features: {},
        verify_methods: ["KEY", "DEVICE"],
        deployment: { available: false, reason: "未配置镜像" },
      };
    if (config.url === "/licenses")
      data = {
        items: [
          { id: 11, app_name: "软件一", key: "KEY1", status: "active" },
          { id: 12, app_name: "软件二", key: "KEY2", status: "unused" },
        ],
        total: 2,
      };
    if (config.url === "/login/options") data = { smtp_configured: false };
    if (config.url === "/switch")
      data = {
        portal_token: "selected-token",
        license: {
          id: 11,
          app_name: "软件一",
          verify_methods: ["KEY", "DEVICE"],
        },
      };
    return {
      config,
      data: { code: "OK", data },
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
    };
  };
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", component: UserCenterView },
      { path: "/portal/licenses", component: PortalLicensesView },
      { path: "/portal/account", component: PortalAccountView },
      { path: "/portal/licenses/:id", component: PortalLicenseDetailView },
    ],
  });
  await router.push("/");
  app = createApp({ render: () => h(RouterView) });
  app.use(createPinia()).use(ElementPlus).use(router);
  app.mount(root);
  await vi.waitFor(() => expect(root.textContent).toContain("名下授权数量"));
  expect(root.textContent).toContain("名下授权数量");
  expect(root.textContent).toContain("最近到期");
  expect(root.textContent).toContain("实例总数");
  await router.push("/portal/account");
  await vi.waitFor(() =>
    expect(root.textContent).toContain("修改用户中心密码"),
  );
  await router.push("/portal/licenses");
  await vi.waitFor(() => expect(root.textContent).toContain("软件二"));
  [...root.querySelectorAll("a")]
    .find((b) => b.textContent?.trim() === "查看授权")!
    .click();
  await vi.waitFor(() =>
    expect(router.currentRoute.value.path).toBe("/portal/licenses/11"),
  );
  await vi.waitFor(() => expect(portalSession.token).toBe("selected-token"));
  expect(portalSession.license.id).toBe(11);
  expect(portalSession.scope).toBe("user");
  expect(requests).toContain("/switch");
});
it("软件详情默认接入标签，技术信息仅在高级折叠区", async () => {
  setAdmin("access", "refresh");
  http.defaults.adapter = async (config) => ({
    config,
    data: {
      code: "OK",
      data:
        config.url === "/applications/7"
          ? {
              id: 7,
              name: "软件甲",
              description: "给用户使用的软件",
              app_key: "public",
              status: "active",
            }
          : config.url === "/system/settings"
            ? {}
            : { items: [], total: 0 },
    },
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
  });
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/admin/applications/:id", component: ApplicationDetailView },
    ],
  });
  await router.push("/admin/applications/7");
  app = createApp({ render: () => h(RouterView) });
  app.use(ElementPlus).use(router);
  app.mount(root);
  await vi.waitFor(() =>
    expect(root.querySelector(".technical-options")).not.toBeNull(),
  );
  await nextTick();
  expect(root.querySelector(".technical-options")?.hasAttribute("open")).toBe(
    false,
  );
  expect(
    root.querySelector('[role="tab"][aria-selected="true"]')?.textContent,
  ).toContain("接入程序");
  const descriptionItems = [...root.querySelectorAll(".el-descriptions")];
  expect(
    descriptionItems.every((item) => item.closest("details.technical-options")),
  ).toBe(true);
});
