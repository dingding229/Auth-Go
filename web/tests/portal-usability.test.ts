import "./admin-bootstrap";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App, type Component } from "vue";
import { createPinia } from "pinia";
import { createMemoryHistory, createRouter, RouterView } from "vue-router";
import { AxiosHeaders } from "axios";
import ElementPlus from "element-plus";
import PortalLicensesView from "../src/views/portal/PortalLicensesView.vue";
import PortalInstancesView from "../src/views/portal/PortalInstancesView.vue";
import UserCenterView from "../src/views/portal/UserCenterView.vue";
import PortalView from "../src/views/portal/PortalView.vue";
import FeatureTable from "../src/components/FeatureTable.vue";
import { portalHttp } from "../src/lib/http";
import { clearPortal, portalSession, setPortal } from "../src/lib/session";
import { readFileSync } from "node:fs";
let root: HTMLElement, app: App | undefined;
beforeEach(() => {
  root = document.createElement("div");
  document.body.append(root);
  clearPortal();
  portalHttp.defaults.adapter = async (config) => ({
    config,
    data: { code: "OK", data: { items: [], total: 0, smtp_configured: false } },
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
  });
});
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.remove();
});
async function mountPage(component: Component, path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path, component, meta: { title: "我的授权" } }],
  });
  await router.push(path);
  app = createApp({ render: () => h(RouterView) });
  app.use(createPinia()).use(ElementPlus).use(router);
  app.mount(root);
  return router;
}
function respond(data: Record<string, unknown>) {
  portalHttp.defaults.adapter = async (config) => ({
    config,
    data: { code: "OK", data: data[config.url!] ?? { items: [], total: 0 } },
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
  });
}
it("无任何授权的用户中心正常显示零汇总与空状态", async () => {
  setPortal("user-token", "user");
  respond({
    "/user": {
      id: 3,
      name: "空账号",
      license_count: 0,
      instances_total: 0,
      next_expires_at: null,
    },
    "/licenses": { items: [], total: 0 },
    "/user/instances": { items: [], total: 0 },
    "/login/options": { smtp_configured: false },
  });
  await mountPage(UserCenterView, "/portal/home");
  await vi.waitFor(() => expect(portalSession.user.id).toBe(3));
  await vi.waitFor(() =>
    expect(root.textContent).toContain("还没有授权，请联系管理员发放"),
  );
  expect(root.textContent).toContain("我的概览");
  expect(root.textContent).not.toContain("我的用户中心");
  expect(root.textContent).not.toContain("暂无到期");
  expect(root.textContent).toContain("还没有实例绑定");
  expect(
    root.querySelectorAll(".user-overview-stats > .stat-card"),
  ).toHaveLength(3);
  expect(
    [...root.querySelectorAll(".user-overview-stats .stat-number")].map((p) =>
      p.textContent?.trim(),
    ),
  ).toEqual(["0", "—", "0"]);
  expect(root.querySelector(".el-alert--error")).toBeNull();
  const source = readFileSync("src/styles/layout.css", "utf8");
  expect(source).toMatch(
    /grid-template-columns:\s*repeat\(3,\s*minmax\(0,\s*1fr\)\)/,
  );
  expect(source).toMatch(/@media\s*\(max-width:\s*767px\)/);
});
it("授权概览展示授权码，去掉技术编号与组合规则，空功能项不渲染", async () => {
  setPortal("license-token");
  portalSession.license = {
    id: 11,
    key: "AUTH-TEST-LICENSE",
    type: "standard",
    status: "active",
    features: {},
    verify_methods: ["KEY", "DEVICE"],
    remaining_unbinds: 3,
  };
  await mountPage(PortalView, "/portal/license");
  await nextTick();
  expect(root.textContent).toContain("授权码");
  expect(root.textContent).toContain("AUTH-TEST-LICENSE");
  expect(root.textContent).not.toContain("授权编号");
  expect(root.textContent).not.toContain("规则组合");
  expect(root.querySelector(".license-features")).toBeNull();
  expect(root.textContent).not.toContain("{}");
});
it("功能项按键值表展示，保留布尔和大整数，不展示原始JSON", async () => {
  app = createApp(FeatureTable, {
    value: {
      导出: true,
      配额: BigInt("18446744073709551615"),
      说明: { 区域: "中国" },
    },
  });
  app.use(ElementPlus);
  app.mount(root);
  await nextTick();
  expect(root.querySelectorAll(".license-features tbody tr")).toHaveLength(3);
  await vi.waitFor(() => expect(root.textContent).toContain("导出"));
  expect(root.textContent).toContain("是");
  expect(root.textContent).toContain("18446744073709551615");
  expect(root.textContent).toContain("区域：中国");
  expect(root.querySelector("pre")).toBeNull();
  expect(root.textContent).not.toContain("{");
});
it("用户中心实例释放不受已删除的解绑次数限制", async () => {
  setPortal("user-token", "user");
  portalSession.user = { id: 3, license_count: 2, instances_total: 2 };
  respond({
    "/licenses": { items: [], total: 0 },
    "/user/instances": {
      items: [
        {
          id: 1,
          hostname: "无额度",
          kind: "floating",
          status: "active",
          remaining_unbinds: 0,
        },
        {
          id: 2,
          hostname: "有额度",
          kind: "floating",
          status: "active",
          remaining_unbinds: 3,
        },
      ],
      total: 2,
    },
    "/login/options": { smtp_configured: false },
  });
  await mountPage(PortalInstancesView, "/portal/instances");
  await vi.waitFor(() => expect(root.textContent).toContain("无额度"));
  expect(root.textContent).not.toContain("解绑次数已用完，请联系管理员");
  const buttons = [
    ...root.querySelectorAll<HTMLButtonElement>(".table-scroll button"),
  ].filter((b) => b.textContent?.trim() === "释放实例");
  expect(buttons).toHaveLength(2);
  expect(buttons[0]!.disabled).toBe(false);
  expect(buttons[1]!.disabled).toBe(false);
});
it.each([0, 3])(
  "我的实例忽略旧剩余%d次，释放按钮保持可用",
  async (remaining) => {
    setPortal("license-token");
    portalSession.license = {
      id: 11,
      status: "active",
      remaining_unbinds: remaining,
      unbind_cooldown_seconds: 0,
    };
    respond({
      "/activations": {
        items: [
          { id: 1, hostname: "电脑", kind: "floating", status: "active" },
        ],
      },
    });
    await mountPage(PortalView, "/portal/activations");
    await vi.waitFor(() => expect(root.textContent).toContain("释放实例"));
    const button = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
      (b) => b.textContent?.trim() === "释放实例",
    )!;
    expect(button.disabled).toBe(false);
    expect(root.textContent?.includes("解绑次数已用完，请联系管理员")).toBe(
      false,
    );
  },
);

it("只有KEY激活的用户：卡片、设备汇总和设备空状态口径一致，零设备不显示分页", async () => {
  setPortal("user-token", "user");
  respond({
    "/user": {
      id: 3,
      name: "KEY用户",
      license_count: 1,
      instances_total: 0,
      next_expires_at: null,
    },
    "/licenses": {
      items: [
        {
          id: 11,
          key: "AUTH-ABCDE-FGHIJ-KLMNP-QRSTU",
          app_name: "记账软件",
          status: "active",
          active_instances: 0,
          online_instances: 0,
          max_activations: 2,
          verify_methods: ["KEY"],
          unlimited_instances: true,
          active_activations: 3,
        },
      ],
      total: 1,
    },
    "/user/instances": { items: [], total: 0 },
    "/login/options": { smtp_configured: false },
  });
  await mountPage(
    {
      render: () =>
        h("div", [
          h(UserCenterView),
          h(PortalLicensesView),
          h(PortalInstancesView),
        ]),
    },
    "/portal/home",
  );
  await vi.waitFor(() =>
    expect(root.querySelector(".user-license-card")?.textContent).toContain(
      "在线实例：0/不限",
    ),
  );
  expect(root.querySelector(".user-license-card")?.textContent).not.toContain(
    "在线实例：3",
  );
  expect(
    [...root.querySelectorAll(".user-overview-stats .stat-number")].map((el) =>
      el.textContent?.trim(),
    ),
  ).toEqual(["1", "—", "0"]);
  expect(root.textContent).toContain("还没有实例绑定");
  const devices = [...root.querySelectorAll(".section-panel")].find(
    (el) => el.querySelector("h2")?.textContent === "我的全部实例",
  );
  expect(devices?.querySelector(".list-pager")).toBeNull();
});
