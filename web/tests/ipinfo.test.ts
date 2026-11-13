import "./admin-bootstrap";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import { createPinia } from "pinia";
import { createMemoryHistory, createRouter } from "vue-router";
import ElementPlus from "element-plus";
import { readFileSync } from "node:fs";
import IpInfo from "../src/components/IpInfo.vue";
import IpAttribution from "../src/components/IpAttribution.vue";
import PortalLayout from "../src/layouts/PortalLayout.vue";
import DataTable from "../src/components/DataTable.vue";
import { clearPortal, portalSession } from "../src/lib/session";
let app: App | undefined;
let root: HTMLElement;
beforeEach(() => {
  root = document.createElement("div");
  document.body.append(root);
  clearPortal();
});
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.remove();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  clearPortal();
});
function mount(component: Parameters<typeof createApp>[0]) {
  app = createApp(component);
  app.use(ElementPlus);
  app.use(createPinia());
  app.use(
    createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/:pathMatch(.*)*", component: { render: () => null } }],
    }),
  );
  app.mount(root);
}
const complete = {
  scope: "public",
  country_code: "CN",
  country: "China",
  region: "上海",
  city: "Shanghai",
  asn: 4134,
  as_org: "China Telecom",
};
it.each([
  [undefined, ""],
  [complete, "中国 Shanghai · AS4134 China Telecom"],
  [{ scope: "public", city: "Paris" }, "Paris"],
  [{ scope: "public", asn: 15169, as_org: "Google LLC" }, "AS15169 Google LLC"],
  [{ scope: "private" }, "内网"],
  [{ scope: "loopback" }, "本机"],
  [{ scope: "unknown" }, "未知"],
  [{ scope: "public" }, ""],
  [{ country_code: "bad", country: "服务端国家名" }, "服务端国家名"],
  [{ country_code: "ZZ", country: "备用名称" }, "备用名称"],
  [{ country_code: "XX", country: "备用名称" }, "备用名称"],
  [
    { country_code: "", country: "原始名称", asn: 0, as_org: "No ASN" },
    "原始名称",
  ],
  [
    { country_code: "US", region: "California", city: "San Jose" },
    "美国 San Jose",
  ],
])("统一 IP 展示状态 %j", async (info, expected) => {
  mount({ render: () => h(IpInfo, { ip: "8.8.*.*", info }) });
  await nextTick();
  expect(root.querySelector(".ip-info-address")?.textContent).toBe("8.8.*.*");
  expect(
    root.querySelector(".ip-info-address")?.classList.contains("code-value"),
  ).toBe(true);
  if (expected)
    expect(root.querySelector(".ip-info-details")?.textContent).toBe(expected);
  else expect(root.querySelector(".ip-info-details")).toBeNull();
  expect(root.textContent).not.toContain("8.8.8.8");
});
it("无效国家码和 Intl 转换失败时使用服务端名称，ASN 0 不显示", async () => {
  vi.spyOn(Intl, "DisplayNames").mockImplementation(function () {
    throw new RangeError("unsupported");
  });
  mount({
    render: () =>
      h(IpInfo, {
        ip: "x",
        info: {
          country_code: "CN",
          country: "回退名称",
          city: "原文城市",
          asn: 0,
        },
      }),
  });
  await nextTick();
  expect(root.textContent).toContain("回退名称 原文城市");
  expect(root.textContent).not.toContain("AS0");
});
it("不执行服务端字段中的 HTML", async () => {
  mount({
    render: () =>
      h(IpInfo, {
        ip: "<img src=x onerror=alert(1)>",
        info: {
          city: "<script>bad</script>",
          asn: 1,
          as_org: "<b>network</b>",
        },
      }),
  });
  await nextTick();
  expect(root.querySelector("img,script,b")).toBeNull();
  expect(root.textContent).toContain("<script>");
});
it("公网第二行始终存在，紧凑展示国家城市和 ASN，省份仅在完整说明中", async () => {
  const info = {
    scope: "public",
    country_code: "US",
    country: "United States",
    region: "California",
    city: "Mountain View",
    asn: 15169,
    as_org: "Google LLC",
  };
  mount({ render: () => h(IpInfo, { ip: "8.8.8.8", info, compact: true }) });
  await nextTick();
  const details = root.querySelector<HTMLElement>(".ip-info-details")!;
  expect(details.textContent).toBe("美国 Mountain View · AS15169 Google LLC");
  expect(details.getAttribute("title")).toBe(
    "美国 California Mountain View · AS15169 Google LLC",
  );
  expect(details.getAttribute("aria-hidden")).toBeNull();
  expect(root.querySelector(".ip-info-address")?.getAttribute("title")).toBe(
    details.title,
  );
  expect(root.querySelector(".ip-info-asn")?.textContent).toBe("AS15169");
  expect(root.querySelector(".ip-info-truncated")).toBeNull();
  const css = readFileSync("src/styles/base.css", "utf8");
  expect(css).not.toContain(".ip-info-compact.ip-info-truncated");
  expect(css).toMatch(/\.ip-info-compact \.ip-info-asn,[\s\S]*?flex: none/);
  expect(css).toContain("text-overflow: ellipsis");
});
it("接近真实数据的完整说明仍通过键盘和悬浮提示可读", async () => {
  const info = {
    ...complete,
    country_code: "US",
    region: "California",
    city: "Mountain View",
    asn: 15169,
    as_org: "Google LLC",
  };
  mount({ render: () => h(IpInfo, { ip: "8.8.8.8", info, compact: true }) });
  await nextTick();
  root.querySelector<HTMLElement>(".ip-info")!.focus();
  await vi.waitFor(() =>
    expect(
      [...document.querySelectorAll('[role="tooltip"]')].some(
        (node) =>
          node.textContent ===
          "美国 California Mountain View · AS15169 Google LLC",
      ),
    ).toBe(true),
  );
});

it("共用表格对 IP/最近 IP 使用统一组件，手机副本不采用紧凑模式", async () => {
  mount({
    render: () =>
      h(DataTable, {
        items: [{ id: 1, ip: "8.8.*.*", ip_info: complete }],
        columns: [
          { key: "id", title: "编号" },
          { key: "ip", title: "来源 IP" },
        ],
      }),
  });
  await nextTick();
  expect(root.querySelector(".table-scroll .ip-info-compact")).not.toBeNull();
  expect(root.querySelector(".table-cards .ip-info")).not.toBeNull();
  expect(root.querySelector(".table-cards .ip-info-compact")).toBeNull();
  expect(
    root.querySelector(".table-cards .ip-info-details")?.textContent,
  ).toContain("中国");
});
it.each([true, false])("署名组件按开关显示与隐藏：%s", async (visible) => {
  mount({ render: () => h(IpAttribution, { visible }) });
  await nextTick();
  const link = root.querySelector("a");
  if (visible) {
    expect(link?.getAttribute("href")).toBe("https://db-ip.com");
    expect(root.textContent).toContain("IP 地理位置数据由 DB-IP.com 提供");
  } else expect(link).toBeNull();
});
it("用户中心页脚使用会话公开字段，未启用或上传库不显示署名，不请求管理接口", async () => {
  mount(PortalLayout);
  await nextTick();
  expect(root.querySelector("footer .ip-attribution")).toBeNull();
  portalSession.ipInfoDBIP = true;
  await nextTick();
  expect(root.querySelector("footer .ip-attribution")?.textContent).toContain(
    "DB-IP.com",
  );
  portalSession.ipInfoDBIP = false;
  await nextTick();
  expect(root.querySelector("footer .ip-attribution")).toBeNull();
  expect(readFileSync("src/layouts/PortalLayout.vue", "utf8")).not.toContain(
    "/system/ip-info",
  );
  expect(readFileSync("src/router/index.ts", "utf8")).toContain(
    "session.ip_info_dbip === true",
  );
});
it("原有所有 IP 入口复用 DataTable/IpInfo，设置页存在操作入口", () => {
  expect(readFileSync("src/components/PortalRecords.vue", "utf8")).toContain(
    "DataTable",
  );
  expect(readFileSync("src/views/portal/UserCenterView.vue", "utf8")).toContain(
    "PortalRecords",
  );
  for (const file of [
    "admin/ActivationsView.vue",
    "admin/LicenseDetailView.vue",
    "admin/UserDetailView.vue",
    "portal/PortalInstancesView.vue",
  ]) {
    expect(readFileSync(`src/views/${file}`, "utf8")).toContain("DataTable");
  }
  expect(
    readFileSync("src/views/admin/ObservationsView.vue", "utf8"),
  ).toContain('key: "ip"');
  expect(readFileSync("src/views/portal/PortalView.vue", "utf8")).toContain(
    ':info="device.ip_info"',
  );
  expect(readFileSync("src/views/admin/SettingsView.vue", "utf8")).toContain(
    'label="IP 库"',
  );
});
