import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { createApp, nextTick, type App } from "vue";
import { createRouter, createMemoryHistory } from "vue-router";
import ElementPlus, { ElMessageBox } from "element-plus";
import { AxiosHeaders } from "axios";
import { http } from "../src/lib/http";
import ActivationsView from "../src/views/admin/ActivationsView.vue";
import LicenseDetailView from "../src/views/admin/LicenseDetailView.vue";
import RepositoryVersions from "../src/components/VersionManagement.vue";
import SchemaEditor from "../src/components/SchemaEditor.vue";
import { licenseFields } from "../src/lib/schema";
let app: App | undefined, root: HTMLElement;
const adapter = http.defaults.adapter;
const license = {
  id: 1,
  app_id: 7,
  app_name: "测试软件",
  key: "AUTH-ABCDE-FGHJK-LMNPQ-RSTUV",
  status: "active",
  type: "standard",
  validity_rule: "perpetual",
  verify_methods: ["KEY", "FLOATING"],
  max_activations: 1,
  features: {},
  metadata: {},
};
const instance = {
  id: 2,
  license_id: 1,
  license_key: license.key,
  kind: "floating",
  status: "active",
  instance_id: "cb02abcd".repeat(8),
  value: "cb02abcd".repeat(8),
  hostname: "worker",
  lease_expires_at: new Date(Date.now() + 3600000).toISOString(),
};
afterEach(() => {
  ElMessageBox.close();
  app?.unmount();
  app = undefined;
  root?.remove();
  http.defaults.adapter = adapter;
  vi.restoreAllMocks();
});
async function mount(
  component: Parameters<typeof createApp>[0],
  props = {},
  path = "/admin/activations",
) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/admin/licenses/:id", component: LicenseDetailView },
      { path: "/:pathMatch(.*)*", component },
    ],
  });
  await router.push(path);
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(component, props);
  app.use(ElementPlus).use(router);
  app.mount(root);
  await nextTick();
}
function stub(writes: string[]) {
  http.defaults.adapter = async (config) => {
    const url = config.url!;
    if (config.method === "post" || config.method === "patch") writes.push(url);
    const data =
      url === "/licenses/1"
        ? license
        : url.endsWith("/repository")
          ? {}
          : url.endsWith("/versions")
            ? {
                items: [
                  {
                    id: 3,
                    version: "2.0.0",
                    disabled: false,
                    mandatory: false,
                  },
                ],
              }
            : { items: [instance], total: 1 };
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data },
    };
  };
}
async function confirmWithoutDrawer(action: string, writes: string[]) {
  await vi.waitFor(() =>
    expect(document.querySelector(".el-message-box")).not.toBeNull(),
  );
  expect(document.querySelector(".el-drawer__body")).toBeNull();
  const confirm = [
    ...document.querySelectorAll<HTMLButtonElement>(
      ".el-message-box__btns button",
    ),
  ].find((b) => b.textContent?.trim() === action)!;
  expect(confirm).toBeDefined();
  expect(confirm.disabled).toBe(false);
  confirm.click();
  await vi.waitFor(() => expect(writes.length).toBe(1));
  expect(document.querySelector(".el-drawer__body")).toBeNull();
}
it.each([".table-scroll", ".table-cards"])(
  "实例行内释放席位不打开抽屉，真实确认框可完成：%s",
  async (region) => {
    const writes: string[] = [];
    stub(writes);
    await mount(ActivationsView);
    await vi.waitFor(() =>
      expect(root.querySelector(`${region} button`)).not.toBeNull(),
    );
    const button = await vi.waitFor(() => {
      const el = [
        ...root.querySelectorAll<HTMLButtonElement>(`${region} button`),
      ].find((b) => b.textContent?.trim() === "释放席位");
      expect(el).toBeDefined();
      return el!;
    });
    button.click();
    await confirmWithoutDrawer("释放席位", writes);
    expect(writes).toEqual(["/activations/2/release-seat"]);
  },
);
it("普通数据单元格仍可打开行详情；复制短号不会打开", async () => {
  stub([]);
  await mount(ActivationsView);
  await vi.waitFor(() =>
    expect(
      root.querySelector(".table-scroll .copy-field button"),
    ).not.toBeNull(),
  );
  (
    root.querySelector(".table-scroll .copy-field button") as HTMLButtonElement
  ).click();
  await nextTick();
  expect(document.querySelector(".el-drawer__body")).toBeNull();
  (
    root.querySelectorAll(
      ".table-scroll .el-table__body tr td",
    )[2] as HTMLElement
  ).click();
  await vi.waitFor(() =>
    expect(document.querySelector(".el-drawer__body")).not.toBeNull(),
  );
});
it.each([".table-scroll", ".table-cards"])(
  "授权详情实例释放席位确认可完成：%s",
  async (region) => {
    const writes: string[] = [];
    stub(writes);
    await mount(LicenseDetailView, {}, "/admin/licenses/1");
    const button = await vi.waitFor(() => {
      const el = [
        ...root.querySelectorAll<HTMLButtonElement>(`${region} button`),
      ].find((b) => b.textContent?.trim() === "释放席位");
      expect(el).toBeDefined();
      return el!;
    });
    button.click();
    await confirmWithoutDrawer("释放席位", writes);
  },
);
it.each([".table-scroll", ".table-cards"])(
  "禁用版本开关不会打开资产抽屉：%s",
  async (region) => {
    const writes: string[] = [];
    stub(writes);
    await mount(RepositoryVersions, { id: "7", appKey: "test" });
    const input = await vi.waitFor(() => {
      const node = root.querySelector<HTMLInputElement>(
        `${region} input[aria-label="禁用版本2.0.0"]`,
      );
      expect(node).not.toBeNull();
      return node!;
    });
    input.click();
    await confirmWithoutDrawer("禁用版本", writes);
    expect(writes).toEqual(["/versions/3"]);
  },
);
it("验证方式的更多选项不再嵌于零字号checkbox-group或使用分割线", async () => {
  stub([]);
  await mount(SchemaEditor, {
    fields: licenseFields,
    initial: { app_id: 7, user_id: 1 },
  });
  expect(root.querySelector(".verification-options")).toBeNull();
  const methods = root.querySelector(".verification-methods")!;
  expect(methods.querySelectorAll('input[type="checkbox"]')).toHaveLength(2);
  expect(methods.textContent).toContain("授权码");
  expect(methods.textContent).toContain("运行实例");
  for (const label of ["设备指纹", "IP地址", "域名"])
    expect(methods.textContent).not.toContain(label);
});
it("跳转链接只按focus-visible显示，页脚和面向客户文档无内部实现说明", () => {
  const css = readFileSync("src/styles/base.css", "utf8");
  expect(css).toContain(".skip-link:focus-visible");
  expect(css).not.toMatch(/\.skip-link:focus\s*\{/);
  const connection = readFileSync(
    "src/components/ConnectionConfig.vue",
    "utf8",
  );
  expect(connection).toContain("查看接入协议");
  expect(connection).not.toContain("其他语言可按统一协议实现客户端");
  const docs = readFileSync("../server/internal/apidocs/docker.md", "utf8"),
    customer = docs.split("## 给客户：")[1]!;
  expect(customer).toBeTruthy();
  expect(customer).not.toMatch(/PHP_SAPI|start_guard|instance_session|worker/);
});
