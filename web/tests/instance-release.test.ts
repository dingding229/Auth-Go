import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, nextTick, type App } from "vue";
import { createMemoryHistory, createRouter } from "vue-router";
import ElementPlus, { ElMessageBox } from "element-plus";
import { AxiosHeaders } from "axios";
import { http } from "../src/lib/http";
import { setAdmin } from "../src/lib/session";
import ActivationsView from "../src/views/admin/ActivationsView.vue";
import LicenseDetailView from "../src/views/admin/LicenseDetailView.vue";
let app: App | undefined;
let root: HTMLElement;
const adapter = http.defaults.adapter;
afterEach(() => {
  app?.unmount();
  root?.remove();
  ElMessageBox.close();
  http.defaults.adapter = adapter;
});
it.each([
  { view: ActivationsView, path: "/admin/activations" },
  { view: LicenseDetailView, path: "/admin/licenses/1" },
])("释放成功后实例行从管理页面消失：$path", async ({ view, path }) => {
  setAdmin("access", "refresh");
  let released = false;
  const record = {
    id: 2,
    license_id: 1,
    kind: "floating",
    instance_id: "ab".repeat(32),
    hostname: "release-instance-worker",
    status: "active",
    lease_expires_at: new Date(Date.now() + 60000).toISOString(),
  };
  http.defaults.adapter = async (config) => {
    if (
      config.method === "post" &&
      config.url === "/activations/2/release-seat"
    )
      released = true;
    const data =
      config.url === "/licenses/1"
        ? {
            id: 1,
            key: "AUTH-ABCDE-FGHJK-LMNPQ-RSTUV",
            status: "active",
            verify_methods: ["KEY", "FLOATING"],
            max_activations: 1,
          }
        : String(config.url).includes("activations")
          ? { items: released ? [] : [record], total: released ? 0 : 1 }
          : { items: [], total: 0 };
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data },
    };
  };
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      {
        path:
          view === LicenseDetailView
            ? "/admin/licenses/:id"
            : "/admin/activations",
        component: view,
      },
    ],
  });
  await router.push(path);
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(view);
  app.use(ElementPlus).use(router);
  app.mount(root);
  await nextTick();
  if (view === LicenseDetailView) {
    const tab = [...root.querySelectorAll<HTMLElement>('[role="tab"]')].find(
      (el) => el.textContent === "实例",
    );
    tab?.click();
  }
  await vi.waitFor(() =>
    expect(root.textContent).toContain("release-instance-worker"),
  );
  for (const old of ["设备", "绑定方式", "绑定值", "IP地址绑定", "域名绑定"])
    expect(root.textContent).not.toContain(old);
  const button = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
    (el) => el.textContent?.trim() === "释放席位",
  )!;
  button.click();
  await vi.waitFor(() =>
    expect(document.querySelector(".el-message-box")).not.toBeNull(),
  );
  const confirm = [
    ...document.querySelectorAll<HTMLButtonElement>(".el-message-box button"),
  ].find((el) => el.textContent?.trim() === "释放席位")!;
  confirm.click();
  await vi.waitFor(() => expect(released).toBe(true));
  await vi.waitFor(() =>
    expect(root.textContent).not.toContain("release-instance-worker"),
  );
});
