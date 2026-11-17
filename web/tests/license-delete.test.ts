import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, nextTick, type App } from "vue";
import { createMemoryHistory, createRouter } from "vue-router";
import ElementPlus, { ElMessageBox } from "element-plus";
import { AxiosHeaders } from "axios";
import LicenseDetailView from "../src/views/admin/LicenseDetailView.vue";
import LicensesView from "../src/views/admin/LicensesView.vue";
import { http } from "../src/lib/http";
import { setAdmin } from "../src/lib/session";
import { parseJSON, type Row } from "../src/lib/json";
import { canDeleteLicense } from "../src/lib/licenses";

let app: App | undefined, root: HTMLElement;
const original = http.defaults.adapter;
afterEach(() => {
  ElMessageBox.close();
  app?.unmount();
  app = undefined;
  root?.remove();
  http.defaults.adapter = original;
  vi.restoreAllMocks();
});
const license = {
  id: 1,
  app_id: 7,
  key: "AUTH-ABCDE-FGHJK-LMNPQ-RSTUV",
  status: "revoked",
  type: "standard",
  source: "",
  verify_methods: ["KEY"],
  match_mode: "all",
  validity_rule: "perpetual",
  features: {},
  metadata: {},
};
async function mount(detail: boolean, row = license) {
  setAdmin("admin", "refresh");
  const writes: Row[] = [];
  http.defaults.adapter = async (config) => {
    if (config.method === "delete" || config.method === "post")
      writes.push({
        method: config.method,
        path: config.url,
        data: config.data ? parseJSON(config.data) : undefined,
      });
    const data =
      config.url === "/licenses/1"
        ? row
        : config.url === "/licenses/purge-revoked"
          ? { count: 1 }
          : { items: [row], total: 1 };
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data },
    };
  };
  const component = detail ? LicenseDetailView : LicensesView;
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/admin/licenses/:id", component: LicenseDetailView },
      { path: "/admin/licenses", component: LicensesView },
    ],
  });
  await router.push(detail ? "/admin/licenses/1" : "/admin/licenses");
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(component).use(ElementPlus).use(router);
  app.mount(root);
  await vi.waitFor(() => expect(root.textContent).toContain(row.key));
  return { writes, router };
}
it.each(["unused", "active", "expired", "suspended", "revoked"])(
  "正式授权 %s 的删除入口仅限吊销状态",
  async (status) => {
    const row = { ...license, status };
    await mount(false, row);
    expect(canDeleteLicense(row)).toBe(status === "revoked");
    const buttons = [...root.querySelectorAll("button")].filter(
      (b) => b.textContent?.trim() === "删除",
    );
    expect(buttons.length > 0).toBe(status === "revoked");
  },
);
it.each([
  { ...license, type: "trial" },
  { ...license, source: "self_trial" },
])("试用或试用转正记录没有删除入口", async (row) => {
  await mount(false, row);
  expect(canDeleteLicense(row)).toBe(false);
  expect(
    [...root.querySelectorAll("button")].some(
      (b) => b.textContent?.trim() === "删除",
    ),
  ).toBe(false);
});
it.each([false, true])("取消删除确认不发请求：详情=%s", async (detail) => {
  const { writes } = await mount(detail);
  const confirmation = vi
    .spyOn(ElMessageBox, "confirm")
    .mockRejectedValue("cancel");
  if (detail) {
    root.querySelector<HTMLButtonElement>('[aria-label="更多操作"]')!.click();
    const action = await vi.waitFor(() => {
      const found = [
        ...document.querySelectorAll<HTMLElement>(".el-dropdown-menu__item"),
      ].find((item) => item.textContent?.trim() === "删除授权");
      expect(found).toBeDefined();
      return found!;
    });
    action.click();
  } else {
    [...root.querySelectorAll<HTMLButtonElement>("button")]
      .find((b) => b.textContent?.trim() === "删除")!
      .click();
  }
  await vi.waitFor(() => expect(confirmation).toHaveBeenCalledOnce());
  await nextTick();
  expect(writes).toEqual([]);
});
it("用户中心两个操作位于统一可换行工具栏", async () => {
  await mount(true, { ...license, status: "active" });
  const tab = [...root.querySelectorAll<HTMLElement>("[role=tab]")].find(
    (t) => t.textContent?.trim() === "用户中心",
  );
  tab!.click();
  await nextTick();
  const button = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.textContent?.trim() === "设置授权查询密码",
  )!;
  const toolbar = button.closest(".action-toolbar");
  expect(toolbar).not.toBeNull();
  expect(toolbar?.textContent).toContain("打开用户中心");
});
it("清理确认说明当前软件范围和数量，取消不删除", async () => {
  const { writes, router } = await mount(false);
  await router.replace({ path: "/admin/licenses", query: { app_id: "7" } });
  await nextTick();
  const confirmation = vi
    .spyOn(ElMessageBox, "confirm")
    .mockRejectedValue("cancel");
  [...root.querySelectorAll<HTMLButtonElement>("button")]
    .find((b) => b.textContent?.trim() === "清理已吊销授权")!
    .click();
  await vi.waitFor(() =>
    expect(confirmation).toHaveBeenCalledWith(
      expect.stringContaining("软件 7下 1 个"),
      "清理已吊销授权",
      expect.anything(),
    ),
  );
  expect(writes).toEqual([]);
});

it("确认删除后详情返回授权列表", async () => {
  const { writes, router } = await mount(true);
  vi.spyOn(ElMessageBox, "confirm").mockResolvedValue("confirm");
  root.querySelector<HTMLButtonElement>('[aria-label="更多操作"]')!.click();
  const action = await vi.waitFor(() => {
    const found = [
      ...document.querySelectorAll<HTMLElement>(".el-dropdown-menu__item"),
    ].find((item) => item.textContent?.trim() === "删除授权");
    expect(found).toBeDefined();
    return found!;
  });
  action.click();
  await vi.waitFor(() =>
    expect(writes).toEqual([
      { method: "delete", path: "/licenses/1", data: undefined },
    ]),
  );
  await vi.waitFor(() =>
    expect(router.currentRoute.value.path).toBe("/admin/licenses"),
  );
});
it("确认清理只提交当前软件范围", async () => {
  const { writes, router } = await mount(false);
  await router.replace({ path: "/admin/licenses", query: { app_id: "7" } });
  await nextTick();
  vi.spyOn(ElMessageBox, "confirm").mockResolvedValue("confirm");
  [...root.querySelectorAll<HTMLButtonElement>("button")]
    .find((b) => b.textContent?.trim() === "清理已吊销授权")!
    .click();
  await vi.waitFor(() =>
    expect(writes).toEqual([
      { method: "post", path: "/licenses/purge-revoked", data: { app_id: 7 } },
    ]),
  );
});
