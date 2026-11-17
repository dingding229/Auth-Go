import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, nextTick, type App } from "vue";
import { createMemoryHistory, createRouter } from "vue-router";
import ElementPlus, { ElMessageBox } from "element-plus";
import { AxiosHeaders } from "axios";
import FeatureTemplates from "../src/components/FeatureTemplates.vue";
import LicenseDetailView from "../src/views/admin/LicenseDetailView.vue";
import { http } from "../src/lib/http";
import { setAdmin } from "../src/lib/session";
import { parseJSON, type Row } from "../src/lib/json";

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
const source = {
  id: 10,
  app_id: 7,
  name: "专业版",
  features: { export: true },
};
async function mount(
  component: Parameters<typeof createApp>[0],
  props = {},
  path = "/admin/applications/7",
) {
  setAdmin("admin", "refresh");
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/admin/licenses/:id", component },
      { path: "/:pathMatch(.*)*", component },
    ],
  });
  await router.push(path);
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(component, props).use(ElementPlus).use(router);
  app.mount(root);
  await nextTick();
}
function stub(linked: number, writes: Row[]) {
  http.defaults.adapter = async (config) => {
    if (config.method === "post")
      writes.push({ path: config.url, body: parseJSON(config.data) });
    const data = config.url?.endsWith("/counts")
      ? { linked, all: 5 }
      : config.method === "post"
        ? { count: 2 }
        : { items: [source], total: 1 };
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data },
    };
  };
}
async function openSyncDialog() {
  const button = await vi.waitFor(() => {
    const found = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
      (b) => b.textContent?.trim() === "同步到授权",
    );
    expect(found).toBeDefined();
    return found!;
  });
  button.click();
  return await vi.waitFor(() => {
    const dialog = [...document.body.querySelectorAll<HTMLElement>("[role=dialog]")].find(
      (element) => element.textContent?.includes("此软件的全部授权（5 个）"),
    );
    expect(dialog).toBeDefined();
    return dialog!;
  });
}
function submit(dialog: HTMLElement) {
  dialog
    .querySelector("form")!
    .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}
it.each(["linked", "all"])(
  "模板同步弹窗显示计数，确认后提交 %s 范围",
  async (scope) => {
    const writes: Row[] = [];
    stub(3, writes);
    const confirmation = vi
      .spyOn(ElMessageBox, "confirm")
      .mockResolvedValue("confirm");
    await mount(FeatureTemplates, { id: "7" });
    const dialog = await openSyncDialog();
    expect(dialog.textContent).toContain("用此模板发放的授权（3 个）");
    expect(dialog.textContent).toContain("会覆盖这些授权各自的功能项");
    expect(
      dialog.querySelector<HTMLInputElement>("input[type=radio][value=linked]")
        ?.checked,
    ).toBe(true);
    if (scope === "all") {
      dialog
        .querySelector<HTMLInputElement>("input[type=radio][value=all]")!
        .click();
      await nextTick();
    }
    submit(dialog);
    await vi.waitFor(() =>
      expect(writes).toEqual([
        { path: "/applications/7/templates/10/sync", body: { scope } },
      ]),
    );
    expect(confirmation).toHaveBeenCalledWith(
      expect.stringContaining("专业版"),
      "同步功能模板",
      expect.objectContaining({ confirmButtonText: "同步到授权" }),
    );
    await vi.waitFor(() =>
      expect(document.body.textContent).toContain("已同步 2 个授权"),
    );
  },
);
it("没有关联授权时默认项禁用，不得提交 linked，但仍可选择全部", async () => {
  const writes: Row[] = [];
  stub(0, writes);
  await mount(FeatureTemplates, { id: "7" });
  const dialog = await openSyncDialog();
  expect(
    dialog.querySelector<HTMLInputElement>("input[type=radio][value=linked]")
      ?.disabled,
  ).toBe(true);
  expect(
    dialog.querySelector<HTMLInputElement>("input[type=radio][value=all]")
      ?.disabled,
  ).toBe(false);
  expect(dialog.textContent).toContain(
    "还没有授权关联此模板。旧版本发放的授权没有记录来源",
  );
  submit(dialog);
  await nextTick();
  expect(writes).toEqual([]);
  vi.spyOn(ElMessageBox, "confirm").mockResolvedValue("confirm");
  dialog
    .querySelector<HTMLInputElement>("input[type=radio][value=all]")!
    .click();
  await nextTick();
  submit(dialog);
  await vi.waitFor(() => expect(writes).toHaveLength(1));
});
it("取消同步确认不写授权", async () => {
  const writes: Row[] = [];
  stub(3, writes);
  const confirmation = vi
    .spyOn(ElMessageBox, "confirm")
    .mockRejectedValue("cancel");
  await mount(FeatureTemplates, { id: "7" });
  const dialog = await openSyncDialog();
  submit(dialog);
  await vi.waitFor(() => expect(confirmation).toHaveBeenCalledOnce());
  await nextTick();
  expect(writes).toEqual([]);
});
it("授权详情确认套用模板后刷新功能项和来源，不修改其他参数", async () => {
  const writes: Row[] = [];
  const license = {
    id: 1,
    app_id: 7,
    key: "AUTH-TEST",
    status: "active",
    type: "standard",
    features: { old: true },
    max_activations: 3,
    validity_rule: "perpetual",
    verify_methods: ["KEY", "FLOATING"],
    match_mode: "all",
    metadata: {},
    template_name: "旧模板",
  };
  let applied = false;
  http.defaults.adapter = async (config) => {
    if (config.method === "post") {
      writes.push({ path: config.url, body: parseJSON(config.data) });
      applied = true;
    }
    const data =
      config.url === "/licenses/1"
        ? {
            ...license,
            features: applied ? source.features : license.features,
            template_name: applied ? source.name : license.template_name,
          }
        : config.url?.endsWith("/templates")
          ? { items: [source], total: 1 }
          : { items: [], total: 0 };
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data },
    };
  };
  const confirmation = vi
    .spyOn(ElMessageBox, "confirm")
    .mockResolvedValue("confirm");
  await mount(LicenseDetailView, {}, "/admin/licenses/1");
  await vi.waitFor(() =>
    expect(root.textContent).toContain("来源模板：旧模板"),
  );
  root.querySelector<HTMLButtonElement>('[aria-label="更多操作"]')!.click();
  const action = await vi.waitFor(() => {
    const found = [
      ...document.querySelectorAll<HTMLElement>(".el-dropdown-menu__item"),
    ].find((item) => item.textContent?.trim() === "套用功能模板");
    expect(found).toBeDefined();
    return found!;
  });
  action.click();
  const dialog = await vi.waitFor(() => {
    const found = document.body.querySelector<HTMLElement>("[role=dialog]");
    expect(found?.textContent).toContain("功能模板");
    return found!;
  });
  dialog.querySelector<HTMLElement>(".el-select__wrapper")!.click();
  const option = await vi.waitFor(() => {
    const found = [
      ...document.querySelectorAll<HTMLElement>(".el-select-dropdown__item"),
    ].find((item) => item.textContent?.trim() === "专业版");
    expect(found).toBeDefined();
    return found!;
  });
  option.click();
  await nextTick();
  submit(dialog);
  await vi.waitFor(() => expect(writes).toHaveLength(1));
  expect(confirmation).toHaveBeenCalledWith(
    "将用模板 专业版 的功能项替换此授权当前的功能项",
    "套用功能模板",
    expect.anything(),
  );
  expect(writes).toEqual([
    { path: "/licenses/1/template", body: { template_id: 10 } },
  ]);
  await vi.waitFor(() =>
    expect(root.textContent).toContain("来源模板：专业版"),
  );
});
