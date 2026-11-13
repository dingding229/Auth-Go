import "./admin-bootstrap";
import { afterEach, expect, it } from "vitest";
import { createApp, h, nextTick, ref, type App } from "vue";
import ElementPlus from "element-plus";
import { AxiosHeaders } from "axios";
import TemplateSelect from "../src/components/TemplateSelect.vue";
import SchemaEditor from "../src/components/SchemaEditor.vue";
import LicenseTemplatePicker from "../src/components/LicenseTemplatePicker.vue";
import { field, policyFields, type Values } from "../src/lib/schema";
import { http } from "../src/lib/http";
import { parseJSON, record, type Row } from "../src/lib/json";
import { licenseRequest } from "../src/lib/validity";
import { setAdmin } from "../src/lib/session";
let app: App | undefined, root: HTMLElement;
const original = http.defaults.adapter;
const editor = ref<InstanceType<typeof SchemaEditor>>();
const template = {
  id: 10,
  name: "专业版",
  features: { export: true, quota: 12345678901234567890n },
  default_max_activations: 5,
  default_days: 30,
  default_maintenance_days: 60,
};
async function flush() {
  for (let i = 0; i < 8; i++) {
    await nextTick();
    await new Promise((r) => setTimeout(r, 0));
  }
}
afterEach(() => {
  app?.unmount();
  root?.remove();
  http.defaults.adapter = original;
});
async function mount(appId = "1", count = 1) {
  setAdmin("admin", "refresh");
  let sent: Row = {};
  http.defaults.adapter = async (config) => {
    let data: Row = {};
    if (config.url?.endsWith("/templates"))
      data = {
        items: config.url.includes("/1/") ? [template] : [],
        total: config.url.includes("/1/") ? 1 : 0,
      };
    else if (config.method === "post") sent = record(parseJSON(config.data));
    return {
      config,
      data: { code: "OK", data },
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
    };
  };
  root = document.createElement("div");
  document.body.append(root);
  app = createApp({
    render: () =>
      h(
        SchemaEditor,
        {
          ref: editor,
          fields: [
            field("app_id", "软件"),
            field("count", "生成数量", { type: "number", default: count }),
            ...policyFields,
            field("maintenance_days", "更新维护天数", {
              type: "number",
              default: 0,
            }),
          ],
          initial: { app_id: appId },
          onSave: async (body: Row) => {
            const request = licenseRequest(body);
            await http.post(request.path, request.data);
          },
        },
        {
          "after-field": ({
            field: current,
            values,
          }: {
            field: { key: string };
            values: Values;
          }) =>
            current.key === "app_id"
              ? h(LicenseTemplatePicker, {
                  values,
                  onApplied: (v: Row) => Object.assign(values, v),
                })
              : null,
        },
      ),
  }).use(ElementPlus);
  app.mount(root);
  await flush();
  return () => sent;
}
async function choose() {
  root.querySelector<HTMLElement>(".el-select__wrapper")!.click();
  await flush();
  const option = Array.from(
    document.querySelectorAll<HTMLElement>(".el-select-dropdown__item"),
  ).find((v) => v.textContent?.includes("专业版"));
  expect(option).toBeTruthy();
  option!.click();
  await flush();
}
it.each([1, 3])("单个或批量%d选模板填入，修改后提交修改值", async (count) => {
  const submitted = await mount("1", count);
  expect(root.textContent).toContain("功能模板（可选）");
  await choose();
  expect(editor.value!.values.max_activations).toBe(5);
  expect(editor.value!.values.duration_days).toBe(30);
  expect(editor.value!.values.maintenance_days).toBe(60);
  expect(root.textContent).toContain("已填入模板内容，可继续修改");
  editor.value!.values.features = '{"export":false,"quota":9007199254740993}';
  editor.value!.values.max_activations = 7;
  await editor.value!.submit();
  await flush();
  expect(submitted().features).toEqual({
    export: false,
    quota: 9007199254740993n,
  });
  expect(submitted().max_activations).toBe(7);
  expect(submitted()).not.toHaveProperty("template_id");
});
it("切换软件清掉模板选择，无模板时隐藏下拉", async () => {
  await mount();
  await choose();
  editor.value!.values.app_id = "2";
  await flush();
  expect(root.textContent).not.toContain("功能模板（可选）");
  expect(root.textContent).not.toContain("已填入模板内容");
  editor.value!.values.app_id = "1";
  await flush();
  expect(root.textContent).toContain("功能模板（可选）");
  expect(
    root.querySelector(".el-select__selected-item")?.textContent,
  ).not.toContain("专业版");
});
it("软件没有模板时不显示下拉", async () => {
  await mount("2");
  expect(root.textContent).not.toContain("功能模板（可选）");
});
it("模板可空数值字段能清空提交为null", async () => {
  setAdmin("admin", "refresh");
  root = document.createElement("div");
  document.body.append(root);
  let submitted: Row = {};
  app = createApp(SchemaEditor, {
    fields: [
      field("default_days", "默认有效天数", {
        type: "number",
        min: 1,
        nullable: true,
      }),
    ],
    onSave: (v: Row) => {
      submitted = v;
    },
  }).use(ElementPlus);
  const vm = app.mount(root) as InstanceType<typeof SchemaEditor>;
  await flush();
  await vm.submit();
  expect(submitted.default_days).toBeNull();
});

it("打开试用模板下拉时读取最新模板，无需刷新页面", async () => {
  setAdmin("admin", "refresh");
  let items: Row[] = [];
  http.defaults.adapter = async (config) => ({
    config, data: { code: "OK", data: { items, total: items.length } },
    status: 200, statusText: "OK", headers: new AxiosHeaders(),
  });
  root = document.createElement("div"); document.body.append(root);
  app = createApp(TemplateSelect, { appId: "1", modelValue: "", label: "试用功能模板" }).use(ElementPlus);
  app.mount(root); await flush();
  items = [template];
  root.querySelector<HTMLElement>(".el-select__wrapper")!.click(); await flush();
  expect(Array.from(document.querySelectorAll(".el-select-dropdown__item")).some(v => v.textContent?.includes("专业版"))).toBe(true);
});
