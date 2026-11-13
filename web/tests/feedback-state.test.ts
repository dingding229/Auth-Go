import "./admin-bootstrap";
import { join } from "node:path";
import { readFileSync, readdirSync } from "node:fs";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, ref, type App } from "vue";
import { createMemoryHistory, createRouter } from "vue-router";
import ElementPlus, { ElForm } from "element-plus";
import NumberInput from "../src/components/NumberInput.vue";
import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import { http } from "../src/lib/http";
import { setAdmin, clearAdmin } from "../src/lib/session";
import { focusReturn } from "../src/lib/overlay-focus";
import { useLoadTask, useTask } from "../src/composables/tasks";
import { useCollection } from "../src/composables/collection";
import DataTable from "../src/components/DataTable.vue";
import RequestNotice from "../src/components/RequestNotice.vue";
import LicensesView from "../src/views/admin/LicensesView.vue";
vi.mock("../src/components/SchemaEditor.vue", () => ({
  default: { emits: ["save"], template: '<button @click="$emit(\'save\', { app_id: 7, user_id: 9, count: 3, validity_rule: \'perpetual\' })">提交测试授权</button>' },
}));
let app: App | undefined, root: HTMLElement;
const original = http.defaults.adapter;
const ok = (config: InternalAxiosRequestConfig, data: unknown) => ({
  config, data: { code: "OK", data }, status: 200, statusText: "", headers: new AxiosHeaders(),
});
beforeEach(() => { root = document.createElement("div"); document.body.append(root); setAdmin("access", "refresh"); });
afterEach(() => { app?.unmount(); app = undefined; root.remove(); http.defaults.adapter = original; clearAdmin(); vi.restoreAllMocks(); });
it("initial read failure has only error/retry; success permits empty state; refresh failure keeps old rows", async () => {
  let fail = true, records: unknown[] = [];
  http.defaults.adapter = async (config) => {
    if (fail) throw new AxiosError("offline", "ERR_NETWORK", config);
    return ok(config, { items: records, total: records.length });
  };
  let collection!: ReturnType<typeof useCollection>;
  app = createApp({ setup() {
    const list = useCollection("/users"); collection = list;
    return () => h("section", [
      h(RequestNotice, { error: list.error.value, onRetry: () => list.load() }),
      h(DataTable, { items: list.items.value, columns: [{ key: "name", title: "姓名" }], loading: list.loading.value, error: list.error.value, empty: "还没有用户", emptyAction: "创建用户" }),
    ]);
  } });
  app.use(ElementPlus).mount(root);
  await vi.waitFor(() => expect(root.textContent).toContain("连接失败，请检查网络或服务地址"));
  expect(root.querySelector(".table-empty")).toBeNull();
  expect(root.textContent).not.toContain("创建用户");
  expect(root.textContent).toContain("重试");
  fail = false; await collection.load(); await nextTick();
  expect(root.textContent).toContain("还没有用户");
  records = [{ id: 1, name: "上次成功的用户" }]; await collection.load(); await nextTick();
  fail = true; await collection.load(); await nextTick();
  expect(root.textContent).toContain("刷新失败，显示上次成功读取的数据");
  expect(root.textContent).toContain("上次成功的用户");
  expect(root.querySelector(".table-empty")).toBeNull();
});
it("inline form feedback never invents a reload/retry action", async () => {
  app = createApp({ render: () => h("form", [h(RequestNotice, { error: "请填写原密码" })]) });
  app.use(ElementPlus).mount(root); await nextTick();
  expect(root.querySelector("form [role=alert]")?.textContent).toContain("请填写原密码");
  expect(root.querySelector("button")).toBeNull();
});
it("batch creation publishes an isolated persistent result, not the transient import report", async () => {
  let finish: (() => void) | undefined, batchReadStarted = false;
  const wait = new Promise<void>((resolve) => { finish = resolve; });
  const rows = [1, 2, 3].map((id) => ({ id, key: `AUTH-test-${id}` }));
  http.defaults.adapter = async (config) => {
    if (config.url === "/applications") return ok(config, { items: [{ id: 7, name: "软件" }], total: 1 });
    if (config.url === "/licenses/batch") return ok(config, { batch_id: "batch-result", count: 3 });
    if (config.url === "/licenses" && config.params?.batch_id) { batchReadStarted = true; await wait; return ok(config, { items: rows, total: 3 }); }
    return ok(config, { items: [], total: 0 });
  };
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: "/admin/licenses", component: LicensesView }] });
  await router.push("/admin/licenses?create=1&user_id=9");
  app = createApp(LicensesView); app.use(ElementPlus).use(router).mount(root);
  const button = (text: string) => [...document.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent?.trim() === text);
  await vi.waitFor(() => expect(button("提交测试授权")).toBeDefined());
  button("提交测试授权")!.click();
  await vi.waitFor(() => expect(batchReadStarted).toBe(true)); await nextTick();
  expect([...document.querySelectorAll('[role="dialog"]')].some((dialog) => dialog.textContent?.includes("批次与导入报告"))).toBe(false);
  finish!();
  await vi.waitFor(() => expect(button("下载批次CSV")).toBeDefined());
  const result = [...document.querySelectorAll('[role="dialog"]')].find((dialog) => dialog.textContent?.includes("授权已生成"))!;
  expect(result.querySelector("textarea")?.value.split("\n")).toHaveLength(3);
  // Complete the actual leave transition of the issuing drawer, then assert the
  // stable dialog still owns its batch instead of a closing report resetting it.
  await vi.waitFor(() => expect(document.querySelector('.el-drawer')?.getAttribute("aria-hidden") ?? "true").toBe("true"));
  expect(button("下载批次CSV")).toBeDefined();
  expect(result.querySelector("textarea")?.value).toBe(rows.map((row) => row.key).join("\n"));
});

it("all page overlays and number fields use shared accessible controls", () => {
  const directory = join(process.cwd(), "src");
  for (const name of readdirSync(directory, { recursive: true }).map(String).filter((name) => name.endsWith(".vue"))) {
    const source = readFileSync(join(directory, name), "utf8");
    expect(source, name).not.toMatch(/<el-(?:dialog|drawer)\b/);
    if (!name.endsWith("/NumberInput.vue")) expect(source, name).not.toMatch(/<el-input-number\b/);
  }
});

it("shared read task labels a failed refresh without labeling form validation as a load error", async () => {
  const reader = useLoadTask(), writer = useTask();
  await reader.run(async () => 1);
  await reader.run(async () => { throw new Error("连接中断"); });
  expect(reader.error.value).toBe("刷新失败，显示上次成功读取的数据：连接中断");
  await writer.run(async () => 1);
  await writer.run(async () => { throw new Error("请填写邮箱"); });
  expect(writer.error.value).toBe("请填写邮箱");
});

it("focus return waits for an async action to re-enable its original trigger", async () => {
  const button = document.createElement("button"); button.textContent = "操作"; root.append(button); button.focus();
  const focus = focusReturn(); button.disabled = true;
  const released = document.createElement("div"); released.tabIndex = -1; root.append(released); released.focus();
  focus.restore(); await nextTick();
  expect(document.activeElement).not.toBe(button);
  button.disabled = false;
  await vi.waitFor(() => expect(document.activeElement).toBe(button));
  expect(button.hasAttribute("data-overlay-focus-return")).toBe(true);
});

it("shared number control follows real form disabled state in both directions without remounting or losing its value", async () => {
  const busy = ref(true), value = ref(3);
  app = createApp({ render: () => h(ElForm, { disabled: busy.value }, () => h(NumberInput, { modelValue: value.value, "onUpdate:modelValue": (next: number) => { value.value = next; } })) });
  app.use(ElementPlus).mount(root); await nextTick();
  const input = root.querySelector<HTMLInputElement>("input")!;
  expect(input.disabled).toBe(true); expect(input.getAttribute("aria-disabled")).toBe("true");
  busy.value = false;
  await vi.waitFor(() => expect(input.getAttribute("aria-disabled")).toBe("false"));
  expect(input.disabled).toBe(false); expect(root.querySelector("input")).toBe(input); expect(input.value).toBe("3");
  busy.value = true;
  await vi.waitFor(() => expect(input.getAttribute("aria-disabled")).toBe("true"));
  expect(input.disabled).toBe(true); expect(input.value).toBe("3");
});

it("hidden native switch inputs restore a visible ring on their persistent control", async () => {
  const control = document.createElement("div"), input = document.createElement("input");
  control.className = "el-switch"; input.type = "checkbox"; control.append(input); root.append(control); input.focus();
  const focus = focusReturn(); input.blur(); focus.restore();
  await vi.waitFor(() => expect(document.activeElement).toBe(input));
  expect(control.hasAttribute("data-overlay-focus-return")).toBe(true);
  expect(input.hasAttribute("data-overlay-focus-return")).toBe(false);
  input.blur(); expect(control.hasAttribute("data-overlay-focus-return")).toBe(false);
});

it("nested overlay return uses its actual parent dialog, not a later hidden sibling", async () => {
  const opener = document.createElement("button"), parent = document.createElement("div"), inside = document.createElement("button"), hidden = document.createElement("div");
  parent.setAttribute("role", "dialog"); parent.setAttribute("data-focus-owner", "parent-owner"); hidden.setAttribute("role", "dialog"); hidden.style.display = "none";
  root.append(opener, parent, hidden); parent.append(inside); opener.focus();
  const parentFocus = focusReturn();
  parentFocus.bind("parent-owner"); inside.focus(); await nextTick();
  const childFocus = focusReturn(); parent.style.display = "none"; inside.remove();
  childFocus.restore();
  await vi.waitFor(() => expect(document.activeElement).toBe(opener));
  expect(opener.hasAttribute("data-overlay-focus-return")).toBe(true);
});
