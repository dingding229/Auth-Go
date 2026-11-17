import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, nextTick, type App } from "vue";
import ElementPlus from "element-plus";
import { AxiosHeaders } from "axios";
import SchemaEditor from "../src/components/SchemaEditor.vue";
import VersionManagement from "../src/components/VersionManagement.vue";
import { http } from "../src/lib/http";
import type { Row } from "../src/lib/json";
import { readFileSync } from "node:fs";
import { versionSpec, type Values } from "../src/lib/schema";
it("手动版本创建编辑可登记加密与构建时间", () => {
  const fields = versionSpec.fields.map((f) => f.key);
  expect(fields).toContain("encrypted");
  expect(fields).toContain("built_at");
  const versions = readFileSync("src/components/VersionManagement.vue", "utf8");
  expect(versions).toContain("保存构建元数据");
  expect(versions).toContain("built_at");
  expect(versions).toContain("不是信任源");
});

let app: App | undefined;
let root: HTMLElement | undefined;
const adapter = http.defaults.adapter;
afterEach(() => {
  app?.unmount();
  root?.remove();
  app = undefined;
  root = undefined;
  http.defaults.adapter = adapter;
});

it.each([false, true])(
  "已确认=%s：版本表单只读并跳过提交受保护字段",
  async (confirmed) => {
    const onSave = vi.fn();
    root = document.createElement("div");
    document.body.append(root);
    app = createApp(SchemaEditor, {
      fields: versionSpec.fields,
      initial: {
        version: "1.0.0",
        encrypted: true,
        build_verified: confirmed,
        built_at: "2026-11-17T03:00:00Z",
        changelog: "原说明",
      },
      editing: true,
      onSave,
    });
    app.use(ElementPlus);
    const vm = app.mount(root) as unknown as {
      values: Values;
      submit: () => Promise<void>;
    };
    await nextTick();
    expect(
      root.querySelector(".el-switch")?.classList.contains("is-disabled"),
    ).toBe(confirmed);
    expect(
      root.querySelector<HTMLInputElement>(".el-date-editor input")?.disabled,
    ).toBe(confirmed);
    vm.values.changelog = "修改说明";
    if (confirmed) {
      // Even a programmatic change must not submit authenticated metadata.
      vm.values.encrypted = false;
      vm.values.built_at = "2026-11-16T00:00:00Z";
    }
    await vm.submit();
    expect(onSave).toHaveBeenCalledOnce();
    const body = onSave.mock.calls[0]?.[0] as Row;
    expect(body.changelog).toBe("修改说明");
    expect(body).not.toHaveProperty("build_verified");
    if (confirmed) {
      expect(body).not.toHaveProperty("encrypted");
      expect(body).not.toHaveProperty("built_at");
    } else {
      expect(body.encrypted).toBe(true);
      expect(body.built_at).toBe("2026-11-17T03:00:00.000Z");
    }
  },
);

it("已确认版本显示标记，元数据弹窗只读且不能提交", async () => {
  const writes: string[] = [];
  const row = {
    id: 3,
    version: "1.0.0",
    encrypted: true,
    build_verified: true,
    built_at: "2026-11-17T03:00:00Z",
  };
  http.defaults.adapter = async (config) => {
    if (config.method !== "get") writes.push(config.url!);
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: { code: "OK", data: { items: [row], total: 1 } },
    };
  };
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(VersionManagement, { id: "7", appKey: "app" });
  app.use(ElementPlus);
  app.mount(root);
  await vi.waitFor(() => expect(root?.textContent).toContain("已由构建确认"));
  const editButton = Array.from(root.querySelectorAll("button")).find((button) =>
    button.textContent?.includes("构建元数据"),
  );
  expect(editButton).toBeDefined();
  editButton!.click();
  await vi.waitFor(() =>
    expect(document.body.querySelector("[role=dialog]")?.textContent).toContain(
      "由加密构建的首次解锁自动登记",
    ),
  );
  const dialog = document.body.querySelector<HTMLElement>("[role=dialog]");
  expect(dialog?.textContent).toContain("由加密构建的首次解锁自动登记");
  expect(
    dialog?.querySelector(".el-switch")?.classList.contains("is-disabled"),
  ).toBe(true);
  expect(
    dialog?.querySelector<HTMLInputElement>(".el-input input")?.readOnly,
  ).toBe(true);
  expect(dialog?.textContent).not.toContain("保存构建元数据");
  dialog?.querySelector("form")?.dispatchEvent(
    new Event("submit", { bubbles: true, cancelable: true }),
  );
  await nextTick();
  expect(writes).toEqual([]);
});
