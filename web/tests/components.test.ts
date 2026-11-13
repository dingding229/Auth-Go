import "./admin-bootstrap";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, nextTick, type App } from "vue";
import { createPinia } from "pinia";
import ElementPlus from "element-plus";
import { AxiosHeaders } from "axios";
import SchemaEditor from "../src/components/SchemaEditor.vue";
import CrudPanel from "../src/components/CrudPanel.vue";
import { field, licenseFields, specs, type Values } from "../src/lib/schema";
import { http } from "../src/lib/http";
import { clearAdmin, setAdmin } from "../src/lib/session";
import { createMemoryHistory, createRouter } from "vue-router";
let app: App | undefined, root: HTMLElement;
beforeEach(() => {
  root = document.createElement("div");
  document.body.append(root);
  clearAdmin();
  setAdmin("access", "refresh", { username: "owner" });
  http.defaults.adapter = async (config) => ({
    config,
    data: {
      code: "OK",
      data: { items: [{ id: 1, name: "应用甲" }], total: 1 },
    },
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
  });
});
afterEach(() => {
  app?.unmount();
  root.remove();
  app = undefined;
});
describe("动态策略与资源视图", () => {
  it("按选中的绑定方式展示字段，KEY始终存在", async () => {
    app = createApp(SchemaEditor, { fields: licenseFields });
    app.use(ElementPlus);
    const vm = app.mount(root) as unknown as { values: Values };
    await nextTick();
    expect(root.textContent).not.toContain("IP白名单");
    expect(root.textContent).not.toContain("要求域名所有权验证");
    vm.values.verify_methods = ["KEY", "IP", "DOMAIN"];
    await nextTick();
    expect(root.textContent).not.toContain("IP白名单");
    expect(root.textContent).not.toContain("要求域名所有权验证");
    vm.values.ip_lock_mode = "first_use";
    await nextTick();
    expect(root.textContent).not.toContain("IP白名单");
    const key = [...root.querySelectorAll("input[type=checkbox]")].find(
      (input) => (input as HTMLInputElement).value === "KEY",
    ) as HTMLInputElement;
    expect(key.checked).toBe(true);
    expect(key.disabled).toBe(true);
  });
  it("表单提交只发送声明的字段，保留大整数JSON", async () => {
    const onSave = vi.fn();
    app = createApp(SchemaEditor, {
      fields: [
        field("name", "名称", { required: true }),
        field("features", "功能", { type: "json" }),
      ],
      initial: {
        name: "测试",
        features: { quota: BigInt("18446744073709551615") },
        private_key: "must-not-send",
      },
      onSave,
    });
    app.use(ElementPlus);
    const vm = app.mount(root) as unknown as { submit: () => Promise<void> };
    await nextTick();
    await vm.submit();
    expect(onSave).toHaveBeenCalledOnce();
    expect(onSave.mock.calls[0]?.[0]).toEqual({
      name: "测试",
      features: { quota: BigInt("18446744073709551615") },
    });
  });
  it("唯一管理员可查看和维护应用", async () => {
    app = createApp(CrudPanel, { spec: specs.applications, embedded: true });
    app
      .use(createPinia())
      .use(ElementPlus)
      .use(
        createRouter({
          history: createMemoryHistory(),
          routes: [{ path: "/", component: { template: "<div />" } }],
        }),
      );
    app.mount(root);
    await nextTick();
    await vi.waitFor(() => expect(root.textContent).toContain("应用甲"));
    const buttons = () =>
      [...root.querySelectorAll("button")].map((b) => b.textContent?.trim());
    expect(buttons()).toContain("新建软件");
    expect(buttons()).toContain("删除");
    expect(root.textContent).not.toContain("软件详情");
    expect(buttons()).toContain("编辑");
    await nextTick();
    expect(root.textContent).toContain("新建软件");
  });
  it("提交处理中禁用输入", async () => {
    app = createApp(SchemaEditor, {
      fields: [field("site_name", "站点名称", { immutable: true })],
      initial: { site_name: "示例站点" },
      busy: true,
    });
    app.use(ElementPlus);
    app.mount(root);
    await nextTick();
    expect(root.textContent).toContain("保存");
    expect((root.querySelector("input") as HTMLInputElement).disabled).toBe(
      true,
    );
  });
});

it("SMTP用户名不会触发管理员新建密码规则，留空密码可保留", async () => {
  const onSave = vi.fn();
  app = createApp(SchemaEditor, {
    fields: [
      field("username", "SMTP用户名"),
      field("password", "SMTP密码", { type: "password" }),
      field("host", "主机"),
    ],
    initial: {
      username: "mailer",
      host: "smtp.example.com",
      has_password: true,
    },
    onSave,
  });
  app.use(ElementPlus);
  const vm = app.mount(root) as unknown as { submit: () => Promise<void> };
  await nextTick();
  await vm.submit();
  expect(onSave).toHaveBeenCalledOnce();
  expect(onSave.mock.calls[0]?.[0]).toEqual({
    username: "mailer",
    host: "smtp.example.com",
  });
});

it("高级字段默认折叠但参与提交，验证错误自动展开定位", async () => {
  const onSave = vi.fn();
  app = createApp(SchemaEditor, {
    fields: [
      field("name", "名称", { required: true }),
      field("features", "功能", {
        type: "json",
        advanced: true,
        default: "{}",
      }),
    ],
    initial: { name: "应用" },
    onSave,
  });
  app.use(ElementPlus);
  const vm = app.mount(root) as unknown as {
    values: Values;
    advancedOpen: boolean;
    submit: () => Promise<void>;
  };
  await nextTick();
  expect(vm.advancedOpen).toBe(false);
  await vm.submit();
  expect(onSave.mock.calls[0]?.[0]).toEqual({ name: "应用", features: {} });
  vm.values.features = "bad JSON";
  await nextTick();
  await vm.submit();
  expect(vm.advancedOpen).toBe(true);
  expect(document.activeElement).toBe(
    root.querySelector('[data-field="features"] textarea'),
  );
  expect(root.textContent).toContain("JSON格式不正确");
  expect(onSave).toHaveBeenCalledTimes(1);
});

it("默认授权表单无需展开即可提交FLOATING与永久有效期", async () => {
  const onSave = vi.fn();
  app = createApp(SchemaEditor, {
    fields: licenseFields,
    initial: { app_id: 1, user_id: 1 },
    onSave,
  });
  app.use(ElementPlus);
  const vm = app.mount(root) as unknown as { submit: () => Promise<void> };
  await nextTick();
  await vm.submit();
  expect(onSave).toHaveBeenCalledOnce();
  const body = onSave.mock.calls[0]![0];
  expect(body.app_id).toBe(1);
  expect(body.verify_methods).toEqual(["KEY", "FLOATING"]);
  expect(body.validity_rule).toBe("perpetual");
  expect(body.duration_days).toBeUndefined();
  expect(body.expires_at).toBeUndefined();
  expect(body.features).toEqual({});
  expect(body.unbind_limit).toBeUndefined();
});

it("单个必须选择用户，批量允许留空且不提交旧联系字段", async () => {
  const onSave = vi.fn();
  app = createApp(SchemaEditor, {
    fields: [
      ...licenseFields,
      field("count", "数量", { type: "number", default: 1, min: 1 }),
    ],
    initial: { app_id: 1 },
    onSave,
  });
  app.use(ElementPlus);
  const vm = app.mount(root) as unknown as {
    values: Values;
    submit: () => Promise<void>;
  };
  await nextTick();
  await vm.submit();
  expect(onSave).not.toHaveBeenCalled();
  expect(root.textContent).toContain("请填写发给谁");
  vm.values.count = 2;
  await nextTick();
  await vm.submit();
  expect(onSave).toHaveBeenCalledOnce();
  expect(onSave.mock.calls[0]![0].user_id).toBeUndefined();
  expect(onSave.mock.calls[0]![0]).not.toHaveProperty("contact_name");
});
it("发放表单支持就地新建用户并自动选中", async () => {
  const onSave = vi.fn();
  http.defaults.adapter = async (config) => ({
    config,
    data: {
      code: "OK",
      data:
        config.method === "post"
          ? { id: 99, name: "新用户" }
          : { items: [{ id: 99, name: "新用户" }], total: 1 },
    },
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
  });
  app = createApp(SchemaEditor, {
    fields: licenseFields,
    initial: { app_id: 1 },
    onSave,
  });
  app.use(ElementPlus);
  const vm = app.mount(root) as unknown as {
    values: Values;
    submit: () => Promise<void>;
  };
  await nextTick();
  await vm.submit();
  expect(onSave).not.toHaveBeenCalled();
  await nextTick();
  expect(root.textContent).toContain("请填写发给谁");
  expect(
    root
      .querySelector('[data-field="user_id"]')
      ?.classList.contains("is-error"),
  ).toBe(true);
  [...root.querySelectorAll("button")]
    .find((b) => b.textContent?.trim() === "就地新建用户")!
    .click();
  await nextTick();
  const input = root.querySelector<HTMLInputElement>(
    '[aria-label="新用户姓名"]',
  )!;
  input.value = "新用户";
  input.dispatchEvent(new Event("input", { bubbles: true }));
  await nextTick();
  [...root.querySelectorAll("button")]
    .find((b) => b.textContent?.trim() === "创建并选择")!
    .click();
  await vi.waitFor(() => expect(vm.values.user_id).toBe("99"));
  await vi.waitFor(() =>
    expect(root.textContent).not.toContain("请填写发给谁"),
  );
  expect(
    root
      .querySelector('[data-field="user_id"]')
      ?.classList.contains("is-error"),
  ).toBe(false);
  await vm.submit();
  expect(onSave).toHaveBeenCalledOnce();
  expect(onSave.mock.calls[0]![0].user_id).toBe(99);
});

it("选择已有用户立即清除发给谁的红框和提示，不发送已删除解绑字段", async () => {
  const onSave = vi.fn();
  app = createApp(SchemaEditor, {
    fields: licenseFields,
    initial: { app_id: 1, unbind_limit: 0 },
    onSave,
  });
  app.use(ElementPlus);
  const vm = app.mount(root) as unknown as {
    values: Values;
    submit: () => Promise<void>;
  };
  await nextTick();
  await vm.submit();
  expect(root.textContent).toContain("请填写发给谁");
  vm.values.user_id = "1";
  await vi.waitFor(() =>
    expect(root.textContent).not.toContain("请填写发给谁"),
  );
  expect(
    root
      .querySelector('[data-field="user_id"]')
      ?.classList.contains("is-error"),
  ).toBe(false);
  await vm.submit();
  expect(onSave.mock.calls[0]![0].unbind_limit).toBeUndefined();
});

it.each([
  { query: "张三", keys: ["Enter"], expected: 9, immediate: true },
  { query: "张三", keys: ["Enter"], expected: 9, immediate: false },
  { query: "张", keys: ["Enter"], expected: 1, immediate: false },
  { query: "张", keys: ["ArrowDown", "Enter"], expected: 9, immediate: false },
  {
    query: "张",
    keys: ["ArrowDown", "ArrowUp", "Enter"],
    expected: 1,
    immediate: false,
  },
])(
  "发放授权仅用键盘选择用户再提交：$query $keys immediate=$immediate",
  async ({ query, keys, expected, immediate }) => {
    const onSave = vi.fn();
    const queries: string[] = [];
    http.defaults.adapter = async (config) => {
      if (config.url === "/users") queries.push(String(config.params?.q ?? ""));
      return {
        config,
        status: 200,
        statusText: "",
        headers: new AxiosHeaders(),
        data: {
          code: "OK",
          data: {
            items:
              config.url === "/users"
                ? [
                    { id: 1, name: "张三丰" },
                    { id: 9, name: "张三" },
                  ]
                : [{ id: 1, name: "应用甲" }],
            total: 2,
          },
        },
      };
    };
    app = createApp(SchemaEditor, {
      fields: licenseFields,
      initial: { app_id: 1 },
      onSave,
    });
    app.use(ElementPlus);
    const vm = app.mount(root) as unknown as { values: Values };
    await nextTick();
    const input = root.querySelector<HTMLInputElement>(
      '[data-field="user_id"] input',
    )!;
    // Await this control's initial load, not another teleported dropdown's text.
    await vi.waitFor(() => expect(input.closest(".el-select")?.getAttribute("aria-busy")).toBe("false"));
    input.focus();
    await nextTick();
    input.value = query;
    input.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: query }));
    if (!immediate)
      await vi.waitFor(() => {
        expect(queries).toContain(query);
        expect(input.closest(".el-select")?.getAttribute("aria-busy")).toBe("false");
        expect(input.getAttribute("aria-expanded")).toBe("true");
        const active = input.getAttribute("aria-activedescendant");
        expect(input.value).toBe(query);
        expect(active).toBeTruthy();
        // A request being sent is not proof that ElSelect has rendered that
        // query's options and reset its previous hover. Wait for the actual
        // default candidate, without increasing the test's wait deadline.
        expect(active && document.getElementById(active)?.dataset.resourceId).toBe(
          query === "张三" ? "9" : "1",
        );
      });
    for (const key of keys) {
      input.dispatchEvent(
        new KeyboardEvent("keydown", {
          key,
          code: key,
          bubbles: true,
          cancelable: true,
        }),
      );
      await nextTick();
    }
    await vi.waitFor(() => expect(vm.values.user_id).toBe(String(expected)));
    expect(onSave).not.toHaveBeenCalled();
    // Happy DOM does not implement native Tab/Enter default actions. Move focus
    // as Tab would, then dispatch the native form submit rather than calling vm.submit.
    input.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Tab", bubbles: true }),
    );
    const submit = root.querySelector<HTMLButtonElement>(
      'button[type="submit"]',
    )!;
    submit.focus();
    expect(document.activeElement).toBe(submit);
    submit.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Enter", bubbles: true }),
    );
    root
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(onSave).toHaveBeenCalledOnce());
    expect(onSave.mock.calls[0]![0].user_id).toBe(expected);
  },
);

it("远程候选未返回时Enter不会误选旧用户或提交，返回后可继续键盘选择", async () => {
  const onSave = vi.fn();
  let release: () => void = () => {};
  let pending = false;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  http.defaults.adapter = async (config) => {
    const requested = config.url === "/users" && config.params?.q === "新用户";
    if (requested) {
      pending = true;
      await gate;
    }
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: {
          items:
            config.url === "/users"
              ? requested
                ? [{ id: 42, name: "新用户" }]
                : [{ id: 1, name: "旧用户" }]
              : [{ id: 1, name: "软件" }],
          total: 1,
        },
      },
    };
  };
  app = createApp(SchemaEditor, {
    fields: licenseFields,
    initial: { app_id: 1, user_id: 1 },
    onSave,
  });
  app.use(ElementPlus);
  const vm = app.mount(root) as unknown as { values: Values };
  await nextTick();
  const input = root.querySelector<HTMLInputElement>(
    '[data-field="user_id"] input',
  )!;
  try {
    await vi.waitFor(() =>
      expect(document.body.textContent).toContain("旧用户"),
    );
    input.focus();
    input.value = "新用户";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await vi.waitFor(() => expect(pending).toBe(true));
    input.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: "Enter",
        code: "Enter",
        bubbles: true,
        cancelable: true,
      }),
    );
    await nextTick();
    expect(vm.values.user_id).toBe("");
    expect(onSave).not.toHaveBeenCalled();
    release();
    await vi.waitFor(() =>
      expect(document.body.textContent).toContain("新用户（42）"),
    );
    input.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: "Enter",
        code: "Enter",
        bubbles: true,
        cancelable: true,
      }),
    );
    await vi.waitFor(() => expect(vm.values.user_id).toBe("42"));
  } finally {
    release();
  }
});
