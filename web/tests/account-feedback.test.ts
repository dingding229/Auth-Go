import "./admin-bootstrap";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App, type Component } from "vue";
import { createPinia } from "pinia";
import { createMemoryHistory, createRouter, RouterView } from "vue-router";
import ElementPlus, { ElMessage, ElMessageBox } from "element-plus";
import {
  AxiosError,
  AxiosHeaders,
  type AxiosAdapter,
  type InternalAxiosRequestConfig,
} from "axios";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { http, portalHttp } from "../src/lib/http";
import {
  clearAdmin,
  clearPortal,
  portalSession,
  setAdmin,
  setPortal,
} from "../src/lib/session";
import UserDetailView from "../src/views/admin/UserDetailView.vue";
import PortalAccountView from "../src/views/portal/PortalAccountView.vue";
import SupportContactSettings from "../src/components/SupportContactSettings.vue";

type Scope = "admin" | "portal";
let root: HTMLElement, app: App | undefined;
let calls: { scope: Scope; method: string; url: string; body: unknown }[];
let options: { smtp_configured: boolean; methods: string[] };
let optionsFailure: boolean, passwordFailure: boolean, supportFailure: boolean;
let optionsGate: Promise<void> | undefined;
const originalAdminAdapter = http.defaults.adapter;
const originalPortalAdapter = portalHttp.defaults.adapter;
const user = {
  id: 9,
  name: "反馈测试用户",
  email: "account@example.com",
  status: "active",
  has_portal_password: true,
};

function unavailable(config: InternalAxiosRequestConfig, message: string) {
  return new AxiosError(message, "ERR_BAD_RESPONSE", config, undefined, {
    config, status: 503, statusText: "Unavailable", headers: new AxiosHeaders(),
    data: { code: "UNAVAILABLE", message },
  });
}
function adapter(scope: Scope): AxiosAdapter {
  return async (config: InternalAxiosRequestConfig) => {
    const method = config.method || "get",
      url = config.url || "";
    const body: unknown =
      typeof config.data === "string" ? JSON.parse(config.data) : config.data;
    calls.push({ scope, method, url, body });
    let data: unknown = { items: [], total: 0 };
    if (scope === "portal" && url === "/login/options") {
      if (optionsGate) await optionsGate;
      if (optionsFailure) throw unavailable(config, "登录方式暂时无法读取");
      data = options;
    } else if (url === "/users/9" || (scope === "portal" && url === "/user")) {
      data =
        method === "patch" ? { ...user, has_portal_password: false } : user;
    } else if (scope === "portal" && url === "/password") {
      if (passwordFailure) throw unavailable(config, "密码保存失败，请重新提交");
      data = {};
    } else if (url === "/system/support") {
      if (method === "patch" && supportFailure)
        throw unavailable(config, "联系方式保存失败");
      data = { support_contact: "原有联系方式" };
    }
    return {
      config,
      data: { code: "OK", data },
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
    };
  };
}

beforeEach(() => {
  clearAdmin();
  clearPortal();
  setAdmin("admin-test", "refresh-test");
  setPortal("portal-test", "user");
  root = document.createElement("div");
  document.body.append(root);
  calls = [];
  options = { smtp_configured: false, methods: ["password"] };
  optionsFailure = passwordFailure = supportFailure = false;
  user.email = "account@example.com";
  optionsGate = undefined;
  http.defaults.adapter = adapter("admin");
  portalHttp.defaults.adapter = adapter("portal");
});
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.remove();
  ElMessage.closeAll();
  http.defaults.adapter = originalAdminAdapter;
  portalHttp.defaults.adapter = originalPortalAdapter;
  clearAdmin();
  clearPortal();
  vi.restoreAllMocks();
});
async function mountPage(component: Component, path = "/portal/account") {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      {
        path: path.startsWith("/admin/users/") ? "/admin/users/:id" : path,
        component,
      },
      {
        path: "/:pathMatch(.*)*",
        component: { template: "<div>登录页面</div>" },
      },
    ],
  });
  await router.push(path);
  app = createApp({ render: () => h(RouterView) });
  app.use(createPinia()).use(ElementPlus).use(router);
  app.mount(root);
  return router;
}
function button(text: string, within: ParentNode = root): HTMLButtonElement {
  const value = [...within.querySelectorAll<HTMLButtonElement>("button")].find(
    (el) => el.textContent?.trim() === text,
  );
  expect(value, `找不到按钮：${text}`).toBeTruthy();
  return value!;
}
function submit(form = root.querySelector("form")) {
  expect(form).not.toBeNull();
  form!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}
async function input(
  element: HTMLInputElement | HTMLTextAreaElement,
  value: string,
) {
  element.value = value;
  element.dispatchEvent(new Event("input", { bubbles: true }));
  await nextTick();
}
function writes(url: string) {
  return calls.filter((call) => call.url === url && call.method !== "get");
}
function reads(url: string) {
  return calls.filter((call) => call.url === url && call.method === "get");
}
async function readyAccount() {
  const router = await mountPage(PortalAccountView);
  await vi.waitFor(() => expect(root.querySelector("form")).not.toBeNull());
  return router;
}

describe("清除用户中心密码按实际可用登录方式确认", () => {
  it.each([false, true])(
    "邮箱验证码可用=%s，确认动作和恢复说明明确",
    async (enabled) => {
      options = {
        smtp_configured: enabled,
        methods: enabled ? ["email_code", "password"] : ["password"],
      };
      const confirm = vi
        .spyOn(ElMessageBox, "confirm")
        .mockResolvedValue("confirm");
      await mountPage(UserDetailView, "/admin/users/9");
      await vi.waitFor(() => expect(root.textContent).toContain(user.name));
      button("清除用户中心密码").click();
      await vi.waitFor(() => expect(confirm).toHaveBeenCalledOnce());
      const [message, title, settings] = confirm.mock.calls[0]!;
      expect(title).toBe("清除用户中心密码");
      expect(settings).toMatchObject({ confirmButtonText: "清除用户中心密码" });
      expect(String(message)).toContain("旧用户中心会话立即失效");
      expect(String(message)).toContain("管理员");
      expect(String(message)).toContain("重新设置");
      if (enabled) {
        expect(String(message)).toContain("关联邮箱接收验证码登录");
        expect(String(message)).not.toContain("用户将无法登录");
      } else {
        expect(String(message)).toContain("邮箱验证码未启用");
        expect(String(message)).toContain("用户将无法登录");
        expect(String(message)).toContain("编辑资料与密码");
      }
      await vi.waitFor(() => expect(writes("/users/9")).toHaveLength(1));
      expect(writes("/users/9")[0]?.body).toEqual({ portal_password: "" });
      expect(reads("/login/options")).toHaveLength(1);
    },
  );
  it("服务已启用验证码但用户未关联邮箱时，警告不可登录及补邮箱恢复方式", async () => {
    user.email = "";
    options = { smtp_configured: true, methods: ["email_code", "password"] };
    const confirm = vi
      .spyOn(ElMessageBox, "confirm")
      .mockResolvedValue("confirm");
    await mountPage(UserDetailView, "/admin/users/9");
    await vi.waitFor(() => expect(root.textContent).toContain(user.name));
    button("清除用户中心密码").click();
    await vi.waitFor(() => expect(confirm).toHaveBeenCalledOnce());
    const message = String(confirm.mock.calls[0]![0]);
    expect(message).toContain("未关联邮箱");
    expect(message).toContain("用户将无法登录");
    expect(message).toContain("补充邮箱并重新设置用户中心密码");
    expect(message).not.toContain("可使用关联邮箱接收验证码登录");
    await vi.waitFor(() => expect(writes("/users/9")).toHaveLength(1));
  });
  it("登录方式读取失败不猜测验证码可用，不清除密码", async () => {
    optionsFailure = true;
    const confirm = vi
      .spyOn(ElMessageBox, "confirm")
      .mockResolvedValue("confirm");
    await mountPage(UserDetailView, "/admin/users/9");
    await vi.waitFor(() => expect(root.textContent).toContain(user.name));
    button("清除用户中心密码").click();
    await vi.waitFor(() =>
      expect(root.querySelector(".request-notice")?.textContent).toContain(
        "登录方式暂时无法读取",
      ),
    );
    expect(confirm).not.toHaveBeenCalled();
    expect(writes("/users/9")).toHaveLength(0);
    const notice = [...root.querySelectorAll(".request-notice")].find((el) =>
      el.textContent?.includes("登录方式暂时无法读取"),
    );
    expect(notice?.querySelector("button")).toBeNull();
  });
  it("取消清除不发送密码修改请求", async () => {
    const confirm = vi
      .spyOn(ElMessageBox, "confirm")
      .mockRejectedValue("cancel");
    await mountPage(UserDetailView, "/admin/users/9");
    await vi.waitFor(() => expect(root.textContent).toContain(user.name));
    button("清除用户中心密码").click();
    await vi.waitFor(() => expect(confirm).toHaveBeenCalledOnce());
    await nextTick();
    expect(writes("/users/9")).toHaveLength(0);
  });
});

describe("账号安全区分认证、表单与加载反馈", () => {
  it("验证码关闭时只要求原密码或联系管理员，校验不变成加载错误", async () => {
    const toast = vi.spyOn(ElMessage, "error");
    await readyAccount();
    expect(root.querySelectorAll("input")).toHaveLength(3);
    expect(root.textContent).not.toContain("可使用邮箱验证码");
    expect(root.textContent).toContain("请联系管理员重新设置密码");
    submit();
    await vi.waitFor(() =>
      expect(root.querySelector(".el-form-item__error")?.textContent).toContain(
        "请填写原密码",
      ),
    );
    expect(
      root.querySelector(".el-form-item__error")?.textContent,
    ).not.toContain("六位邮箱验证码");
    expect(root.querySelector(".request-notice")).toBeNull();
    expect(writes("/password")).toHaveLength(0);
    expect(toast).not.toHaveBeenCalled();
    expect(reads("/login/options")).toHaveLength(1);
  });
  it("验证码启用时提供二选一认证提示，错误留在表单且无加载重试", async () => {
    options = { smtp_configured: true, methods: ["email_code", "password"] };
    await readyAccount();
    expect(root.querySelectorAll("input")).toHaveLength(4);
    expect(root.textContent).toContain(
      "首次设置或忘记旧密码时，可使用邮箱验证码",
    );
    submit();
    await vi.waitFor(() =>
      expect(root.querySelector(".el-form-item__error")?.textContent).toContain(
        "原密码或有效的六位邮箱验证码",
      ),
    );
    expect(root.querySelector(".request-notice")).toBeNull();
    expect(writes("/password")).toHaveLength(0);
  });
  it("加载失败保留真正的GET重试，成功之前不提供改密表单", async () => {
    optionsFailure = true;
    await mountPage(PortalAccountView);
    await vi.waitFor(() =>
      expect(root.querySelector(".request-notice")?.textContent).toContain(
        "登录方式暂时无法读取",
      ),
    );
    expect(root.querySelector("form")).toBeNull();
    optionsFailure = false;
    button("重试").click();
    await vi.waitFor(() => expect(root.querySelector("form")).not.toBeNull());
    expect(reads("/login/options")).toHaveLength(2);
    expect(writes("/password")).toHaveLength(0);
  });
  it("尚在读取认证方式时不显示可误操作的密码表单", async () => {
    let release!: () => void;
    optionsGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    await mountPage(PortalAccountView);
    await vi.waitFor(() => expect(reads("/login/options")).toHaveLength(1));
    expect(root.querySelector("form")).toBeNull();
    expect(root.textContent).not.toContain("当前未启用邮箱验证码");
    release();
    await vi.waitFor(() => expect(root.querySelector("form")).not.toBeNull());
  });
  it("提交失败留在表单并保留输入，不出现会重载资料的重试", async () => {
    passwordFailure = true;
    await readyAccount();
    const fields = root.querySelectorAll<HTMLInputElement>("input");
    await input(fields[0]!, "old-password");
    await input(fields[1]!, "new-password");
    await input(fields[2]!, "new-password");
    submit();
    await vi.waitFor(() =>
      expect(root.querySelector("form .request-notice")?.textContent).toContain(
        "密码保存失败",
      ),
    );
    expect(root.querySelector("form .request-notice button")).toBeNull();
    expect([...fields].map((field) => field.value)).toEqual([
      "old-password",
      "new-password",
      "new-password",
    ]);
    expect(reads("/user")).toHaveLength(1);
    expect(reads("/login/options")).toHaveLength(1);
    expect(portalSession.token).toBe("portal-test");
    passwordFailure = false;
    submit();
    await vi.waitFor(() => expect(portalSession.token).toBe(""));
    expect(writes("/password")).toHaveLength(2);
  });
  it("新密码字节长度与确认校验不会发请求、弹toast或提供加载重试", async () => {
    const toast = vi.spyOn(ElMessage, "error");
    await readyAccount();
    const fields = root.querySelectorAll<HTMLInputElement>("input");
    await input(fields[0]!, "old-password");
    await input(fields[1]!, "中".repeat(25));
    await input(fields[2]!, "中".repeat(25));
    submit();
    await vi.waitFor(() =>
      expect(root.textContent).toContain("新密码须为8至72字节"),
    );
    await input(fields[1]!, "new-password");
    submit();
    await vi.waitFor(() =>
      expect(root.textContent).toContain("两次新密码输入不一致"),
    );
    expect(writes("/password")).toHaveLength(0);
    expect(root.querySelector(".request-notice")).toBeNull();
    expect(toast).not.toHaveBeenCalled();
  });
});

describe("其他设置表单不复用加载失败重试", () => {
  it("支持联系方式本地校验错误内联，保留草稿且不触发GET", async () => {
    await mountPage(SupportContactSettings, "/support-test");
    await vi.waitFor(() =>
      expect(root.querySelector("textarea")).not.toBeNull(),
    );
    const value = "中".repeat(201);
    await input(root.querySelector("textarea")!, value);
    submit();
    await vi.waitFor(() =>
      expect(root.querySelector("form .request-notice")?.textContent).toContain(
        "最多 200 字",
      ),
    );
    expect(root.querySelector("form .request-notice button")).toBeNull();
    expect(root.querySelector("textarea")?.value).toBe(value);
    expect(writes("/system/support")).toHaveLength(0);
    expect(reads("/system/support")).toHaveLength(1);
  });
  it("支持联系方式提交错误不提供加载重试，不覆盖未保存内容", async () => {
    supportFailure = true;
    await mountPage(SupportContactSettings, "/support-test");
    await vi.waitFor(() =>
      expect(root.querySelector("textarea")).not.toBeNull(),
    );
    await input(root.querySelector("textarea")!, "尚未保存的联系方式");
    submit();
    await vi.waitFor(() =>
      expect(root.querySelector("form .request-notice")?.textContent).toContain(
        "联系方式保存失败",
      ),
    );
    expect(root.querySelector("form .request-notice button")).toBeNull();
    expect(root.querySelector("textarea")?.value).toBe("尚未保存的联系方式");
    expect(reads("/system/support")).toHaveLength(1);
  });
});

it("全站业务确认调用显式提供动作，不依赖公共函数按文案猜测", () => {
  const sourceRoot = join(process.cwd(), "src");
  const failures: string[] = [];
  let count = 0;
  for (const relative of readdirSync(sourceRoot, { recursive: true })) {
    if (typeof relative !== "string" || !/\.(vue|ts)$/.test(relative)) continue;
    let source = readFileSync(join(sourceRoot, relative), "utf8");
    if (relative.endsWith(".vue"))
      source = source.match(/<script\b[^>]*>([\s\S]*?)<\/script>/)?.[1] || "";
    const parsed = ts.createSourceFile(
      relative,
      source,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS,
    );
    const visit = (node: ts.Node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === "confirmAction"
      ) {
        count++;
        const arg = node.arguments[2];
        const action =
          arg &&
          ts.isObjectLiteralExpression(arg) &&
          arg.properties.find(
            (property) =>
              ts.isPropertyAssignment(property) &&
              (ts.isIdentifier(property.name) ||
                ts.isStringLiteral(property.name)) &&
              property.name.text === "action",
          );
        if (
          !action ||
          (ts.isPropertyAssignment(action) &&
            ts.isStringLiteral(action.initializer) &&
            !action.initializer.text.trim())
        )
          failures.push(relative);
      }
      ts.forEachChild(node, visit);
    };
    visit(parsed);
  }
  expect(count).toBeGreaterThan(15);
  expect(failures).toEqual([]);
});
