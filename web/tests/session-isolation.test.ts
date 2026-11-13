import "./admin-bootstrap";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App, type Component } from "vue";
import { createPinia } from "pinia";
import { createMemoryHistory, createRouter, RouterView } from "vue-router";
import { AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import ElementPlus, { ElMessageBox } from "element-plus";
import ApplicationDetailView from "../src/views/admin/ApplicationDetailView.vue";
import LicenseDetailView from "../src/views/admin/LicenseDetailView.vue";
import UserDetailView from "../src/views/admin/UserDetailView.vue";
import SettingsView from "../src/views/admin/SettingsView.vue";
import PortalAccountView from "../src/views/portal/PortalAccountView.vue";
import SetupView from "../src/views/SetupView.vue";
import ForbiddenView from "../src/views/ForbiddenView.vue";
import NotFoundView from "../src/views/NotFoundView.vue";
import UnavailableView from "../src/views/UnavailableView.vue";
import { http, portalHttp } from "../src/lib/http";
import {
  clearAdmin,
  clearPortal,
  portalSession,
  setAdmin,
  setPortal,
} from "../src/lib/session";
import { entryPath } from "../src/lib/entry";
import type { Row } from "../src/lib/json";

let root: HTMLElement, app: App | undefined;
beforeEach(() => {
  clearAdmin();
  clearPortal();
  root = document.createElement("div");
  document.body.append(root);
});
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.remove();
  vi.restoreAllMocks();
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
const ok = (config: InternalAxiosRequestConfig, data: unknown) => ({
  config,
  data: { code: "OK", data },
  status: 200,
  statusText: "OK",
  headers: new AxiosHeaders(),
});
const entity = (id: number, name = `记录${id}`): Row => ({
  id,
  name,
  email: `${id}@example.com`,
  app_id: 7,
  app_name: name,
  app_key: `public-${id}`,
  key: `AUTH-${name}`,
  status: "active",
  type: "standard",
  verify_methods: ["KEY"],
  validity_rule: "perpetual",
  features: {},
  metadata: {},
});
async function mount(
  component: Component,
  path: string,
  pattern = path.split("?")[0]!,
) {
  const empty = { template: "<div>destination</div>" };
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: pattern, component },
      { path: "/:pathMatch(.*)*", component: empty },
    ],
  });
  await router.push(path);
  app = createApp({ render: () => h(RouterView) });
  app.use(createPinia()).use(ElementPlus).use(router);
  app.mount(root);
  return router;
}
function button(text: string): HTMLButtonElement {
  const found = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.textContent?.trim() === text,
  );
  expect(found, `button ${text}`).toBeTruthy();
  return found!;
}
async function flush() {
  for (let i = 0; i < 20; i++) await Promise.resolve();
  await nextTick();
}
async function clickAction(text: string) {
  const direct = [...root.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.textContent?.trim() === text,
  );
  if (direct) {
    direct.click();
    return;
  }
  root
    .querySelector<HTMLButtonElement>('button[aria-label="更多操作"]')!
    .click();
  let item: HTMLElement | undefined;
  await vi.waitFor(() => {
    item = [
      ...document.querySelectorAll<HTMLElement>(
        '.action-menu-popper [role="menuitem"]',
      ),
    ].find((el) => el.textContent?.trim() === text);
    expect(item).toBeTruthy();
  });
  item!.click();
}
function input(el: HTMLInputElement, value: string) {
  el.value = value;
  el.dispatchEvent(new Event("input", { bubbles: true }));
}
const details = [
  {
    base: "applications",
    component: ApplicationDetailView,
    action: "查看软件密钥",
  },
  { base: "users", component: UserDetailView, action: "停用用户" },
  { base: "licenses", component: LicenseDetailView, action: "暂停" },
];
it.each(details)(
  "$base ignores reversed detail reads and disables mismatched IDs",
  async ({ base, component }) => {
    setAdmin("access", "refresh");
    const first = deferred<Row>(),
      second = deferred<Row>();
    const requests: string[] = [];
    http.defaults.adapter = async (config) => {
      requests.push(config.url!);
      if (config.url === `/${base}/1`) return ok(config, await first.promise);
      if (config.url === `/${base}/2`) return ok(config, await second.promise);
      if (config.url === `/${base}/3`)
        return ok(config, entity(999, "错误编号"));
      return ok(config, { items: [], total: 0 });
    };
    const router = await mount(
      component,
      `/admin/${base}/1`,
      `/admin/${base}/:id`,
    );
    await vi.waitFor(() => expect(requests).toContain(`/${base}/1`));
    await router.push(`/admin/${base}/2`);
    await vi.waitFor(() => expect(requests).toContain(`/${base}/2`));
    second.resolve(entity(2, "正确乙"));
    await vi.waitFor(() => expect(root.textContent).toContain("正确乙"));
    first.resolve(entity(1, "过时甲"));
    await flush();
    expect(root.textContent).not.toContain("过时甲");
    expect(root.textContent).toContain("正确乙");
    await router.push(`/admin/${base}/3`);
    expect(root.textContent).not.toContain("正确乙");
    await vi.waitFor(() =>
      expect(root.textContent).toContain("详情响应编号不一致"),
    );
    expect(root.textContent).not.toContain("错误编号");
    if (base === "applications") {
      expect(root.textContent).not.toContain("查看软件密钥");
    } else {
      expect(button(base === "users" ? "启用用户" : "分配用户").disabled).toBe(
        true,
      );
    }
  },
);
it.each(details)(
  "$base captures ID before confirmation and rejects navigation",
  async ({ base, component, action }) => {
    setAdmin("access", "refresh");
    const confirm = deferred<"confirm">();
    const spy = vi
      .spyOn(ElMessageBox, "confirm")
      .mockImplementation(() => confirm.promise);
    const operations: string[] = [];
    http.defaults.adapter = async (config) => {
      if (config.method !== "get" || config.url?.endsWith("/secret"))
        operations.push(config.url!);
      const match = config.url?.match(new RegExp(`^/${base}/([12])$`));
      return ok(
        config,
        match
          ? entity(Number(match[1]), `对象${match[1]}`)
          : { items: [], total: 0 },
      );
    };
    const router = await mount(
      component,
      `/admin/${base}/1`,
      `/admin/${base}/:id`,
    );
    await vi.waitFor(() => expect(root.textContent).toContain("对象1"));
    if (base === "applications") {
      root.querySelector("details")!.open = true;
      await nextTick();
    }
    await clickAction(action);
    await vi.waitFor(() => expect(spy).toHaveBeenCalled());
    await router.push(`/admin/${base}/2`);
    await vi.waitFor(() => expect(root.textContent).toContain("对象2"));
    confirm.resolve("confirm");
    await vi.waitFor(() => expect(root.textContent).toContain("页面已切换"));
    expect(operations).toEqual([]);
    expect(root.textContent).not.toContain("对象1");
  },
);
it("software secrets clear immediately and late secret responses cannot reopen them", async () => {
  setAdmin("access", "refresh");
  vi.spyOn(ElMessageBox, "confirm").mockResolvedValue("confirm");
  const late = deferred<Row>();
  let secretReads = 0;
  http.defaults.adapter = async (config) => {
    if (config.url === "/applications/1/secret") {
      secretReads++;
      return ok(
        config,
        secretReads === 1
          ? { app_secret: "FIRST_PRIVATE_SECRET" }
          : await late.promise,
      );
    }
    const match = config.url?.match(/^\/applications\/([12])$/);
    return ok(
      config,
      match ? entity(Number(match[1])) : { items: [], total: 0 },
    );
  };
  const router = await mount(
    ApplicationDetailView,
    "/admin/applications/1",
    "/admin/applications/:id",
  );
  await vi.waitFor(() => expect(root.textContent).toContain("记录1"));
  button("查看软件密钥").click();
  await vi.waitFor(() =>
    expect(
      document.querySelector('[aria-label="显示软件密钥"]'),
    ).not.toBeNull(),
  );
  document
    .querySelector<HTMLButtonElement>('[aria-label="显示软件密钥"]')!
    .click();
  await vi.waitFor(() =>
    expect(document.body.textContent).toContain("FIRST_PRIVATE_SECRET"),
  );
  await router.push("/admin/applications/2");
  await nextTick();
  document
    .querySelector<HTMLButtonElement>('[aria-label="显示软件密钥"]')
    ?.click();
  await flush();
  expect(document.body.textContent).not.toContain("FIRST_PRIVATE_SECRET");
  await router.push("/admin/applications/1");
  await vi.waitFor(() => expect(root.textContent).toContain("记录1"));
  button("查看软件密钥").click();
  await vi.waitFor(() => expect(secretReads).toBe(2));
  await router.push("/admin/applications/2");
  late.resolve({ app_secret: "LATE_PRIVATE_SECRET" });
  await flush();
  document
    .querySelector<HTMLButtonElement>('[aria-label="显示软件密钥"]')
    ?.click();
  await flush();
  expect(document.body.textContent).not.toContain("LATE_PRIVATE_SECRET");
});
it.each(details.slice(1))(
  "$base late mutation cannot overwrite the new record",
  async ({ base, component, action }) => {
    setAdmin("access", "refresh");
    vi.spyOn(ElMessageBox, "confirm").mockResolvedValue("confirm");
    const late = deferred<Row>();
    let writes = 0;
    http.defaults.adapter = async (config) => {
      if (config.method !== "get") {
        writes++;
        return ok(config, await late.promise);
      }
      const match = config.url?.match(new RegExp(`^/${base}/([12])$`));
      return ok(
        config,
        match
          ? entity(Number(match[1]), `对象${match[1]}`)
          : { items: [], total: 0 },
      );
    };
    const router = await mount(
      component,
      `/admin/${base}/1`,
      `/admin/${base}/:id`,
    );
    await vi.waitFor(() => expect(root.textContent).toContain("对象1"));
    await clickAction(action);
    await vi.waitFor(() => expect(writes).toBe(1));
    await router.push(`/admin/${base}/2`);
    await vi.waitFor(() => expect(root.textContent).toContain("对象2"));
    late.resolve(entity(1, "过时写入"));
    await flush();
    expect(root.textContent).not.toContain("过时写入");
    expect(root.textContent).toContain("对象2");
  },
);
it("settings describe additive proxy trust and fixed audit retention", async () => {
  setAdmin("access", "refresh");
  http.defaults.adapter = async (config) =>
    ok(config, {
      site_name: "AuthGo",
      trusted_proxies: [],
      smtp: {},
      notification_days: [7, 3, 1],
    });
  await mount(SettingsView, "/admin/settings");
  await vi.waitFor(() =>
    expect(root.textContent).toContain("此处清空不能取消环境配置"),
  );
  expect(root.textContent).toContain("部署环境的可信代理与此处列表合并生效");
  expect(root.textContent).toContain("审计日志保留 365 天");
  expect(root.textContent).toContain("不自动归档");
});
it("password validates UTF8 length and confirmation before submitting, then logs out", async () => {
  setPortal("portal-user", "user");
  const writes: Row[] = [];
  const saved = deferred<Row>();
  portalHttp.defaults.adapter = async (config) => {
    if (config.url === "/password") {
      writes.push(JSON.parse(String(config.data)));
      return ok(config, await saved.promise);
    }
    return ok(
      config,
      config.url === "/user"
        ? { name: "用户", email: "u@example.com" }
        : { smtp_configured: false },
    );
  };
  const router = await mount(PortalAccountView, "/portal/account");
  await vi.waitFor(() => expect(root.textContent).toContain("u@example.com"));
  await flush();
  await vi.waitFor(() =>
    expect(button("保存密码并重新登录").classList.contains("is-loading")).toBe(
      false,
    ),
  );
  const fields = [...root.querySelectorAll<HTMLInputElement>("input")];
  expect(fields).toHaveLength(3);
  const submit = () =>
    root
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  submit();
  await vi.waitFor(() => expect(root.textContent).toContain("请填写原密码"));
  expect(writes).toHaveLength(0);
  input(fields[0]!, "old-password");
  input(fields[1]!, "short");
  input(fields[2]!, "short");
  submit();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("新密码须为8至72字节"),
  );
  expect(writes).toHaveLength(0);

  input(fields[1]!, "中".repeat(25));
  input(fields[2]!, "中".repeat(25));
  submit();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("新密码须为8至72字节"),
  );
  expect(writes).toHaveLength(0);
  input(fields[1]!, "new-password");
  input(fields[2]!, "different-password");
  submit();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("两次新密码输入不一致"),
  );
  expect(writes).toHaveLength(0);
  input(fields[2]!, "new-password");
  submit();
  submit();
  await vi.waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toEqual({
    old_password: "old-password",
    new_password: "new-password",
    code: "",
  });
  saved.resolve({});
  await vi.waitFor(() =>
    expect(router.currentRoute.value.path).toBe("/portal/login"),
  );
  expect(portalSession.token).toBe("");
  expect(sessionStorage.getItem("authgo.portal.token")).toBeNull();
});
it("scoped entries cover portal, admin, both sessions, and signed-out visitors", () => {
  expect(entryPath()).toBe("/admin/login");
  expect(entryPath("/portal/unknown")).toBe("/portal/login");
  setPortal("p", "user");
  expect(entryPath()).toBe("/portal/home");
  expect(entryPath("/admin/unknown")).toBe("/admin/login");
  setAdmin("a", "r");
  expect(entryPath("/portal/unknown")).toBe("/portal/home");
  expect(entryPath("/admin/unknown")).toBe("/admin/overview");
  setPortal("p", "license");
  expect(entryPath("/portal/unknown")).toBe("/portal/license");
  clearPortal();
  expect(entryPath()).toBe("/admin/overview");
});
it.each([ForbiddenView, NotFoundView, UnavailableView])(
  "error page returns portal-only user to portal",
  async (component) => {
    setPortal("p", "user");
    const router = await mount(component, "/error?next=https://evil.example");
    const anchor = root.querySelector<HTMLAnchorElement>("a");
    if (anchor) anchor.click();
    else button("重新加载页面").click();
    await vi.waitFor(() =>
      expect(router.currentRoute.value.path).toBe("/portal/home"),
    );
  },
);
it.each([false, true])(
  "initialization status retry preserves memory-only capability (already initialized=%s)",
  async (initialized) => {
    const token = "ONE_TIME_PRIVATE_SETUP_CAPABILITY";
    let reads = 0;
    const writes: Row[] = [];
    const pending = deferred<Row>();
    http.defaults.adapter = async (config) => {
      if (config.url === "/status") {
        reads++;
        if (reads === 1) throw new Error("temporary network error");
        return ok(config, await pending.promise);
      }
      if (config.url === "/auth/setup") {
        writes.push(JSON.parse(String(config.data)));
        return ok(config, {
          access_token: "a",
          refresh_token: "r",
          admin: { username: "admin" },
        });
      }
      return ok(config, {});
    };
    const router = await mount(
      SetupView,
      `/admin/setup?token=${token}`,
      "/admin/setup",
    );
    await vi.waitFor(() =>
      expect(root.textContent).toContain("重试读取初始化状态"),
    );
    expect(router.currentRoute.value.fullPath).toBe("/admin/setup");
    expect(root.textContent).not.toContain("请从当前服务日志");
    expect(
      JSON.stringify({ ...sessionStorage, ...localStorage }),
    ).not.toContain(token);
    button("重试读取初始化状态").click();
    button("重试读取初始化状态").click();
    await vi.waitFor(() => expect(reads).toBe(2));
    pending.resolve({ setup_required: !initialized });
    if (initialized) {
      await vi.waitFor(() =>
        expect(router.currentRoute.value.path).toBe("/not-found"),
      );
      expect(writes).toHaveLength(0);
      return;
    }
    await vi.waitFor(() => expect(root.querySelector("form")).not.toBeNull());
    const inputs = [...root.querySelectorAll<HTMLInputElement>("input")];
    input(inputs[1]!, "initial-password");
    input(inputs[2]!, "initial-password");
    root
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() =>
      expect(router.currentRoute.value.path).toBe("/admin/overview"),
    );
    expect(writes).toHaveLength(1);
    expect(writes[0]?.token).toBe(token);
    expect(
      JSON.stringify({ ...sessionStorage, ...localStorage }),
    ).not.toContain(token);
  },
);

it("user navigation clears related records before the next collection arrives", async () => {
  setAdmin("a", "r");
  const pending = deferred<Row>();
  http.defaults.adapter = async (config) => {
    const match = config.url?.match(/^\/users\/([12])$/);
    if (match) return ok(config, entity(Number(match[1]), `用户${match[1]}`));
    if (config.url === "/licenses")
      return ok(
        config,
        config.params?.user_id === "1"
          ? {
              items: [
                { id: 9, key: "PREVIOUS_USER_LICENSE", status: "active" },
              ],
              total: 1,
            }
          : await pending.promise,
      );
    return ok(config, { items: [], total: 0 });
  };
  const router = await mount(
    UserDetailView,
    "/admin/users/1",
    "/admin/users/:id",
  );
  await vi.waitFor(() =>
    expect(root.textContent).toContain("PREVIOUS_USER_LICENSE"),
  );
  await router.push("/admin/users/2");
  await vi.waitFor(() => expect(root.textContent).toContain("用户2"));
  expect(root.textContent).not.toContain("PREVIOUS_USER_LICENSE");
  pending.resolve({ items: [], total: 0 });
  await flush();
});
it("email verification accepts a 72-byte confirmed password without an old password", async () => {
  setPortal("p", "user");
  const writes: Row[] = [];
  portalHttp.defaults.adapter = async (config) => {
    if (config.url === "/password") {
      writes.push(JSON.parse(String(config.data)));
      return ok(config, {});
    }
    return ok(
      config,
      config.url === "/user"
        ? { name: "用户", email: "u@example.com" }
        : { smtp_configured: true },
    );
  };
  const router = await mount(PortalAccountView, "/portal/account");
  await vi.waitFor(() =>
    expect(root.querySelectorAll("input")).toHaveLength(4),
  );
  await flush();
  const fields = [...root.querySelectorAll<HTMLInputElement>("input")];
  input(fields[1]!, "12345");
  input(fields[2]!, "中".repeat(24));
  input(fields[3]!, "中".repeat(24));
  const submit = () =>
    root
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  submit();
  await vi.waitFor(() => expect(root.textContent).toContain("六位邮箱验证码"));
  expect(writes).toHaveLength(0);
  input(fields[1]!, "123456");
  submit();
  await vi.waitFor(() =>
    expect(router.currentRoute.value.path).toBe("/portal/login"),
  );
  expect(writes).toEqual([
    { old_password: "", new_password: "中".repeat(24), code: "123456" },
  ]);
  expect(portalSession.token).toBe("");
});
