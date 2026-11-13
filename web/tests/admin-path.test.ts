import { injectAdminRuntime } from "./admin-bootstrap";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, nextTick, type App, type Component } from "vue";
import { createPinia, setActivePinia } from "pinia";
import { createRouter, createMemoryHistory } from "vue-router";
import ElementPlus from "element-plus";
import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import { adminPath, adminPage, adminApiPath } from "../src/lib/runtime";
import { runtimePages, canonicalPages } from "../src/lib/ui-routes";
import { entryPath } from "../src/lib/entry";
import { get, download, http, portalHttp, authTransport } from "../src/lib/http";
import { adminSession, clearAdmin, clearPortal, setAdmin, setPortal } from "../src/lib/session";
import AdminPathSettings from "../src/components/AdminPathSettings.vue";
import LoginView from "../src/views/LoginView.vue";
import IntegrationDocsView from "../src/views/admin/IntegrationDocsView.vue";
vi.mock("../src/composables/tasks", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/composables/tasks")>(),
  confirmAction: vi.fn(async () => {}),
}));
import { confirmAction } from "../src/composables/tasks";
const adminAdapter = http.defaults.adapter, portalAdapter = portalHttp.defaults.adapter,
  refreshAdapter = authTransport.defaults.adapter;
let app: App | undefined, root: HTMLElement;
const ok = (config: InternalAxiosRequestConfig, data: unknown) => ({
  config, status: 200, statusText: "", headers: new AxiosHeaders(), data: { code: "OK", data },
});
beforeEach(() => {
  injectAdminRuntime("/my-console");
  clearAdmin(); clearPortal();
  root = document.createElement("div"); document.body.append(root);
  setActivePinia(createPinia());
});
afterEach(() => {
  app?.unmount(); app = undefined; root.remove();
  http.defaults.adapter = adminAdapter; portalHttp.defaults.adapter = portalAdapter;
  authTransport.defaults.adapter = refreshAdapter;
  clearAdmin(); clearPortal(); injectAdminRuntime();
  vi.restoreAllMocks();
});
async function mount(component: Component, path = "/my-console/settings", props: Record<string, unknown> = {}) {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: "/:pathMatch(.*)*", component }] });
  await router.push(path);
  app = createApp(component, props); app.use(createPinia()).use(ElementPlus).use(router); app.mount(root);
  return router;
}
it("runtime is strictly a non-executable HTML JSON slot, never URL/storage/default", () => {
  expect(adminPath()).toBe("/my-console");
  expect(adminPage("/login")).toBe("/my-console/login");
  expect(adminApiPath("/auth/refresh")).toBe("/api/v1/my-console/auth/refresh");
  for (const invalid of [null, "/bad/path", "//remote", "/admin?next=x", "/UPPER", "/:segment", "/-console", "/console-", "/" + "a".repeat(49)]) {
    injectAdminRuntime(invalid);
    expect(adminPath()).toBeNull();
    expect(() => adminPage("/login")).toThrow("运行时配置");
  }
  injectAdminRuntime("/my--console");
  expect(adminPath()).toBe("/my--console");
  injectAdminRuntime("/" + "a".repeat(48));
  expect(adminPath()).toBe("/" + "a".repeat(48));
  injectAdminRuntime("/my-console");
  document.getElementById("authgo-runtime")!.setAttribute("type", "text/javascript");
  expect(adminPath()).toBeNull();
  injectAdminRuntime("/my-console");
  document.getElementById("authgo-runtime")!.textContent = "{broken}";
  expect(adminPath()).toBeNull();
});
it("actual router consumes all shared paths; custom and absent bootstrap cannot register /admin", async () => {
  expect(canonicalPages.every((p) => p.scope === "admin" || p.scope === "public")).toBe(true);
  expect(canonicalPages.every((p) => p.scope !== "admin" || !p.path.startsWith("/admin"))).toBe(true);
  expect(canonicalPages.every((p) => !p.path.includes("pathMatch") && (p.path === "" || p.path.startsWith("/")))).toBe(true);
  const pages = runtimePages();
  expect(pages.find((p) => p.id === "admin-users-detail")?.path).toBe("/my-console/users/:id");
  vi.resetModules();
  const router = (await import("../src/router")).default;
  for (const page of pages) expect(router.getRoutes().some((r) => r.path === page.path)).toBe(true);
  expect(router.resolve("/my-console/login").matched).toHaveLength(1);
  expect(router.resolve("/admin/login").matched).toHaveLength(0);
  injectAdminRuntime(null);
  expect(runtimePages().every((p) => p.scope === "public")).toBe(true);
  vi.resetModules();
  const publicRouter = (await import("../src/router")).default;
  expect(publicRouter.getRoutes().some((r) => r.path.startsWith("/my-console"))).toBe(false);
  expect(publicRouter.getRoutes().some((r) => r.path.startsWith("/admin"))).toBe(false);
  expect(publicRouter.resolve("/").matched[0]?.redirect).toBe("/portal");
});
it("custom API, refresh and download all use the same runtime prefix and Bearer", async () => {
  setAdmin("expired", "refresh");
  let refreshes = 0;
  authTransport.defaults.adapter = async (config) => {
    refreshes++;
    expect(config.url).toBe("/api/v1/my-console/auth/refresh");
    return ok(config, { access_token: "renewed", refresh_token: "next-refresh" });
  };
  const urls: string[] = [];
  http.defaults.adapter = async (config) => {
    expect(config.baseURL).toBe("/api/v1/my-console");
    if (config.headers.get("Authorization") === "Bearer expired")
      throw new AxiosError("expired", "ERR_BAD_REQUEST", config, undefined, { ...ok(config, null), status: 401 });
    expect(config.headers.get("Authorization")).toBe("Bearer renewed");
    urls.push(config.baseURL! + config.url!);
    return config.responseType === "blob" ? { ...ok(config, null), data: new Blob(["backup"]), headers: new AxiosHeaders({ "content-type": "application/octet-stream" }) } : ok(config, {});
  };
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:authgo-download-test");
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  await get("/system/settings");
  await download("admin", "/system/backups/backup.bin", "backup.bin");
  expect(refreshes).toBe(1);
  expect(urls).toEqual(["/api/v1/my-console/system/settings", "/api/v1/my-console/system/backups/backup.bin"]);
});
it("missing bootstrap refuses admin traffic before transport but keeps portal API and public entry", async () => {
  injectAdminRuntime(null);
  setAdmin("stale-admin", "stale-refresh");
  const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => ok(config, {}));
  http.defaults.adapter = adapter; authTransport.defaults.adapter = adapter;
  await expect(get("/auth/status", undefined, { quiet: true })).rejects.toThrow();
  await expect(download("admin", "/system/backups/latest", "latest", { quiet: true })).rejects.toThrow();
  expect(adapter).not.toHaveBeenCalled();
  expect(entryPath()).toBe("/portal/login");
  expect(entryPath("/admin/login")).toBe("/portal/login");
  portalHttp.defaults.adapter = async (config) => {
    expect(config.baseURL).toBe("/api/v1/portal");
    return ok(config, { smtp_configured: false });
  };
  await mount(LoginView, "/portal/login", { mode: "portal" });
  await vi.waitFor(() => expect(root.textContent).toContain("进入用户中心"));
  expect(root.textContent).not.toContain("管理员登录");
  expect(root.querySelector('a[href*="console"]')).toBeNull();
});
it("a separate single-field form PATCHes, clears admin session and does a full login navigation", async () => {
  setAdmin("access", "refresh", { username: "owner" });
  setPortal("portal-token", "user");
  const assign = vi.spyOn(window.location, "assign").mockImplementation(() => {});
  const writes: unknown[] = [];
  http.defaults.adapter = async (config) => {
    expect(config.baseURL).toBe("/api/v1/my-console");
    expect(config.headers.get("Authorization")).toBe("Bearer access");
    expect(config.url).toBe("/system/admin-path");
    if (config.method === "patch") {
      writes.push(JSON.parse(String(config.data)));
      return ok(config, { path: "/new-console", login_url: "/new-console/login" });
    }
    return ok(config, { path: "/my-console", reserved: ["api", "portal"] });
  };
  await mount(AdminPathSettings);
  await vi.waitFor(() => expect(root.querySelector("input")?.value).toBe("/my-console"));
  expect(root.querySelectorAll("input")).toHaveLength(1);
  expect(root.textContent).toContain("全部管理员都需要重新登录");
  expect(root.textContent).toContain("api、portal");
  const input = root.querySelector("input")!;
  input.value = "/new-console"; input.dispatchEvent(new Event("input", { bubbles: true }));
  await nextTick();
  root.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(assign).toHaveBeenCalledWith("/new-console/login"));
  expect(writes).toEqual([{ path: "/new-console" }]);
  expect(confirmAction).toHaveBeenCalled();
  expect(adminSession.access).toBe(""); expect(adminSession.refresh).toBe("");
  expect(sessionStorage.getItem("authgo.admin.access")).toBeNull();
  expect(sessionStorage.getItem("authgo.admin.refresh")).toBeNull();
  expect(sessionStorage.getItem("authgo.portal.token")).toBe("portal-token");
});
it("malformed success navigation never authorizes an external URL and still clears revoked credentials", async () => {
  setAdmin("access", "refresh");
  const assign = vi.spyOn(window.location, "assign").mockImplementation(() => {});
  http.defaults.adapter = async (config) => ok(config, config.method === "patch"
    ? { path: "/new-console", login_url: "https://evil.example/login" }
    : { path: "/my-console", reserved: [] });
  await mount(AdminPathSettings);
  await vi.waitFor(() => expect(root.querySelector("input")).not.toBeNull());
  const input = root.querySelector("input")!; input.value = "/new-console";
  input.dispatchEvent(new Event("input", { bubbles: true })); await nextTick();
  root.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(root.textContent).toContain("后台地址已更新，请使用新地址重新登录"));
  expect(assign).not.toHaveBeenCalled();
  expect(adminSession.access).toBe(""); expect(adminSession.refresh).toBe("");
});
it("canceling the re-login confirmation never changes path or credentials", async () => {
  setAdmin("access", "refresh");
  vi.mocked(confirmAction).mockRejectedValueOnce("cancel");
  const writes: string[] = [];
  http.defaults.adapter = async (config) => {
    if (config.method === "patch") writes.push(config.url!);
    return ok(config, { path: "/my-console", reserved: [] });
  };
  await mount(AdminPathSettings);
  await vi.waitFor(() => expect(root.querySelector("input")).not.toBeNull());
  const input = root.querySelector("input")!; input.value = "/new-console";
  input.dispatchEvent(new Event("input", { bubbles: true })); await nextTick();
  root.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(vi.mocked(confirmAction)).toHaveBeenCalled());
  await nextTick();
  expect(writes).toEqual([]); expect(adminSession.access).toBe("access");
});
it("failed changes retain the session and never navigate", async () => {
  setAdmin("access", "refresh");
  const assign = vi.spyOn(window.location, "assign").mockImplementation(() => {});
  http.defaults.adapter = async (config) => {
    if (config.method === "patch") throw new AxiosError("invalid", "ERR_BAD_REQUEST", config, undefined, { ...ok(config, null), status: 400, data: { code: "INVALID_PATH", message: "路径不可用" } });
    return ok(config, { path: "/my-console", reserved: ["portal"] });
  };
  await mount(AdminPathSettings);
  await vi.waitFor(() => expect(root.querySelector("input")).not.toBeNull());
  const input = root.querySelector("input")!; input.value = "/new-console";
  input.dispatchEvent(new Event("input", { bubbles: true })); await nextTick();
  root.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(root.textContent).toContain("路径不可用"));
  expect(assign).not.toHaveBeenCalled(); expect(adminSession.access).toBe("access");
});
it("private OpenAPI loads through the authenticated runtime http client only", async () => {
  setAdmin("docs-access", "docs-refresh");
  http.defaults.adapter = async (config) => {
    expect(config.baseURL).toBe("/api/v1/my-console");
    expect(config.url).toBe("/docs/openapi.json");
    expect(config.headers.get("Authorization")).toBe("Bearer docs-access");
    return ok(config, { openapi: "3.0.0", paths: { "/api/v1/my-console/system/admin-path": {} } });
  };
  await mount(IntegrationDocsView, "/my-console/docs?tab=admin-api");
  await vi.waitFor(() => expect(root.textContent).toContain('"openapi": "3.0.0"'));
  expect(root.textContent).toContain("/api/v1/my-console/system/admin-path");
  expect(root.querySelector("iframe")).toBeNull();
});

it.each(["/UPPER", "/portal", "/api", "/bad/path", "/-start", "/end-", "/" + "a".repeat(49)])("invalid or reserved address %s stays inline before confirmation or writes", async (path) => {
  vi.mocked(confirmAction).mockClear();
  const writes: string[] = [];
  http.defaults.adapter = async (config) => {
    if (config.method === "patch") writes.push(config.url!);
    return ok(config, { path: "/my-console", reserved: ["portal", "api"] });
  };
  await mount(AdminPathSettings);
  await vi.waitFor(() => expect(root.querySelector("input")).not.toBeNull());
  const input = root.querySelector("input")!; input.value = path;
  input.dispatchEvent(new Event("input", { bubbles: true })); await nextTick();
  root.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(root.querySelector(".el-form-item__error")).not.toBeNull());
  expect(vi.mocked(confirmAction)).not.toHaveBeenCalled();
  expect(writes).toEqual([]); expect(input.value).toBe(path);
  expect(root.textContent).not.toContain("重试");
});
it("save failure preserves the edit and offers resubmission, never reload/reset", async () => {
  http.defaults.adapter = async (config) => {
    if (config.method === "patch") throw new AxiosError("save failed", "ERR_BAD_RESPONSE", config, undefined, { ...ok(config, null), status: 503, data: { code: "UNAVAILABLE", message: "保存失败，请检查连接" } });
    return ok(config, { path: "/my-console", reserved: [] });
  };
  await mount(AdminPathSettings);
  await vi.waitFor(() => expect(root.querySelector("input")).not.toBeNull());
  const input = root.querySelector("input")!; input.value = "/retained-console";
  input.dispatchEvent(new Event("input", { bubbles: true })); await nextTick();
  root.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(root.querySelector("form")!.textContent).toContain("保存失败"));
  expect(input.value).toBe("/retained-console");
  expect(root.textContent).not.toContain("重试");
});
