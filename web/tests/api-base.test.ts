import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { AxiosError, AxiosHeaders } from "axios";
import { createPinia, setActivePinia } from "pinia";
afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});
it("同源用于管理、门户、刷新和所有文件下载", async () => {
  vi.resetModules();
  const transport = await import("../src/lib/http");
  const sessions = await import("../src/lib/session");
  expect(transport.http.defaults.baseURL).toBe("/api/v1/admin");
  expect(transport.portalHttp.defaults.baseURL).toBe("/api/v1/portal");
  expect(transport.integrationOrigin()).toBe(window.location.origin);
  sessions.setAdmin("expired", "refresh");
  sessions.setPortal("portal-session");
  transport.authTransport.defaults.adapter = async (config) => {
    expect(config.url).toBe("/api/v1/admin/auth/refresh");
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: { access_token: "renewed", refresh_token: "renewed-refresh" },
      },
    };
  };
  const calls: string[] = [];
  transport.http.defaults.adapter = async (config) => {
    if (config.headers.get("Authorization") === "Bearer expired")
      throw new AxiosError("expired", "ERR_BAD_REQUEST", config, undefined, {
        config,
        status: 401,
        statusText: "",
        headers: new AxiosHeaders(),
        data: { code: "UNAUTHORIZED" },
      });
    calls.push(config.baseURL! + config.url!);
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data:
        config.responseType === "blob"
          ? new Blob(["zip"])
          : { code: "OK", data: {} },
    };
  };
  transport.portalHttp.defaults.adapter = async (config) => {
    calls.push(config.baseURL! + config.url!);
    expect(config.headers.get("Authorization")).toBe("Bearer portal-session");
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: new Blob(["asset"]),
    };
  };
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:download");
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  await transport.get("/applications");
  await transport.download("admin", "/licenses/export", "licenses.csv");
  await transport.download("admin", "/system/backups/file", "backup.zip");
  expect("downloadPortalAsset" in transport).toBe(false);
  expect(calls).toContain("/api/v1/admin/licenses/export");
  expect(calls).toContain("/api/v1/admin/system/backups/file");
  vi.restoreAllMocks();
});
it("初始化页由公开状态API关闭，与后端页面路径无关", async () => {
  vi.resetModules();
  const pinia = createPinia();
  setActivePinia(pinia);
  const { http } = await import("../src/lib/http");
  const requests: string[] = [];
  http.defaults.adapter = async (config) => {
    requests.push(config.url!);
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: { code: "OK", data: { setup_required: false } },
    };
  };
  const { default: router } = await import("../src/router");
  await router.push("/admin/setup?token=not-an-admin-credential");
  const { createApp, h } = await import("vue");
  const { RouterView } = await import("vue-router");
  const { default: ElementPlus } = await import("element-plus");
  const root = document.createElement("div");
  document.body.append(root);
  const app = createApp({ render: () => h(RouterView) });
  app.use(pinia).use(ElementPlus).use(router);
  app.mount(root);
  try {
    await vi.waitFor(() =>
      expect(router.currentRoute.value.path).toBe("/not-found"),
    );
    expect(requests).toContain("/status");
  } finally {
    app.unmount();
    root.remove();
  }
});

it("真实初始化路由先清除token再读状态，断网重试不经next泄露能力", async () => {
  vi.resetModules();
  const pinia = createPinia();
  setActivePinia(pinia);
  const { http } = await import("../src/lib/http");
  const { default: router } = await import("../src/router");
  const { createApp, h } = await import("vue");
  const { RouterView } = await import("vue-router");
  const { default: ElementPlus } = await import("element-plus");
  const capability = "ROUTER_SETUP_PRIVATE_CAPABILITY";
  let reads = 0;
  const paths: string[] = [];
  const bodies: Record<string, unknown>[] = [];
  http.defaults.adapter = async (config) => {
    if (config.url === "/status") {
      paths.push(router.currentRoute.value.fullPath);
      reads++;
      if (reads === 1) throw new Error("temporary network failure");
      return {
        config,
        status: 200,
        statusText: "",
        headers: new AxiosHeaders(),
        data: { code: "OK", data: { setup_required: true } },
      };
    }
    if (config.url === "/auth/setup") {
      bodies.push(JSON.parse(String(config.data)));
      throw new Error("stop after verifying request");
    }
    throw new Error(`unexpected ${config.url}`);
  };
  await router.push(`/admin/setup?token=${capability}`);
  const root = document.createElement("div");
  document.body.append(root);
  const app = createApp({ render: () => h(RouterView) });
  app.use(pinia).use(ElementPlus).use(router);
  app.mount(root);
  try {
    await vi.waitFor(() =>
      expect(root.textContent).toContain("重试读取初始化状态"),
    );
    expect(router.currentRoute.value.fullPath).toBe("/admin/setup");
    expect(paths).toEqual(["/admin/setup"]);
    [...root.querySelectorAll<HTMLButtonElement>("button")]
      .find((b) => b.textContent?.trim() === "重试读取初始化状态")!
      .click();
    await vi.waitFor(() => expect(root.querySelector("form")).not.toBeNull());
    const inputs = [...root.querySelectorAll<HTMLInputElement>("input")];
    for (const el of inputs.slice(1)) {
      el.value = "initial-password";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }
    root
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]?.token).toBe(capability);
    expect(paths).toEqual(["/admin/setup", "/admin/setup"]);
    expect(router.currentRoute.value.fullPath).toBe("/admin/setup");
    for (const storage of [sessionStorage, localStorage])
      for (let i = 0; i < storage.length; i++)
        expect(storage.getItem(storage.key(i)!)).not.toContain(capability);
  } finally {
    app.unmount();
    root.remove();
  }
});
