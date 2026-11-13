// @vitest-environment node
import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import {
  confirmedDevAdminPath,
  devAdminCandidate,
  devApiTarget,
  devRuntimePlugin,
  devRuntimeTags,
  type DevUIRoute,
} from "../scripts/dev-runtime.mjs";
import type { IndexHtmlTransformContext } from "vite";

const routes: DevUIRoute[] = JSON.parse(readFileSync(new URL("../../server/internal/webui/routes.json", import.meta.url), "utf8"));
const envelope = (path: string) => ({ code: "OK", data: { admin_path: path } });
const jsonResponse = (value: unknown, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { "Content-Type": "application/json" },
});
afterEach(() => vi.unstubAllGlobals());

describe("dev-only Go-confirmed HTML runtime", () => {
  it("only proposes shaped candidates on actual shared admin UI routes", () => {
    for (const base of ["/admin", "/my-console", "/my--console", "/" + "a".repeat(48)]) {
      for (const suffix of ["", "/login", "/setup", "/applications/42", "/settings"])
        expect(devAdminCandidate(base + suffix + "?token=private-setup-capability", routes)).toBe(base);
    }
    for (const url of [
      undefined, "", "/", "/index.html", "/portal", "/portal/login", "/portal/licenses/42",
      "/forbidden", "/unavailable", "/not-found", "/my-console/unknown", "/my-console/users/0",
      "/my-console/users/not-an-id", "/my-console/users/42/extra", "/my-console//login",
      "/my-console/../login", "/my-console/%2e%2e/login", "/my-console/login/",
      "/UPPER/login", "/-console/login", "/console-/login", "/" + "a".repeat(49) + "/login",
      "//evil.example/login", "https://evil.example/my-console/login", "/my-console\\evil/login",
      "/my%2dconsole/login", "/my-console/login#fragment", "/my-console/login\r\nHost: evil.example",
    ]) expect(devAdminCandidate(url, routes), String(url)).toBeNull();
  });

  it("does not hardcode public root exclusions apart from the real manifest", () => {
    expect(devAdminCandidate("/new-public/login", [
      { path: "/login", scope: "admin" }, { path: "/new-public/home", scope: "public" },
    ])).toBeNull();
  });

  it("requires an OK envelope whose path exactly matches the candidate", () => {
    expect(confirmedDevAdminPath("/my-console", envelope("/my-console"))).toBe("/my-console");
    for (const value of [null, {}, { code: "OK" }, { admin_path: "/my-console" },
      { code: "UNAUTHORIZED", data: { admin_path: "/my-console" } }, envelope("/admin"),
      envelope("/my-console/"), envelope("//evil.example"), envelope("/my-console</script>")])
      expect(confirmedDevAdminPath("/my-console", value)).toBeNull();
    expect(confirmedDevAdminPath(null, envelope("/admin"))).toBeNull();
    expect(confirmedDevAdminPath("/bad/path", envelope("/bad/path"))).toBeNull();
  });

  it("injects only non-executable JSON after the fixed Go status endpoint confirms, never forwarding capability or auth", async () => {
    const request = vi.fn<typeof fetch>(async () => jsonResponse(envelope("/my-console")));
    const tags = await devRuntimeTags("/my-console/setup?token=private-setup-capability", routes, request);
    expect(request).toHaveBeenCalledTimes(1);
    const [url, options] = request.mock.calls[0]!;
    expect(url).toBe("http://127.0.0.1:8080/api/v1/my-console/status");
    expect(options).toEqual({
      method: "GET", headers: { Accept: "application/json" }, credentials: "omit",
      redirect: "error", cache: "no-store", signal: expect.any(AbortSignal),
    });
    expect(JSON.stringify(request.mock.calls)).not.toContain("private-setup-capability");
    expect(tags).toEqual([{
      tag: "script", attrs: { id: "authgo-runtime", type: "application/json" },
      children: '{"admin_path":"/my-console"}', injectTo: "head-prepend",
    }]);
    expect(devApiTarget).toBe("http://127.0.0.1:8080");
  });

  it("bootstraps initial setup at the default path only after Go confirms that same candidate", async () => {
    const request = vi.fn<typeof fetch>(async () => jsonResponse(envelope("/admin")));
    expect(await devRuntimeTags("/admin/setup?token=initial-capability", routes, request)).toEqual([{
      tag: "script", attrs: { id: "authgo-runtime", type: "application/json" },
      children: '{"admin_path":"/admin"}', injectTo: "head-prepend",
    }]);
    expect(request.mock.calls[0]![0]).toBe(devApiTarget + "/api/v1/admin/status");
  });

  it("leaves public and invalid HTML without runtime and without probing Go", async () => {
    const request = vi.fn<typeof fetch>(async () => jsonResponse(envelope("/my-console")));
    for (const url of ["/", "/portal/login", "/my-console/unknown", "/UPPER/login", "/not-found"])
      expect(await devRuntimeTags(url, routes, request)).toEqual([]);
    expect(request).not.toHaveBeenCalled();
  });

  it("refuses an old or wrong prefix without discovering or following the current one", async () => {
    const request = vi.fn<typeof fetch>(async () => jsonResponse(envelope("/new-console")));
    expect(await devRuntimeTags("/admin/login", routes, request)).toEqual([]);
    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0]![0]).toBe(devApiTarget + "/api/v1/admin/status");
    request.mockImplementation(async () => jsonResponse({ code: "NOT_FOUND", data: null }, 404));
    expect(await devRuntimeTags("/old-console/login", routes, request)).toEqual([]);
  });

  it("does not cache a confirmed path across changes, even between HTML requests", async () => {
    const request = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(envelope("/my-console")))
      .mockResolvedValueOnce(jsonResponse({ code: "NOT_FOUND" }, 404));
    expect(await devRuntimeTags("/my-console/login", routes, request)).toHaveLength(1);
    expect(await devRuntimeTags("/my-console/login", routes, request)).toEqual([]);
    expect(request).toHaveBeenCalledTimes(2);
  });

  it("fails closed on bad HTTP, JSON, redirect/network/timeout errors", async () => {
    for (const status of [201, 301, 401, 403, 404, 500]) {
      const request = vi.fn<typeof fetch>(async () => jsonResponse(envelope("/my-console"), status));
      expect(await devRuntimeTags("/my-console/login", routes, request)).toEqual([]);
    }
    const invalidJSON = vi.fn<typeof fetch>(async () => new Response("<html>not JSON</html>"));
    expect(await devRuntimeTags("/my-console/login", routes, invalidJSON)).toEqual([]);
    for (const error of [new Error("redirect rejected"), new Error("connection refused"), new DOMException("deadline", "TimeoutError")]) {
      const request = vi.fn<typeof fetch>(async () => { throw error; });
      expect(await devRuntimeTags("/my-console/login", routes, request)).toEqual([]);
    }
  });

  it("wires the dev-only plugin and explicitly permits the shared repository manifest", () => {
    const config = readFileSync(new URL("../vite.config.ts", import.meta.url), "utf8");
    expect(config).toContain('from "./scripts/dev-runtime.mjs"');
    expect(config).toContain("devRuntimePlugin()");
    expect(config).toContain('fs: { allow: [fileURLToPath(new URL("..", import.meta.url))] }');
    expect(config).toContain('"/api": { target: devApiTarget');
    expect(config).not.toContain("/admin");
  });

  it("is serve-only, uses the original HTML URL, and never fetches/injects at build time", async () => {
    const request = vi.fn<typeof fetch>(async () => jsonResponse(envelope("/my-console")));
    vi.stubGlobal("fetch", request);
    const plugin = devRuntimePlugin();
    expect(plugin.apply).toBe("serve");
    const hook = plugin.transformIndexHtml;
    if (!hook || typeof hook !== "object" || !("handler" in hook) || typeof hook.handler !== "function")
      throw new Error("Missing dev HTML hook");
    const context = { path: "/index.html", filename: "/web/index.html", originalUrl: "/my-console/login" };
    // No ViteDevServer in a build context. Even a matching URL cannot inject.
    expect(await hook.handler("<html></html>", context)).toEqual([]);
    expect(request).not.toHaveBeenCalled();
    const devContext = { ...context, server: {} } as IndexHtmlTransformContext;
    expect(await hook.handler("<html></html>", devContext)).toEqual([{
      tag: "script", attrs: { id: "authgo-runtime", type: "application/json" },
      children: '{"admin_path":"/my-console"}', injectTo: "head-prepend",
    }]);
    request.mockClear();
    expect(await hook.handler("<html></html>", { ...devContext, originalUrl: "/portal/login" })).toEqual([]);
    expect(request).not.toHaveBeenCalled();
  });
});
