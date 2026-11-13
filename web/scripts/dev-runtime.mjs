import { readFileSync } from "node:fs";

// This is the existing Vite proxy upstream, not a discovery endpoint or setting.
export const devApiTarget = "http://127.0.0.1:8080";
const adminPathPattern = /^\/[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/;

// The request only supplies a candidate. Public/unknown pages and malformed
// paths cannot bootstrap an admin router even when Vite serves its SPA HTML.
export function devAdminCandidate(requestUrl, routes) {
  if (typeof requestUrl !== "string" || !requestUrl.startsWith("/") ||
      requestUrl.startsWith("//") || /[\\\r\n\0#]/.test(requestUrl)) return null;
  const pathname = requestUrl.split("?", 1)[0];
  const segments = pathname.split("/");
  const candidate = "/" + segments[1];
  if (!adminPathPattern.test(candidate)) return null;
  if (routes.some((route) => route.scope === "public" && route.path.split("/")[1] === segments[1]))
    return null;
  const relative = pathname.slice(candidate.length);
  const knownPage = routes.some((route) => {
    if (route.scope !== "admin") return false;
    const expected = route.path.split("/"), actual = relative.split("/");
    return expected.length === actual.length && expected.every((part, index) =>
      part === ":id" ? /^[1-9]\d*$/.test(actual[index]) : part === actual[index]);
  });
  return knownPage ? candidate : null;
}

export function confirmedDevAdminPath(candidate, envelope) {
  if (typeof candidate !== "string" || !adminPathPattern.test(candidate) ||
      envelope?.code !== "OK" || envelope?.data?.admin_path !== candidate) return null;
  return candidate;
}

export async function devRuntimeTags(requestUrl, routes, request = globalThis.fetch) {
  const candidate = devAdminCandidate(requestUrl, routes);
  if (!candidate) return [];
  try {
    // No cookies, tokens, original query string, Host, or other browser headers
    // are forwarded. Redirects/errors/timeouts must fail closed, without logs.
    const response = await request(devApiTarget + "/api/v1" + candidate + "/status", {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(2000),
    });
    if (!response.ok || response.status !== 200) return [];
    const path = confirmedDevAdminPath(candidate, await response.json());
    if (!path) return [];
    return [{
      tag: "script",
      attrs: { id: "authgo-runtime", type: "application/json" },
      children: JSON.stringify({ admin_path: path }),
      injectTo: "head-prepend",
    }];
  } catch {
    return [];
  }
}

export function devRuntimePlugin() {
  const routes = JSON.parse(readFileSync(new URL("../../server/internal/webui/routes.json", import.meta.url), "utf8"));
  return {
    name: "authgo-dev-runtime",
    apply: "serve",
    transformIndexHtml: {
      order: "post",
      handler(_html, context) {
        // Defense in depth: production transforms must never query or inject.
        if (!context.server) return [];
        return devRuntimeTags(context.originalUrl ?? context.path, routes);
      },
    },
  };
}
