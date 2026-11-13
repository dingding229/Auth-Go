// @vitest-environment node
import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  auditFrontend,
  compareRequests,
  extractRequests,
  readRouteContract,
  sourceDigest,
} from "../scripts/route-contract.mjs";

const root = fileURLToPath(new URL("../..", import.meta.url));
const prefix = "/virtual/web/src/";
const transport = `
import axios from "axios";
const http = axios.create({baseURL:"/api/v1/admin"});
const portalHttp = axios.create({baseURL:"/api/v1/portal"});
export async function api(scope, url, config = {}) {
  return (scope === "admin" ? http : portalHttp).request({url, ...config});
}
export const get = (path, params, config = {}) => api("admin", path, {params, ...config});
export const post = (path, data) => api("admin", path, {method:"POST", data});
export const pget = (path) => api("portal", path);
export const download = (scope, path, name, config = {}) => api(scope, path, config);
`;
function extract(source: string, extra: Record<string, string> = {}) {
  return extractRequests({
    [prefix + "lib/http.ts"]: transport,
    [prefix + "views/Example.vue"]: source,
    ...Object.fromEntries(Object.entries(extra).map(([k, v]) => [prefix + k, v])),
  });
}
const route = (method: string, path: string) => ({ method, path });

describe("frontend / actual Gin method-path contract", () => {
  it("compares the complete current UI against the fresh real service table", () => {
    const { requests, routes, contexts } = auditFrontend(root);
    expect(contexts.map((context: { admin_path: string }) => context.admin_path)).toEqual(["/admin", "/route-check"]);
    for (const context of contexts)
      expect(context.requests.some((r: { path: string }) => r.path.startsWith(`/api/v1${context.admin_path}/`))).toBe(true);
    expect(requests.length).toBeGreaterThan(80);
    expect(routes.length).toBeGreaterThan(80);
    for (const scope of ["admin", "portal"])
      expect(requests.some((r: { path: string }) => r.path.startsWith(`/api/v1/${scope}/`))).toBe(true);
  });

  it("fails closed without a fresh source-matched real route table", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "authgo-route-contract-"));
    try {
      fs.mkdirSync(path.join(dir, "server"));
      fs.mkdirSync(path.join(dir, "web/src"), { recursive: true });
      fs.writeFileSync(path.join(dir, "server/router.go"), "package example");
      fs.writeFileSync(path.join(dir, "web/src/page.ts"), "export {};");
      expect(() => readRouteContract(dir)).toThrow("Missing");
      fs.writeFileSync(path.join(dir, "server/.route-contract.json"), JSON.stringify({
        schema: 2, source: sourceDigest(dir), contexts: [
          { admin_path: "/admin", routes: [route("GET", "/api/v1/admin/status")] },
          { admin_path: "/route-check", routes: [route("GET", "/api/v1/route-check/status")] },
        ],
      }));
      expect(readRouteContract(dir)).toHaveLength(2);
      fs.mkdirSync(path.join(dir, "server/internal/webui"), { recursive: true });
      fs.writeFileSync(path.join(dir, "server/internal/webui/routes.json"), "[]");
      expect(() => readRouteContract(dir)).toThrow("Stale");
      fs.rmSync(path.join(dir, "server/internal/webui/routes.json"));
      fs.writeFileSync(path.join(dir, "web/src/page.ts"), "export const changed = true;");
      expect(() => readRouteContract(dir)).toThrow("Stale");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("uses only the reviewed HTML runtime slot, with a finite prefix in each context", () => {
    const runtimeSource = fs.readFileSync(path.join(root, "web/src/lib/runtime.ts"), "utf8");
    const sources = {
      [prefix + "lib/runtime.ts"]: runtimeSource,
      [prefix + "lib/http.ts"]: transport.replace('import axios from "axios";', 'import axios from "axios"; import { adminApiPath } from "./runtime";')
        .replace('baseURL:"/api/v1/admin"', 'baseURL:adminApiPath()'),
      [prefix + "views/Example.vue"]: '<script setup>import {get} from "../lib/http"; get("/status");</script>',
    };
    expect(() => extractRequests(sources)).toThrow("trusted HTML runtime admin_path");
    for (const bad of ["", "/bad/path", "/:segment", "https://example.com", "/console?x=1"])
      expect(() => extractRequests(sources, { admin_path: bad })).toThrow("trusted HTML runtime admin_path");
    for (const admin_path of ["/admin", "/route-check"])
      expect(extractRequests(sources, { admin_path })).toEqual([
        expect.objectContaining({ method: "GET", path: `/api/v1${admin_path}/status` }),
      ]);
    expect(() => extractRequests({ ...sources, [prefix + "lib/runtime.ts"]: runtimeSource.replace('const slot = document.getElementById("authgo-runtime");', 'const slot = document.getElementById("public-bootstrap");') }, { admin_path: "/route-check" }))
      .toThrow("unreviewed trusted runtime reader");
    const hardcoded = extractRequests({ ...sources, [prefix + "lib/http.ts"]: transport }, { admin_path: "/route-check" });
    expect(() => compareRequests(hardcoded, [route("GET", "/api/v1/route-check/status")])).toThrow("absent from real Gin");
    const wrongPrefix = extractRequests(sources, { admin_path: "/wrong-console" });
    expect(() => compareRequests(wrongPrefix, [route("GET", "/api/v1/route-check/status")])).toThrow("absent from real Gin");
  });

  it("resolves shorthand object fields back to caller parameters", () => {
    const requests = extract(`<script setup>
      import {get} from "../lib/http";
      const path='/status'; get(path);
    </script>`);
    expect(requests).toEqual([expect.objectContaining({ method: "GET", path: "/api/v1/admin/status" })]);
  });

  it("keeps unresolved external imports distinct from Axios instances", () => {
    const actualImportShape = transport.replace('import axios from "axios";', `
      import axios, { AxiosHeaders, type AxiosRequestConfig } from "axios";
      declare module "axios" { interface AxiosRequestConfig { quiet?: boolean; } }
    `);
    const requests = extract(`<script setup lang="ts">
      import {get} from "../lib/http";
      import {state} from "external-state";
      state.current = true;
      get('/status');
    </script>`, { "lib/http.ts": actualImportShape });
    expect(() => compareRequests(requests, [route("GET", "/api/v1/admin/status")])).not.toThrow();
  });

  it("reports the outer request caller without accepting an unknown URL", () => {
    let diagnostic = "";
    try {
      extract(`<script setup>
        import {get} from "../lib/http";
        get(window.location.hash);
      </script>`);
    } catch (error) {
      diagnostic = error instanceof Error ? error.message : String(error);
    }
    expect(diagnostic).toContain("unresolved method/baseURL/path");
    expect(diagnostic).toContain("Request call chain (outermost first)");
    expect(diagnostic).toContain("method=string:GET");
    expect(diagnostic).toContain('baseURL=path:"/api/v1/admin"');
    expect(diagnostic).toContain("path=<unresolved>");
    expect(diagnostic).toContain("/virtual/web/src/views/Example.vue:");
    expect(diagnostic).toContain("/virtual/web/src/lib/http.ts:");
  });

  it("uses known omitted CRUD listPath as undefined through the real collection wrapper", () => {
    const source = `<script setup>
      import Child from "../components/CrudPanel.vue";
    </script><template>
      <child :spec="{path:'/users'}" />
      <child :spec="{path:'/versions'}" list-path="/applications/7/versions" />
    </template>`;
    const extra = {
      "composables/collection.ts": fs.readFileSync(path.join(root, "web/src/composables/collection.ts"), "utf8"),
      "components/CrudPanel.vue": `<script setup lang="ts">
        import {computed} from "vue";
        import {useCollection} from "../composables/collection";
        const props=defineProps<{spec:{path:string};listPath?:string}>();
        const path=computed(()=>props.listPath || props.spec.path);
        useCollection(path);
      </script>`,
    };
    const routes = [route("GET", "/api/v1/admin/users"), route("GET", "/api/v1/admin/applications/:id/versions")];
    expect(() => compareRequests(extract(source, extra), routes)).not.toThrow();
    expect(() => compareRequests(extract(source.replace('/applications/7/versions', '/deleted'), extra), routes)).toThrow("/deleted");
    expect(() => extract(source.replace('list-path="/applications/7/versions"', ':list-path="unknownPath"'), extra)).toThrow("unresolved");
  });

  it("extracts HTTP calls in Vue interpolations instead of silently ignoring them", () => {
    const requests = extract(`<script setup>
      import {get as read} from "../lib/http";
    </script><template>{{ read('/bad') }}</template>`);
    expect(requests).toEqual([expect.objectContaining({ method: "GET", path: "/api/v1/admin/bad" })]);
    expect(() => compareRequests(requests, [route("GET", "/api/v1/admin/status")])).toThrow("/bad");
    expect(() => extract(`<script setup>
      import {get} from "../lib/http";
    </script><template>{{ get(unknownPath) }}</template>`)).toThrow("unresolved");
  });

  it("rejects the deleted login status alias instead of restoring it", () => {
    const requests = extract(`<script setup lang="ts">
      import {get as read} from "../lib/http";
      read("/auth/status");
    </script>`);
    expect(() => compareRequests(requests, [route("GET", "/api/v1/admin/status")])).toThrow("/auth/status");
  });

  it("detects wrong methods, including through imported wrappers", () => {
    const requests = extract(`<script setup lang="ts">
      import {load} from "../lib/wrapper"; load("/status");
    </script>`, { "lib/wrapper.ts": `import {post} from "./http"; export const load=(path)=>post(path);` });
    expect(() => compareRequests(requests, [route("GET", "/api/v1/admin/status")])).toThrow("POST");
  });

  it("expands action unions but never turns unknown route structure into a wildcard", () => {
    const requests = extract(`<script setup lang="ts">
      import {post} from "../lib/http";
      function act(id: string, action: "ban" | "release-seat") {post(\`/activations/\${id}/\${action}\`);}
    </script>`);
    expect(new Set(requests.map((r: { path: string }) => r.path))).toEqual(new Set([
      "/api/v1/admin/activations/:segment/ban", "/api/v1/admin/activations/:segment/release-seat",
    ]));
    expect(() => compareRequests(requests, [route("POST", "/api/v1/admin/activations/:id/release-seat")])).toThrow("/ban");
    expect(() => extract(`<script setup>import {get} from "../lib/http"; get(window.location.hash);</script>`)).toThrow("unresolved");
  });

  it("keeps conditional methods and paths correlated", () => {
    const requests = extract(`<script setup lang="ts">
      import {api} from "../lib/http";
      function act(action: "enable" | "delete") {
        api("admin", \`/system/ip-info\${action === "delete" ? "" : "/enable"}\`, {method: action === "delete" ? "DELETE" : "POST"});
      }
    </script>`);
    expect(() => compareRequests(requests, [route("POST", "/api/v1/admin/system/ip-info/enable"), route("DELETE", "/api/v1/admin/system/ip-info")])).not.toThrow();
  });

  it("parses Vue template downloads, props, concatenation and query stripping", () => {
    const requests = extract(`<script setup lang="ts">
      import Child from "../components/Child.vue";
      import {download} from "../lib/http";
    </script><template>
      <child endpoint="/licenses" />
      <button @click="download('admin', '/system/backups/' + encodeURIComponent(name) + '?raw=1', 'backup.zip')">save</button>
    </template>`, { "components/Child.vue": `<script setup lang="ts">
      import {pget} from "../lib/http"; const props=defineProps<{endpoint:string}>(); pget(props.endpoint);
    </script>` });
    expect(() => compareRequests(requests, [route("GET", "/api/v1/portal/licenses"), route("GET", "/api/v1/admin/system/backups/:name")])).not.toThrow();
  });

  it("refuses dynamic static-segment substitutions and bypass transports", () => {
    const requests = extract(`<script setup>import {get} from "../lib/http"; get('/' + encodeURIComponent(input));</script>`);
    expect(() => compareRequests(requests, [route("GET", "/api/v1/admin/status")])).toThrow();
    expect(() => extract(`<script setup>fetch('/api/v1/admin/status');</script>`)).toThrow("lib/http.ts");
  });

  it("does not prune request branches using mutable initial values", () => {
    const requests = extract(`<script setup>
      import {get,post} from "../lib/http";
      const editing=ref(false);
      if(editing.value) post('/not-registered'); else get('/status');
    </script>`);
    expect(() => compareRequests(requests, [route("GET", "/api/v1/admin/status")])).toThrow("POST");
    expect(() => compareRequests(extract(`<script setup>
      import {get} from "../lib/http";
      let endpoint='/status'; endpoint='/deleted'; get(endpoint);
    </script>`), [route("GET", "/api/v1/admin/status")])).toThrow("/deleted");
  });

  it("does not extract strings or comments as requests", () => {
    const requests = extract(`<script setup>
      import {get} from "../lib/http";
      // post('/not-a-route')
      const sample="get('/also-not-a-route')";
      get('/status');
    </script>`);
    expect(requests.map((r: { path: string }) => r.path)).toEqual(["/api/v1/admin/status"]);
  });
});
