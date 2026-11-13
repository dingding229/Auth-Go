import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, type App } from "vue";
import ElementPlus from "element-plus";
import { AxiosHeaders } from "axios";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import ts from "typescript";
import ActionMenu from "../src/components/ActionMenu";
import ProtocolDocument from "../src/components/ProtocolDocument.vue";
import { http } from "../src/lib/http";
import { setAdmin } from "../src/lib/session";
let app: App | undefined;
const root = document.createElement("div");
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.replaceChildren();
  root.remove();
});
it("接入文档路由和导航顺序、共用示例与query标签", () => {
  const router = readFileSync("src/router/index.ts", "utf8");
  const manifest = JSON.parse(readFileSync("../server/internal/webui/routes.json", "utf8"));
  const pages = manifest;
  expect(pages.findIndex((p: { path: string; scope: string }) => p.scope === "admin" && p.path === "/docs")).toBeGreaterThan(-1);
  expect(pages.findIndex((p: { path: string; scope: string }) => p.scope === "admin" && p.path === "/docs")).toBeLessThan(pages.findIndex((p: { path: string; scope: string }) => p.scope === "admin" && p.path === "/verify-logs"));
  expect(pages.find((p: { path: string; scope: string }) => p.scope === "admin" && p.path === "/docs").title).toBe("接入文档");
  expect(router).toContain("runtimePages()");
  expect(router).toContain('import("../views/admin/IntegrationDocsView.vue")');
  const view = readFileSync("src/views/admin/IntegrationDocsView.vue", "utf8");
  expect(view).toContain("route.query.tab");
  expect(view).toContain("SDKExamples");
  expect(view).toContain("ProtocolDocument");
  expect(readFileSync("src/components/ConnectionConfig.vue", "utf8")).toContain(
    "DockerWizard",
  );
  expect(readFileSync("src/components/DockerWizard.vue", "utf8")).toContain(
    "sdkExamples",
  );
});
it("协议来自认证接口，原始HTML及危险链接不执行，代码可复制", async () => {
  setAdmin("access", "refresh");
  let attempts = 0;
  http.defaults.adapter = async (config) => {
    attempts++;
    expect(config.url).toBe("/integration/protocol");
    expect(config.headers.get("Authorization")).toBe("Bearer access");
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: {
          text: '# 协议\n<img src=x onerror="window.pwn=1">\n[危险](javascript:alert(1))\n[安全](https://example.com)\n\n```js\nalert("example")\n```',
        },
      },
    };
  };
  document.body.append(root);
  app = createApp(ProtocolDocument);
  app.use(ElementPlus);
  app.mount(root);
  await vi.waitFor(() =>
    expect(root.querySelector(".protocol-markdown")).not.toBeNull(),
  );
  expect(attempts).toBe(1);
  expect(root.querySelector("img")).toBeNull();
  expect(root.querySelector("script")).toBeNull();
  expect(root.querySelector('a[href^="javascript:"]')).toBeNull();
  expect(root.textContent).toContain("<img");
  expect(root.querySelector(".protocol-toc a")?.getAttribute("href")).toMatch(
    /^#protocol-section-/,
  );
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
  (root.querySelector("[data-copy-code]") as HTMLButtonElement).click();
  await nextTick();
  expect(writeText).toHaveBeenCalledWith('alert("example")\n');
});
it("协议读取失败后可以在区块内重试", async () => {
  let attempts = 0;
  http.defaults.adapter = async (config) => {
    attempts++;
    if (attempts === 1) throw new Error("暂时不可用");
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: { code: "OK", data: { text: "# 重试成功" } },
    };
  };
  document.body.append(root);
  app = createApp(ProtocolDocument);
  app.use(ElementPlus);
  app.mount(root);
  await vi.waitFor(() => expect(root.textContent).toContain("重试"));
  const retry = [...root.querySelectorAll("button")].find((b) =>
    b.textContent?.includes("重试"),
  );
  expect(retry).toBeTruthy();
  retry!.click();
  await vi.waitFor(() =>
    expect(root.querySelector("h2")?.textContent).toBe("重试成功"),
  );
  expect(attempts).toBe(2);
});
it("前端仅允许共享UI清单在web之外，传输仅在http.ts", () => {
  const web = process.cwd();
  function files(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
      e.isDirectory()
        ? files(path.join(dir, e.name))
        : [path.join(dir, e.name)],
    );
  }
  for (const file of [...files("src"), "vite.config.ts"]) {
    const raw = readFileSync(file, "utf8");
    const source = ts.createSourceFile(file, raw, ts.ScriptTarget.Latest, true);
    function visit(node: ts.Node) {
      let module: string | undefined;
      if (
        (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier)
      )
        module = node.moduleSpecifier.text;
      if (
        ts.isCallExpression(node) &&
        node.expression.kind === ts.SyntaxKind.ImportKeyword &&
        node.arguments[0] &&
        ts.isStringLiteral(node.arguments[0])
      )
        module = node.arguments[0].text;
      if (module?.startsWith(".")) {
        const target = path.resolve(path.dirname(file), module.split("?")[0]!);
        const sharedManifest = path.resolve(web, "../server/internal/webui/routes.json");
        if (file === "src/lib/ui-routes.ts" && target === sharedManifest)
          expect(module).toBe("../../../server/internal/webui/routes.json");
        else expect(target.startsWith(web + path.sep), `${file}: ${module}`).toBe(true);
      }
      if (module?.startsWith("/"))
        expect.fail(`${file}: absolute import ${module}`);
      ts.forEachChild(node, visit);
    }
    visit(source);
    if (file !== "src/lib/http.ts")
      expect(raw, file).not.toMatch(
        /\bfetch\s*\(|\baxios\.(?:create|get|post|put|patch|delete|request)\s*\(|new\s+(?:XMLHttpRequest|WebSocket|EventSource)\b/,
      );
  }
});

it("手机只有一个操作时直接显示按钮，不折叠更多", async () => {
  document.body.append(root);
  app = createApp({
    render: () =>
      h(
        ActionMenu,
        { mobile: true, keepPrimary: true },
        { default: () => h("button", { type: "button" }, "标记下线") },
      ),
  });
  app.use(ElementPlus);
  app.mount(root);
  await nextTick();
  expect(root.textContent).toContain("标记下线");
  expect(root.textContent).not.toContain("更多");
  expect(root.querySelector(".el-dropdown")).toBeNull();
});
