import { injectAdminRuntime } from "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, ref, type App } from "vue";
import ElementPlus from "element-plus";
import {
  renderDocument,
  headingSlug,
  safeDocumentLink,
  type DocumentName,
} from "../src/lib/markdown";
import ProtocolDocument from "../src/components/ProtocolDocument.vue";
import AdminApiReference from "../src/components/AdminApiReference.vue";
import { apiGroups } from "../src/lib/openapi";
import { http } from "../src/lib/http";
import { AxiosHeaders } from "axios";
import { createMemoryHistory, createRouter } from "vue-router";
import IntegrationDocsView from "../src/views/admin/IntegrationDocsView.vue";
let app: App | undefined;
const root = document.createElement("div");
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.replaceChildren();
  root.remove();
  injectAdminRuntime();
});
it("标题 slug 不受行号影响且重复标题、预占后缀不会碰撞，目录只含二三级", () => {
  const source =
    "# 文档\n\n## 概览\n\n### API `Check`\n\n## 概览-1\n\n## 概览\n\n```text\n## 不是目录\n```";
  const rendered = renderDocument(source);
  expect(rendered.sections.map((s) => s.id)).toEqual([
    "概览",
    "api-check",
    "概览-1",
    "概览-2",
  ]);
  expect(renderDocument("\n说明\n\n" + source).sections).toEqual(
    rendered.sections,
  );
  expect(headingSlug("6. 请求与响应")).toBe("6-请求与响应");
  expect(rendered.html).toContain('data-copy-anchor="概览"');
});
it("只允许 HTTP(S)、页内锚点与白名单文档 tab，原始 HTML 不执行", () => {
  for (const link of [
    "https://example.com/a",
    "http://localhost/a",
    "#概览",
    "?tab=protocol#2-编码约定",
    "?tab=customer",
    "?tab=sdk",
  ])
    expect(safeDocumentLink(link), link).toBe(true);
  for (const link of [
    "javascript:alert(1)",
    "data:text/html,x",
    "//evil.example",
    "../README.md",
    "README.md",
    "sdk/go",
    "?tab=evil",
    "?tab=protocol&redirect=evil",
    "?url=https://evil.example",
  ])
    expect(safeDocumentLink(link), link).toBe(false);
  const div = document.createElement("div");
  div.innerHTML = renderDocument(
    '<img src=x onerror="window.pwn=1">\n[危险](javascript:alert(1))\n[本地](../README.md)\n[协议](?tab=protocol#1-概览)',
  ).html;
  expect(div.querySelector("img, script")).toBeNull();
  expect(div.querySelector('a[href^="javascript:"]')).toBeNull();
  expect(div.querySelector('a[href="../README.md"]')).toBeNull();
  expect(div.querySelector('a[href^="?tab=protocol"]')).not.toBeNull();
});
it("表格独立滚动、代码语言和提示框使用统一标记，代码内容不执行", () => {
  const { html } = renderDocument(
    "> **注意**\n> 保持验签\n\n> **提示**\n> 使用 SDK\n\n| 字段 | 含义 |\n| --- | --- |\n| x | y |\n\n```html\n<script>alert(1)</script>\n```",
  );
  const div = document.createElement("div");
  div.innerHTML = html;
  expect(
    div.querySelector(".document-callout--warning")?.textContent,
  ).toContain("保持验签");
  expect(div.querySelector(".document-callout--tip")?.textContent).toContain(
    "使用 SDK",
  );
  expect(
    div.querySelector(".document-table[tabindex='0'] table th")?.textContent,
  ).toBe("字段");
  expect(div.querySelector(".document-codebar")?.textContent).toContain("html");
  expect(div.querySelector("script")).toBeNull();
  expect(div.querySelector("code")?.textContent).toBe(
    "<script>alert(1)</script>\n",
  );
});
it("章节链接和代码可复制，移动目录收起并保留清晰的定位链接", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
  document.body.append(root);
  app = createApp(ProtocolDocument, {
    content: "# 文档\n\n## 概览\n\n```go\nCheck()\n```",
  });
  app.use(ElementPlus);
  app.mount(root);
  await nextTick();
  (root.querySelector("[data-copy-code]") as HTMLButtonElement).click();
  await nextTick();
  expect(writeText).toHaveBeenCalledWith("Check()\n");
  (root.querySelector("[data-copy-anchor]") as HTMLAnchorElement).click();
  await nextTick();
  expect(new URL(writeText.mock.calls.at(-1)![0] as string).hash).toBe(
    "#" + encodeURIComponent("文档"),
  );
  const details = root.querySelector<HTMLDetailsElement>("details")!;
  details.open = true;
  (details.querySelector("a") as HTMLAnchorElement).click();
  expect(details.open).toBe(false);
  await nextTick();
  expect(
    root.querySelectorAll('.protocol-toc a[aria-current="location"]').length,
  ).toBe(2);
});
it("切换文档时旧请求的迟到结果不能覆盖新文档", async () => {
  let complete: (() => void) | undefined;
  http.defaults.adapter = async (config) => {
    if (config.url === "/integration/protocol")
      await new Promise<void>((resolve) => {
        complete = resolve;
      });
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: {
          text:
            config.url === "/integration/protocol" ? "# 协议" : "# 客户说明",
        },
      },
    };
  };
  document.body.append(root);
  const name = ref<DocumentName>("protocol");
  app = createApp({
    render: () => h(ProtocolDocument, { document: name.value }),
  });
  app.use(ElementPlus);
  app.mount(root);
  await vi.waitFor(() => expect(complete).toBeTypeOf("function"));
  // Change the same component's input to exercise request generation isolation.
  name.value = "customer";
  await vi.waitFor(() => expect(root.textContent).toContain("客户说明"));
  complete?.();
  await nextTick();
  await nextTick();
  expect(root.textContent).not.toContain("协议");
});
it("OpenAPI 按标签路径展示并解析引用的正文参数，远端文字不作为 HTML", async () => {
  const spec = {
    components: {
      schemas: {
        Input: {
          type: "object",
          required: ["name"],
          properties: {
            name: { type: "string", description: "软件名称" },
            tags: { type: "array", items: { type: "string" } },
          },
        },
      },
    },
    paths: {
      "/api/v1/console/applications": {
        post: {
          tags: ["软件"],
          summary: "<img src=x>创建软件",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: { $ref: "#/components/schemas/Input" },
              },
            },
          },
          responses: { "200": { description: "成功" } },
        },
      },
    },
  };
  const groups = apiGroups(spec);
  expect(groups[0]?.operations[0]?.fields).toEqual([
    {
      name: "name",
      location: "body (application/json)",
      required: true,
      type: "string",
      description: "软件名称",
    },
    {
      name: "tags",
      location: "body (application/json)",
      required: false,
      type: "string[]",
      description: "—",
    },
  ]);
  document.body.append(root);
  app = createApp(AdminApiReference, { spec });
  app.mount(root);
  await nextTick();
  expect(root.querySelector("summary")?.textContent).toContain(
    "/api/v1/console/applications",
  );
  expect(root.querySelector("img")).toBeNull();
  expect(root.querySelector("details table")?.textContent).toContain(
    "软件名称",
  );
  expect(root.textContent).not.toContain('"paths"');
});

it("文档互链保留中文章节锚点，自定义后台路径仍走当前管理接口", async () => {
  injectAdminRuntime("/console");
  http.defaults.adapter = async (config) => {
    expect(config.baseURL).toBe("/api/v1/console");
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: {
          text:
            config.url === "/integration/quickstart"
              ? "# 快速开始\n\n## 入门\n\n[票据](?tab=protocol#5-票据与缓存)"
              : "# 协议\n\n## 5. 票据与缓存\n\n原始字节验签",
        },
      },
    };
  };
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/console/docs", component: IntegrationDocsView }],
  });
  await router.push("/console/docs?tab=quickstart");
  document.body.append(root);
  app = createApp(IntegrationDocsView);
  app.use(router);
  app.use(ElementPlus);
  app.mount(root);
  await vi.waitFor(() =>
    expect(
      root.querySelector('.protocol-markdown a[href^="?tab=protocol"]'),
    ).not.toBeNull(),
  );
  (
    root.querySelector(
      '.protocol-markdown a[href^="?tab=protocol"]',
    ) as HTMLAnchorElement
  ).click();
  await vi.waitFor(() => expect(root.textContent).toContain("原始字节验签"));
  expect(router.currentRoute.value.query.tab).toBe("protocol");
  expect(router.currentRoute.value.hash).toBe("#5-票据与缓存");
  expect(root.querySelectorAll(".protocol-markdown").length).toBe(1);
});
