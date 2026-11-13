import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { createApp, nextTick, type App } from "vue";
import ElementPlus from "element-plus";
import { AxiosHeaders } from "axios";
import PortalUpdate from "../src/components/PortalUpdate.vue";
import { portalHttp } from "../src/lib/http";
import { setPortal, clearPortal } from "../src/lib/session";
let app: App | undefined, root: HTMLElement | undefined;
afterEach(() => {
  app?.unmount();
  root?.remove();
  clearPortal();
  vi.restoreAllMocks();
});
it("更新说明始终是纯文本，不执行或插入HTML", async () => {
  setPortal("portal-test");
  portalHttp.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "OK",
    headers: new AxiosHeaders(),
    data: {
      code: "OK",
      data: {
        available: true,
        version: "2.0.0",
        changelog:
          "<script>window.pwned=true</script><img src=x onerror=alert(1)>",
        assets: [],
      },
    },
  });
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(PortalUpdate, { license: { id: 1, status: "active" } });
  app.use(ElementPlus);
  app.mount(root);
  for (let i = 0; i < 10; i++) {
    await Promise.resolve();
    await nextTick();
  }
  expect(root.textContent).toContain("<script>");
  expect(root.querySelector("script")).toBeNull();
  expect(root.querySelector("img")).toBeNull();
});
it("Docker更新视图无GitHub凭据、资产下载或外部文件链接", () => {
  const portal = readFileSync("src/components/PortalUpdate.vue", "utf8");
  for (const x of [
    "v-html",
    "github_token",
    "token_encrypted",
    "downloadPortalAsset",
    "download_url",
  ])
    expect(portal).not.toContain(x);
  expect(portal).toContain("docker_pull");
  expect(portal).toMatch(/\["active",\s*"unused"\]/);
});

it.each([
  "https://example.test/app",
  "http://example.test/app",
  "javascript:alert(1)",
  "data:text/html,test",
])("已删除文件链接任何scheme均不渲染：%s", async (link) => {
  setPortal("portal-test");
  portalHttp.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "OK",
    headers: new AxiosHeaders(),
    data: {
      code: "OK",
      data: {
        available: true,
        version: "2.1.0",
        changelog: "手动版本",
        download_url: link,
        assets: [],
      },
    },
  });
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(PortalUpdate, { license: { id: 1, status: "unused" } });
  app.use(ElementPlus);
  app.mount(root);
  for (let i = 0; i < 10; i++) {
    await Promise.resolve();
    await nextTick();
  }
  expect(root.querySelector("a")).toBeNull();
  expect(root.textContent).not.toContain(link);
});
