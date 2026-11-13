import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, nextTick, type App } from "vue";
import ElementPlus, { ElMessageBox } from "element-plus";
import { AxiosHeaders } from "axios";
import { createRouter, createMemoryHistory } from "vue-router";
import DockerHubSync from "../src/components/DockerHubSync.vue";
import PortalUpdate from "../src/components/PortalUpdate.vue";
import RepositoryVersions from "../src/components/VersionManagement.vue";
import DockerWizard from "../src/components/DockerWizard.vue";
import { http, portalHttp } from "../src/lib/http";
import { setAdmin, setPortal } from "../src/lib/session";
let app: App | undefined, root: HTMLElement;
const original = http.defaults.adapter,
  portalOriginal = portalHttp.defaults.adapter;
afterEach(() => {
  app?.unmount();
  app = undefined;
  root?.remove();
  http.defaults.adapter = original;
  portalHttp.defaults.adapter = portalOriginal;
  vi.restoreAllMocks();
});
async function mount(component: Parameters<typeof createApp>[0], props = {}) {
  setAdmin("admin", "refresh");
  setPortal("portal", "license");
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/:pathMatch(.*)*", component }],
  });
  await router.push("/admin/applications/7");
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(component, props);
  app.use(ElementPlus).use(router);
  app.mount(root);
  await nextTick();
}
it("镜像附近显示状态和错误，连接与手动同步都走管理接口", async () => {
  const writes: string[] = [];
  http.defaults.adapter = async (config) => {
    if (config.method === "post") writes.push(config.url!);
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: config.url!.endsWith("/test")
          ? { total_tags: 200, accepted_tags: 30, ignored_tags: 70 }
          : {
              configured: true,
              image: "org/repo",
              last_result: "同步成功",
              last_error: "仓库不存在或不是公开仓库",
              collected: 12,
              ignored: 7,
              last_sync_at: "2026-11-07T00:00:00Z",
              next_sync_at: "2026-11-07T00:10:00Z",
            },
      },
    };
  };
  await mount(DockerHubSync, { id: "7", image: "org/repo" });
  await vi.waitFor(() => expect(root.textContent).toContain("收录版本：12"));
  expect(root.textContent).toContain("已忽略标签：7");
  expect(root.textContent).toContain("仓库不存在或不是公开仓库");
  const button = (name: string) =>
    [...root.querySelectorAll<HTMLButtonElement>("button")].find(
      (b) => b.textContent?.trim() === name,
    )!;
  button("测试连接").click();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("首页可接受标签：30"),
  );
  button("立即同步").click();
  await vi.waitFor(() =>
    expect(writes).toEqual([
      "/applications/7/dockerhub/test",
      "/applications/7/dockerhub/sync",
    ]),
  );
});
it("429提示不覆盖上次同步结果，也不伪装成功", async () => {
  http.defaults.adapter = async (config) => ({
    config,
    status: config.method === "post" ? 429 : 200,
    statusText: "",
    headers: new AxiosHeaders(),
    data:
      config.method === "post"
        ? {
            code: "RATE_LIMITED",
            message: "Docker Hub请求过于频繁，请等待重试时间后再同步",
          }
        : {
            code: "OK",
            data: {
              configured: true,
              image: "org/repo",
              last_result: "同步成功",
              collected: 2,
              ignored: 3,
              last_error: "Docker Hub请求过于频繁",
            },
          },
  });
  await mount(DockerHubSync, { id: "7" });
  await vi.waitFor(() => expect(root.textContent).toContain("收录版本：2"));
  [...root.querySelectorAll<HTMLButtonElement>("button")]
    .find((b) => b.textContent?.trim() === "立即同步")!
    .click();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("请等待重试时间后再同步"),
  );
  expect(root.textContent).toContain("同步成功");
  expect(root.textContent).toContain("收录版本：2");
});
it("用户中心只复制有效的Docker拉取命令，不提供坏下载链接和无关平台选项", async () => {
  portalHttp.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
    data: {
      code: "OK",
      data: {
        available: true,
        docker_image: "org/repo",
        docker_pull: "docker pull org/repo:v1.2.3",
        version: "1.2.3",
        assets: [],
      },
    },
  });
  await mount(PortalUpdate, { license: { id: 1, status: "active" } });
  await vi.waitFor(() =>
    expect(root.textContent).toContain("docker pull org/repo:v1.2.3"),
  );
  expect(root.querySelector('[aria-label="下载平台"]')).toBeNull();
  expect(root.querySelector("a")).toBeNull();
  expect(root.textContent).not.toContain("请联系管理员获取安装方式");
  const copy = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: copy },
  });
  root
    .querySelector<HTMLButtonElement>('[aria-label="复制Docker拉取命令"]')!
    .click();
  await vi.waitFor(() =>
    expect(copy).toHaveBeenCalledWith("docker pull org/repo:v1.2.3"),
  );
});
it("没有该授权或授权失效不显示拉取命令", async () => {
  let requests = 0;
  portalHttp.defaults.adapter = async (config) => {
    requests++;
    return {
      config,
      status: 403,
      statusText: "",
      headers: new AxiosHeaders(),
      data: { code: "LICENSE_REVOKED", message: "授权已吊销" },
    };
  };
  await mount(PortalUpdate, { license: { id: 1, status: "revoked" } });
  await nextTick();
  expect(requests).toBe(0);
  expect(root.textContent).not.toContain("docker pull");
});
it("版本列表区分Docker Hub来源，保留原禁用入口", async () => {
  http.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
    data: {
      code: "OK",
      data: config.url!.endsWith("/repository")
        ? {}
        : {
            items: [
              { id: 1, version: "1.2.3", source: "docker", disabled: false },
            ],
          },
    },
  });
  await mount(RepositoryVersions, { id: "7", appKey: "app" });
  await vi.waitFor(() =>
    expect(
      root.querySelector(".el-table__body-wrapper")?.textContent,
    ).toContain("Docker Hub"),
  );
  expect(root.querySelector('[aria-label="禁用版本1.2.3"]')).not.toBeNull();
});
it("镜像名可以清空，保存后显示停止同步状态", async () => {
  const bodies: unknown[] = [];
  let image = "org/repo";
  http.defaults.adapter = async (config) => {
    if (config.method === "patch") {
      const data = JSON.parse(String(config.data));
      bodies.push(data);
      image = data.docker_image;
    }
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: config.url!.endsWith("/dockerhub")
          ? { configured: !!image, image }
          : { docker_image: image },
      },
    };
  };
  await mount(DockerWizard, { id: "7", config: "" });
  const input = await vi.waitFor(() => {
    const el = root.querySelector<HTMLInputElement>(
      'input[placeholder="your-org/your-app"]',
    )!;
    expect(el.value).toBe("org/repo");
    return el;
  });
  input.value = "";
  input.dispatchEvent(new Event("input", { bubbles: true }));
  await nextTick();
  root.querySelector<HTMLButtonElement>('button[type="submit"]')!.click();
  await vi.waitFor(() => expect(bodies).toEqual([{ docker_image: "" }]));
  await vi.waitFor(() =>
    expect(root.textContent).toContain("保存Docker Hub镜像名后自动开始同步"),
  );
});

it("后台同步期间显示运行中并禁用重复提交，刷新显示最终结果", async () => {
  let running = false;
  http.defaults.adapter = async (config) => {
    if (config.method === "post") running = true;
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: {
          configured: true,
          running,
          image: "org/repo",
          last_result: "同步成功",
          collected: 2,
        },
      },
    };
  };
  await mount(DockerHubSync, { id: "7" });
  const button = (name: string) =>
    [...root.querySelectorAll<HTMLButtonElement>("button")].find(
      (b) => b.textContent?.trim() === name,
    )!;
  await vi.waitFor(() => expect(button("立即同步")).toBeTruthy());
  button("立即同步").click();
  await vi.waitFor(() => expect(root.textContent).toContain("正在后台同步"));
  expect(button("立即同步").disabled).toBe(true);
  running = false;
  button("刷新同步状态").click();
  await vi.waitFor(() => expect(button("立即同步").disabled).toBe(false));
  expect(root.textContent).toContain("同步成功");
});


it("Docker Hub版本可确认禁用和重新启用，刷新后列表状态与服务响应一致", async () => {
  let disabled = false;
  const writes: unknown[] = [];
  const confirmation = vi.spyOn(ElMessageBox, "confirm").mockResolvedValue("confirm");
  http.defaults.adapter = async (config) => {
    if (config.method === "patch") {
      expect(config.url).toBe("/versions/1");
      const body = JSON.parse(String(config.data));
      writes.push(body);
      disabled = body.disabled;
    }
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: config.method === "patch" ? {} : {
          items: [{ id: 1, version: "1.2.3", source: "docker", disabled }],
          total: 1,
        },
      },
    };
  };
  await mount(RepositoryVersions, { id: "7", appKey: "app" });
  const control = (action: string) => root.querySelector<HTMLInputElement>(`[aria-label="${action}版本1.2.3"]`);
  await vi.waitFor(() => expect(control("禁用")).not.toBeNull());
  control("禁用")!.closest(".el-switch")!.querySelector<HTMLElement>(".el-switch__core")!.click();
  await vi.waitFor(() => expect(control("启用")?.getAttribute("aria-checked")).toBe("true"));
  expect(writes).toEqual([{ disabled: true }]);
  expect(confirmation).toHaveBeenCalledWith(expect.stringContaining("下次联网会被拒绝"), "版本禁用", expect.objectContaining({ confirmButtonText: "禁用版本" }));
  [...root.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent?.trim() === "启用版本")!.click();
  await vi.waitFor(() => expect(control("禁用")?.getAttribute("aria-checked")).toBe("false"));
  expect(writes).toEqual([{ disabled: true }, { disabled: false }]);
  expect(confirmation).toHaveBeenLastCalledWith(expect.stringContaining("可恢复在线验证"), "版本禁用", expect.objectContaining({ confirmButtonText: "启用版本" }));
  expect(root.querySelector(".el-table__body-wrapper")?.textContent).toContain("Docker Hub");
});
