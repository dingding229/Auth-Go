import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, nextTick, h, ref, type App, type Component } from "vue";
import ElementPlus from "element-plus";
import { AxiosHeaders } from "axios";
import { http } from "../src/lib/http";
import type { Row } from "../src/lib/json";
import { clearAdmin, setAdmin } from "../src/lib/session";
import PublishingSettings from "../src/components/PublishingSettings.vue";
import AutoPublish from "../src/components/AutoPublish.vue";
vi.mock("../src/composables/tasks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/composables/tasks")>()),
  confirmAction: vi.fn(async () => {}),
}));
import { confirmAction } from "../src/composables/tasks";
const adapter = http.defaults.adapter;
let app: App | undefined, root: HTMLElement;
afterEach(() => {
  app?.unmount();
  app = undefined;
  root?.remove();
  http.defaults.adapter = adapter;
  clearAdmin();
  vi.restoreAllMocks();
  vi.useRealTimers();
});
function mount(component: Component, props: Record<string, unknown> = {}) {
  root = document.createElement("div");
  document.body.append(root);
  setAdmin("access", "refresh");
  app = createApp(component, props);
  app.use(ElementPlus);
  app.mount(root);
}
function button(text: string) {
  return [...root.querySelectorAll<HTMLButtonElement>("button")].find(
    (node) => node.textContent?.trim() === text,
  )!;
}
async function input(index: number, value: string) {
  const element = root.querySelectorAll<HTMLInputElement>("input")[index]!;
  element.value = value;
  element.dispatchEvent(new Event("input", { bubbles: true }));
  await nextTick();
}
it("发布设置未加载时不渲染表单，响应完成后从加载结果初始化", async () => {
  let resolveSettings: ((settings: Row) => void) | undefined;
  const pending = new Promise<Row>((resolve) => {
    resolveSettings = resolve;
  });
  http.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
    data: { code: "OK", data: await pending },
  });
  mount(PublishingSettings);
  await nextTick();
  expect(root.querySelector("form")).toBeNull();
  expect(root.querySelectorAll("input")).toHaveLength(0);
  expect(root.textContent).toContain("正在读取发布设置");
  if (!resolveSettings) throw new Error("发布设置响应尚未初始化");
  resolveSettings({
    docker_username: "loaded-owner",
    has_github_token: true,
    has_docker_token: false,
  });
  await vi.waitFor(() =>
    expect(root.querySelectorAll("input")).toHaveLength(3),
  );
  const username = root.querySelectorAll<HTMLInputElement>("input").item(1);
  expect(username.value).toBe("loaded-owner");
  expect(root.textContent).not.toContain("正在读取发布设置");
});
it("发布令牌只写，留空保持且清除动作有明确确认", async () => {
  const writes: unknown[] = [];
  let configured = true;
  http.defaults.adapter = async (config) => {
    if (config.method === "patch") {
      const body = JSON.parse(String(config.data));
      writes.push(body);
      if (body.github_token === "") configured = false;
    }
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: {
          has_github_token: configured,
          has_docker_token: true,
          docker_username: "example",
        },
      },
    };
  };
  mount(PublishingSettings);
  await vi.waitFor(() =>
    expect(root.querySelectorAll("input")).toHaveLength(3),
  );
  expect(root.querySelectorAll<HTMLInputElement>("input")[0]!.value).toBe("");
  expect(root.querySelectorAll<HTMLInputElement>("input")[2]!.value).toBe("");
  button("保存发布凭据").click();
  await vi.waitFor(() =>
    expect(writes).toEqual([{ docker_username: "example" }]),
  );
  await vi.waitFor(() => expect(button("保存发布凭据").disabled).toBe(false));
  await input(0, "github-write-only");
  await input(2, "docker-write-only");
  button("保存发布凭据").click();
  await vi.waitFor(() =>
    expect(writes[1]).toEqual({
      docker_username: "example",
      github_token: "github-write-only",
      docker_token: "docker-write-only",
    }),
  );
  await vi.waitFor(() =>
    expect(root.querySelectorAll<HTMLInputElement>("input")[0]!.value).toBe(""),
  );
  expect(root.textContent).not.toContain("github-write-only");
  button("清除 GitHub 访问令牌").click();
  await vi.waitFor(() => expect(writes[2]).toEqual({ github_token: "" }));
  expect(confirmAction).toHaveBeenCalledWith(
    expect.any(String),
    "清除 GitHub 访问令牌",
    { action: "清除 GitHub 访问令牌", danger: true },
  );
});
it("保存构建选项后测试、同步、发布，显示受控运行链接", async () => {
  const writes: [string, unknown][] = [];
  http.defaults.adapter = async (config) => {
    const body = config.data ? JSON.parse(String(config.data)) : undefined;
    if (config.method !== "get") writes.push([String(config.url), body]);
    const data = config.url?.endsWith("/runs")
      ? {
          items: [
            {
              id: 99,
              status: "completed",
              conclusion: "success",
              created_at: "2026-11-15T00:00:00Z",
              url: "https://github.com/owner/repo/actions/runs/99",
            },
          ],
        }
      : {
          repository: "owner/repo",
          branch: "main",
          language: "Go",
          mode: "cli",
          encrypted: false,
        };
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: { code: "OK", data },
    };
  };
  mount(AutoPublish, {
    id: "7",
    language: "Go",
    mode: "cli",
    encrypted: false,
    ready: true,
  });
  await vi.waitFor(() =>
    expect(root.querySelectorAll("input")).toHaveLength(3),
  );
  await input(1, "release");
  expect(button("同步配置到仓库").disabled).toBe(true);
  button("保存仓库与构建选项").click();
  await vi.waitFor(() =>
    expect(writes[0]).toEqual([
      "/applications/7/publishing",
      {
        repository: "owner/repo",
        branch: "release",
        language: "Go",
        mode: "cli",
        encrypted: false,
      },
    ]),
  );
  await vi.waitFor(() => expect(button("测试连接").disabled).toBe(false));
  button("测试连接").click();
  await vi.waitFor(() =>
    expect(writes[1]).toEqual(["/applications/7/publishing/test", {}]),
  );
  await vi.waitFor(() => expect(button("同步配置到仓库").disabled).toBe(false));
  button("同步配置到仓库").click();
  await vi.waitFor(() =>
    expect(writes[2]).toEqual(["/applications/7/publishing/sync", {}]),
  );
  await input(2, "1.2.3");
  await vi.waitFor(() => expect(button("发布新版本").disabled).toBe(false));
  button("发布新版本").click();
  await vi.waitFor(() =>
    expect(writes[3]).toEqual([
      "/applications/7/publishing/dispatch",
      { version: "1.2.3" },
    ]),
  );
  await vi.waitFor(() =>
    expect(root.querySelector("a")?.href).toBe(
      "https://github.com/owner/repo/actions/runs/99",
    ),
  );
  expect(root.textContent).toContain("成功");
});
it("已提交但运行尚未出现时继续轮询，完成后停止并在卸载时清理", async () => {
  vi.useFakeTimers();
  let reads = 0,
    dispatched = false;
  http.defaults.adapter = async (config) => {
    if (config.url?.endsWith("/dispatch")) dispatched = true;
    let data: unknown = {
      repository: "owner/repo",
      branch: "main",
      language: "Go",
      mode: "cli",
      encrypted: false,
    };
    if (config.url?.endsWith("/runs")) {
      reads++;
      data = {
        items:
          dispatched && reads >= 3
            ? [
                {
                  id: 1,
                  status: "completed",
                  conclusion: "success",
                  url: "https://github.com/owner/repo/actions/runs/1",
                },
              ]
            : [],
      };
    }
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: { code: "OK", data },
    };
  };
  mount(AutoPublish, {
    id: "7",
    language: "Go",
    mode: "cli",
    encrypted: false,
    ready: true,
  });
  await vi.waitFor(() => expect(reads).toBe(1));
  await input(2, "1.0.0");
  await vi.waitFor(() => expect(button("发布新版本").disabled).toBe(false));
  button("发布新版本").click();
  await vi.waitFor(() => expect(reads).toBe(2));
  expect(root.textContent).toContain("正在等待 GitHub 创建运行");
  await vi.advanceTimersByTimeAsync(5000);
  expect(reads).toBe(3);
  await vi.advanceTimersByTimeAsync(5000);
  expect(reads).toBe(3);
  app?.unmount();
  app = undefined;
  await vi.advanceTimersByTimeAsync(5000);
  expect(reads).toBe(3);
});
it("验证已保存发布凭据并显示两个平台账号，保存失败显示服务端原因", async () => {
  const writes: string[] = [];
  http.defaults.adapter = async (config) => {
    if (config.method === "patch") {
      return {
        config,
        status: 200,
        statusText: "",
        headers: new AxiosHeaders(),
        data: { code: "INVALID_REQUEST", message: "GitHub 令牌无效或已过期" },
      };
    }
    if (config.method === "post") {
      writes.push(String(config.url));
      return {
        config,
        status: 200,
        statusText: "",
        headers: new AxiosHeaders(),
        data: {
          code: "OK",
          data: {
            github: { valid: true, login: "verified-owner" },
            docker_hub: { valid: true, username: "verified-hub" },
          },
        },
      };
    }
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: {
          docker_username: "example",
          has_github_token: true,
          has_docker_token: true,
        },
      },
    };
  };
  mount(PublishingSettings);
  await vi.waitFor(() => expect(button("验证")).toBeDefined());
  button("验证").click();
  await vi.waitFor(() =>
    expect(root.textContent).toContain(
      "已验证：GitHub verified-owner，Docker Hub verified-hub",
    ),
  );
  expect(writes).toEqual(["/system/publishing/verify"]);
  await vi.waitFor(() => expect(button("保存发布凭据").disabled).toBe(false));
  await input(0, "rejected-secret");
  button("保存发布凭据").click();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("GitHub 令牌无效或已过期"),
  );
  expect(root.textContent).not.toContain("rejected-secret");
  expect(root.textContent).not.toContain("已验证：");
});
it("验证失败分别显示两个平台的原因，不显示成功状态", async () => {
  http.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "",
    headers: new AxiosHeaders(),
    data: {
      code: "OK",
      data:
        config.method === "post"
          ? {
              github: { valid: false, error: "GitHub 令牌无效或已过期" },
              docker_hub: {
                valid: false,
                error: "Docker Hub 用户名或访问令牌无效",
              },
            }
          : {
              docker_username: "example",
              has_github_token: true,
              has_docker_token: true,
            },
    },
  });
  mount(PublishingSettings);
  await vi.waitFor(() => expect(button("验证")).toBeDefined());
  button("验证").click();
  await vi.waitFor(() =>
    expect(root.textContent).toContain("GitHub 令牌无效或已过期"),
  );
  expect(root.textContent).toContain("Docker Hub 用户名或访问令牌无效");
  expect(root.textContent).not.toContain("已验证：");
});
it("取消同步确认不会写仓库，确认提示包含目标仓库", async () => {
  const writes: string[] = [];
  http.defaults.adapter = async (config) => {
    if (config.method === "post") writes.push(String(config.url));
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: config.url?.endsWith("/runs")
          ? { items: [] }
          : {
              repository: "owner/repo",
              branch: "main",
              language: "Go",
              mode: "cli",
              encrypted: false,
            },
      },
    };
  };
  mount(AutoPublish, {
    id: "7",
    language: "Go",
    mode: "cli",
    encrypted: false,
    ready: true,
  });
  await vi.waitFor(() =>
    expect(button("同步配置到仓库")?.disabled).toBe(false),
  );
  vi.mocked(confirmAction).mockRejectedValueOnce("cancel");
  button("同步配置到仓库").click();
  await nextTick();
  expect(confirmAction).toHaveBeenCalledWith(
    expect.stringContaining("将向 GitHub 仓库 owner/repo 写入或覆盖工作流文件"),
    "同步配置到仓库",
    { action: "同步配置到仓库", danger: true },
  );
  expect(writes).toEqual([]);
});

it("自动发布的加密选项与已保存值不同时提示，保存后消失", async () => {
  let saved = false;
  http.defaults.adapter = async (config) => {
    if (config.method === "patch")
      saved = Boolean(JSON.parse(String(config.data)).encrypted);
    return {
      config,
      status: 200,
      statusText: "",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data: config.url?.endsWith("/runs")
          ? { items: [] }
          : {
              repository: "owner/repo",
              branch: "main",
              language: "Go",
              mode: "cli",
              encrypted: saved,
            },
      },
    };
  };
  const encrypted = ref(false);
  mount({
    setup: () => () =>
      h(AutoPublish, {
        id: "7",
        language: "Go",
        mode: "cli",
        encrypted: encrypted.value,
        ready: true,
      }),
  });
  await vi.waitFor(() => expect(button("保存仓库与构建选项")).toBeDefined());
  expect(root.textContent).not.toContain("保存仓库配置后才生效");
  encrypted.value = true;
  await nextTick();
  expect(root.textContent).toContain("保存仓库配置后才生效");
  button("保存仓库与构建选项").click();
  await vi.waitFor(() => expect(saved).toBe(true));
  await vi.waitFor(() =>
    expect(root.textContent).not.toContain("保存仓库配置后才生效"),
  );
});
