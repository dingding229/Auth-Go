import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, reactive, ref, type App } from "vue";
import ElementPlus, { ElMessageBox } from "element-plus";
import { AxiosHeaders } from "axios";
import PayloadKeys from "../src/components/PayloadKeys.vue";
import { http } from "../src/lib/http";
import { setAdmin } from "../src/lib/session";
import { readFileSync } from "node:fs";
import { protectedTemplate } from "../src/lib/docker-wizard";
import type { Row } from "../src/lib/json";
let app: App | undefined, root: HTMLElement;
const adapter = http.defaults.adapter;
async function flush() {
  for (let i = 0; i < 8; i++) {
    await nextTick();
    await new Promise((r) => setTimeout(r, 0));
  }
}
afterEach(() => {
  app?.unmount();
  root?.remove();
  http.defaults.adapter = adapter;
  vi.restoreAllMocks();
  document
    .querySelectorAll(".el-overlay, .el-message")
    .forEach((e) => e.remove());
});
const oldKey = {
  key_id: "pk_old",
  public_key: "public_old",
  is_current: true,
  created_at: "2026-11-07T00:00:00Z",
};
async function mount(initial: (typeof oldKey)[]) {
  setAdmin("admin", "refresh");
  let items = [...initial],
    posts = 0;
  http.defaults.adapter = async (config) => {
    if (config.method === "post") {
      posts++;
      items = [
        { ...oldKey, key_id: "pk_new", public_key: "public_new" },
        ...items.map((k) => ({ ...k, is_current: false })),
      ];
    }
    return {
      config,
      data: {
        code: "OK",
        data: config.method === "post" ? items[0] : { items },
      },
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
    };
  };
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(PayloadKeys, { id: "7", appKey: "app_example" }).use(
    ElementPlus,
  );
  app.mount(root);
  await flush();
  return () => posts;
}
function button(text: string) {
  return [...root.querySelectorAll<HTMLButtonElement>("button")].find((b) =>
    b.textContent?.includes(text),
  )!;
}
it("软件详情页包含功能模板后的打包密钥页签且保留地址标签", () => {
  const source = readFileSync(
    "src/views/admin/ApplicationDetailView.vue",
    "utf8",
  );
  expect(source.indexOf('name="payload-keys"')).toBeGreaterThan(
    source.indexOf('name="templates"'),
  );
  expect(source).toContain('label="打包密钥"');
  expect(source).toContain('"payload-keys"');
});
it("空状态生成密钥，显示真实公钥和可复制命令", async () => {
  const posts = await mount([]);
  expect(root.textContent).toContain("不加密代码的程序不需要这一步");
  expect(root.textContent).toContain("还没有打包密钥");
  button("生成打包密钥").click();
  await flush();
  expect(posts()).toBe(1);
  expect(root.textContent).toContain("pk_new");
  expect(root.textContent).toContain("public_new");
  expect(root.textContent).toContain(
    "authgo-pack --public-key 'public_new' --key-id 'pk_new' --app-key 'app_example'",
  );
  expect(root.querySelector('[aria-label="复制打包公钥"]')).not.toBeNull();
  expect(root.querySelector('[aria-label="复制打包命令"]')).not.toBeNull();
});
it("轮换必须确认，取消不写入，确认后保留历史", async () => {
  const posts = await mount([oldKey]);
  let approve: (() => void) | undefined;
  const confirmation = vi.spyOn(ElMessageBox, "confirm").mockImplementation(
    () =>
      new Promise((resolve) => {
        approve = () => resolve("confirm");
      }),
  );
  button("轮换密钥").click();
  await flush();
  expect(posts()).toBe(0);
  expect(confirmation).toHaveBeenCalledWith(
    expect.stringContaining("旧版本仍可解开"),
    "轮换打包密钥",
    expect.any(Object),
  );
  approve!();
  await flush();
  expect(posts()).toBe(1);
  expect(root.textContent).toContain("pk_old");
  expect(root.textContent).toContain("pk_new");
  expect(root.textContent).toContain("历史");
  confirmation.mockRejectedValueOnce("cancel");
  button("轮换密钥").click();
  await flush();
  expect(posts()).toBe(1);
});

it("窄屏顶栏优先收缩面包屑，不挤压用户操作菜单", () => {
  const styles = readFileSync("src/styles/layout.css", "utf8");
  expect(styles).toMatch(/\.user-menu\s*\{[^}]*flex-shrink:\s*0/);
  expect(styles).toMatch(
    /\.admin-topbar \.el-breadcrumb\s*\{[^}]*min-width:\s*0/,
  );
});
it("提供Go、Rust整体保护命令且配置只作构建参数", async () => {
  await mount([oldKey]);
  expect(
    root.querySelector('[aria-label="复制Go、Rust 整体加密命令"]'),
  ).not.toBeNull();
  expect(root.textContent).toContain("--protect '<编译后的ELF程序>'");
  expect(root.textContent).toContain("--config '<构建时接入配置>'");
  expect(root.textContent).not.toContain("AUTHGO_CONFIG=");
  expect(root.textContent).toContain("最终镜像仅复制替换后的程序");
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
function targetKey(id: string, rotated = false) {
  return {
    ...oldKey,
    key_id: `pk_${id}_${rotated ? "rotated" : "current"}`,
    public_key: (rotated ? "C" : id === "7" ? "A" : "B").repeat(43),
  };
}
async function mountChangingKeys(
  reply: (url: string, method: string) => unknown | Promise<unknown>,
) {
  setAdmin("admin", "refresh");
  const target = reactive({ id: "7", appKey: "app_7" });
  const selected = ref<Row>();
  const changes: (Row | undefined)[] = [];
  http.defaults.adapter = async (config) => ({
    config,
    data: { code: "OK", data: await reply(config.url!, config.method!) },
    status: 200,
    statusText: "OK",
    headers: new AxiosHeaders(),
  });
  root = document.createElement("div");
  document.body.append(root);
  app = createApp({
    setup: () => () =>
      h("div", [
        h(PayloadKeys, {
          ...target,
          onChange: (key: Row | undefined) => {
            selected.value = key;
            changes.push(key);
          },
        }),
        // Use the same generator as DockerWizard: a stale emitted key must not
        // leak into the currently selected application's generated Dockerfile.
        h(
          "pre",
          { "data-testid": "generated-dockerfile" },
          selected.value
            ? protectedTemplate("Go", "cli", {
                toolsImage: "example-org/authgo-tools",
                toolsVersion: "v1",
                appKey: target.appKey,
                keyId: String(selected.value.key_id),
                publicKey: String(selected.value.public_key),
              }).files.Dockerfile
            : "",
        ),
      ]),
  }).use(ElementPlus);
  app.mount(root);
  await flush();
  return {
    target,
    changes,
    file: () =>
      root.querySelector('[data-testid="generated-dockerfile"]')!.textContent,
  };
}

it("目标隔离：延迟轮换确认期间切换id，旧确认不得POST到新软件", async () => {
  const confirmation = deferred<"confirm">();
  const confirm = vi
    .spyOn(ElMessageBox, "confirm")
    .mockImplementation(() => confirmation.promise);
  const posts: string[] = [];
  const view = await mountChangingKeys((url, method) => {
    if (method === "post") posts.push(url);
    return { items: [targetKey(url.includes("/7/") ? "7" : "8")] };
  });
  button("轮换密钥").click();
  await flush();
  expect(confirm).toHaveBeenCalledTimes(1);
  expect(posts).toEqual([]);
  Object.assign(view.target, { id: "8", appKey: "app_8" });
  await flush();
  confirmation.resolve("confirm");
  await flush();
  expect(posts).toEqual([]);
  expect(root.textContent).toContain("pk_8_current");
  expect(view.file()).toContain("ARG PAYLOAD_KEY_ID=pk_8_current");
  expect(view.file()).toContain("ARG PAYLOAD_APP_KEY=app_8");
  expect(view.file()).not.toContain("pk_7_current");
  expect(view.changes.at(-1)?.key_id).toBe("pk_8_current");
});

it("目标隔离：已发出的轮换固定旧id，迟到POST结果不回读或覆盖新软件", async () => {
  vi.spyOn(ElMessageBox, "confirm").mockResolvedValue("confirm");
  const response = deferred<unknown>();
  const calls: string[] = [];
  const view = await mountChangingKeys((url, method) => {
    calls.push(`${method} ${url}`);
    if (method === "post") return response.promise;
    return { items: [targetKey(url.includes("/7/") ? "7" : "8")] };
  });
  button("轮换密钥").click();
  await flush();
  expect(calls.filter((call) => call.startsWith("post"))).toEqual([
    "post /applications/7/payload-keys",
  ]);
  Object.assign(view.target, { id: "8", appKey: "app_8" });
  await flush();
  const currentFile = view.file(),
    changes = [...view.changes];
  response.resolve(targetKey("7", true));
  await flush();
  expect(calls).toEqual([
    "get /applications/7/payload-keys",
    "post /applications/7/payload-keys",
    "get /applications/8/payload-keys",
  ]);
  expect(root.textContent).toContain("pk_8_current");
  expect(view.file()).toBe(currentFile);
  expect(view.file()).toContain("ARG PAYLOAD_KEY_ID=pk_8_current");
  expect(view.changes).toEqual(changes);
});

it("目标隔离：加载乱序保持generation保护，旧GET不能覆盖新软件", async () => {
  const oldResponse = deferred<unknown>();
  const view = await mountChangingKeys((url) =>
    url.includes("/7/") ? oldResponse.promise : { items: [targetKey("8")] },
  );
  Object.assign(view.target, { id: "8", appKey: "app_8" });
  await flush();
  expect(root.textContent).toContain("pk_8_current");
  const changes = [...view.changes];
  oldResponse.resolve({ items: [targetKey("7")] });
  await flush();
  expect(view.changes).toEqual(changes);
  expect(view.file()).toContain("ARG PAYLOAD_KEY_ID=pk_8_current");
  expect(view.file()).not.toContain("pk_7_current");
});

it("目标隔离：轮换后的旧GET迟到不能覆盖当前key或生成文件", async () => {
  vi.spyOn(ElMessageBox, "confirm").mockResolvedValue("confirm");
  const refresh = deferred<unknown>();
  let oldReads = 0;
  const view = await mountChangingKeys((url, method) => {
    if (method === "post") return targetKey("7", true);
    if (url.includes("/7/") && ++oldReads > 1) return refresh.promise;
    return { items: [targetKey(url.includes("/7/") ? "7" : "8")] };
  });
  button("轮换密钥").click();
  await flush();
  expect(oldReads).toBe(2);
  Object.assign(view.target, { id: "8", appKey: "app_8" });
  await flush();
  const changes = [...view.changes];
  refresh.resolve({ items: [targetKey("7", true)] });
  await flush();
  expect(view.changes).toEqual(changes);
  expect(view.file()).toContain("ARG PAYLOAD_KEY_ID=pk_8_current");
  expect(view.file()).not.toContain("pk_7_rotated");
});

it("目标隔离：id切走再返回同id仍取消旧确认，不复用旧操作作用域", async () => {
  const confirmation = deferred<"confirm">();
  vi.spyOn(ElMessageBox, "confirm").mockImplementation(
    () => confirmation.promise,
  );
  const posts: string[] = [];
  const view = await mountChangingKeys((url, method) => {
    if (method === "post") posts.push(url);
    return { items: [targetKey(url.includes("/7/") ? "7" : "8")] };
  });
  button("轮换密钥").click();
  await flush();
  Object.assign(view.target, { id: "8", appKey: "app_8" });
  await flush();
  Object.assign(view.target, { id: "7", appKey: "app_7" });
  await flush();
  confirmation.resolve("confirm");
  await flush();
  expect(posts).toEqual([]);
  expect(view.file()).toContain("ARG PAYLOAD_KEY_ID=pk_7_current");
});
