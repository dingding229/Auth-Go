import "./admin-bootstrap";
import { afterEach, expect, it, vi } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { createApp, nextTick, type App } from "vue";
import ElementPlus from "element-plus";
import { AxiosHeaders } from "axios";
import { createRouter, createMemoryHistory } from "vue-router";
import {
  dockerTemplates,
  dockerTemplate,
  dockerLanguages,
  customerCompose,
  githubActions,
  guardCode,
  validDockerImage,
  type DockerLanguage,
  type PHPMode,
} from "../src/lib/docker-wizard";
import { instanceOnline, instanceUsage } from "../src/lib/presentation";
import { licenseFields } from "../src/lib/schema";
import SchemaEditor from "../src/components/SchemaEditor.vue";
import DockerWizard from "../src/components/DockerWizard.vue";
import ProtocolDocument from "../src/components/ProtocolDocument.vue";
import { http } from "../src/lib/http";
import { confirmAction } from "../src/composables/tasks";
import ActivationsView from "../src/views/admin/ActivationsView.vue";
import RepositoryVersions from "../src/components/VersionManagement.vue";
vi.mock("../src/composables/tasks", async (original) => ({
  ...(await original<typeof import("../src/composables/tasks")>()),
  confirmAction: vi.fn().mockResolvedValue(undefined),
}));

let app: App | undefined, root: HTMLElement | undefined;
const originalAdapter = http.defaults.adapter;
afterEach(() => {
  app?.unmount();
  app = undefined;
  root?.remove();
  http.defaults.adapter = originalAdapter;
  vi.clearAllMocks();
});
function respond(
  data: (url: string, method: string, body: unknown) => unknown,
) {
  http.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "OK",
    headers: new AxiosHeaders(),
    data: { code: "OK", data: data(config.url!, config.method!, config.data) },
  });
}
async function mount(
  component: Parameters<typeof createApp>[0],
  props = {},
  path = "/admin/docs",
) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/:pathMatch(.*)*", component }],
  });
  await router.push(path);
  root = document.createElement("div");
  document.body.append(root);
  app = createApp(component, props);
  app.use(ElementPlus).use(router);
  app.mount(root);
  await nextTick();
}
const variants: [DockerLanguage, PHPMode][] = [
  ...dockerLanguages
    .filter((l) => l !== "PHP")
    .map((l) => [l, "cli"] as [DockerLanguage, PHPMode]),
  ["PHP", "cli"],
  ["PHP", "fpm"],
  ["PHP", "apache"],
];
it.each(variants)(
  "%s/%s Dockerfile及compose与真实示例一致，交付配置无运行时AUTHGO_CONFIG",
  (language, mode) => {
    const t = dockerTemplate(language, mode);
    for (const [name, content] of Object.entries(t.files))
      expect(content, `${t.directory}/${name}`).toBe(
        readFileSync(`../${t.directory}/${name}`, "utf8"),
      );
    expect(t.files.Dockerfile).toBeTruthy();
    if (t.files["Dockerfile.nginx"])
      expect(t.files["Dockerfile.nginx.dockerignore"]).toContain(
        `!${t.directory}/nginx.conf.template`,
      );
    expect(t.files["docker-compose.yml"]).toBeTruthy();
    const compose = customerCompose(language, mode, "example-org/example-app");
    const expected = t.files["docker-compose.yml"]!.replace(
      /^ {4}build:\n(?: {6}.*\n)*/gm,
      "",
    ).replace(
      /^ {4}image: (.+)$/gm,
      (_line, original: string) =>
        `    image: example-org/example-app${original.includes("fpm-nginx") ? "-nginx" : ""}:latest`,
    );
    expect(compose).toBe(expected);
    expect(t.files.Dockerfile).not.toMatch(/^\s*ENV\s+.*AUTHGO_CONFIG/m);
    expect(
      guardCode(language, mode).trim().split("\n").length,
    ).toBeLessThanOrEqual(20);
    expect(compose).not.toContain("AUTHGO_CONFIG");
    expect(compose).not.toMatch(/\bbuild:/);
    expect(compose).toContain("AUTHGO_LICENSE:");
    expect(compose).toContain("read_only: true");
    expect(compose).toContain("cap_drop: [ALL]");
    expect(compose).toContain("no-new-privileges:true");
    expect(compose).toContain("authgo_cache:/var/lib/authgo");
    expect(compose).toContain("example-org/example-app:latest");
    if (mode === "fpm")
      expect(compose).toContain("example-org/example-app-nginx:latest");
    const workflow = githubActions(language, mode, "example-org/example-app");
    expect(
      [...workflow.matchAll(/secrets\.([A-Z_]+)/g)].map((m) => m[1]).sort(),
    ).toEqual(["DOCKERHUB_TOKEN", "DOCKERHUB_USERNAME"]);
    expect(workflow).toContain("vars.AUTHGO_CONFIG");
    expect(workflow).toContain(`${t.directory}/Dockerfile`);
    expect(workflow).toContain("version=${GITHUB_REF_NAME#v}");
    expect(workflow).toContain("steps.release.outputs.version");
    expect(workflow).not.toContain("auth.kkxk");
    expect(guardCode(language, mode)).not.toMatch(
      /(?:getenv|Getenv|GetEnvironmentVariable)\(["']AUTHGO_CONFIG/,
    );
  },
);
it("向导模板不遗漏语言、PHP三种及构建支持文件", () => {
  expect(Object.keys(dockerTemplates)).toHaveLength(9);
  for (const t of Object.values(dockerTemplates)) {
    const actual = readdirSync(`../${t.directory}`, {
      recursive: true,
      withFileTypes: true,
    }).filter(
      (p) =>
        p.isFile() &&
        p.name !== "README.md" &&
        (t.directory !== "examples/docker" ||
          p.parentPath === "../examples/docker"),
    );
    expect(actual.length).toBe(Object.keys(t.files).length);
  }
  expect(guardCode("PHP", "fpm")).not.toContain("exit(");
  expect(guardCode("PHP", "apache")).toContain("http_response_code(503)");
});
it("默认FLOATING和一个实例，旧授权初始值不变", () => {
  expect(
    licenseFields.find((f) => f.key === "verify_methods")?.default,
  ).toEqual(["KEY", "FLOATING"]);
  expect(licenseFields.find((f) => f.key === "max_activations")?.default).toBe(
    1,
  );
});
it("在线状态严格按浮动租约，等于截止即离线；用online_instances而不是历史激活数", () => {
  const now = Date.parse("2026-11-06T00:00:00Z"),
    live = {
      kind: "floating",
      status: "active",
      lease_expires_at: new Date(now + 1).toISOString(),
    };
  expect(instanceOnline(live, now)).toBe(true);
  for (const patch of [
    { kind: "key" },
    { status: "unbound" },
    { offline_at: new Date(now).toISOString() },
    { lease_expires_at: new Date(now).toISOString() },
    { lease_expires_at: "bad" },
  ])
    expect(instanceOnline({ ...live, ...patch }, now)).toBe(false);
  expect(
    instanceUsage({
      verify_methods: ["KEY", "FLOATING"],
      active_activations: 99,
      online_instances: 1,
      max_activations: 2,
    }),
  ).toBe("1/2");
});
it("保存镜像调用管理接口，只有PHP展示运行方式且切换影响代码", async () => {
  const writes: unknown[] = [];
  respond((url, method, body) => {
    if (method === "patch") writes.push([url, JSON.parse(String(body))]);
    return { docker_image: "example-org/example-app" };
  });
  await mount(DockerWizard, { id: "7", config: "authgo2.placeholder" });
  await vi.waitFor(() =>
    expect(root!.querySelector("input")?.value).toBe("example-org/example-app"),
  );
  (root!.querySelector('button[type="submit"]') as HTMLButtonElement).click();
  await vi.waitFor(() =>
    expect(writes).toEqual([
      ["/applications/7", { docker_image: "example-org/example-app" }],
    ]),
  );
  expect(root!.querySelector('[aria-label="PHP运行方式"]')).toBeNull();
  const php = [...root!.querySelectorAll(".el-segmented__item")].find(
    (n) => n.textContent === "PHP",
  ) as HTMLElement;
  php.click();
  await nextTick();
  expect(root!.querySelector('[aria-label="PHP运行方式"]')).not.toBeNull();
  const apache = [...root!.querySelectorAll(".el-radio")].find((n) =>
    n.textContent?.includes("请求式Apache"),
  ) as HTMLElement;
  apache.click();
  await nextTick();
  expect(root!.textContent).toContain("http_response_code(503)");
});
it("镜像名拒绝注入内容", () => {
  for (const value of [
    "https://host/repo",
    "org/repo:tag",
    "org/repo\nrun: bad",
    "org/repo;cmd",
    "org/repo${{secrets.X}}",
    "",
  ])
    expect(validDockerImage(value)).toBe(false);
  expect(() => githubActions("Go", "cli", "evil\nrun: bad")).toThrow();
});
it("Docker文档从接口读取，原始HTML仍不执行", async () => {
  const paths: string[] = [];
  respond((url) => {
    paths.push(url);
    return {
      text: '# Docker\n<img src=x onerror="window.pwn=1">\n```sh\ndocker compose up -d\n```',
    };
  });
  await mount(ProtocolDocument, { document: "docker" });
  await vi.waitFor(() =>
    expect(root!.querySelector(".protocol-markdown")).not.toBeNull(),
  );
  expect(paths).toEqual(["/integration/docker"]);
  expect(root!.querySelector("img")).toBeNull();
  expect(root!.querySelector("[data-copy-code]")).not.toBeNull();
});
it("实例页显示租约在线状态并通过确认调用释放席位接口", async () => {
  const paths: string[] = [];
  respond((url, method) => {
    if (method === "post") paths.push(url);
    return {
      items: [
        {
          id: 1,
          license_id: 1,
          license_key: "AUTH-ABCDE-FGHIJ-KLMNP-QRSTU",
          kind: "floating",
          status: "active",
          instance_id: "12345678abcdef",
          hostname: "worker",
          lease_expires_at: new Date(Date.now() + 60000).toISOString(),
        },
      ],
      total: 1,
    };
  });
  await mount(ActivationsView, {}, "/admin/activations");
  await vi.waitFor(() => expect(root!.textContent).toContain("12345678"));
  expect(root!.textContent).toContain("在线");
  (
    [...root!.querySelectorAll("button")].find(
      (n) => n.textContent?.trim() === "释放席位",
    ) as HTMLButtonElement
  ).click();
  await vi.waitFor(() =>
    expect(paths).toEqual(["/activations/1/release-seat"]),
  );
  expect(confirmAction).toHaveBeenCalled();
});
it("版本禁用开关先确认再PATCH", async () => {
  const writes: unknown[] = [];
  respond((url, method, body) => {
    if (method === "patch") writes.push([url, JSON.parse(String(body))]);
    if (url.endsWith("/repository")) return {};
    return { items: [{ id: 3, version: "1.0.0", disabled: false }] };
  });
  await mount(RepositoryVersions, { id: "7", appKey: "app-test" });
  await vi.waitFor(() =>
    expect(root!.querySelector('[aria-label="禁用版本1.0.0"]')).not.toBeNull(),
  );
  (root!.querySelector('[aria-label="禁用版本1.0.0"]') as HTMLElement).click();
  await vi.waitFor(() =>
    expect(writes).toEqual([["/versions/3", { disabled: true }]]),
  );
  expect(confirmAction).toHaveBeenCalled();
});

it("编辑存量KEY-only授权不会擅自变成FLOATING", async () => {
  const save = vi.fn();
  respond(() => ({ items: [{ id: 1, name: "已有用户" }], total: 1 }));
  await mount(SchemaEditor, {
    fields: licenseFields,
    editing: true,
    initial: {
      app_id: 1,
      user_id: 1,
      verify_methods: ["KEY"],
      max_activations: 5,
    },
    onSave: save,
  });
  (root!.querySelector('button[type="submit"]') as HTMLButtonElement).click();
  await vi.waitFor(() => expect(save).toHaveBeenCalledOnce());
  expect(save.mock.calls[0]![0]).toMatchObject({
    verify_methods: ["KEY"],
  });
  expect(save.mock.calls[0]![0].max_activations).toBeUndefined();
});
