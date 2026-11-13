// Run the Playwright Docker wizard layout test against the production build; API traffic is mocked.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";
const dist = resolve(fileURLToPath(new URL("../dist/", import.meta.url)));
const runtimeHtml = async () => {
  const html = await readFile(resolve(dist, "index.html"), "utf8");
  return html.replace(
    "</head>",
    '<script id="authgo-runtime" type="application/json">{"admin_path":"/admin"}</script></head>',
  );
};
const server = createServer(async (req, res) => {
  const p = resolve(dist, "." + new URL(req.url, "http://localhost").pathname);
  if (!p.startsWith(dist + "/") && p !== dist) return res.writeHead(404).end();
  try {
    const data = await readFile(p);
    res.setHeader(
      "content-type",
      {
        ".js": "text/javascript",
        ".css": "text/css",
        ".html": "text/html",
        ".woff2": "font/woff2",
      }[extname(p)] || "application/octet-stream",
    );
    res.end(extname(p) === ".html" ? await runtimeHtml() : data);
  } catch {
    res.setHeader("content-type", "text/html");
    res.end(await runtimeHtml());
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = "http://127.0.0.1:" + server.address().port;
const { chromium } = await import(
  process.env.AUTHGO_PLAYWRIGHT || "playwright"
);
const browser = await chromium.launch({
  headless: true,
  args: ["--no-sandbox"],
});
const dockerDoc = await readFile(
  new URL("../../server/internal/apidocs/docker.md", import.meta.url),
  "utf8",
);
const results = [];
try {
  for (const width of [1440, 375, 320]) {
    const context = await browser.newContext({
      viewport: { width, height: 1000 },
    });
    await context.addInitScript(() => {
      sessionStorage.setItem("authgo.portal.token", "portal-test-only");
      sessionStorage.setItem("authgo.admin.access", "test-only");
      sessionStorage.setItem("authgo.admin.refresh", "test-only");
      sessionStorage.setItem(
        "authgo.admin.user",
        JSON.stringify({ id: 1, username: "测试管理员" }),
      );
    });
    const page = await context.newPage(),
      errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const software = {
      id: 7,
      name: "测试软件",
      status: "active",
      app_key: "test-only",
      docker_image: "example-org/example-app",
      grace_hours: 72,
      next_check_in: 3600,
      heartbeat_interval: 60,
      allowed_client_versions: "",
    };
    const license = {
      id: 1,
      app_id: 7,
      app_name: software.name,
      key: "AUTH-ABCDE-FGHJK-LMNPQ-RSTUV",
      status: "active",
      type: "standard",
      verify_methods: ["KEY", "FLOATING"],
      max_activations: 1,
      online_instances: 1,
      features: {},
      metadata: {},
      validity_rule: "perpetual",
    };
    const activation = {
      id: 1,
      license_id: 1,
      license_key: license.key,
      kind: "floating",
      value: "a".repeat(64),
      instance_id: "a".repeat(64),
      hostname: "worker",
      client_version: "1.0.0",
      last_ip: "203.0.113.1",
      status: "active",
      lease_expires_at: "2036-01-01T00:00:00Z",
      last_seen_at: "2026-11-06T00:00:00Z",
    };
    await page.route("**/api/v1/**", async (route) => {
      const p = new URL(route.request().url()).pathname.replace(
        "/api/v1/admin",
        "",
      );
      let data = { items: [], total: 0 };
      if (p === "/auth/me") data = { id: 1, username: "测试管理员" };
      else if (p === "/status") data = { initialized: true };
      else if (p === "/system/settings")
        data = { public_url: "https://auth.example.com" };
      else if (p === "/applications/7/dockerhub")
        data = {
          configured: true,
          image: "example-org/example-app",
          last_result: "同步成功",
          last_error: "仓库不存在或不是公开仓库，请检查镜像名后重试。",
          collected: 100,
          ignored: 200,
          last_sync_at: "2026-11-07T00:00:00Z",
          next_sync_at: "2026-11-07T00:10:00Z",
        };
      else if (p === "/applications/7") data = software;
      else if (p === "/applications") data = { items: [software], total: 1 };
      else if (p === "/users")
        data = { items: [{ id: 1, name: "测试用户" }], total: 1 };
      else if (p === "/applications/7/repository") data = {};
      else if (p === "/applications/7/versions")
        data = {
          items: [
            {
              id: 1,
              version: "1.0.0",
              disabled: false,
              source: "docker",
              asset_count: 0,
            },
          ],
          total: 1,
        };
      else if (p === "/licenses") data = { items: [license], total: 1 };
      else if (p === "/activations")
        data = {
          items: [
            activation,
            {
              ...activation,
              id: 2,
              instance_id: "b".repeat(64),
              lease_expires_at: "2020-01-01T00:00:00Z",
            },
          ],
          total: 2,
        };
      else if (p === "/integration/docker") data = { text: dockerDoc };
      if (p === "/api/v1/portal/session")
        data = { scope: "license", selected_license_id: 1 };
      else if (p === "/api/v1/portal/license")
        data = {
          ...license,
          app_name: software.name,
          remaining_unbinds: 3,
          max_activations: 1,
        };
      else if (p === "/api/v1/portal/update")
        data = {
          available: true,
          version: "1.2.3",
          docker_image: "example-org/example-app",
          docker_pull: "docker pull example-org/example-app:v1.2.3",
          assets: [],
        };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ code: "OK", data }),
      });
    });
    async function fits(label) {
      const box = await page.evaluate(() => ({
        viewport: globalThis.innerWidth,
        scroll: globalThis.document.documentElement.scrollWidth,
      }));
      assert.ok(
        box.scroll <= box.viewport,
        `${width}/${label}: ${JSON.stringify(box)}`,
      );
    }
    await page.goto(origin + "/admin/applications/7");
    const wizard = page.locator(".docker-wizard");
    await wizard.getByText("收录版本：100", { exact: false }).waitFor();
    await fits("Docker Hub同步状态");
    await wizard.getByRole("button", { name: "保存镜像名并继续" }).click();
    const variants = [
      ["Go", ""],
      ["Python", ""],
      ["Node.js", ""],
      ["Java", ""],
      ["C#", ""],
      ["Rust", ""],
      ["PHP", "常驻CLI"],
      ["PHP", "请求式FPM"],
      ["PHP", "请求式Apache"],
    ];
    for (const [index, [language, mode]] of variants.entries()) {
      if (index > 0)
        for (let n = 0; n < 3; n++)
          await wizard
            .getByRole("button", { name: "上一步", exact: true })
            .click();
      await wizard
        .locator(".el-segmented__item")
        .getByText(language, { exact: true })
        .click();
      if (mode) await wizard.getByText(mode, { exact: true }).click();
      await fits(language + "/" + mode + "/code");
      await wizard.getByRole("button", { name: "下一步", exact: true }).click();
      assert.ok(
        (
          await wizard.locator(".el-tab-pane:visible pre").first().innerText()
        ).includes("FROM "),
      );
      await fits(language + "/" + mode + "/Dockerfile");
      await wizard.getByRole("button", { name: "下一步", exact: true }).click();
      const actions = await wizard
        .locator(".el-tab-pane:visible pre")
        .innerText();
      assert.deepEqual(
        [...actions.matchAll(/secrets\.([A-Z_]+)/g)].map((m) => m[1]).sort(),
        ["DOCKERHUB_TOKEN", "DOCKERHUB_USERNAME"],
      );
      await fits(language + "/" + mode + "/Actions");
      await wizard.getByRole("button", { name: "下一步", exact: true }).click();
      const compose = await wizard
        .locator(".el-tab-pane:visible pre")
        .innerText();
      assert.ok(
        compose.includes("AUTHGO_LICENSE:") &&
          !compose.includes("AUTHGO_CONFIG"),
      );
      await fits(language + "/" + mode + "/compose");
    }
    await page.goto(origin + "/admin/docs?tab=docker");
    await page.locator(".protocol-markdown h2").first().waitFor();
    await fits("Docker文档");
    await page.goto(origin + "/admin/activations");
    await page.getByRole("heading", { name: "实例", exact: true }).waitFor();
    await page
      .locator(".copy-field-value:visible")
      .filter({ hasText: /^aaaaaaaa$/ })
      .first()
      .waitFor();
    await fits("实例列表");
    await page.goto(origin + "/admin/licenses?create=1");
    await page.locator(".el-drawer .schema-form").waitFor();
    assert.equal(
      await page.locator('[data-field="max_activations"] input').inputValue(),
      "1",
    );
    await fits("发放授权");
    await page.goto(origin + "/admin/applications/7?tab=versions");
    await page
      .locator(".el-switch:visible")
      .filter({ has: page.locator('input[aria-label="禁用版本1.0.0"]') })
      .waitFor();
    await fits("版本禁用");
    await page.goto(origin + "/portal/license");
    await page
      .getByText("docker pull example-org/example-app:v1.2.3", { exact: true })
      .waitFor();
    await fits("用户中心Docker拉取命令");
    assert.deepEqual(errors, []);
    results.push({
      width,
      wizard_variants: 9,
      steps: "PASS",
      docs_instances_license_versions: "PASS",
      docker_hub_status_and_portal_pull: "PASS",
      horizontal_overflow: false,
    });
    await context.close();
  }
  console.log(JSON.stringify({ layout: "PASS", results }, null, 2));
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
