/* global document, requestAnimationFrame, innerWidth, getComputedStyle */
// Production-build browser QA with synthetic data only. Playwright stays external.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";
const dist = resolve(fileURLToPath(new URL("../dist/", import.meta.url)));
const server = createServer(async (request, response) => {
  const path = resolve(
    dist,
    "." + new URL(request.url, "http://localhost").pathname,
  );
  if (!path.startsWith(dist + "/") && path !== dist)
    return response.writeHead(404).end();
  try {
    const data = await readFile(path);
    response.setHeader(
      "content-type",
      { ".js": "text/javascript", ".css": "text/css", ".html": "text/html" }[
        extname(path)
      ] || "application/octet-stream",
    );
    response.end(data);
  } catch {
    response.setHeader("content-type", "text/html");
    response.end(await readFile(resolve(dist, "index.html")));
  }
});
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const origin = `http://127.0.0.1:${server.address().port}`;
const { chromium } = await import(
  process.env.AUTHGO_PLAYWRIGHT || "playwright"
);
const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.CHROMIUM_EXECUTABLE || undefined,
  args: ["--no-sandbox"],
});
const screenshotDir = process.env.AUTHGO_SCREEN_DIR;
if (screenshotDir) await mkdir(screenshotDir, { recursive: true });
const contact = "支持邮箱 support@example.test，工单支持请联系软件提供方。";
const info = {
  scope: "public",
  country_code: "US",
  region: "California",
  city: "Mountain View",
  asn: 15169,
  as_org: "Google LLC",
};
const deployment = {
  available: true,
  ports_hint: "如程序需要对外提供服务，请按软件文档添加 ports",
  compose:
    'services:\n  app:\n    image: "example/software:2.0.0"\n    restart: unless-stopped\n    environment:\n      AUTHGO_LICENSE: "AUTH-TESTA-TESTB-TESTC-TESTD"\n    volumes:\n      - authgo_cache:/var/lib/authgo\nvolumes:\n  authgo_cache:\n',
  steps: [
    "docker compose pull",
    "docker compose up -d",
    "docker compose logs --tail=50",
  ],
  guide:
    "### 实例与缓存\n每个实例使用独立的缓存卷。\n\n<script>alert('unsafe')</script>\n\n[不安全链接](javascript:alert(1))\n\n```sh\ndocker compose logs --tail=50\n```",
};
const license = {
  id: 42,
  app_id: 7,
  app_name:
    "EnterpriseDockerApplicationProductionService 企业级容器应用与数据处理服务平台（正式授权版本）",
  key: "AUTH-TESTA-TESTB-TESTC-TESTD",
  status: "active",
  type: "trial",
  verify_methods: ["KEY", "FLOATING", "DOMAIN"],
  max_activations: 2,
  online_instances: 1,
  remaining_unbinds: 2,
  unbind_cooldown_seconds: 3600,
  has_announcements: true,
  features: {},
  metadata: {},
  remaining_days: 7,
  trial_remaining_days: 7,
  expires_at: "2026-12-01T00:00:00Z",
  maintenance_until: "2026-12-01T00:00:00Z",
  latest_entitled_version: "2.0.0",
  renewal_required: true,
  deployment,
};
assert.equal(
  license.key.length,
  28,
  "fixture must retain a real-length synthetic key",
);
assert.ok(
  license.app_name.length > 50,
  "fixture must retain a long application name",
);
const instance = {
  id: 1,
  license_id: 42,
  app_id: 7,
  app_name: license.app_name,
  hostname: "production-worker-container",
  os: "Linux",
  kind: "floating",
  status: "active",
  client_version: "1.0.0",
  last_ip: "8.8.*.*",
  ip_info: info,
  last_seen_at: "2026-11-07T00:00:00Z",
  remaining_unbinds: 2,
};
const log = {
  id: 1,
  license_id: 42,
  app_id: 7,
  app_name: license.app_name,
  created_at: instance.last_seen_at,
  action: "verify",
  code: "OK",
  ip: "8.8.*.*",
  ip_info: info,
  client_version: "1.0.0",
};
const results = [];
try {
  for (const width of [1440, 375, 320]) {
    const context = await browser.newContext({
      viewport: { width, height: 1000 },
    });
    await context.addInitScript(() => {
      sessionStorage.setItem("authgo.portal.token", "synthetic-user");
    });
    const page = await context.newPage();
    const errors = [];
    const calls = [];
    page.on("pageerror", (e) => errors.push(e.message));
    let scope = "user",
      unavailable = false,
      empty = false,
      noVersion = false;
    await page.route("**/api/v1/**", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      calls.push(url.pathname + url.search);
      assert.ok(
        !url.pathname.includes("/admin/"),
        "user page accessed admin API",
      );
      const path = url.pathname.replace(/^\/api\/v1\/portal/, "");
      let data = { items: [], total: 0 };
      let status = 200;
      if (path === "/session")
        data = {
          scope,
          selected_license_id: 42,
          ip_info_dbip: true,
          support_contact: contact,
        };
      else if (path === "/user")
        data = {
          id: 1,
          name: "示例用户",
          email: "user@example.test",
          license_count: 1,
          instances_total: 1,
          next_expires_at: license.expires_at,
        };
      else if (path === "/switch") {
        assert.equal(JSON.parse(request.postData()).license_id, 42);
        data = { portal_token: "synthetic-selected", license };
      } else if (path === "/license" || path === "/licenses/42")
        data = {
          ...license,
          deployment: unavailable
            ? {
                available: false,
                reason: "软件未配置 Docker 镜像，请联系软件提供方",
                compose: "MUST-NOT-DISPLAY",
              }
            : deployment,
        };
      else if (path === "/licenses/999") {
        status = 404;
      } else if (path === "/licenses") data = { items: [license], total: 1 };
      else if (path === "/user/instances" || path === "/activations")
        data = { items: [instance], total: 1 };
      else if (path === "/user/logs" || path === "/logs")
        data = { items: [log], total: 1 };
      else if (path === "/user/attention")
        data = {
          items: empty
            ? []
            : Array.from(
                { length: 20 },
                (_, index) =>
                  [
                    "expired",
                    "expiring",
                    "suspended",
                    "unbind_exhausted",
                    "update_available",
                    "maintenance_expiring",
                    "version_disabled",
                  ][index % 7],
              ).map((type, index) => ({
                type,
                severity: index < 3 ? "danger" : "warning",
                license_id: 42,
                app_name: license.app_name,
                support_contact: contact,
              })),
          total: empty ? 0 : 201,
        };
      else if (path === "/user/updates")
        data = {
          items: empty
            ? []
            : [
                {
                  app_id: 7,
                  app_name: license.app_name,
                  license_id: 42,
                  version: noVersion ? "" : "3.0.0",
                  latest_entitled_version: noVersion ? "" : "2.0.0",
                  published_at: noVersion ? null : instance.last_seen_at,
                  maintenance_until: license.maintenance_until,
                  renewal_required: true,
                  docker_pull: noVersion
                    ? ""
                    : "docker pull example/software:2.0.0",
                  changelog: noVersion
                    ? ""
                    : "性能改进与兼容性更新 <script>不会执行</script>",
                },
              ],
          total: empty ? 0 : 1,
        };
      else if (path === "/update")
        data = {
          available: false,
          docker_image: "example/software",
          reason: "已是授权范围内最新版本",
        };
      else if (path === "/user/announcements" || path === "/announcements")
        data = {
          items: empty
            ? []
            : [
                {
                  id: 1,
                  app_id: 7,
                  app_name: license.app_name,
                  title: "软件维护公告",
                  content: "请妥善保管授权码 <script>不会执行</script>",
                  published_at: instance.last_seen_at,
                },
              ],
          total: empty ? 0 : 1,
        };
      else if (path === "/login/options") data = { smtp_configured: false };
      await route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(
          status === 404
            ? { code: "NOT_FOUND", message: "授权不存在" }
            : { code: "OK", data },
        ),
      });
    });
    async function checkLicenseKeys() {
      const metrics = await page
        .locator(".portal-license-key:visible")
        .evaluateAll((nodes) =>
          nodes.map((node) => {
            const rect = node.getBoundingClientRect(),
              value = node.querySelector(".copy-field-value"),
              controls = node.querySelector(".copy-controls");
            return {
              right: rect.right,
              left: rect.left,
              controlRight: controls.getBoundingClientRect().right,
              controlLeft: controls.getBoundingClientRect().left,
              overflow: getComputedStyle(value).overflow,
              wrap: getComputedStyle(value).overflowWrap,
              scroll: value.scrollWidth,
              client: value.clientWidth,
              text: value.textContent.trim(),
            };
          }),
        );
      for (const m of metrics) {
        assert.equal(m.text, license.key);
        assert.ok(
          m.left >= 0 && m.right <= width,
          `license key outside viewport: ${JSON.stringify(m)}`,
        );
        assert.ok(
          m.controlRight <= m.right + 1 && m.controlLeft >= m.left,
          `copy buttons squeezed out: ${JSON.stringify(m)}`,
        );
        assert.equal(
          m.overflow,
          "visible",
          "license key must wrap, not be cropped",
        );
        assert.equal(m.wrap, "anywhere");
        assert.ok(
          m.scroll <= m.client + 1,
          `key did not wrap: ${JSON.stringify(m)}`,
        );
      }
      const cards = await page
        .locator(".user-license-card")
        .evaluateAll((nodes) =>
          nodes.map((node) => ({
            right: node.getBoundingClientRect().right,
            panelRight: node.closest("section").getBoundingClientRect().right,
          })),
        );
      assert.ok(
        cards.every((c) => c.right <= c.panelRight),
        "license card widened its panel",
      );
    }
    async function checkInstanceTable() {
      const metrics = await page
        .locator(".table-scroll .el-table")
        .evaluate((table) => {
          const outer = table.closest(".table-scroll");
          const viewport = table.querySelector(
            ".el-table__body-wrapper .el-scrollbar__wrap",
          );
          const button = [
            ...table.querySelectorAll(".el-table__body button"),
          ].find((node) => node.textContent.trim() === "解绑");
          const status = table.querySelector(".el-table__body .status-badge");
          const bounds = viewport.getBoundingClientRect();
          const action = button?.getBoundingClientRect(),
            badge = status?.getBoundingClientRect();
          return {
            outerScroll: outer.scrollWidth,
            outerClient: outer.clientWidth,
            scroll: viewport.scrollWidth,
            client: viewport.clientWidth,
            scrollLeft: viewport.scrollLeft,
            left: bounds.left,
            right: bounds.right,
            action: action && {
              left: action.left,
              right: action.right,
              width: action.width,
            },
            status: badge && {
              left: badge.left,
              right: badge.right,
              width: badge.width,
            },
          };
        });
      assert.ok(
        metrics.outerScroll <= metrics.outerClient,
        `instance table outer overflow: ${JSON.stringify(metrics)}`,
      );
      assert.ok(
        metrics.scroll <= metrics.client,
        `instance table needs horizontal scrolling: ${JSON.stringify(metrics)}`,
      );
      assert.equal(
        metrics.scrollLeft,
        0,
        "instance actions must be visible without scrolling",
      );
      for (const field of ["status", "action"]) {
        const item = metrics[field];
        assert.ok(
          item &&
            item.width > 0 &&
            item.left >= metrics.left &&
            item.right <= metrics.right,
          `${field} outside instance viewport: ${JSON.stringify(metrics)}`,
        );
      }
      console.log("instance-table-ok", JSON.stringify({ width, ...metrics }));
    }
    async function inspect(path, expected) {
      await page.goto(origin + path);
      await page
        .getByText(expected, { exact: false })
        .filter({ visible: true })
        .first()
        .waitFor();
      await page.evaluate(() => document.fonts.ready);
      await page.evaluate(
        () =>
          new Promise((done) =>
            requestAnimationFrame(() => requestAnimationFrame(done)),
          ),
      );
      const metrics = await page.evaluate(() => ({
        scroll: document.documentElement.scrollWidth,
        width: innerWidth,
      }));
      assert.ok(
        metrics.scroll <= metrics.width,
        `${width} ${path} overflow ${JSON.stringify(metrics)}`,
      );
      await checkLicenseKeys();
      if (
        width === 1440 &&
        (path === "/portal/instances" || path.includes("?tab=instances"))
      )
        await checkInstanceTable();
      assert.deepEqual(errors, [], `${path} runtime errors`);
      assert.ok(await page.locator("footer .ip-attribution").isVisible());
      assert.ok((await page.locator("footer").innerText()).includes(contact));
      assert.ok(!(await page.locator("main").innerText()).includes("保护级别"));
      results.push({ width, path, overflow: false });
      console.log("layout-ok", width, path);
    }
    await inspect("/portal/home", "我的概览");
    assert.equal(await page.locator(".portal-nav a").count(), 6);
    await page.locator(".portal-attention-list li").nth(19).waitFor();
    assert.equal(await page.locator(".portal-attention-list li").count(), 20);
    const attentionPanel = page.locator(".portal-attention-list").locator("..");
    const nextAttention = page.waitForResponse(
      (response) =>
        response.url().includes("/portal/user/attention?") &&
        new URL(response.url()).searchParams.get("page") === "2",
    );
    await attentionPanel.locator(".el-pagination .btn-next").click();
    await nextAttention;
    assert.equal(
      await attentionPanel.locator(".el-pager .is-active").innerText(),
      "2",
    );
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
      "attention pagination overflow",
    );
    assert.ok(
      calls.some(
        (path) => path.includes("/user/logs?") && path.includes("page_size=10"),
      ),
    );
    await inspect("/portal/licenses", "查看授权");
    assert.ok(
      (await page.locator("main").innerText()).includes("联系提供方转正"),
    );
    await inspect("/portal/instances", "production-worker-container");
    const line = page
      .locator(
        width === 1440
          ? ".el-table__body .ip-info-details:visible"
          : ".table-cards .ip-info-details:visible",
      )
      .first();
    assert.ok((await line.innerText()).includes("AS15169"));
    assert.ok((await line.getAttribute("title")).includes("California"));
    if (width === 1440) {
      const heights = await page
        .locator(".el-table__body tr:visible")
        .evaluateAll((nodes) =>
          nodes.map((node) => node.getBoundingClientRect().height),
        );
      assert.ok(
        heights.length > 0 && heights.every((h) => Math.abs(h - 44) <= 1),
        `row heights: ${heights}`,
      );
    }
    assert.ok(!(await page.locator("main").innerText()).includes("8.8.8.8"));
    await inspect("/portal/updates", "docker pull example/software:2.0.0");
    noVersion = true;
    await inspect("/portal/updates", "暂无可用版本");
    const versionless = page.locator(".portal-record");
    assert.equal(
      (await versionless.locator("h2").innerText()).replace(/\s+/g, " ").trim(),
      `${license.app_name} · 暂无可用版本`,
    );
    assert.ok(!(await versionless.innerText()).includes("发布时间"));
    assert.ok(!(await versionless.innerText()).includes("暂无更新说明"));
    assert.equal(await versionless.locator(".announcement-body").count(), 0);
    noVersion = false;
    await inspect("/portal/announcements", "软件维护公告");
    assert.equal(await page.locator("main script").count(), 0);
    await inspect("/portal/account", "由管理员维护");
    for (const [tab, expected] of [
      ["overview", "可用版本到"],
      ["instances", "production-worker-container"],
      ["updates", "暂无可用的Docker版本"],
      ["deployment", "请妥善保管"],
      ["offline", "离线"],
      ["logs", "来源 IP"],
      ["domains", "域名"],
      ["announcements", "软件维护公告"],
    ]) {
      await inspect(`/portal/licenses/42?tab=${tab}`, expected);
      assert.equal(await page.getByRole("tab").count(), 8);
      if (tab === "deployment") {
        assert.equal(
          await page.locator(".portal-deployment script").count(),
          0,
        );
        assert.equal(
          await page
            .locator('.portal-deployment a[href^="javascript:"]')
            .count(),
          0,
        );
        await page
          .getByRole("button", { name: "显示docker-compose.yml", exact: true })
          .click();
        assert.ok(
          (await page.locator(".portal-deployment").innerText()).includes(
            "restart: unless-stopped",
          ),
        );
        assert.ok(
          (await page.locator(".portal-deployment").innerText()).includes(
            license.key,
          ),
        );
        assert.ok(
          (await page.locator(".portal-deployment").innerText()).includes(
            deployment.ports_hint,
          ),
        );
        const composeMetrics = await page
          .locator(".portal-deployment > .copy-field .copy-field-value")
          .evaluate((node) => ({
            width: node.getBoundingClientRect().width,
            container: node.parentElement.clientWidth,
          }));
        assert.ok(
          composeMetrics.width >= composeMetrics.container - 26,
          "compose controls must not squeeze the code column",
        );
        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth > innerWidth,
        );
        assert.equal(overflow, false, "expanded compose overflow");
        if (screenshotDir)
          await page.screenshot({
            path: resolve(screenshotDir, `${width}-deployment.png`),
            fullPage: true,
          });
      }
    }
    unavailable = true;
    await inspect(
      "/portal/licenses/42?tab=deployment",
      "软件未配置 Docker 镜像",
    );
    assert.equal(
      await page.locator(".portal-deployment .copy-field").count(),
      0,
    );
    assert.ok(
      !(await page.locator("main").innerText()).includes("MUST-NOT-DISPLAY"),
    );
    unavailable = false;
    await inspect("/portal/licenses/999", "无法查看该授权");
    assert.equal(await page.locator(".portal-deployment").count(), 0);
    assert.ok(
      await page
        .getByRole("link", { name: "返回授权列表", exact: true })
        .isVisible(),
    );
    empty = true;
    await inspect("/portal/home", "目前没有需要处理的事项");
    await inspect("/portal/updates", "软件尚未发布更新");
    await inspect("/portal/announcements", "软件尚未发布公告");
    empty = false;
    for (const [old, destination] of [
      ["license", "/portal/licenses/42?tab=overview"],
      ["activations", "/portal/instances"],
      ["offline", "/portal/licenses/42?tab=offline"],
      ["domains", "/portal/licenses/42?tab=domains"],
      ["logs", "/portal/licenses/42?tab=logs"],
    ]) {
      await page.goto(`${origin}/portal/${old}`);
      await page.waitForURL(origin + destination);
    }
    scope = "license";
    for (const path of [
      "license",
      "activations",
      "logs",
      "offline",
      "domains",
      "announcements",
    ]) {
      await page.goto(`${origin}/portal/${path}`);
      await page.locator(".portal-nav a").first().waitFor();
      assert.equal(new URL(page.url()).pathname, `/portal/${path}`);
      if (path === "license") {
        await page.locator(".portal-license-key").waitFor();
        await checkLicenseKeys();
      }
      const links = await page
        .locator(".portal-nav a")
        .evaluateAll((nodes) => nodes.map((n) => n.getAttribute("href")));
      assert.ok(
        !links.includes("/portal/account") &&
          !links.includes("/portal/updates"),
      );
      assert.ok(
        links.includes("/portal/license") &&
          links.includes("/portal/activations"),
      );
    }
    await context.close();
  }
  console.log(
    JSON.stringify(
      { PASS: true, fixtureOnly: true, cases: results.length, results },
      null,
      2,
    ),
  );
} finally {
  await browser.close();
  await new Promise((done) => server.close(done));
}
