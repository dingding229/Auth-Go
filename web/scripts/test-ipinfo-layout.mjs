/* global document, requestAnimationFrame, innerWidth, getComputedStyle */
// Browser QA against the production build, with synthetic API fixtures only.
// Supply Playwright externally; no additional project dependency is required.
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
  if (!path.startsWith(dist + "/") && path !== dist) {
    response.writeHead(404).end();
    return;
  }
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
const info = {
  scope: "public",
  country_code: "US",
  country: "United States",
  region: "California",
  city: "Mountain View",
  asn: 15169,
  as_org: "Google LLC",
};
const instance = {
  id: 1,
  license_id: 42,
  license_key: "AUTH-SYNTHETIC-ONLY",
  hostname: "实例名称",
  kind: "floating",
  value: "synthetic-instance",
  status: "active",
  os: "Linux",
  last_ip: "2001:4860:4860:0:0:0:0:8888",
  first_ip: "8.8.8.8",
  ip_info: info,
  last_seen_at: "2026-11-07T00:00:00Z",
};
const license = {
  id: 42,
  app_id: 7,
  app_name: "软件",
  key: "AUTH-SYNTHETIC-ONLY",
  type: "standard",
  status: "active",
  verify_methods: ["FLOATING"],
  max_activations: 2,
  active_activations: 1,
  online_instances: 1,
  features: {},
  metadata: {},
  user_id: 1,
  unbind_limit: 2,
  remaining_unbinds: 2,
};
const db = {
  source: "db-ip",
  data_date: "2026-11-01T00:00:00Z",
  size: 123456789,
  updated_at: "2026-11-07T00:00:00Z",
};
const statusError = "City 上传失败：MMDB 库类型不匹配，请上传对应的 City 库";
let dbStatus = { enabled: true, city: db, asn: db, last_error: statusError };
const log = {
  id: 1,
  license_id: 42,
  license_key: license.key,
  created_at: "2026-11-07T00:00:00Z",
  action: "verify",
  code: "OK",
  status_code: 200,
  ip: instance.last_ip,
  ip_info: info,
  resource: "授权",
  device: "synthetic",
};
const cases = [
  "/admin/settings",
  "/admin/verify-logs",
  "/admin/audit-logs",
  "/admin/activations",
  "/admin/licenses/42",
  "/admin/users/1",
  "/portal/home",
  "/portal/activations",
  "/portal/logs",
];
const results = [];
try {
  for (const width of [1440, 375, 320]) {
    const context = await browser.newContext({
      viewport: { width, height: 1000 },
    });
    await context.addInitScript(() => {
      sessionStorage.setItem("authgo.admin.access", "synthetic-admin");
      sessionStorage.setItem("authgo.admin.refresh", "synthetic-refresh");
      sessionStorage.setItem(
        "authgo.admin.user",
        JSON.stringify({ id: 1, username: "管理员" }),
      );
      sessionStorage.setItem("authgo.portal.token", "synthetic-portal");
    });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.route("**/api/v1/**", async (route) => {
      const url = new URL(route.request().url());
      const portal = url.pathname.startsWith("/api/v1/portal");
      const path = url.pathname.replace(/^\/api\/v1\/(admin|portal)/, "");
      if (portal && path.startsWith("/system"))
        throw new Error("Portal called management API");
      let data = { items: [], total: 0 };
      const masked = { ...instance, last_ip: "8.8.*.*", first_ip: "8.8.*.*" };
      if (path === "/auth/me") data = { id: 1, username: "管理员" };
      else if (path === "/session")
        data = { scope: "user", selected_license_id: 42, ip_info_dbip: true };
      else if (path === "/user" || path === "/users/1")
        data = {
          id: 1,
          name: "用户",
          email: "user@example.test",
          license_count: 1,
          instances_total: 1,
        };
      else if (path === "/switch")
        data = { portal_token: "synthetic-selected", license };
      else if (path === "/license" || path === "/licenses/42")
        data = { ...license, activations: [instance] };
      else if (path === "/system/settings")
        data = { site_name: "Auth Go", public_url: origin, smtp: {} };
      else if (path === "/system/support")
        data = { support_contact: "支持邮箱 support@example.test" };
      else if (path === "/system/ip-info") data = dbStatus;
      else if (path === "/system/ip-info/enable") {
        dbStatus = { enabled: true, city: db, asn: db, last_error: "" };
        data = dbStatus;
      } else if (path === "/licenses") data = { items: [license], total: 1 };
      else if (
        path === "/activations" ||
        path === "/licenses/42/activations" ||
        path === "/user/instances" ||
        path === "/user/instances"
      )
        data = { items: [portal ? masked : instance], total: 1 };
      else if (
        path === "/verify-logs" ||
        path === "/audit-logs" ||
        path === "/logs" ||
        path === "/user/logs"
      )
        data = {
          items: portal
            ? [{ ...log, ip: "8.8.*.*" }]
            : [
                { ...log, ip: "8.8.8.8" },
                {
                  ...log,
                  id: 2,
                  ip: "114.114.114.114",
                  ip_info: {
                    ...info,
                    country_code: "CN",
                    country: "China",
                    region: "Jiangsu",
                    city: "Nanjing",
                    asn: 174,
                    as_org: "Cogent Communications",
                  },
                },
                {
                  ...log,
                  id: 3,
                  ip: "10.0.0.1",
                  ip_info: { scope: "private" },
                },
              ],
          total: portal ? 1 : 3,
        };
      else if (path === "/applications")
        data = { items: [{ id: 7, name: "软件" }], total: 1 };
      else if (path === "/users")
        data = { items: [{ id: 1, name: "用户" }], total: 1 };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ code: "OK", data }),
      });
    });
    for (const path of cases) {
      await page.goto(origin + path);
      if (path === "/admin/settings") {
        await page
          .getByRole("heading", { name: "支持联系方式", exact: true })
          .waitFor();
        const support = page.locator('textarea[maxlength="200"]');
        await support.fill(
          "支持邮箱 support@example.test，工单支持请联系软件提供方。".repeat(4),
        );
        assert.ok(
          await page
            .getByRole("button", { name: "保存支持联系方式", exact: true })
            .isVisible(),
        );
        assert.ok(
          await page.evaluate(
            () => document.documentElement.scrollWidth <= innerWidth,
          ),
          `${width} support settings overflow`,
        );
        await page.getByRole("tab", { name: "IP 库", exact: true }).click();
        await page.getByText("City 地理位置库", { exact: true }).waitFor();
      } else if (path === "/admin/licenses/42")
        await page.getByRole("tab", { name: "实例", exact: true }).click();
      else if (path === "/admin/users/1")
        await page.getByRole("tab", { name: "验证记录", exact: true }).click();
      const target = path === "/admin/settings" ? ".ipdb-files" : ".ip-info";
      await page.locator(target).first().waitFor({ state: "attached" });
      await page.evaluate(() => document.fonts.ready);
      // Give ResizeObserver and Element Plus layout two frames, without timers.
      await page.evaluate(
        () =>
          new Promise((done) =>
            requestAnimationFrame(() => requestAnimationFrame(done)),
          ),
      );
      const overflow = await page.evaluate(() => ({
        scroll: document.documentElement.scrollWidth,
        width: innerWidth,
      }));
      assert.ok(
        overflow.scroll <= overflow.width,
        `${width} ${path} overflow: ${JSON.stringify(overflow)}`,
      );
      if (path !== "/admin/settings" && width === 1440) {
        const rows = await page
          .locator(".table-scroll .el-table__body tr:visible")
          .evaluateAll((nodes) =>
            nodes.map((n) => n.getBoundingClientRect().height),
          );
        assert.ok(
          rows.every((height) => Math.abs(height - 44) <= 1),
          `${path} row heights ${rows}`,
        );
      }
      if (path === "/admin/settings") {
        assert.equal(
          await page.locator(".ipdb-error").count(),
          1,
          "global library error must appear once",
        );
        assert.equal(
          await page.locator(".ipdb-error").innerText(),
          statusError,
        );
        assert.ok(
          !(await page.locator(".ipdb-files").innerText()).includes(
            statusError,
          ),
          "error duplicated into library cards",
        );
        assert.ok(
          !(await page.locator(".ipdb-files").innerText()).includes("最近错误"),
        );
      } else {
        const rootSelector =
          width === 1440
            ? ".table-scroll .ip-info:visible"
            : ".table-cards .ip-info:visible, .device-card .ip-info:visible";
        const metrics = await page.locator(rootSelector).evaluateAll((nodes) =>
          nodes
            .filter((node) => node.querySelector(".ip-info-details"))
            .map((node) => {
              const line = node.querySelector(".ip-info-details");
              const asn = node.querySelector(".ip-info-asn");
              const rect = line.getBoundingClientRect();
              const style = getComputedStyle(line);
              const id = asn?.getBoundingClientRect();
              return {
                text: line.textContent.trim(),
                title: line.title,
                height: rect.height,
                width: rect.width,
                visibility: style.visibility,
                display: style.display,
                position: style.position,
                asn: asn?.textContent,
                asnWidth: id?.width,
                asnScroll: asn?.scrollWidth,
                asnClient: asn?.clientWidth,
                asnRight: id?.right,
                lineRight: rect.right,
              };
            }),
        );
        // Portal instance cards are not tables on desktop; check those directly too.
        if (path !== "/portal/activations" || width !== 1440)
          assert.ok(
            metrics.length > 0,
            `${width} ${path} no visible IP metadata`,
          );
        for (const metric of metrics) {
          assert.ok(
            metric.height >= 15 &&
              metric.width > 0 &&
              metric.visibility !== "hidden" &&
              metric.display !== "none" &&
              metric.position !== "absolute",
            `${width} ${path} hidden metadata: ${JSON.stringify(metric)}`,
          );
          if (metric.asn) {
            assert.ok(
              metric.asnWidth > 0 &&
                metric.asnScroll <= metric.asnClient + 1 &&
                metric.asnRight <= metric.lineRight + 1,
              `${width} ${path} clipped ASN: ${JSON.stringify(metric)}`,
            );
            assert.ok(
              !metric.text.includes("California") &&
                !metric.text.includes("Jiangsu"),
              "province must not crowd out the ASN",
            );
          }
        }
        if (width === 1440 && path === "/admin/audit-logs") {
          const line = page
            .locator(
              '.table-scroll .ip-info-details[title="美国 California Mountain View · AS15169 Google LLC"]',
            )
            .first();
          await line.hover();
          const tooltip = page
            .getByRole("tooltip")
            .filter({
              hasText: "美国 California Mountain View · AS15169 Google LLC",
            })
            .first();
          await tooltip.waitFor({ state: "visible" });
          assert.ok(
            (await tooltip.innerText()).includes("California"),
            "full province missing from tooltip",
          );
          await page.mouse.move(0, 0);
        }
      }
      if (path.startsWith("/portal")) {
        assert.ok(await page.locator("footer .ip-attribution").isVisible());
        assert.ok(
          !(await page.locator("main").innerText()).includes(instance.last_ip),
          "portal raw IP exposed",
        );
      }
      if (width < 640 && path !== "/admin/settings") {
        const visible = await page.locator(".ip-info-details:visible").count();
        assert.ok(visible > 0, `${path} mobile metadata hidden`);
      }
      if (
        screenshotDir &&
        [
          "/admin/settings",
          "/admin/audit-logs",
          "/portal/activations",
          "/admin/activations",
        ].includes(path)
      )
        await page.screenshot({
          path: resolve(
            screenshotDir,
            `${width}-${path.replaceAll("/", "-")}.png`,
          ),
          fullPage: true,
        });
      assert.deepEqual(errors, [], `${path} page errors`);
      results.push({ width, path, overflow: false });
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
