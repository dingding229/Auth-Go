/* global document, requestAnimationFrame, innerWidth */
// Production build browser QA with synthetic summary records; no real IP database downloads.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
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
const results = [];
const license = {
  id: 42,
  app_id: 7,
  app_name: "SharingDetectionEnterpriseApplication 企业容器软件",
  key: "AUTH-TESTA-TESTB-TESTC-TESTD",
  type: "standard",
  status: "active",
  verify_methods: ["KEY", "FLOATING"],
  max_activations: 3,
  online_instances: 1,
  remaining_unbinds: 2,
  features: {},
  metadata: {},
  suspected_sharing: true,
};
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
    });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    let count = 1,
      ignored = 0;
    let summary = {
      available: true,
      flagged: true,
      ignored: false,
      ignored_until: null,
      instance_count: 8,
      updated_at: "2026-11-07T00:00:00Z",
      last_seen_at: "2026-11-07T00:00:00Z",
      countries: ["CN", "US", "JP", "FR"].map((code) => ({ code, count: 2 })),
      asns: Array.from({ length: 6 }, (_, i) => ({
        asn: 4134 + i,
        org: "SyntheticEnterpriseNetworkOrganization Telecom",
        count: i === 0 ? 3 : 1,
      })),
    };
    await page.route("**/api/v1/**", async (route) => {
      const url = new URL(route.request().url()),
        path = url.pathname.replace(/^\/api\/v1\/admin/, "");
      let data = { items: [], total: 0 };
      if (path === "/auth/me") data = { id: 1, username: "管理员" };
      else if (path === "/stats/overview")
        data = {
          counts: {
            users_total: 1,
            applications_total: 1,
            licenses_total: 1,
            suspected_sharing: count,
          },
          expiring: [],
        };
      else if (path === "/trials/stats")
        data = { trial_count: 0, converted_count: 0 };
      else if (path === "/licenses") {
        if (url.searchParams.has("suspected_sharing"))
          assert.equal(url.searchParams.get("suspected_sharing"), "true");
        data = { items: [license], total: 1 };
      } else if (path === "/licenses/42") data = license;
      else if (path === "/licenses/42/sharing") data = summary;
      else if (path === "/licenses/42/sharing/ignore") {
        assert.equal(route.request().method(), "POST");
        ignored++;
        summary = {
          ...summary,
          flagged: false,
          ignored: true,
          ignored_until: "2026-12-07T00:00:00Z",
        };
        data = summary;
      } else if (path === "/applications")
        data = { items: [{ id: 7, name: license.app_name }], total: 1 };
      else if (path === "/users")
        data = { items: [{ id: 1, name: "用户" }], total: 1 };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ code: "OK", data }),
      });
    });
    async function check(label) {
      await page.evaluate(() => document.fonts.ready);
      await page.evaluate(
        () =>
          new Promise((done) =>
            requestAnimationFrame(() => requestAnimationFrame(done)),
          ),
      );
      const m = await page.evaluate(() => ({
        scroll: document.documentElement.scrollWidth,
        width: innerWidth,
      }));
      assert.ok(
        m.scroll <= m.width,
        `${width} ${label} overflow ${JSON.stringify(m)}`,
      );
      assert.deepEqual(errors, []);
      results.push({ width, page: label, overflow: false });
    }
    await page.goto(origin + "/admin/overview");
    await page.locator(".sharing-overview a").waitFor();
    assert.equal(
      await page.locator(".sharing-overview a").getAttribute("href"),
      "/admin/licenses?suspected_sharing=true",
    );
    await check("overview");
    count = 0;
    await page.goto(origin + "/admin/overview");
    await page
      .getByRole("heading", { name: "自助试用", exact: true })
      .waitFor();
    await page.getByText("名下授权", { exact: false }).count();
    await page.waitForFunction(
      () => !document.querySelector(".stat-number-skeleton"),
    );
    assert.equal(await page.locator(".sharing-overview").count(), 0);
    await check("overview-zero");
    count = 1;
    await page.goto(origin + "/admin/licenses?suspected_sharing=true");
    const marker = page.locator(
      width === 1440
        ? ".table-scroll .el-table__body .sharing-mark"
        : ".table-cards .sharing-mark",
    );
    await marker.waitFor({ state: "visible" });
    assert.ok(
      (await page.locator(".advanced-filters").innerText()).includes(
        "疑似共享",
      ),
    );
    await check("license-filter-and-marker");
    await page.goto(origin + "/admin/licenses/42");
    await page.locator(".sharing-panel .data-table").first().waitFor();
    assert.ok(
      (await page.locator(".sharing-panel").innerText()).includes(
        "AS4134 SyntheticEnterpriseNetworkOrganization",
      ),
    );
    assert.ok(
      (await page.locator(".sharing-panel").innerText()).includes(
        "不会影响授权",
      ),
    );
    await check("sharing-flagged");
    await page
      .getByRole("button", { name: "忽略此次提示", exact: true })
      .click();
    await page.getByRole("button", { name: "取消", exact: true }).click();
    assert.equal(ignored, 0);
    await page
      .getByRole("button", { name: "忽略此次提示", exact: true })
      .click();
    await page.getByRole("button", { name: "继续操作", exact: true }).click();
    await page.getByText("已忽略至", { exact: false }).waitFor();
    assert.equal(ignored, 1);
    await check("sharing-ignored");
    summary = { ...summary, available: false };
    await page.goto(origin + "/admin/licenses/42");
    await page
      .getByText("需要先在系统设置启用 IP 库。", { exact: false })
      .waitFor();
    assert.equal(
      await page.locator(".sharing-panel a").getAttribute("href"),
      "/admin/settings",
    );
    assert.equal(await page.locator(".sharing-panel .data-table").count(), 0);
    await check("sharing-disabled");
    summary = {
      ...summary,
      available: true,
      flagged: false,
      ignored: false,
      instance_count: 0,
      countries: [],
      asns: [],
    };
    await page.goto(origin + "/admin/licenses/42");
    await page.getByText("最近 24 小时未发现异常", { exact: true }).waitFor();
    await check("sharing-clear");
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
