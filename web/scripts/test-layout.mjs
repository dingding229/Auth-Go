// Run against vite preview on the test environment with Playwright provided externally.
// No production API or credentials are used: every API request is intercepted.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";
const dist = fileURLToPath(new URL("../dist/", import.meta.url));
const runtimeHtml = async () => {
  const html = await readFile(resolve(dist, "index.html"), "utf8");
  return html.replace(
    "</head>",
    '<script id="authgo-runtime" type="application/json">{"admin_path":"/admin"}</script></head>',
  );
};
const server = createServer(async (req, res) => {
  const path = resolve(
    dist,
    "." + new URL(req.url, "http://localhost").pathname,
  );
  if (!path.startsWith(dist)) {
    res.writeHead(404).end();
    return;
  }
  try {
    const data = await readFile(path);
    res.setHeader(
      "content-type",
      {
        ".js": "text/javascript",
        ".css": "text/css",
        ".html": "text/html",
        ".woff2": "font/woff2",
      }[extname(path)] || "application/octet-stream",
    );
    res.end(extname(path) === ".html" ? await runtimeHtml() : data);
  } catch {
    res.setHeader("content-type", "text/html");
    res.end(await runtimeHtml());
  }
});
if (!process.env.AUTHGO_LAYOUT_URL)
  await new Promise((resolve) => server.listen(4173, "127.0.0.1", resolve));
const { chromium } = await import(
  process.env.AUTHGO_PLAYWRIGHT || "playwright"
);
const browser = await chromium.launch({
  headless: true,
  args: ["--no-sandbox"],
});
const origin = process.env.AUTHGO_LAYOUT_URL || "http://127.0.0.1:4173";
const key = "ABCDEFGHJKLMNPQR-ABCDE-FGHJK-LMNPQ-RSTUV";
const license = {
  id: 42,
  app_id: 7,
  app_name: "测试软件",
  key,
  status: "active",
  type: "standard",
  verify_methods: ["KEY"],
  validity_rule: "perpetual",
  max_activations: 2,
  active_activations: 3,
  features: {},
  metadata: {},
  user_id: 1,
};
const activations = Array.from({ length: 3 }, (_, i) => ({
  id: i + 1,
  license_id: 42,
  license_key: key,
  hostname: `测试激活${i + 1}`,
  kind: "key",
  value: "a".repeat(64),
  os: "Linux",
  status: "active",
  last_ip: "192.0.2.1",
  last_seen_at: "2026-11-05T00:00:00Z",
}));
const results = [];
try {
  for (const width of [1440, 1024]) {
    const context = await browser.newContext({
      viewport: { width, height: 1000 },
    });
    await context.addInitScript(() => {
      sessionStorage.setItem("authgo.admin.access", "layout-test");
      sessionStorage.setItem("authgo.admin.refresh", "layout-refresh");
      sessionStorage.setItem(
        "authgo.admin.user",
        JSON.stringify({ id: 1, username: "测试管理员" }),
      );
    });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("**/api/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname.replace(
        "/api/v1/admin",
        "",
      );
      let data = { items: [], total: 0 };
      if (path === "/auth/me") data = { id: 1, username: "测试管理员" };
      else if (path === "/integration/protocol")
        data = {
          text:
            '# 协议示例\n\n<img src=x onerror="window.protocolXSS=1">\n\n[不安全](javascript:alert(1))\n\n## 网关\n\n```json\n' +
            JSON.stringify({ ciphertext: "a".repeat(512) }) +
            "\n```",
        };
      else if (path === "/system/settings")
        data = { site_name: "Auth Go", public_url: origin };
      else if (path === "/activations") data = { items: activations, total: 3 };
      else if (path === "/licenses/42") data = license;
      else if (path === "/licenses/42/activations")
        data = { items: activations, total: 3 };
      else if (path === "/licenses") data = { items: [license], total: 1 };
      else if (path === "/applications")
        data = { items: [{ id: 7, name: "测试软件" }], total: 1 };
      else if (path === "/applications/7")
        data = { id: 7, name: "测试软件", allowed_client_versions: "" };
      else if (path === "/users")
        data = { items: [{ id: 1, name: "测试用户" }], total: 1 };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ code: "OK", data }),
      });
    });
    await page.goto(origin + "/admin/activations");
    const cell = page
      .locator(".table-scroll .el-table__body-wrapper tbody tr")
      .first()
      .locator("td")
      .last();
    await cell.getByText("标记下线", { exact: true }).waitFor();
    const metrics = await cell.evaluate((el) => ({
      scroll: el.scrollWidth,
      client: el.clientWidth,
      rowHeight: el.getBoundingClientRect().height,
      right: el.getBoundingClientRect().right,
      fixed: el.classList.contains("el-table-fixed-column--right"),
      buttons: [...el.querySelectorAll("button")].map((b) => ({
        text: b.textContent.trim(),
        scroll: b.scrollWidth,
        client: b.clientWidth,
      })),
    }));
    assert.ok(metrics.scroll <= metrics.client, JSON.stringify(metrics));
    assert.ok(metrics.fixed, JSON.stringify(metrics));
    assert.ok(metrics.right <= width, JSON.stringify(metrics));
    assert.ok(Math.abs(metrics.rowHeight - 44) <= 1, JSON.stringify(metrics));
    for (const button of metrics.buttons)
      assert.ok(button.scroll <= button.client, JSON.stringify(button));
    results.push({ width, device_actions: "PASS", ...metrics });
    await page.goto(origin + "/admin/licenses/42");
    await page.getByRole("tab", { name: "实例", exact: true }).click();
    const body = page.locator(
      "details.activation-section .table-scroll .el-table__body",
    );
    await body.first().waitFor({ state: "visible" });
    assert.equal(
      await page.getByText("还没有运行实例", { exact: true }).count(),
      0,
    );
    if (width === 1440) {
      const fit = await body.first().evaluate((el) => ({
        table: el.getBoundingClientRect().width,
        container: el.closest(".el-table").clientWidth,
      }));
      assert.ok(fit.table <= fit.container + 1, JSON.stringify(fit));
      results.push({ width, activation_table: "PASS", ...fit });
    }
    await page.goto(origin + "/admin/licenses?create=1");
    const numbers = page.locator(
      ".el-drawer .el-input-number .el-input__inner",
    );
    await numbers.first().waitFor({ state: "visible" });
    for (const input of await numbers.all())
      assert.equal(
        await input.evaluate(
          (el) => el.ownerDocument.defaultView.getComputedStyle(el).textAlign,
        ),
        "left",
      );
    results.push({ width, number_align: "left" });
    for (const mobile of [375, 320]) {
      await page.setViewportSize({ width: mobile, height: 1000 });
      await page.goto(origin + "/admin/licenses/42");
      const value = page.locator(".page-heading .copy-field-value");
      await value.waitFor();
      const full = await value.evaluate((el) => ({
        text: el.textContent.trim(),
        overflow:
          el.ownerDocument.defaultView.getComputedStyle(el).textOverflow,
        whiteSpace:
          el.ownerDocument.defaultView.getComputedStyle(el).whiteSpace,
        scroll: el.scrollWidth,
        client: el.clientWidth,
      }));
      assert.equal(full.text, key);
      assert.notEqual(full.overflow, "ellipsis");
      assert.notEqual(full.whiteSpace, "nowrap");
      assert.ok(full.scroll <= full.client, JSON.stringify(full));
      await page
        .locator(".page-heading")
        .getByRole("button", { name: "更多操作" })
        .click();
      const menu = page.locator(".action-menu-popper:visible");
      await menu.waitFor();
      // Wait for Popper's post-render positioning, measuring the visible menu.
      for (let frame = 0; frame < 40; frame++) {
        if (
          (await menu.evaluate((el) => el.getBoundingClientRect().right)) <=
          mobile - 8 + 1
        )
          break;
        await page.waitForTimeout(50);
      }
      const edge = await menu.evaluate(
        (el) => el.getBoundingClientRect().right,
      );
      assert.ok(edge <= mobile - 8 + 1, `menu right edge ${edge}/${mobile}`);
      assert.equal(
        await menu.locator("button").count(),
        0,
        "dropdown items must be plain menu rows",
      );
      await menu.getByText("吊销授权", { exact: true }).click();
      await page.getByPlaceholder("输入 RSTUV").waitFor();
      assert.equal(
        await page.locator(".el-message-box__title").innerText(),
        "吊销授权",
      );
      const gap = await page.locator(".el-message-box__btns").evaluate((el) => {
        const [cancel, confirm] = el.querySelectorAll("button");
        return (
          confirm.getBoundingClientRect().left -
          cancel.getBoundingClientRect().right
        );
      });
      assert.ok(Math.abs(gap - 8) <= 1, `confirm button gap ${gap}`);
      await page
        .locator(".el-message-box")
        .getByRole("button", { name: "取消", exact: true })
        .click();
      results.push({ width: mobile, complete_license_title: "PASS", ...full });
    }
    for (const docsWidth of [1440, 1024, 375, 320]) {
      await page.setViewportSize({ width: docsWidth, height: 1000 });
      await page.goto(origin + "/admin/docs?tab=protocol");
      await page.locator(".protocol-markdown h2").waitFor();
      assert.equal(await page.locator(".protocol-markdown img").count(), 0);
      assert.equal(
        await page.locator('.protocol-markdown a[href^="javascript:"]').count(),
        0,
      );
      assert.equal(
        await page.evaluate(() => globalThis.protocolXSS),
        undefined,
      );
      const size = await page.evaluate(() => ({
        scroll: globalThis.document.documentElement.scrollWidth,
        width: globalThis.innerWidth,
      }));
      assert.ok(
        size.scroll <= size.width,
        `docs page overflow at ${docsWidth}: ${JSON.stringify(size)}`,
      );
      await page.getByRole("tab", { name: "SDK示例", exact: true }).click();
      await page.waitForURL("**/admin/docs?tab=sdk");
      await page.getByText("其他语言", { exact: true }).click();
      await page.getByRole("link", { name: "阅读接入协议与实现清单" }).click();
      await page.waitForURL("**/admin/docs?tab=protocol");
      await page.locator(".protocol-markdown h2").waitFor();
      await page.waitForTimeout(250);
      assert.equal(await page.locator("h1").count(), 1);
      if (process.env.AUTHGO_SCREENSHOT_DIR)
        await page.screenshot({
          path: `${process.env.AUTHGO_SCREENSHOT_DIR}/docs-${docsWidth}.png`,
          fullPage: true,
        });
      results.push({
        width: docsWidth,
        docs_markdown_and_tabs: "PASS",
        ...size,
      });
    }
    assert.deepEqual(errors, []);
    await context.close();
  }
  console.log(JSON.stringify({ layout: "PASS", results }, null, 2));
} finally {
  await browser.close();
  if (server.listening) await new Promise((resolve) => server.close(resolve));
}
