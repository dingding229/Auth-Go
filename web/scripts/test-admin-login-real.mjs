// Exercise the production UI against a freshly initialized real server, never mocks.
// Use the temporary, pinned Playwright tooling container; do not print credentials.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { chromium } from "playwright";
import { exerciseUIFeedback } from "./test-ui-feedback-real.mjs";
const [base, fixtureFile] = process.argv.slice(2);
const fixture = JSON.parse(await readFile(fixtureFile, "utf8"));
let browser, stage = "initialize";
try {
  browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(10000);
  const errors = [];
  page.on("pageerror", () => errors.push("pageerror"));
  await page.goto(base + "/admin/setup?token=" + encodeURIComponent(fixture.token));
  await page.getByLabel("管理员用户名", { exact: true }).fill(fixture.username);
  await page.getByLabel("管理员密码", { exact: true }).fill(fixture.password);
  await page.getByLabel("再次输入密码", { exact: true }).fill(fixture.password);
  const setup = page.waitForResponse((r) => r.url().endsWith("/api/v1/admin/auth/setup") && r.request().method() === "POST");
  await page.getByRole("button", { name: "完成初始化并登录", exact: true }).click();
  assert.equal((await setup).status(), 200, "real initialization must succeed");
  await page.waitForURL(base + "/admin/overview");
  console.log("PASS real browser fresh initialization -> signed in");
  stage = "logout";
  await page.locator(".user-menu").getByRole("button").hover();
  const logout = page.waitForResponse((r) => r.url().endsWith("/api/v1/admin/auth/logout") && r.request().method() === "POST");
  await page.getByText("退出登录", { exact: true }).click();
  assert.equal((await logout).status(), 200, "real logout must succeed");
  await page.waitForURL(base + "/admin/login");
  // Finish the logout destination's initial options read before deliberately
  // reloading it; otherwise waitForResponse can capture that aborted old read.
  await page.waitForFunction(() => {
    const button = globalThis.document.querySelector('button[type="submit"]');
    return !!button && !button.disabled;
  });
  console.log("PASS real browser logout -> /admin/login");
  stage = "login-options";
  // Reload the direct login URL, so neither setup nor an in-memory session can hide a broken path.
  const options = page.waitForResponse((r) => /\/api\/v1\/admin\/(?:auth\/)?status$/.test(r.url()));
  await page.goto(base + "/admin/login");
  const status = await options;
  console.log("LOGIN_OPTIONS " + new URL(status.url()).pathname + " HTTP=" + status.status());
  assert.equal(status.status(), 200, "login options must use a registered API route");
  assert.equal((await status.json()).data.setup_required, false);
  stage = "login";
  await page.getByLabel("用户名", { exact: true }).fill(fixture.username);
  await page.getByLabel("登录密码", { exact: true }).fill(fixture.password);
  const button = page.getByRole("button", { name: "登录控制台", exact: true });
  await page.waitForFunction(() => !globalThis.document.querySelector('button[type="submit"]')?.disabled);
  assert.equal(await button.isEnabled(), true, "login button must become enabled");
  const login = page.waitForResponse((r) => r.url().endsWith("/api/v1/admin/auth/login") && r.request().method() === "POST");
  await button.press("Enter");
  assert.equal((await login).status(), 200, "real admin login must succeed");
  await page.waitForURL(base + "/admin/overview");
  await page.locator(".user-menu").getByRole("button", { name: fixture.username }).waitFor();
  assert.deepEqual(errors, []);
  console.log("PASS real browser initialize -> logout -> direct login page -> admin login; no mocks");
  const consolePath = "/my-console", apiPath = "/api/v1/my-console";
  async function signIn(path) {
    await page.getByLabel("用户名", { exact: true }).fill(fixture.username);
    await page.getByLabel("登录密码", { exact: true }).fill(fixture.password);
    const response = page.waitForResponse((r) => r.url().endsWith("/api/v1" + path + "/auth/login") && r.request().method() === "POST");
    await page.getByRole("button", { name: "登录控制台", exact: true }).press("Enter");
    const result = await response;
    assert.equal(result.status(), 200);
    const token = (await result.json()).data.access_token;
    await page.waitForURL(base + path + "/overview");
    return token;
  }
  async function signOut(path) {
    await page.locator(".user-menu").getByRole("button").hover();
    const response = page.waitForResponse((r) => r.url().endsWith("/api/v1" + path + "/auth/logout") && r.request().method() === "POST");
    await page.getByText("退出登录", { exact: true }).click();
    assert.equal((await response).status(), 200);
    await page.waitForURL(base + path + "/login");
    await page.waitForFunction(() => {
      const button = globalThis.document.querySelector('button[type="submit"]');
      return !!button && !button.disabled;
    });
  }
  stage = "change-management-path";
  await page.goto(base + "/admin/settings");
  await page.getByLabel("后台地址", { exact: true }).fill(consolePath);
  await page.getByRole("button", { name: "保存后台地址并重新登录", exact: true }).click();
  const changed = page.waitForResponse((r) => r.url().endsWith("/api/v1/admin/system/admin-path") && r.request().method() === "PATCH");
  const newOptions = page.waitForResponse((r) => r.url().endsWith(apiPath + "/status"));
  await page.getByRole("dialog").getByRole("button", { name: "更换后台地址并重新登录", exact: true }).click();
  assert.equal((await changed).status(), 200);
  await page.waitForURL(base + consolePath + "/login");
  assert.equal((await newOptions).status(), 200);
  let token = await signIn(consolePath);
  console.log("PASS real settings save -> management page/API changed together -> forced new-address login");

  stage = "old-path-opaque-404";
  for (const method of ["GET", "HEAD", "POST"]) {
    for (const old of ["/admin", "/admin/login", "/admin/setup", "/admin/overview", "/api/v1/admin/status", "/api/v1/admin/auth/login", "/api/v1/admin/system/settings"]) {
      const opts = { method, headers: { Authorization: "Bearer " + token } };
      const oldResponse = await page.request.fetch(base + old, opts);
      const missing = await page.request.fetch(base + "/opaque-missing-route/example", opts);
      assert.equal(oldResponse.status(), 404);
      assert.equal(oldResponse.status(), missing.status());
      assert.equal(await oldResponse.text(), await missing.text());
      assert.deepEqual(oldResponse.headers(), missing.headers());
      assert.equal(oldResponse.headers().location, undefined);
    }
  }
  console.log("PASS retired pages/APIs equal arbitrary missing routes byte-for-byte (GET/HEAD/POST status/body/headers), no redirects");

  stage = "authenticated-management-docs";
  const publicDoc = await page.request.get(base + "/swagger/openapi.json");
  assert.equal(publicDoc.status(), 200);
  const publicRaw = await publicDoc.text();
  assert.ok(!publicRaw.includes("/api/v1/admin") && !publicRaw.includes(apiPath) && !publicRaw.includes("AdminBearer"));
  const deniedDocs = await page.request.get(base + apiPath + "/docs/openapi.json");
  assert.equal(deniedDocs.status(), 401);
  const privateDocResponse = page.waitForResponse((r) => r.url().endsWith(apiPath + "/docs/openapi.json"));
  await page.goto(base + consolePath + "/docs?tab=admin-api");
  const docResponse = await privateDocResponse;
  assert.equal(docResponse.status(), 200);
  const privateDoc = (await docResponse.json()).data;
  assert.ok(privateDoc.paths[apiPath + "/auth/login"]);
  assert.ok(!JSON.stringify(privateDoc).includes("/api/v1/admin/"));
  await page.getByRole("heading", { name: "管理API文档", exact: true }).waitFor();
  await page.getByRole("button", { name: "下载 OpenAPI JSON", exact: true }).waitFor();
  console.log("PASS public Swagger excludes management; logged-in management document entry uses the live prefix");

  stage = "new-address-logout-login";
  await signOut(consolePath);
  const customOptions = page.waitForResponse((r) => r.url().endsWith(apiPath + "/status"));
  await page.goto(base + consolePath + "/login");
  assert.equal((await customOptions).status(), 200);
  token = await signIn(consolePath);
  console.log("PASS new-address logout -> direct new login page -> authenticated login");

  await exerciseUIFeedback(page, base, consolePath, token, fixture, (next) => { stage = next; });

  stage = "live-cli-reset";
  // The host performs one fixed Docker exec after this private file handshake.
  // The browser tooling container never receives the Docker daemon socket.
  const fixtureDir = fixtureFile.slice(0, fixtureFile.lastIndexOf("/"));
  await writeFile(fixtureDir + "/reset-request", "reset\n", { mode: 0o600 });
  const deadline = Date.now() + 10000;
  let receipt;
  while (Date.now() < deadline) {
    try { receipt = JSON.parse(await readFile(fixtureDir + "/reset-done.json", "utf8")); break; }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.deepEqual(receipt, { path: "/admin", same_process: true });
  const stale = await page.request.get(base + "/api/v1/admin/auth/me", { headers: { Authorization: "Bearer " + token } });
  assert.equal(stale.status(), 401);
  const oldCustom = await page.request.get(base + apiPath + "/status");
  const missing = await page.request.get(base + "/opaque-missing-route/example");
  assert.equal(oldCustom.status(), 404);
  assert.equal(await oldCustom.text(), await missing.text());
  assert.deepEqual(oldCustom.headers(), missing.headers());
  const resetOptions = page.waitForResponse((r) => r.url().endsWith("/api/v1/admin/status"));
  await page.goto(base + "/admin/login");
  assert.equal((await resetOptions).status(), 200);
  await signIn("/admin");
  assert.deepEqual(errors, []);
  console.log("PASS container admin-path reset -> same running process -> /admin login restored; previous tokens revoked");

} catch (error) {
  // Only emit callsite/name, never assertion values or Playwright input logs.
  const site = String(error?.stack || "").match(/test(?:-ui-feedback-real)?\.mjs:\d+:\d+/)?.[0] || "no-callsite";
  console.error("FAIL real admin login regression at safe stage: " + stage + " " + error?.name + " " + site);
  process.exitCode = 1;
} finally {
  await browser?.close();
}
