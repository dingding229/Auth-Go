// Run in the temporary Playwright tool container against an isolated real server.
// Credentials and license keys are never printed or captured in screenshots.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { chromium } from "playwright";
const [base, credentialsFile] = process.argv.slice(2);
const credentials = JSON.parse(await readFile(credentialsFile, "utf8"));
let stage = "seed",
  browser;
try {
  async function api(path, body, token) {
    const response = await fetch(base + "/api/v1/admin" + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: "Bearer " + token } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    assert.equal(response.status, 200, "fixture API status");
    const value = await response.json();
    assert.equal(value.code, "OK");
    return value.data;
  }
  const token = (await api("/auth/login", credentials)).access_token;
  await api("/applications", { name: "Keyboard regression" }, token);
  const exact = await api("/users", { name: "张三" }, token);
  await api("/users", { name: "张三丰" }, token);
  browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
  });
  const errors = [];
  page.on("pageerror", () => errors.push("pageerror"));
  stage = "login";
  await page.goto(base + "/admin/login");
  await page.getByLabel("用户名", { exact: true }).fill(credentials.username);
  await page.getByLabel("登录密码", { exact: true }).fill(credentials.password);
  await page
    .getByRole("button", { name: "登录控制台", exact: true })
    .press("Enter");
  await page.waitForURL(
    (url) =>
      url.pathname.startsWith("/admin") && url.pathname !== "/admin/login",
  );
  await page.goto(base + "/admin/licenses");
  async function tabTo(target) {
    for (let i = 0; i < 35; i++) {
      if (
        await target.evaluate((el) => el === globalThis.document.activeElement)
      )
        return;
      await page.keyboard.press("Tab");
    }
    throw new Error("keyboard focus did not reach target");
  }
  for (const mode of ["exact", "down", "up"]) {
    stage = "open-" + mode;
    await page
      .locator(".page-heading")
      .getByRole("button", { name: "创建授权", exact: true })
      .press("Enter");
    const drawer = page.locator(".el-drawer:visible");
    const input = drawer.locator('[data-field="user_id"] input');
    await input.waitFor();
    await tabTo(input);
    stage = "select-" + mode;
    const suggestions = page.waitForResponse(
      (response) =>
        response.request().method() === "GET" &&
        response.url().includes("/api/v1/admin/users?") &&
        new URL(response.url()).searchParams.get("q") ===
          (mode === "exact" ? "张三" : "张"),
    );
    await page.keyboard.type(mode === "exact" ? "张三" : "张");
    await suggestions;
    await page.waitForFunction(() => {
      const input = globalThis.document.querySelector(
        '.el-drawer [data-field="user_id"] input',
      );
      return (
        input?.closest(".el-select")?.getAttribute("aria-busy") === "false" &&
        input?.getAttribute("aria-expanded") === "true" &&
        !!input.getAttribute("aria-activedescendant")
      );
    });
    let expected = String(exact.id);
    if (mode !== "exact") {
      const highlighted = () =>
        input.evaluate(
          (el) =>
            globalThis.document.getElementById(
              el.getAttribute("aria-activedescendant"),
            )?.dataset.resourceId,
        );
      const first = await highlighted();
      await page.keyboard.press("ArrowDown");
      const second = await highlighted();
      assert.ok(
        first && second && first !== second,
        "native ArrowDown did not change candidate",
      );
      if (mode === "up") {
        await page.keyboard.press("ArrowUp");
        assert.equal(
          await highlighted(),
          first,
          "native ArrowUp did not restore candidate",
        );
      }
      expected = await highlighted();
      assert.ok(expected, "native arrow did not highlight a candidate");
    }
    await page.keyboard.press("Enter");
    const submit = drawer.getByRole("button", {
      name: "创建授权",
      exact: true,
    });
    stage = "tab-submit-" + mode;
    await tabTo(submit);
    const issued = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        new URL(response.url()).pathname === "/api/v1/admin/licenses",
    );
    await page.keyboard.press("Enter");
    const response = await issued;
    assert.equal(response.status(), 200);
    const body = await response.json();
    assert.equal(body.code, "OK");
    assert.equal(String(body.data.user_id), expected);
    await page.getByRole("dialog", { name: "授权已生成" }).waitFor();
    await page.keyboard.press("Escape");
    await page
      .getByRole("dialog", { name: "授权已生成" })
      .waitFor({ state: "hidden" });
    console.log(
      "PASS real browser keyboard issuance: " +
        mode +
        " -> Enter, native Tab, Enter",
    );
  }
  assert.deepEqual(errors, []);
  console.log(
    "PASS real HTTP + production UI + Chromium keyboard; no page errors (secrets redacted)",
  );
} catch {
  console.error(
    "FAIL real browser keyboard regression at safe stage: " + stage,
  );
  process.exitCode = 1;
} finally {
  await browser?.close();
}
