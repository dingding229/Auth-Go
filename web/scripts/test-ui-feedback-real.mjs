import assert from "node:assert/strict";

// Called by the existing fresh-service smoke browser. No API responses are
// mocked: the only interception below simulates a controlled network outage.
export async function exerciseUIFeedback(page, base, path, token, fixture, stage) {
  const api = "/api/v1" + path;
  async function create(endpoint, body) {
    const response = await page.request.post(base + api + endpoint, {
      headers: { Authorization: "Bearer " + token }, data: body,
    });
    assert.equal(response.status(), 200, "real UI fixture creation must succeed");
    return (await response.json()).data;
  }
  const software = await create("/applications", { name: "界面回归软件" });
  const user = await create("/users", { name: "界面回归用户", email: "ui-feedback@example.com", portal_password: fixture.password });
  await create(`/applications/${software.id}/versions`, { version: "1.0.0", changelog: "界面回归版本" });
  async function focusCheck(control, open, dialog) {
    await control.evaluate((element) => element.setAttribute("data-focus-return-check", "current"));
    await control.focus(); await open();
    await dialog.waitFor({ state: "visible" });
    await page.keyboard.press("Escape");
    await dialog.waitFor({ state: "hidden" });
    await page.waitForFunction(() => globalThis.document.activeElement?.getAttribute("data-focus-return-check") === "current");
    const visible = await control.evaluate((element) => {
      const visual = element.closest(".el-switch,.el-checkbox,.el-radio") || element;
      const css = globalThis.getComputedStyle(visual), box = visual.getBoundingClientRect();
      return box.width > 0 && box.height > 0 && css.outlineStyle !== "none" && parseFloat(css.outlineWidth) >= 2;
    });
    assert.equal(visible, true, "restored keyboard focus must have a visible outline");
    await control.evaluate((element) => element.removeAttribute("data-focus-return-check"));
  }
  for (const width of [1440, 375]) {
    stage("batch-result-" + width);
    await page.setViewportSize({ width, height: 1000 });
    await page.goto(base + path + `/licenses?user_id=${user.id}&app_id=${software.id}`);
    const issue = page.locator(".page-heading").getByRole("button", { name: "创建授权", exact: true });
    await issue.evaluate((element) => element.setAttribute("data-focus-return-check", "issue-button"));
    await issue.focus(); await issue.press("Enter");
    const drawer = page.getByRole("dialog", { name: "发放授权", exact: true });
    stage("batch-form-" + width);
    await drawer.waitFor();
    // Use ordinary accessible input actions: stale aria-disabled must fail,
    // never be hidden by force-filling or changing DOM state from the test.
    const quantity = drawer.getByLabel("生成数量", { exact: true });
    await quantity.fill("3"); await quantity.press("Tab");
    stage("batch-create-" + width);
    const created = page.waitForResponse((response) => response.url().endsWith(api + "/licenses/batch") && response.request().method() === "POST");
    await drawer.getByRole("button", { name: "创建授权", exact: true }).click();
    assert.equal((await created).status(), 200);
    stage("batch-display-" + width);
    const result = page.getByRole("dialog", { name: "授权已生成", exact: true });
    await result.waitFor(); await drawer.waitFor({ state: "hidden" });
    stage("batch-stability-" + width);
    const snapshot = await result.getByRole("textbox").inputValue();
    assert.equal(snapshot.split("\n").length, 3);
    // Assert throughout the previously observed 0.9-second disappearing window,
    // rather than merely checking the button on the first rendered frame.
    for (let step = 0; step < 12; step++) {
      assert.equal(await result.getByRole("button", { name: "下载批次CSV", exact: true }).isVisible(), true);
      assert.equal(await result.getByRole("textbox").inputValue(), snapshot);
      await page.waitForTimeout(100);
    }
    stage("batch-download-" + width);
    const downloaded = page.waitForEvent("download");
    await result.getByRole("button", { name: "下载批次CSV", exact: true }).click();
    const download = await downloaded;
    assert.equal(await download.failure(), null);
    const stream = await download.createReadStream();
    const chunks = []; for await (const chunk of stream) chunks.push(chunk);
    const csv = Buffer.concat(chunks).toString("utf8");
    for (const key of snapshot.split("\n")) assert.ok(csv.includes(key));
    await page.keyboard.press("Escape"); await result.waitFor({ state: "hidden" });
    await page.waitForFunction(() => globalThis.document.activeElement?.getAttribute("data-focus-return-check") === "issue-button");
    await issue.evaluate((element) => element.removeAttribute("data-focus-return-check"));
    console.log(`PASS real batch result persists through transitions and downloads all three rows (${width}px)`);

    stage("profile-focus-" + width);
    await page.goto(base + path + "/profile");
    await page.getByLabel("当前登录密码", { exact: true }).fill(fixture.password);
    const setup = page.getByRole("button", { name: "开始绑定认证器", exact: true });
    await focusCheck(setup, () => setup.press("Enter"), page.getByRole("dialog", { name: "绑定认证器", exact: true }));

    stage("version-confirm-focus-" + width);
    await page.goto(base + path + `/applications/${software.id}?tab=versions`);
    const toggle = page.getByRole("switch", { name: "禁用版本1.0.0", exact: true });
    await focusCheck(toggle, () => toggle.press("Space"), page.getByRole("dialog", { name: "版本禁用", exact: true }));
    assert.equal(await toggle.getAttribute("aria-checked"), "false");
    // Confirm and cancel-confirm both preserve the triggering control and the
    // real server version state (no product polling/HTTP retries).
    await toggle.evaluate((element) => element.setAttribute("data-focus-return-check", "version-action"));
    await toggle.press("Space");
    const disable = page.waitForResponse((response) => response.url().includes(api + "/versions/") && response.request().method() === "PATCH");
    await page.getByRole("dialog", { name: "版本禁用", exact: true }).getByRole("button", { name: "禁用版本", exact: true }).click();
    assert.equal((await disable).status(), 200);
    const enable = page.getByRole("switch", { name: "启用版本1.0.0", exact: true });
    await enable.waitFor({ state: "attached" });
    assert.equal(await enable.locator("..").isVisible(), true, "visible switch control must remain on screen");
    assert.equal(await enable.getAttribute("aria-checked"), "true");
    await page.waitForFunction(() => globalThis.document.activeElement?.getAttribute("data-focus-return-check") === "version-action");
    await enable.press("Space");
    const enabled = page.waitForResponse((response) => response.url().includes(api + "/versions/") && response.request().method() === "PATCH");
    await page.getByRole("dialog", { name: "版本禁用", exact: true }).getByRole("button", { name: "启用版本", exact: true }).click();
    assert.equal((await enabled).status(), 200); await toggle.waitFor({ state: "attached" });
    assert.equal(await toggle.locator("..").isVisible(), true);
    assert.equal(await toggle.getAttribute("aria-checked"), "false");
    await page.waitForFunction(() => globalThis.document.activeElement?.getAttribute("data-focus-return-check") === "version-action");
    await toggle.evaluate((element) => element.removeAttribute("data-focus-return-check"));

    stage("drawer-focus-" + width);
    await page.goto(base + path + "/users");
    const newUser = page.getByRole("button", { name: "新建用户", exact: true });
    await focusCheck(newUser, () => newUser.press("Enter"), page.getByRole("dialog", { name: "新建用户", exact: true }));
    console.log(`PASS real async dialog/drawer/confirmation Esc returns visible focus to opener; version disable/enable succeeds (${width}px)`);
  }
  stage("initial-read-failure");
  let failedReads = 0;
  const outage = async (route) => { failedReads++; await route.abort("failed"); };
  await page.route("**" + api + "/users?*", outage);
  await page.goto(base + path + "/users");
  await page.getByRole("button", { name: "重试", exact: true }).waitFor();
  assert.ok(failedReads > 0);
  assert.equal(await page.locator(".table-empty").count(), 0);
  assert.equal(await page.locator(".table-empty").getByText("创建用户").count(), 0);
  await page.unroute("**" + api + "/users?*", outage);
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await page.getByRole("link", { name: "界面回归用户", exact: true }).waitFor();
  await page.route("**" + api + "/users?*", outage);
  await page.getByRole("button", { name: "查询", exact: true }).click();
  await page.getByText(/刷新失败，显示上次成功读取的数据/).waitFor();
  assert.equal(await page.getByRole("link", { name: "界面回归用户", exact: true }).isVisible(), true);
  await page.unroute("**" + api + "/users?*", outage);
  console.log("PASS controlled first-read outage has error/retry only; refresh outage preserves successful rows");
}
