import "./admin-bootstrap";
import { expect, it } from "vitest";
it("所有页面和公共组件均可编译加载，避免只通过类型检查却无法生产构建", async () => {
  const modules = import.meta.glob("../src/**/*.vue");
  expect(Object.keys(modules).length).toBeGreaterThan(25);
  for (const load of Object.values(modules))
    expect(await load()).toHaveProperty("default");
});
