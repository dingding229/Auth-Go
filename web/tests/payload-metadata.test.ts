import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { versionSpec } from "../src/lib/schema";
it("手动版本创建编辑可登记加密与构建时间，系统设置有镜像与版本入口", () => {
  const fields = versionSpec.fields.map((f) => f.key);
  expect(fields).toContain("encrypted");
  expect(fields).toContain("built_at");
  const view = readFileSync("src/views/admin/SettingsView.vue", "utf8");
  expect(view).toContain("tools_image");
  expect(view).toContain("tools_version");
  const versions = readFileSync("src/components/VersionManagement.vue", "utf8");
  expect(versions).toContain("保存构建元数据");
  expect(versions).toContain("built_at");
  expect(versions).toContain("不是信任源");
});
