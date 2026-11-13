import { expect, it } from "vitest";
import { sdkExamples, sdkLanguages } from "../src/lib/sdk-examples";
import { readFileSync } from "node:fs";
it("接入语言覆盖七种官方SDK，示例在源码固定配置，安装仅指向本仓库", () => {
  expect(sdkLanguages).toEqual([
    "Go",
    "Python",
    "Node.js",
    "Java",
    "C#",
    "PHP",
    "Rust",
    "其他语言",
  ]);
  for (const sample of Object.values(sdkExamples)) {
    expect(sample.code).toContain("authgo2.");
    expect(sample.code).not.toContain("AUTHGO_CONFIG");
    expect(sample.code).toContain("AUTHGO_LICENSE");
    expect(sample.install).toContain("本仓库");
  }
  const component = readFileSync("src/components/SDKExamples.vue", "utf8");
  expect(component).toContain('aria-label="SDK语言"');
  expect(component).toContain("adminPage('/docs?tab=protocol')");
  expect(component).not.toContain("v-html");
});
