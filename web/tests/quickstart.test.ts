import { describe, expect, it } from "vitest";
import { validityPayload, licenseRequest } from "../src/lib/validity";
import { minimalGoExample } from "../src/lib/sdk-example";
import { licenseFields, specs } from "../src/lib/schema";
describe("简化发码契约", () => {
  it("有效期映射不发送互斥的旧值", () => {
    expect(
      validityPayload({
        validity_rule: "perpetual",
        duration_days: 30,
        expires_at: "old",
      }),
    ).toEqual({ validity_rule: "perpetual" });
    expect(
      validityPayload({ validity_rule: "fixed_days", duration_days: 7 }),
    ).toEqual({ validity_rule: "fixed_days", duration_days: 7 });
    expect(
      validityPayload({ validity_rule: "after_activation", duration_days: 7 }),
    ).toEqual({ validity_rule: "after_activation", duration_days: 7 });
    const date = new Date(Date.now() + 86400000).toISOString();
    expect(
      validityPayload({ validity_rule: "fixed_expiry", expires_at: date }),
    ).toEqual({ validity_rule: "fixed_expiry", expires_at: date });
    expect(() =>
      validityPayload({ validity_rule: "fixed_days", duration_days: 0 }),
    ).toThrow();
    expect(() =>
      validityPayload({ validity_rule: "fixed_expiry", expires_at: "bad" }),
    ).toThrow();
  });
  it("单个和批量使用同一数量入口", () => {
    expect(licenseRequest({ count: 1, app_id: 1 })).toEqual({
      path: "/licenses",
      data: { app_id: 1 },
    });
    expect(licenseRequest({ count: 5, app_id: 1 })).toEqual({
      path: "/licenses/batch",
      data: { app_id: 1, count: 5 },
    });
    expect(() => licenseRequest({ count: 10001 })).toThrow();
  });
  it("软件只显示名称，授权默认运行实例方式", () => {
    expect(
      specs.applications!.fields.filter((f) => !f.advanced).map((f) => f.key),
    ).toEqual(["name"]);
    expect(
      licenseFields.find((f) => f.key === "verify_methods")?.default,
    ).toEqual(["KEY", "FLOATING"]);
  });
  it("页面示例和实际最简程序相同", () => {
    expect(minimalGoExample).toContain("sdk.New(authConfig)");
    expect(minimalGoExample).toContain(
      'client.Check(context.Background(), os.Getenv("AUTHGO_LICENSE"))',
    );
  });
});
