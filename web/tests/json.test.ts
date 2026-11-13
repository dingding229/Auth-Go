import { expect, it } from "vitest";
import { parseJSON, record, stringify } from "../src/lib/json";
it.each([
  "0.10714285714285714",
  "1.7976931348623157e308",
  "-1.5e-7",
  "1.0",
  "0.25",
  "9007199254740993.0",
  "1e20",
])("小数和指数%s始终是Number", (raw) => {
  expect(parseJSON(raw)).toBe(Number(raw));
  expect(typeof parseJSON(raw)).toBe("number");
});
it.each(["12345678901234567890", "9007199254740993", "-9007199254740993"])(
  "大整数%s精确往返",
  (raw) => {
    expect(parseJSON(raw)).toBe(BigInt(raw));
    expect(stringify(parseJSON(raw))).toBe(raw);
    expect(record(parseJSON(`{"id":${raw}}`)).id).toBe(BigInt(raw));
  },
);
it("任意键名保留为数据且不污染原型", () => {
  const raw =
    '{"__proto__":{"polluted":true},"constructor":{"prototype":{"bad":1}},"nested":[{"__proto__":2}]}';
  const value = record(parseJSON(raw));
  expect(Object.getPrototypeOf(value)).toBeNull();
  expect(Object.hasOwn(value, "__proto__")).toBe(true);
  expect(record(value.__proto__).polluted).toBe(true);
  expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  expect(stringify(value)).toBe(raw);
});
it.each([
  "01",
  "1.",
  "1e",
  "[1,]",
  '{"a":1,"a":2}',
  "true false",
  '"\\x"',
  '{"x":1,}',
  "",
  "+1",
])("拒绝非法JSON%s", (raw) =>
  expect(() => parseJSON(raw)).toThrow(SyntaxError),
);
