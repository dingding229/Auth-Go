import type { Values } from "./schema";
import type { Row } from "./json";
export function validityPayload(values: Values): Row {
  const rule = String(values.validity_rule || "perpetual");
  if (rule === "fixed_days" || rule === "after_activation") {
    const days = Number(values.duration_days);
    if (!Number.isInteger(days) || days < 1 || days > 36500)
      throw new Error("有效天数必须为1至36500的整数");
    return { validity_rule: rule, duration_days: days };
  }
  if (rule === "fixed_expiry") {
    const time = new Date(String(values.expires_at));
    if (!Number.isFinite(time.getTime()) || time.getTime() <= Date.now())
      throw new Error("请选择未来的到期日期");
    return { validity_rule: rule, expires_at: time.toISOString() };
  }
  if (rule !== "perpetual") throw new Error("有效期选项无效");
  return { validity_rule: rule };
}
export function licenseRequest(body: Row) {
  const { count: raw, ...data } = body;
  const count = Number(raw ?? 1);
  if (!Number.isInteger(count) || count < 1 || count > 10000)
    throw new Error("生成数量必须为1至10000");
  return {
    path: count > 1 ? "/licenses/batch" : "/licenses",
    data: count > 1 ? { ...data, count } : data,
  };
}
