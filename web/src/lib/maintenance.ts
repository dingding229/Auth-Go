import { dateText } from "./json";
export function maintenanceText(value: unknown, now = Date.now()): string {
  if (!value) return "不限";
  const date = new Date(String(value));
  return `${dateText(value)}${date.getTime() < now ? "（维护期已到期）" : ""}`;
}
export function renewalMaintenance(change: boolean, days: number) {
  if (!change) return {};
  if (!Number.isInteger(days) || days < 0 || days > 36500)
    throw new Error("维护天数必须为0至36500，0表示不限");
  return { maintenance_days: days };
}
