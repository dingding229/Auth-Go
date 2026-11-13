import { idText, type Row } from "./json";
// Presentation-only grouping: never changes the activation objects or API state.
export function deviceRows(rows: Row[]): Row[] {
  const groups = new Map<string, Row>();
  for (const row of rows) {
    if (row.kind === "key") continue;
    const key = [row.kind, row.instance_id || row.id].join(":");
    const previous = groups.get(key);
    if (previous) {
      previous.license_key = [
        ...new Set(
          [
            ...String(previous.license_key || "").split("、"),
            idText(row.license_key),
          ].filter(Boolean),
        ),
      ].join("、");
    } else groups.set(key, { ...row });
  }
  return [...groups.values()];
}

// KEY-only activations do not consume a binding quota. Floating still has a seat quota.
export function keyOnly(license: Row): boolean {
  return (
    Array.isArray(license.verify_methods) &&
    license.verify_methods.length > 0 &&
    license.verify_methods.every((v) => v === "KEY")
  );
}
export function activationQuota(license: Row, detail = false): string {
  return keyOnly(license)
    ? detail
      ? "不限（仅授权码）"
      : "不限"
    : String(license.max_activations ?? "—");
}
export function deviceUsage(license: Row): string {
  return `${license.active_activations ?? 0}/${activationQuota(license)}`;
}
export function effectiveDays(license: Row): string {
  return license.validity_rule === "perpetual"
    ? "—"
    : String(license.duration_days || "—");
}
export function keyTail(value: unknown): string {
  const key = String(value ?? "");
  return key ? key.split("-").at(-1)! : "—";
}

// Online is a live floating lease, never merely an active historical binding.
export function instanceOnline(row: Row, now = Date.now()): boolean {
  return (
    row.kind === "floating" &&
    row.status === "active" &&
    !row.offline_at &&
    Number.isFinite(Date.parse(String(row.lease_expires_at || ""))) &&
    Date.parse(String(row.lease_expires_at)) > now
  );
}
export function instanceUsage(row: Row): string {
  return `${row.online_instances ?? 0}/${activationQuota(row)}`;
}
