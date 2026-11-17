import type { Row } from "./json";
import { confirmAction } from "../composables/tasks";

export function canDeleteLicense(row: Row): boolean {
  return (
    row.status === "revoked" &&
    row.type !== "trial" &&
    row.source !== "self_trial"
  );
}
export function confirmLicenseDeletion(row: Row) {
  return confirmAction(
    `将永久删除授权 ${String(row.key)} 及其激活记录，验证日志保留。此操作无法恢复。`,
    "删除授权",
    { action: "删除授权", danger: true },
  );
}
