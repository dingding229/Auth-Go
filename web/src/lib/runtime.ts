// Only the server-rendered, non-executable HTML slot may reveal the admin path.
// Public pages intentionally have no slot. Never infer it from URL or storage.
export function adminPath(): string | null {
  const slot = document.getElementById("authgo-runtime");
  if (slot?.tagName !== "SCRIPT" || slot.getAttribute("type") !== "application/json")
    return null;
  try {
    const value: unknown = JSON.parse(slot.textContent ?? "");
    const path = (value as { admin_path?: unknown } | null)?.admin_path;
    return typeof path === "string" && path.length <= 49 &&
      /^\/[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(path) ? path : null;
  } catch {
    return null;
  }
}
export function adminPage(suffix = ""): string {
  const path = adminPath();
  if (!path) throw new Error("缺少有效的后台运行时配置，请重新打开后台地址");
  if (suffix && !suffix.startsWith("/")) throw new Error("后台相对路径无效");
  return path + suffix;
}
export function adminApiPath(suffix = ""): string {
  return "/api/v1" + adminPage(suffix);
}
export function isAdminPage(path: string): boolean {
  const base = adminPath();
  return !!base && (path === base || path.startsWith(base + "/"));
}
