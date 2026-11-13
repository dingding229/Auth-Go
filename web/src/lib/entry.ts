import { adminPath, adminPage, isAdminPage } from "./runtime";
import { adminSession, portalSession } from "./session";

// Error pages retain their original scope; absent context prefers the only
// active session rather than always sending portal users to the admin login.
export function entryPath(context: unknown = ""): string {
  const path = typeof context === "string" ? context : "";
  const portal =
    !adminPath() ||
    path.startsWith("/portal/") ||
    (!isAdminPage(path) &&
      !!portalSession.token &&
      !adminSession.access);
  if (portal)
    return portalSession.token
      ? portalSession.scope === "user"
        ? "/portal/home"
        : "/portal/license"
      : "/portal/login";
  return adminSession.access ? adminPage("/overview") : adminPage("/login");
}
