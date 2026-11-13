import { reactive } from "vue";
import { parseJSON, record, stringify } from "./json";

function stored(key: string): string {
  try {
    return sessionStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}
const user = (() => {
  try {
    return record(parseJSON(stored("authgo.admin.user") || "{}"));
  } catch {
    return {};
  }
})();
export const adminSession = reactive({
  access: stored("authgo.admin.access"),
  refresh: stored("authgo.admin.refresh"),
  user,
  generation: 0,
});
export const portalSession = reactive({
  token: stored("authgo.portal.token"),
  ipInfoDBIP: false,
  supportContact: "",
  license: {} as ReturnType<typeof record>,
  user: {} as ReturnType<typeof record>,
  scope: "license" as "license" | "user",
});
function save(key: string, value: string) {
  try {
    if (value) sessionStorage.setItem(key, value);
    else sessionStorage.removeItem(key);
  } catch {
    /* Current session can still operate in memory. */
  }
}
export function setAdmin(access: string, refresh: string, data?: unknown) {
  adminSession.access = access;
  adminSession.refresh = refresh;
  save("authgo.admin.access", access);
  save("authgo.admin.refresh", refresh);
  if (data) {
    adminSession.user = record(data);
    save("authgo.admin.user", stringify(data));
  }
}
export function clearAdmin() {
  adminSession.generation++;
  setAdmin("", "");
  adminSession.user = {};
  save("authgo.admin.user", "");
}
export function setPortal(
  token: string,
  scope: "user" | "license" = "license",
) {
  portalSession.scope = scope;
  portalSession.ipInfoDBIP = false;
  portalSession.supportContact = "";
  portalSession.license = {};
  portalSession.user = {};
  portalSession.token = token;
  save("authgo.portal.token", token);
}
export function clearPortal() {
  setPortal("");
  portalSession.license = {};
}

// Selecting an owned license is not a new login: retain account and footer metadata.
export function selectUserPortal(token: string, license: unknown) {
  portalSession.scope = "user";
  portalSession.token = token;
  portalSession.license = record(license);
  save("authgo.portal.token", token);
}
