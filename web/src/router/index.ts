import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";
import { useAuth } from "../stores/auth";
import { ElMessage } from "element-plus";
import { APIError, api } from "../lib/http";
import { portalSession } from "../lib/session";
import { adminPath, adminPage } from "../lib/runtime";
import { runtimePages, type UIPage } from "../lib/ui-routes";
export { portalPages, userPortalPages } from "../lib/portal-navigation";
const pages = runtimePages();
export const adminPages = pages.filter((page) => page.scope === "admin" && page.section);
const components: Record<string, () => Promise<unknown>> = {
  setup: () => import("../views/SetupView.vue"),
  login: () => import("../views/LoginView.vue"),
  "admin-layout": () => import("../layouts/AdminLayout.vue"),
  "portal-layout": () => import("../layouts/PortalLayout.vue"),
  dashboard: () => import("../views/admin/DashboardView.vue"),
  crud: () => import("../views/admin/CrudView.vue"),
  licenses: () => import("../views/admin/LicensesView.vue"),
  activations: () => import("../views/admin/ActivationsView.vue"),
  "integration-docs": () => import("../views/admin/IntegrationDocsView.vue"),
  observations: () => import("../views/admin/ObservationsView.vue"),
  settings: () => import("../views/admin/SettingsView.vue"),
  profile: () => import("../views/admin/ProfileView.vue"),
  "user-detail": () => import("../views/admin/UserDetailView.vue"),
  "application-detail": () => import("../views/admin/ApplicationDetailView.vue"),
  "license-detail": () => import("../views/admin/LicenseDetailView.vue"),
  "user-center": () => import("../views/portal/UserCenterView.vue"),
  portal: () => import("../views/portal/PortalView.vue"),
  "portal-activity": () => import("../views/portal/PortalActivityView.vue"),
  "portal-licenses": () => import("../views/portal/PortalLicensesView.vue"),
  "portal-instances": () => import("../views/portal/PortalInstancesView.vue"),
  "portal-account": () => import("../views/portal/PortalAccountView.vue"),
  "portal-license-detail": () => import("../views/portal/PortalLicenseDetailView.vue"),
  forbidden: () => import("../views/ForbiddenView.vue"),
  unavailable: () => import("../views/UnavailableView.vue"),
  "not-found": () => import("../views/NotFoundView.vue"),
};
function routeFor(page: UIPage): RouteRecordRaw {
  const children = pages.filter((child) => child.parent === page.id).map(routeFor);
  if (page.component && !components[page.component]) throw new Error(`Unknown UI component: ${page.component}`);
  return {
    path: page.path,
    ...(page.component ? { component: components[page.component] } : {}),
    ...(page.redirect ? { redirect: page.redirect } : {}),
    ...(page.mode ? { props: { mode: page.mode } } : {}),
    meta: {
      title: page.title,
      resource: page.resource,
      userOnly: page.userOnly,
      ...(page.protected ? { scope: page.scope === "admin" ? "admin" : "portal" } : {}),
    },
    ...(children.length ? { children } : {}),
  } as RouteRecordRaw;
}
const router = createRouter({
  history: createWebHistory(),
  routes: pages.filter((page) => !page.parent).map(routeFor),
});
let checkedPortalToken = "",
  portalCheckedAt = 0;
router.beforeEach(async (to, from) => {
  if (!to.matched.length) return "/not-found";
  const auth = useAuth();
  // SetupView owns the public availability check: it first removes the
  // one-time capability from the URL and can retry a transient network failure
  // without bouncing through /unavailable?next=<capability>.
  if (to.params.id && !/^[1-9]\d*$/.test(String(to.params.id)))
    return "/not-found";
  if (to.meta.scope === "admin") {
    if (!auth.admin.access && !auth.admin.refresh)
      return { path: adminPage("/login"), query: { next: to.fullPath } };
    try {
      await auth.me();
    } catch (error) {
      if (
        (error instanceof APIError && error.status === 401) ||
        !auth.admin.access
      )
        return { path: adminPage("/login"), query: { next: to.fullPath } };
      ElMessage.error("无法确认当前权限，请稍后重试");
      return from.matched.length
        ? false
        : { path: "/unavailable", query: { next: to.fullPath } };
    }
  }
  if (to.meta.scope === "portal") {
    if (!auth.portal.token)
      return { path: "/portal/login", query: { next: to.fullPath } };
    if (
      checkedPortalToken !== auth.portal.token ||
      Date.now() - portalCheckedAt > 30000
    ) {
      try {
        const token = auth.portal.token;
        const session = await api("portal", "/session", { quiet: true });
        const scope = session.scope === "user" ? "user" : "license";
        const profile =
          scope === "user" ? await api("portal", "/user", { quiet: true }) : {};
        const selected =
          scope === "license" && session.selected_license_id
            ? await api("portal", "/license", { quiet: true })
            : null;
        if (auth.portal.token !== token) return false;
        portalSession.ipInfoDBIP = session.ip_info_dbip === true;
        portalSession.supportContact =
          typeof session.support_contact === "string"
            ? session.support_contact
            : "";
        portalSession.scope = scope;
        portalSession.user = profile;
        portalSession.license =
          scope === "license"
            ? selected || {}
            : session.selected_license_id
              ? String(portalSession.license.id) ===
                String(session.selected_license_id)
                ? portalSession.license
                : { id: session.selected_license_id }
              : {};
        checkedPortalToken = token;
        portalCheckedAt = Date.now();
      } catch (error) {
        if (
          (error instanceof APIError && error.status === 401) ||
          !auth.portal.token
        )
          return { path: "/portal/login", query: { next: to.fullPath } };
        ElMessage.error("暂时无法加载授权，请稍后重试");
        return from.matched.length
          ? false
          : { path: "/unavailable", query: { next: to.fullPath } };
      }
    }
    if (portalSession.scope === "license" && (to.meta.userOnly || to.path === "/portal/home"))
      return "/portal/license";
    if (
      portalSession.scope === "license" &&
      to.path === "/portal/announcements" &&
      !auth.portal.license.has_announcements
    )
      return "/portal/license";
  }
});
router.afterEach((to) => {
  document.title = `${String(to.meta.title ?? "页面不存在")} · Auth Go`;
});
window.addEventListener("authgo:expired", (event) => {
  const scope = (event as CustomEvent<string>).detail;
  const base = scope === "admin" ? adminPath() : scope === "portal" ? "/portal" : null;
  if (
    base &&
    router.currentRoute.value.path.startsWith(base + "/") &&
    !router.currentRoute.value.path.endsWith("/login")
  )
    void router.replace({
      path: `${base}/login`,
      query: { next: router.currentRoute.value.fullPath },
    });
});
export default router;
