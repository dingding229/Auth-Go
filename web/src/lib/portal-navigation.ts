import { canonicalPages } from "./ui-routes";
export const portalPages = canonicalPages.filter((page) => page.portalMenu).map((page) => ({ path: page.path, title: page.portalMenu! }));
export const userPortalPages = canonicalPages.filter((page) => page.userMenu).sort((a, b) => a.userMenuOrder! - b.userMenuOrder!).map((page) => ({ path: page.path, title: page.userMenu! }));
