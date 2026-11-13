import manifest from "../../../server/internal/webui/routes.json";
import { adminPath } from "./runtime";

export interface UIPage {
  id: string;
  path: string;
  scope: string;
  parent?: string;
  component?: string;
  title?: string;
  redirect?: string;
  mode?: string;
  protected?: boolean;
  resource?: string;
  section?: string;
  userOnly?: boolean;
  portalMenu?: string;
  userMenu?: string;
  userMenuOrder?: number;
}
export const canonicalPages: readonly UIPage[] = manifest;
// Admin route paths are relative to the trusted runtime root, never a fallback.
export function runtimePages(): UIPage[] {
  const base = adminPath();
  return canonicalPages.filter((page) => page.scope !== "admin" || base).map((page) => {
    if (page.scope !== "admin") return { ...page };
    const project = (path: string) => base! + path;
    return { ...page, path: project(page.path), ...(page.redirect ? { redirect: project(page.redirect) } : {}) };
  });
}
