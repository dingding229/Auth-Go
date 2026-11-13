import { adminPage } from "./runtime";
// A create intent is consumed by the destination, not forwarded as an API filter.
export function issueLicenseLocation(appId?: string, userId?: string) {
  return {
    path: adminPage("/licenses"),
    query: {
      create: "1",
      ...(appId ? { app_id: appId } : {}),
      ...(userId ? { user_id: userId } : {}),
    },
  };
}
export function integrationLocation(appId: string) {
  return {
    path: adminPage(`/applications/${encodeURIComponent(appId)}`),
    query: { tab: "integration" },
  };
}
