import { api, get, patch, post, fetchAll } from "./http";
import type { Row } from "./json";
// Large database transfers have a route-local timeout; other APIs keep their normal deadline.
export const ipDatabaseTimeout = 4 * 60 * 1000;
export interface IpDatabaseFile {
  source: string;
  database_type: string;
  data_date: string;
  size: number;
  updated_at: string;
}
export interface IpSyncPlan {
  enabled: boolean;
  cron: string;
}
export interface IpSyncSchedule extends IpSyncPlan {
  running?: boolean;
  last_sync_at?: string;
  last_result: string;
  next_run_at?: string;
  failures: number;
}
export const saveIpSyncPlan = (plan: IpSyncPlan) =>
  patch<IpDatabaseStatus>("/system/ip-info/schedule", plan);
export interface IpDatabaseStatus {
  schedule?: IpSyncSchedule;
  enabled: boolean;
  city?: IpDatabaseFile;
  asn?: IpDatabaseFile;
  updated_at?: string;
  last_error: string;
  attribution?: string;
  attribution_url?: string;
}
export const ipDatabaseStatus = () => get<IpDatabaseStatus>("/system/ip-info");
export const ipDatabaseAction = (action: "enable" | "update" | "delete") =>
  api<IpDatabaseStatus>(
    "admin",
    `/system/ip-info${action === "delete" ? "" : `/${action}`}`,
    {
      method: action === "delete" ? "DELETE" : "POST",
      timeout: ipDatabaseTimeout,
    },
  );
export const uploadIpDatabase = (
  kind: "city" | "asn",
  file: File,
  progress: (percent: number) => void,
) => {
  const body = new FormData();
  body.append("file", file);
  return api<IpDatabaseStatus>("admin", `/system/ip-info/${kind}`, {
    method: "POST",
    data: body,
    timeout: ipDatabaseTimeout,
    onUploadProgress: (event) => {
      if (event.total) progress(Math.round((event.loaded / event.total) * 100));
    },
  });
};

export const userLicenseDetail = (id: string, signal?: AbortSignal) =>
  api<Row>("portal", `/licenses/${encodeURIComponent(id)}`, {
    signal,
    quiet: true,
  });
export const selectUserLicense = (id: string, signal?: AbortSignal) =>
  api<Row>("portal", "/switch", {
    method: "POST",
    data: { license_id: BigInt(id) },
    signal,
    quiet: true,
  });
export const supportSettings = () =>
  get<{ support_contact: string }>("/system/support");
export const saveSupportSettings = (support_contact: string) =>
  patch<{ support_contact: string }>("/system/support", { support_contact });
// This is paginated metadata collection, never one request per software/license.
export async function portalSoftwareOptions(signal?: AbortSignal) {
  return fetchAll("portal", "/user/updates", {}, signal);
}

export const licenseSharing = (id: string, signal?: AbortSignal) =>
  get<Row>(`/licenses/${encodeURIComponent(id)}/sharing`, undefined, {
    signal,
  });
export const ignoreLicenseSharing = (id: string) =>
  post<Row>(`/licenses/${encodeURIComponent(id)}/sharing/ignore`, {});
