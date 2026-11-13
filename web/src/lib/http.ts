import { adminApiPath, adminPath } from "./runtime";
import axios, {
  AxiosHeaders,
  type AxiosRequestConfig,
  type AxiosResponse,
} from "axios";
import { ElMessage } from "element-plus";
import {
  adminSession,
  clearAdmin,
  clearPortal,
  portalSession,
  setAdmin,
} from "./session";
import {
  cleanParams,
  parseJSON,
  record,
  stringify,
  type Row,
  type Page,
} from "./json";

declare module "axios" {
  interface AxiosRequestConfig {
    quiet?: boolean;
    retried?: boolean;
    sessionGeneration?: number;
  }
}
// The UI and API always share an origin (Vite proxies /api in development).
export const apiURL = (path: string) => path;
export const integrationOrigin = () => window.location.origin;
export type Scope = "admin" | "portal";
export class APIError extends Error {
  constructor(
    public code: string,
    message: string,
    public status = 0,
  ) {
    super(message);
    this.name = "APIError";
  }
}
const decode = (data: unknown) =>
  typeof data === "string" && data ? parseJSON(data) : data;
const encode = (data: unknown, headers: AxiosHeaders) => {
  if (
    data instanceof FormData ||
    data instanceof Blob ||
    typeof data === "string" ||
    data === undefined
  )
    return data;
  headers.setContentType("application/json");
  return stringify(data);
};
export const authTransport = axios.create({
  timeout: 20_000,
  transformResponse: [decode],
  transformRequest: [encode],
});
export const http = axios.create({
  baseURL: apiURL("/api/v1" + (adminPath() ?? "")),
  timeout: 20_000,
  transformResponse: [decode],
  transformRequest: [encode],
});
export const portalHttp = axios.create({
  baseURL: apiURL("/api/v1/portal"),
  timeout: 20_000,
  transformResponse: [decode],
  transformRequest: [encode],
});
interface RefreshFlight {
  generation: number;
  token: string;
  promise: Promise<void>;
}
let refreshing: RefreshFlight | undefined;
function expire(scope: Scope) {
  if (scope === "admin") clearAdmin();
  else clearPortal();
  window.dispatchEvent(new CustomEvent("authgo:expired", { detail: scope }));
}
async function refresh() {
  const generation = adminSession.generation;
  const refreshToken = adminSession.refresh;
  if (
    refreshing?.generation === generation &&
    refreshing.token === refreshToken
  )
    return refreshing.promise;
  if (!refreshToken)
    throw new APIError("UNAUTHORIZED", "登录已过期，请重新登录", 401);
  const flight: RefreshFlight = {
    generation,
    token: refreshToken,
    promise: Promise.resolve(),
  };
  flight.promise = (async () => {
    const response = await authTransport.post(
      apiURL(adminApiPath("/auth/refresh")),
      {
        refresh_token: refreshToken,
      },
    );
    const envelope = record(response.data);
    const data = record(envelope.data);
    if (envelope.code !== "OK" || !data.access_token || !data.refresh_token)
      throw new APIError("UNAUTHORIZED", "登录已过期，请重新登录", 401);
    if (
      generation !== adminSession.generation ||
      refreshToken !== adminSession.refresh
    )
      throw new APIError("SESSION_CHANGED", "登录会话已变化，请重新操作");
    setAdmin(String(data.access_token), String(data.refresh_token), data.admin);
  })().finally(() => {
    if (refreshing === flight) refreshing = undefined;
  });
  refreshing = flight;
  return flight.promise;
}
async function failure(error: unknown): Promise<APIError> {
  if (error instanceof APIError) return error;
  if (axios.isAxiosError(error)) {
    let payload: unknown = error.response?.data;
    if (payload instanceof Blob) {
      try {
        payload = parseJSON(await payload.text());
      } catch {
        payload = {};
      }
    }
    const body = record(payload);
    return new APIError(
      String(body.code ?? error.code ?? "NETWORK_ERROR"),
      String(
        body.message ??
          (error.response
            ? "服务器响应异常，请重试"
            : "连接失败，请检查网络或服务地址"),
      ),
      error.response?.status ?? 0,
    );
  }
  return new APIError("INVALID_DATA", "服务器返回内容格式异常，请重试");
}
for (const [scope, client] of [
  ["admin", http],
  ["portal", portalHttp],
] as const) {
  client.interceptors.request.use((config) => {
    if (scope === "admin") config.baseURL = apiURL(adminApiPath());
    const token = scope === "admin" ? adminSession.access : portalSession.token;
    const publicRoute =
      /^\/(?:status|auth\/(?:login|refresh|status|setup))$/.test(
        config.url ?? "",
      ) || /^\/(?:user\/)?login(?:\/|$)/.test(config.url ?? "");
    if (token && !publicRoute)
      config.headers.set("Authorization", `Bearer ${token}`);
    config.sessionGeneration = adminSession.generation;
    if (config.params) config.params = cleanParams(config.params as Row);
    // Let the browser generate multipart boundaries.
    if (config.data instanceof FormData) config.headers.delete("Content-Type");
    return config;
  });
  client.interceptors.response.use(
    (response) => {
      if (!(response.data instanceof Blob)) {
        const envelope = record(response.data);
        if (envelope.code !== "OK") {
          const error = new APIError(
            String(envelope.code ?? "INVALID_RESPONSE"),
            typeof envelope.message === "string"
              ? envelope.message
              : "服务器响应格式不正确，请稍后重试",
            response.status,
          );
          if (!response.config.quiet) ElMessage.error(error.message);
          throw error;
        }
      }
      return response;
    },
    async (error: unknown) => {
      if (axios.isCancel(error)) throw error;
      const config = axios.isAxiosError(error) ? error.config : undefined;
      const status = axios.isAxiosError(error) ? error.response?.status : 0;
      const publicRoute =
        /\/(auth\/)?login(?:\/|$)|\/auth\/(refresh|status|setup)$/.test(
          config?.url ?? "",
        );
      if (
        scope === "admin" &&
        status === 401 &&
        config &&
        !publicRoute &&
        !config.retried &&
        config.sessionGeneration === adminSession.generation
      ) {
        config.retried = true;
        try {
          const used = AxiosHeaders.from(config.headers).get("Authorization");
          if (!adminSession.access || used === `Bearer ${adminSession.access}`)
            await refresh();
          config.headers.set("Authorization", `Bearer ${adminSession.access}`);
        } catch (refreshError) {
          const safe = await failure(refreshError);
          if (config.sessionGeneration === adminSession.generation) {
            if (safe.status === 401 || safe.status === 403) expire("admin");
            if (!config.quiet)
              ElMessage.error(
                safe.status === 401 || safe.status === 403
                  ? "登录已过期，请重新登录"
                  : "暂时无法刷新登录，请稍后重试",
              );
          }
          throw safe;
        }
        return client.request(config);
      }
      if (
        status === 401 &&
        !publicRoute &&
        (scope === "portal"
          ? config?.headers.get("Authorization") ===
            `Bearer ${portalSession.token}`
          : config?.retried &&
            config.sessionGeneration === adminSession.generation)
      )
        expire(scope);
      const safe = await failure(error);
      if (!config?.quiet) ElMessage.error(safe.message);
      throw safe;
    },
  );
}
export async function api<T = Row>(
  scope: Scope,
  url: string,
  config: AxiosRequestConfig = {},
): Promise<T> {
  const response = await (scope === "admin" ? http : portalHttp).request({
    url,
    ...config,
  });
  return record(response.data).data as T;
}
export const get = <T = Row>(
  path: string,
  params?: Row,
  config?: AxiosRequestConfig,
) => api<T>("admin", path, { params, ...config });
export const post = <T = Row>(path: string, data?: unknown) =>
  api<T>("admin", path, {
    method: "POST",
    data,
    ...(path === "/system/backups" ? { timeout: 370_000 } : {}),
  });
export const patch = <T = Row>(path: string, data?: unknown) =>
  api<T>("admin", path, { method: "PATCH", data });
export const remove = (path: string) =>
  api("admin", path, { method: "DELETE" });
export const pget = <T = Row>(path: string, params?: Row) =>
  api<T>("portal", path, { params });
export const ppost = <T = Row>(path: string, data?: unknown) =>
  api<T>("portal", path, { method: "POST", data });
export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename.replace(/[\\/\r\n]/g, "_");
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export async function download(
  scope: Scope,
  path: string,
  fallback: string,
  config: AxiosRequestConfig = {},
) {
  const response: AxiosResponse<Blob> = await (
    scope === "admin" ? http : portalHttp
  ).request({
    url: path,
    responseType: "blob",
    ...(scope === "admin" &&
    /^\/system\/backups\/[^/]+$/.test(path.split("?")[0]!)
      ? { timeout: 310_000 }
      : {}),
    ...config,
  });
  if (
    String(response.headers["content-type"] ?? "").includes("application/json")
  ) {
    const body = record(parseJSON(await response.data.text()));
    const error = new APIError(
      String(body.code && body.code !== "OK" ? body.code : "INVALID_FILE"),
      body.code && body.code !== "OK" && typeof body.message === "string"
        ? body.message
        : "服务器未返回可下载文件",
      response.status,
    );
    if (!config.quiet) ElMessage.error(error.message);
    throw error;
  }
  const name =
    /filename="?([^";]+)"?/i.exec(
      String(response.headers["content-disposition"] ?? ""),
    )?.[1] ?? fallback;
  saveBlob(response.data, name);
}
export async function copy(value: string) {
  try {
    await navigator.clipboard.writeText(value);
    ElMessage.success("已复制");
  } catch {
    ElMessage.warning("无法访问剪贴板，请选中文本手动复制");
  }
}

export async function integrationProtocol(): Promise<string> {
  const result = await get("/integration/protocol");
  if (typeof result.text !== "string")
    throw new APIError("INVALID_RESPONSE", "协议内容格式不正确");
  return result.text;
}
export async function integrationDocker(): Promise<string> {
  const result = await get("/integration/docker");
  if (typeof result.text !== "string")
    throw new APIError("INVALID_RESPONSE", "Docker文档格式不正确");
  return result.text;
}

// Large database transfers have a route-local timeout; other APIs keep their normal deadline.
export const ipDatabaseTimeout = 4 * 60 * 1000;
export interface IpDatabaseFile {
  source: string;
  database_type: string;
  data_date: string;
  size: number;
  updated_at: string;
}
export interface IpDatabaseStatus {
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
  const out: Row[] = [];
  for (let page = 1; ; page++) {
    const value = await api<Page>("portal", "/user/updates", {
      params: { page, page_size: 100 },
      signal,
    });
    out.push(...value.items);
    if (!value.items.length || out.length >= Number(value.total)) return out;
  }
}

export const licenseSharing = (id: string, signal?: AbortSignal) =>
  get<Row>(`/licenses/${encodeURIComponent(id)}/sharing`, undefined, {
    signal,
  });
export const ignoreLicenseSharing = (id: string) =>
  post<Row>(`/licenses/${encodeURIComponent(id)}/sharing/ignore`, {});
