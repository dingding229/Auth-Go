import "./admin-bootstrap";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  AxiosError,
  AxiosHeaders,
  type InternalAxiosRequestConfig,
} from "axios";
vi.mock("element-plus", () => ({
  ElMessage: { error: vi.fn(), warning: vi.fn(), success: vi.fn() },
}));
import {
  api,
  authTransport,
  get,
  http,
  portalHttp,
  post,
  download,
} from "../src/lib/http";
import {
  adminSession,
  clearAdmin,
  clearPortal,
  portalSession,
  setAdmin,
  setPortal,
} from "../src/lib/session";
import { parseJSON, record, stringify } from "../src/lib/json";
function response(
  config: InternalAxiosRequestConfig,
  data: unknown,
  status = 200,
) {
  return {
    config,
    data: stringify(data),
    status,
    statusText: "",
    headers: new AxiosHeaders(),
  };
}
function unauthorized(
  config: InternalAxiosRequestConfig,
  code = "UNAUTHORIZED",
  status = 401,
): never {
  throw new AxiosError(
    "Rejected",
    "ERR_BAD_REQUEST",
    config,
    undefined,
    response(config, { code, message: "拒绝访问", data: null }, status),
  );
}
const ok = (config: InternalAxiosRequestConfig) =>
  response(config, {
    code: "OK",
    data: { value: 1 },
    message: "操作成功",
    signature: null,
  });
beforeEach(() => {
  clearAdmin();
  clearPortal();
  setAdmin("old-access", "old-refresh");
  http.defaults.adapter = async (config) => ok(config);
  portalHttp.defaults.adapter = async (config) => ok(config);
});
describe("管理端自动刷新", () => {
  it("并发过期请求只轮换一次refresh token", async () => {
    let refreshes = 0;
    authTransport.defaults.adapter = async (config) => {
      refreshes++;
      await new Promise((resolve) => setTimeout(resolve, 15));
      expect(record(parseJSON(config.data)).refresh_token).toBe("old-refresh");
      return response(config, {
        code: "OK",
        data: { access_token: "new-access", refresh_token: "new-refresh" },
      });
    };
    http.defaults.adapter = async (config) => {
      if (config.headers.get("Authorization") === "Bearer old-access")
        unauthorized(config);
      return ok(config);
    };
    const result = await Promise.all([
      get("/applications", undefined, { quiet: true }),
      get("/licenses", undefined, { quiet: true }),
      get("/activations", undefined, { quiet: true }),
    ]);
    expect(result).toHaveLength(3);
    expect(refreshes).toBe(1);
    expect(adminSession.refresh).toBe("new-refresh");
  });
  it("迟到的旧access 401复用已刷新的token，不二次轮换", async () => {
    let refreshes = 0;
    authTransport.defaults.adapter = async (config) => {
      refreshes++;
      return response(config, {
        code: "OK",
        data: { access_token: "new-access", refresh_token: "new-refresh" },
      });
    };
    http.defaults.adapter = async (config) => {
      if (config.headers.get("Authorization") === "Bearer old-access") {
        if (config.url === "/late")
          await new Promise((resolve) => setTimeout(resolve, 25));
        unauthorized(config);
      }
      return ok(config);
    };
    await Promise.all([
      get("/fast", undefined, { quiet: true }),
      get("/late", undefined, { quiet: true }),
    ]);
    expect(refreshes).toBe(1);
  });
  it("重试后的权限拒绝不会误清除有效会话", async () => {
    authTransport.defaults.adapter = async (config) =>
      response(config, {
        code: "OK",
        data: { access_token: "new-access", refresh_token: "new-refresh" },
      });
    http.defaults.adapter = async (config) => {
      if (config.headers.get("Authorization") === "Bearer old-access")
        unauthorized(config);
      unauthorized(config, "FORBIDDEN", 403);
    };
    await expect(
      get("/admins", undefined, { quiet: true }),
    ).rejects.toMatchObject({ status: 403 });
    expect(adminSession.access).toBe("new-access");
  });
  it("登出或重新登录后，旧刷新响应不能覆盖新会话", async () => {
    let finish!: () => void;
    authTransport.defaults.adapter = async (config) => {
      await new Promise<void>((resolve) => {
        finish = resolve;
      });
      return response(config, {
        code: "OK",
        data: { access_token: "stale", refresh_token: "stale" },
      });
    };
    http.defaults.adapter = async (config) => unauthorized(config);
    const pending = get("/old", undefined, { quiet: true }).catch((e) => e);
    await vi.waitFor(() => expect(finish).toBeTypeOf("function"));
    clearAdmin();
    setAdmin("another-access", "another-refresh");
    finish();
    await pending;
    expect(adminSession.access).toBe("another-access");
    expect(adminSession.refresh).toBe("another-refresh");
  });
  it("刷新失败清理会话，登录失败不触发刷新", async () => {
    const refresh = vi.fn(async (config: InternalAxiosRequestConfig) =>
      unauthorized(config),
    );
    authTransport.defaults.adapter = refresh;
    http.defaults.adapter = async (config) => unauthorized(config);
    await expect(
      get("/protected", undefined, { quiet: true }),
    ).rejects.toMatchObject({ status: 401 });
    expect(adminSession.access).toBe("");
    expect(refresh).toHaveBeenCalledTimes(1);
    setAdmin("still-here", "refresh");
    await expect(
      api("admin", "/auth/login", { method: "POST", data: {}, quiet: true }),
    ).rejects.toMatchObject({ status: 401 });
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(adminSession.access).toBe("still-here");
  });
});
describe("门户、文件与精度", () => {
  it("门户令牌独立且不使用管理员refresh", async () => {
    setPortal("portal-token");
    const refresh = vi.fn();
    authTransport.defaults.adapter = refresh;
    portalHttp.defaults.adapter = async (config) => {
      expect(config.headers.get("Authorization")).toBe("Bearer portal-token");
      unauthorized(config, "PORTAL_UNAUTHORIZED");
    };
    await expect(
      api("portal", "/license", { quiet: true }),
    ).rejects.toMatchObject({ code: "PORTAL_UNAUTHORIZED" });
    expect(portalSession.token).toBe("");
    expect(adminSession.access).toBe("old-access");
    expect(refresh).not.toHaveBeenCalled();
  });
  it("旧门户请求不能清除新登录令牌", async () => {
    setPortal("old-portal");
    portalHttp.defaults.adapter = async (config) => {
      setPortal("new-portal");
      unauthorized(config, "PORTAL_UNAUTHORIZED");
    };
    await expect(
      api("portal", "/license", { quiet: true }),
    ).rejects.toMatchObject({ status: 401 });
    expect(portalSession.token).toBe("new-portal");
  });
  it("支持原样传递multipart，不强制JSON Content-Type", async () => {
    const file = new FormData();
    file.append(
      "file",
      new Blob(["key,app_id\n"], { type: "text/csv" }),
      "licenses.csv",
    );
    http.defaults.adapter = async (config) => {
      expect(config.data).toBe(file);
      expect(config.headers.get("Content-Type")).not.toBe("application/json");
      return ok(config);
    };
    await api("admin", "/licenses/import", {
      method: "POST",
      data: file,
      quiet: true,
    });
  });
  it("features大整数往返不被JS Number舍入", () => {
    const input = '{"features":{"quota":18446744073709551615,"enabled":true}}';
    const parsed = parseJSON(input);
    expect(stringify(parsed)).toBe(input);
  });
});

it("临时刷新网络失败保留refresh token以便重试", async () => {
  authTransport.defaults.adapter = async (config) => {
    throw new AxiosError("Network Error", "ERR_NETWORK", config);
  };
  http.defaults.adapter = async (config) => unauthorized(config);
  await expect(
    get("/temporarily-offline", undefined, { quiet: true }),
  ).rejects.toMatchObject({ code: "ERR_NETWORK" });
  expect(adminSession.refresh).toBe("old-refresh");
});

it("保留JSON元数据特殊键且不污染对象原型，拒绝重复键", () => {
  const input =
    '{"features":{"__proto__":{"authgo_polluted":true},"constructor":{"prototype":{"authgo_polluted":true}}}}';
  const value = parseJSON(input);
  expect(stringify(value)).toBe(input);
  expect(({} as Record<string, unknown>).authgo_polluted).toBeUndefined();
  expect(() => parseJSON('{"quota":1,"quota":2}')).toThrow();
});

it("不将缺少统一响应信封的200 JSON误报为成功", async () => {
  http.defaults.adapter = async (config) =>
    response(config, { unexpected: true });
  await expect(
    get("/invalid-response", undefined, { quiet: true }),
  ).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
});

it("初始化令牌错误不触发管理员刷新或清除已有会话", async () => {
  const refresh = vi.fn();
  authTransport.defaults.adapter = refresh;
  http.defaults.adapter = async (config) => {
    expect(config.headers.get("Authorization")).toBeUndefined();
    unauthorized(config, "SETUP_TOKEN_INVALID");
  };
  await expect(
    api("admin", "/auth/setup", {
      method: "POST",
      data: { token: "wrong" },
      quiet: true,
    }),
  ).rejects.toMatchObject({ code: "SETUP_TOKEN_INVALID" });
  expect(refresh).not.toHaveBeenCalled();
  expect(adminSession.access).toBe("old-access");
});

// Overview ratios are often non-terminating decimal fractions on the wire.
it("概览接口长小数能解析并显示百分比", async () => {
  http.defaults.adapter = async (config) => ({
    config,
    status: 200,
    statusText: "OK",
    headers: new AxiosHeaders(),
    data: '{"code":"OK","data":{"today_failure_rate":0.10714285714285714}}',
  });
  const overview = await get("/stats/overview");
  expect(typeof overview.today_failure_rate).toBe("number");
  expect(`${(Number(overview.today_failure_rate) * 100).toFixed(1)}%`).toBe(
    "10.7%",
  );
});

it("备份创建/下载使用独立期限而普通请求不变", async () => {
  setAdmin("access", "refresh");
  const seen: number[] = [];
  http.defaults.adapter = async (config) => {
    seen.push(config.timeout!);
    if (config.responseType === "blob") throw new Error("stop-before-saving");
    return response(config, { code: "OK", data: {} });
  };
  await post("/system/backups", {});
  await get("/applications");
  await download(
    "admin",
    "/system/backups/authgo-test.db",
    "backup.zip",
  ).catch(() => {});
  await download("admin", "/licenses/export", "licenses.csv").catch(() => {});
  expect(seen).toEqual([370_000, 20_000, 310_000, 20_000]);
});
