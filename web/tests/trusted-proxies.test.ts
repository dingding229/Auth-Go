import { describe, expect, it } from "vitest";
import {
  INTERNAL_TRUSTED_PROXIES,
  CLOUDFLARE_TRUSTED_PROXIES,
  mergeTrustedProxies,
} from "../src/lib/trusted-proxies";

describe("受信代理网段合并", () => {
  it("保留原有行和顺序，新网段追加在后", () => {
    expect(
      mergeTrustedProxies("203.0.113.8\n198.51.100.0/24", [
        "192.0.2.0/24",
        "203.0.113.8",
      ]),
    ).toBe("203.0.113.8\n198.51.100.0/24\n192.0.2.0/24");
  });

  it("去重忽略首尾空白，兼容 CRLF 且不产生空行", () => {
    expect(
      mergeTrustedProxies(" \n 10.0.0.0/8 \r\n\r\n\t::1/128\t\n10.0.0.0/8\n", [
        " ::1/128 ",
        " ",
        "192.168.0.0/16 ",
        "192.168.0.0/16",
        "",
      ]),
    ).toBe("10.0.0.0/8\n::1/128\n192.168.0.0/16");
    expect(mergeTrustedProxies(" \r\n\t", [])).toBe("");
  });

  it("重复填入结果不变，也不修改传入的网段数组", () => {
    const additions = Object.freeze([" 10.0.0.0/8 ", "", "::1/128"]);
    const once = mergeTrustedProxies("203.0.113.8", additions);
    expect(mergeTrustedProxies(once, additions)).toBe(once);
    expect(additions).toEqual([" 10.0.0.0/8 ", "", "::1/128"]);
  });

  it("预置包含 8 个内网网段和 Cloudflare 的 15 个 IPv4、7 个 IPv6 网段", () => {
    expect(INTERNAL_TRUSTED_PROXIES).toHaveLength(8);
    expect(
      CLOUDFLARE_TRUSTED_PROXIES.filter((cidr) => cidr.includes(".")),
    ).toHaveLength(15);
    expect(
      CLOUDFLARE_TRUSTED_PROXIES.filter((cidr) => cidr.includes(":")),
    ).toHaveLength(7);
    const all = [...INTERNAL_TRUSTED_PROXIES, ...CLOUDFLARE_TRUSTED_PROXIES];
    expect(new Set(all).size).toBe(30);
    expect(mergeTrustedProxies("", all)).toBe(all.join("\n"));
  });
});
