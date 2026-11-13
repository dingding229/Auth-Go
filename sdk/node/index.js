import * as payloadKeys from "./payload.js";
export { Payload, parsePayload, payloadBinding } from "./payload.js";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import http from "node:http";
import https from "node:https";
import { execFileSync } from "node:child_process";
export const temporaryCodes = new Set(
  "INTERNAL_ERROR RATE_LIMITED REPLAY_DETECTED TIMESTAMP_INVALID SIGNATURE_INVALID INVALID_REQUEST PAYLOAD_INVALID".split(
    " ",
  ),
);
export class AuthGoError extends Error {
  constructor(code, message = "", authenticated = false, cause) {
    super(code + (message ? ": " + message : ""), { cause });
    this.code = code;
    this.authenticated = authenticated;
    this.latestVersion = "";
    this.latestEntitledVersion = "";
  }
  get refusal() {
    return (
      this.authenticated && this.code !== "OK" && !temporaryCodes.has(this.code)
    );
  }
}
const err = (c, m = "") => new AuthGoError(c, m),
  buf = (x) => Buffer.from(x),
  random = crypto.randomBytes;
export const b64 = (b) => buf(b).toString("base64url");
export function unb64(s) {
  if (
    typeof s !== "string" ||
    !/^[A-Za-z0-9_-]*$/.test(s) ||
    b64(Buffer.from(s, "base64url")) !== s
  )
    throw err("SDK_RESPONSE_INVALID");
  return Buffer.from(s, "base64url");
}
function standard(s) {
  const raw = Buffer.from(s, "base64");
  if (raw.toString("base64") !== s) throw err("SDK_RESPONSE_INVALID");
  return raw;
}
export const sha = (x) => crypto.createHash("sha256").update(x).digest("hex");
export const hkdf = (ikm, salt, info, n = 32) =>
  buf(crypto.hkdfSync("sha256", ikm, salt, info, n));
const mac = (k, x) => crypto.createHmac("sha256", k).update(x).digest("hex");
class NumberLexeme {
  constructor(s) {
    this.source = s;
  }
  valueOf() {
    return Number(this.source);
  }
  toString() {
    return this.source;
  }
}
export function parse(raw) {
  const s = buf(raw).toString("utf8");
  if (!buf(s).equals(buf(raw))) throw err("SDK_RESPONSE_INVALID");
  let at = 0;
  const ws = () => {
    while (/[ \r\n\t]/.test(s[at] || "x")) at++;
  };
  function value(depth = 0) {
    if (depth > 100) throw Error("depth");
    ws();
    const c = s[at];
    if (c === '"') {
      const begin = at++;
      while (at < s.length) {
        if (s[at++] === "\\") {
          at++;
          continue;
        }
        if (s[at - 1] === '"') {
          const str = JSON.parse(s.slice(begin, at));
          if (!str.isWellFormed()) throw Error("unicode");
          return str;
        }
      }
      throw Error("string");
    }
    if (c === "{" || c === "[") {
      at++;
      const object = c === "{",
        out = object ? Object.create(null) : [],
        close = object ? "}" : "]";
      ws();
      if (s[at] === close) {
        at++;
        return out;
      }
      while (true) {
        if (object) {
          ws();
          if (s[at] !== '"') throw Error("key");
          const k = value(depth + 1);
          ws();
          if (s[at++] !== ":" || Object.hasOwn(out, k))
            throw Error("duplicate");
          out[k] = value(depth + 1);
        } else out.push(value(depth + 1));
        ws();
        if (s[at] === close) {
          at++;
          return out;
        }
        if (s[at++] !== ",") throw Error("comma");
      }
    }
    const m =
      /^(true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
        s.slice(at),
      );
    if (!m) throw Error("value");
    at += m[0].length;
    return m[0] === "true"
      ? true
      : m[0] === "false"
        ? false
        : m[0] === "null"
          ? null
          : new NumberLexeme(m[0]);
  }
  try {
    const v = value();
    ws();
    if (at !== s.length) throw Error("trailing");
    return v;
  } catch {
    throw err("SDK_RESPONSE_INVALID", "JSON无效");
  }
}
export function canonical(v) {
  if (v instanceof NumberLexeme) return v.source;
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v && typeof v === "object")
    return (
      "{" +
      Object.keys(v)
        .sort((a, b) => {
          const x = Array.from(a),
            y = Array.from(b);
          for (let i = 0; i < Math.min(x.length, y.length); i++) {
            const n = x[i].codePointAt(0) - y[i].codePointAt(0);
            if (n) return n;
          }
          return x.length - y.length;
        })
        .map((k) => canonical(k) + ":" + canonical(v[k]))
        .join(",") +
      "}"
    );
  return JSON.stringify(v).replace(
    /[<>&\u2028\u2029]/g,
    (x) => "\\u" + x.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}
export function pad(b) {
  const n = Math.max(4096, Math.ceil((b.length + 4) / 512) * 512),
    out = random(n);
  out.writeUInt32BE(b.length);
  b.copy(out, 4);
  return out;
}
export function unpad(b) {
  if (b.length < 4) throw err("SDK_RESPONSE_INVALID");
  const n = b.readUInt32BE();
  if (
    !n ||
    n + 4 > b.length ||
    b.length !== Math.max(4096, Math.ceil((n + 4) / 512) * 512)
  )
    throw err("SDK_RESPONSE_INVALID");
  return b.subarray(4, 4 + n);
}
export function seal(key, n, data, aad) {
  const c = crypto.createCipheriv("aes-256-gcm", key, n);
  c.setAAD(aad);
  return Buffer.concat([c.update(data), c.final(), c.getAuthTag()]);
}
export function open(key, n, data, aad) {
  if (n.length !== 12 || data.length < 16) throw err("SDK_RESPONSE_INVALID");
  const c = crypto.createDecipheriv("aes-256-gcm", key, n);
  c.setAAD(aad);
  c.setAuthTag(data.subarray(-16));
  return Buffer.concat([c.update(data.subarray(0, -16)), c.final()]);
}
const pub = (type, raw) =>
  crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from(
        type === "ed" ? "302a300506032b6570032100" : "302a300506032b656e032100",
        "hex",
      ),
      raw,
    ]),
    format: "der",
    type: "spki",
  });
export function verifySignature(publicKey, raw, sig) {
  return crypto.verify(null, raw, pub("ed", publicKey), sig);
}
export function sharedSecret(privateRaw, publicRaw) {
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b656e04220420", "hex"),
      privateRaw,
    ]),
    format: "der",
    type: "pkcs8",
  });
  return crypto.diffieHellman({
    privateKey: priv,
    publicKey: pub("x", publicRaw),
  });
}
const date = (x) => (x == null ? Infinity : Date.parse(x) / 1000);
const command = (p, ...args) =>
  execFileSync(p, args, { encoding: "utf8", timeout: 3000 }).trim();
export function validateKey(key) {
  const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ",
    p = key.split("-");
  if (
    p.length !== 5 ||
    p[0].length < 1 ||
    p[0].length > 16 ||
    p.slice(1).some((v) => v.length !== 5) ||
    p.some((v) => [...v].some((c) => !alphabet.includes(c)))
  )
    throw err("INVALID_LICENSE_KEY");
  let check = p[0].length % 32;
  for (const c of p[0] + p.slice(1, 4).join("") + p[4].slice(0, 4))
    check = (check * 17 + alphabet.indexOf(c)) % 32;
  if (p[4][4] !== alphabet[check]) throw err("INVALID_LICENSE_KEY");
}
export function parseLinuxCPU(raw) {
  const fields = raw.split("\n").map((line) => {
    const i = line.indexOf(":");
    return i < 0 ? [line, ""] : [line.slice(0, i), line.slice(i + 1)];
  });
  for (const [k, v] of fields)
    if (["model name", "Hardware", "cpu model"].includes(k.trim()) && v.trim())
      return v.trim();
  let implementer = "",
    part = "",
    uarch = "",
    seen = false,
    done = false;
  for (const [key, value] of fields) {
    const k = key.trim(),
      v = value.trim();
    if (!k && !v && seen) done = true;
    if (k === "uarch" && !uarch) uarch = v;
    if (!done) {
      if (k === "CPU implementer") {
        seen = true;
        if (!implementer) implementer = v.replace(/\s/g, "").toLowerCase();
      }
      if (k === "CPU part") {
        seen = true;
        if (!part) part = v.replace(/\s/g, "").toLowerCase();
      }
    }
  }
  return implementer && part ? `arm:${implementer}:${part}` : uarch;
}

export function identityHash(machine, mac, cpu) {
  machine = machine.trim().toLowerCase();
  cpu = cpu.toLowerCase().trim().split(/\s+/).join(" ");
  mac = mac.trim().toLowerCase().replaceAll("-", ":");
  if (
    !machine ||
    !cpu ||
    !/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}(?::[0-9a-f]{2}){0,2}$/.test(mac)
  )
    throw err("SDK_FINGERPRINT_UNAVAILABLE");
  return sha("authgo/fingerprint/v1\0" + machine + "\0" + mac + "\0" + cpu);
}
export function fingerprint() {
  try {
    let machine,
      cpu,
      preferred = "",
      items = [];
    if (os.platform() === "linux") {
      machine = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .map((p) => {
          try {
            return fs.readFileSync(p, "utf8");
          } catch {
            return "";
          }
        })
        .find((s) => s.trim());
      cpu = parseLinuxCPU(fs.readFileSync("/proc/cpuinfo", "utf8"));
      preferred =
        fs
          .readFileSync("/proc/net/route", "utf8")
          .split("\n")
          .map((s) => s.trim().split(/\s+/))
          .find((f) => f[1] === "00000000")?.[0] || "";
      items = fs
        .readdirSync("/sys/class/net")
        .filter(
          (s) =>
            !(
              parseInt(
                fs.readFileSync("/sys/class/net/" + s + "/flags", "utf8"),
                16,
              ) & 8
            ),
        )
        .map((name) => ({
          name,
          index: Number(
            fs.readFileSync("/sys/class/net/" + name + "/ifindex", "utf8"),
          ),
          mac: fs
            .readFileSync("/sys/class/net/" + name + "/address", "utf8")
            .trim(),
          up: !!(
            parseInt(
              fs.readFileSync("/sys/class/net/" + name + "/flags", "utf8"),
              16,
            ) & 1
          ),
        }));
    } else if (os.platform() === "darwin") {
      machine = /"IOPlatformUUID"\s*=\s*"([^"]+)"/.exec(
        command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"),
      )[1];
      try {
        cpu = command("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string");
      } catch {
        cpu = command("/usr/sbin/sysctl", "-n", "hw.model");
      }
      try {
        preferred =
          /interface:\s*(\S+)/.exec(
            command("/sbin/route", "-n", "get", "default"),
          )?.[1] || "";
      } catch {}
      const raw = command("/sbin/ifconfig", "-a", "-v");
      items = raw
        .split(/\n(?=\S)/)
        .map((block) => {
          const name = /^(\S+):/.exec(block)?.[1],
            index = Number(/index\s+(\d+)/.exec(block)?.[1]),
            mac = /ether\s+([0-9a-f:]+)/.exec(block)?.[1];
          return { name, index, mac, up: /<[^>]*\bUP\b/.test(block) };
        })
        .filter((x) => x.name && x.mac && x.index);
    } else if (os.platform() === "win32") {
      const root = process.env.SystemRoot || "C:\\Windows",
        reg = path.join(root, "System32", "reg.exe"),
        ps = path.join(
          root,
          "System32",
          "WindowsPowerShell",
          "v1.0",
          "powershell.exe",
        );
      machine = /MachineGuid\s+REG_SZ\s+(.+)/.exec(
        command(
          reg,
          "query",
          "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
          "/v",
          "MachineGuid",
          "/reg:64",
        ),
      )[1];
      cpu = /ProcessorNameString\s+REG_SZ\s+(.+)/.exec(
        command(
          reg,
          "query",
          "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
          "/v",
          "ProcessorNameString",
        ),
      )[1];
      try {
        preferred = command(
          ps,
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex",
        );
      } catch {}
      items = JSON.parse(
        command(
          ps,
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -IncludeHidden | Select-Object ifIndex,Name,MacAddress,Status)",
        ),
      )
        .filter((x) => x.MacAddress)
        .map((v) => ({
          name: String(v.ifIndex),
          index: v.ifIndex,
          mac: v.MacAddress,
          up: v.Status === "Up",
        }));
    } else throw Error("platform");
    items = items
      .filter((x) => x.mac.replace(/[:-]/g, "").replaceAll("0", ""))
      .sort((a, b) => a.index - b.index);
    const nic =
      items.find(
        (x) => x.name === preferred || String(x.index) === preferred,
      ) ||
      items.find((x) => x.up) ||
      items[0];
    return identityHash(machine, nic.mac, cpu);
  } catch {
    throw err(
      "SDK_FINGERPRINT_UNAVAILABLE",
      "无法采集实例指纹，请提供 fingerprint 覆盖",
    );
  }
}
export function httpRequest(
  url,
  body = null,
  headers = {},
  timeout = 10000,
  limit = 5 * 1024 * 1024,
  tls = {},
) {
  return new Promise((resolve, reject) => {
    const req = (url.startsWith("https:") ? https : http).request(
      url,
      { method: body == null ? "GET" : "POST", headers, ...tls },
      (res) => {
        let n = 0,
          chunks = [];
        res.on("data", (b) => {
          n += b.length;
          if (n > limit) {
            req.destroy(err("SDK_RESPONSE_INVALID", "响应过大"));
            return;
          }
          chunks.push(b);
        });
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks),
          }),
        );
        res.on("error", () =>
          reject(err("SDK_RESPONSE_INVALID", "响应不完整")),
        );
      },
    );
    const timer = setTimeout(
      () => req.destroy(err("SDK_NETWORK_ERROR", "连接超时")),
      timeout,
    );
    req.on("close", () => clearTimeout(timer));
    req.on("error", (e) =>
      reject(
        e instanceof AuthGoError
          ? e
          : new AuthGoError(
              e.code?.startsWith("CERT") || e.code?.includes("CERT")
                ? "SDK_RESPONSE_INVALID"
                : "SDK_NETWORK_ERROR",
              "连接失败",
              false,
              e,
            ),
      ),
    );
    if (body) req.write(body);
    req.end();
  });
}
function heartbeatInterval(data, cached) {
  const value = Number(cached);
  if (typeof cached !== "boolean" && Number.isInteger(value) && value >= 1 && value <= 3600) return value;
  if (data.floating) {
    const span = date(data.lease_expires_at) - date(data.issued_at);
    if (Number.isFinite(span) && span > 0) return Math.max(1, Math.min(3600, Math.ceil(span / 2)));
  }
  return Math.max(1, Math.min(3600, Number(data.next_check_in) || 1));
}

function cloneGuardValue(value) {
  if (value instanceof NumberLexeme) return new NumberLexeme(value.source);
  if (Array.isArray(value)) return value.map(cloneGuardValue);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,cloneGuardValue(v)]));
  return value;
}

export class Result {
  #client;
  #proof;
  #seed;
  #end;
  constructor(
    client,
    data,
    ticket = "",
    seed = Buffer.alloc(0),
    status = "online",
    end = Infinity,
    reason = "",
  ) {
    this.#client = client;
    this.cacheWarning = client.cacheWarning;
    this.data = data;
    this.maintenanceUntil = data.maintenance_until ?? null;
    this.latestEntitledVersion = data.latest_entitled_version || "";
    this.heartbeatInterval = heartbeatInterval(data, client.state?.heartbeat_interval);
    this.#proof = ticket;
    this.#seed = seed;
    this.status = this.availability = status;
    this.offline = status !== "online";
    this.isTrial = !!data.is_trial;
    this.features = data.features || {};
    this.#end = end;
    this.reason = reason;
    this.remainingSeconds = Number.isFinite(end)
      ? Math.max(0, Math.floor(end - client.now()))
      : 0;
  }
  ticket() {
    return this.#proof;
  }
  _guardSnapshot() {
    const result = new Result(this.#client, cloneGuardValue(this.data), this.#proof,
      Buffer.from(this.#seed), this.status, this.#end, this.reason);
    result.cacheWarning = this.cacheWarning;
    result.remainingSeconds = this.remainingSeconds;
    result.heartbeatInterval = this.heartbeatInterval;
    return result;
  }
  _guardDeadline() { return this.#end; }

}
const processSession = b64(random(16));
const replacedInstances = new Set(), memoryInstances = new Map();
export function detectContainer(read = p => fs.readFileSync(p), env = process.env) {
  if (["0", "1"].includes(env.AUTHGO_CONTAINER)) return env.AUTHGO_CONTAINER === "1";
  for (const p of ["/.dockerenv", "/run/.containerenv"]) { try { read(p); return true; } catch {} }
  try { return ["docker","containerd","kubepods","libpod"].some(x => read("/proc/1/cgroup").toString().includes(x)); } catch { return false; }
}
export function instanceFingerprint(id) { return sha(buf("authgo/instance/v1\0" + id)); }
// Use non-recursive mkdir for the final component. Some filesystems (notably
// procfs) report ENOENT even when the parent exists; recursive mkdir may retry
// indefinitely instead of letting the SDK fall back to an in-memory identity.
function makeCacheDirectory(dir) {
  try { fs.mkdirSync(dir, {mode:0o700}); }
  catch(error) {
    if(error.code === "EEXIST") { if(!fs.statSync(dir).isDirectory())throw error;return; }
    if(error.code !== "ENOENT")throw error;
    const parent=path.dirname(dir);
    if(parent===dir)throw error;
    makeCacheDirectory(parent);
    try {fs.mkdirSync(dir,{mode:0o700});}
    catch(e){if(e.code!=="EEXIST" || !fs.statSync(dir).isDirectory())throw e;}
  }
}
function containerIdentity(dir) {
  try {
    if (!dir) throw Error();
    makeCacheDirectory(dir);
    const target = path.join(dir,"instance-id");
    const read = () => { const st=fs.lstatSync(target), value=fs.readFileSync(target,"utf8"); if(!st.isFile() || (st.mode&0o777)!==0o600 || !/^[0-9a-f]{64}$/.test(value))throw Error();return value; };
    if(fs.existsSync(target))return [read(),false];
    const temp=path.join(dir,".instance-"+b64(random(16)));
    let cleanupError;
    try {
      const fd=fs.openSync(temp,"wx",0o600);
      try {fs.writeFileSync(fd,random(32).toString("hex"));fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
      try {fs.linkSync(temp,target);} catch(e){if(e.code!=="EEXIST")throw e;}
    } finally {try{fs.unlinkSync(temp);}catch(e){if(e.code!=="ENOENT")cleanupError=e;}}
    // Cleanup failure still falls back to an in-memory identity, as before.
    if(cleanupError)throw cleanupError;
    return [read(),false];
  }catch { const key=path.resolve(dir||".");if(!memoryInstances.has(key))memoryInstances.set(key,random(32).toString("hex"));return [memoryInstances.get(key),true]; }
}

export class Client {
  constructor(
    config,
    {
      fingerprint: fp,
      cacheDir,
      version = "",
      clock = () => Date.now() / 1000,
      transport = httpRequest,
    } = {},
  ) {
    try {
      if (
        typeof config !== "string" ||
        config.length > 32768 ||
        !config.startsWith("authgo2.")
      )
        throw Error();
      const c = parse(unb64(config.slice(8)));
      if (
        Object.keys(c).some(
          (k) =>
            ![
              "url",
              "app_key",
              "app_secret",
              "public_key",
              "gateway_key",
                          ].includes(k),
        )
      )
        throw Error();
      for (const k of [
        "url",
        "app_key",
        "app_secret",
        "public_key",
        "gateway_key",
      ])
        if (typeof c[k] !== "string" || !c[k]) throw Error();
      const url = new URL(c.url);
      if (
        url.username ||
        url.password ||
        url.search ||
        url.hash ||
        !url.hostname ||
        (url.protocol !== "https:" &&
          !(
            url.protocol === "http:" &&
            ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
          ))
      )
        throw Error();
      if (
        /\/(?:\.|\.\.)(?:\/|$)|%|\/\//.test(
          c.url.slice(c.url.indexOf("://") + 3).replace(/^[^/]*/, ""),
        )
      )
        throw Error();
      this.endpoint = c.url.replace(/\/$/, "");
      if (!this.endpoint.endsWith("/api/v1/client"))
        this.endpoint += "/api/v1/client";
      this.public = standard(c.public_key);
      this.gateway = unb64(c.gateway_key);
      if (
        this.public.length !== 32 ||
        this.public.toString("base64") !== c.public_key ||
        this.gateway.length !== 32
      )
        throw Error();
      this.config = c;
    } catch {
      throw err("SDK_INVALID_CONFIG", "请在后台重新复制接入配置");
    }
    this.now = clock;
    this.transport = transport;
    const container = detectContainer();
    const root =
      os.platform() === "win32"
        ? process.env.LOCALAPPDATA ||
          path.join(os.homedir(), "AppData", "Local")
        : os.platform() === "darwin"
          ? path.join(os.homedir(), "Library", "Caches")
          : process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache");
    this.cache = cacheDir ?? (process.env.AUTHGO_CACHE_DIR || (container ? "/var/lib/authgo" : path.join(root,"authgo",sha(this.config.app_key))));
    this.memoryCache = this.cache === "";
    this.cacheWarning = null;
    if(fp !== undefined) this.fp=fp.toLowerCase();
    else if(process.env.AUTHGO_INSTANCE_ID) this.fp=instanceFingerprint(process.env.AUTHGO_INSTANCE_ID);
    else if(container) { const [id,memory]=containerIdentity(this.cache);this.fp=instanceFingerprint(id);this.memoryCache=memory;if(memory)this.cacheWarning=err("SDK_CACHE_UNAVAILABLE","此实例重启后是新实例，没有断连宽限"); }
    else this.fp=fingerprint().toLowerCase();
    if(!/^[0-9a-f]{64}$/.test(this.fp))throw err("SDK_INVALID_CONFIG");
    this.version=version;this.state={};this.tail=Promise.resolve();
    this.onlineTicket="";this.onlineUntil=0;this.offlineTicket="";this.offlineUntil=0;
    this.payloadReady=false;this.payloadNoCache=false;
    this.aad = buf(
      "authgo/node/cache/v2\0" +
        this.endpoint +
        "\0" +
        this.config.app_key +
        "\0" +
        this.fp,
    );
    this.cacheKey = hkdf(
      buf(this.config.app_secret),
      Buffer.from(sha(this.aad), "hex"),
      buf("authgo/multi/cache/key"),
    );
    this.file = path.join(this.cache, sha(this.aad) + ".cache");
    try {
      if (!this.memoryCache && fs.existsSync(this.file)) {
        if (fs.statSync(this.file).size > 16 * 1024 * 1024) throw Error();
        const raw = fs.readFileSync(this.file);
        if (raw.length > 16 * 1024 * 1024) throw Error();
        this.state = parse(
          open(this.cacheKey, raw.subarray(0, 12), raw.subarray(12), this.aad),
        );
      }
    } catch {
      this.state = {};
      this.cacheError = err("SDK_CACHE_INVALID");
    }
  }
  exclusive(fn) {
    const p = this.tail.then(fn);
    this.tail = p.catch(() => {});
    return p;
  }
  save() {
    if(this.memoryCache)return;
    try {
      makeCacheDirectory(this.cache);
      const n = random(12),
        temp = this.file + "." + b64(random(12));
      const fd = fs.openSync(temp, "wx", 0o600);
      try {
        fs.writeFileSync(
          fd,
          Buffer.concat([
            n,
            seal(this.cacheKey, n, buf(canonical(this.state)), this.aad),
          ]),
        );
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(temp, this.file);
    } catch {
      throw err("SDK_CACHE_UNAVAILABLE");
    }
  }
  saveWarning() {if(!this.memoryCache)this.cacheWarning=null;try{this.save();}catch(e){this.cacheWarning=e;} }
  revokeCache() {
    this.payloadReady = false;
    payloadKeys.clearPayloadKeys(this);
    Object.assign(this.state, { ticket: "", seed: "", refused: true });
    try {
      this.save();
    } catch {
      try {
        fs.rmSync(this.file, { force: true });
      } catch {}
    }
  }
  body() {
    return {
      instance_session: processSession,
      license_key: this.state.key || "",
      activation_token: this.state.token || "",
      device_fingerprint: this.fp,
      client_version: this.version,
      hostname: os.hostname().slice(0, 128),
      os: os.platform() === "win32" ? "windows" : os.platform(),
    };
  }
  async request(op, body = null) {
    const challenge = b64(random(32)),
      nonce = b64(random(32)),
      timestamp = String(Math.floor(this.now()));
    if (body !== null) body = { ...body, challenge };
    const raw = body === null ? "" : canonical(body),
      signature = mac(
        this.config.app_secret,
        op + timestamp + nonce + sha(raw),
      );
    const pair = crypto.generateKeyPairSync("x25519"),
      ep = b64(
        pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32),
      ),
      k = sha(this.gateway).slice(0, 16),
      aad = buf("authgo-gateway-v2\0" + k + "\0" + ep),
      salt = Buffer.from(sha(aad), "hex");
    let env;
    try {
      const shared = crypto.diffieHellman({
          privateKey: pair.privateKey,
          publicKey: pub("x", this.gateway),
        }),
        n = random(12),
        c = seal(
          hkdf(shared, salt, buf("authgo/v2/request")),
          n,
          pad(
            buf(
              canonical({
                app_key: this.config.app_key,
                op,
                timestamp,
                nonce,
                signature,
                body,
              }),
            ),
          ),
          aad,
        );
      const packet = { v: 2, k, e: ep, n: b64(n), c: b64(c) },
        responseAAD = Buffer.concat([
          aad,
          buf("\0" + sha(packet.n + "." + packet.c)),
        ]);
      const res = await this.transport(
        this.endpoint + "/gateway",
        buf(canonical(packet)),
        { "Content-Type": "application/json" },
        10000,
        2 * 1024 * 1024,
      );
      if (res.status !== 200) throw err("SDK_RESPONSE_INVALID");
      const outer = parse(res.body);
      if (Object.keys(outer).sort().join(",") !== "c,n") throw Error();
      env = parse(
        unpad(
          open(
            hkdf(shared, salt, buf("authgo/v2/response")),
            unb64(outer.n),
            unb64(outer.c),
            responseAAD,
          ),
        ),
      );
    } catch (e) {
      if (e instanceof AuthGoError) throw e;
      throw err("SDK_RESPONSE_INVALID");
    }
    try {
      if (
        typeof env.signature !== "string" ||
        !verifySignature(
          this.public,
          buf(canonical({ code: env.code, data: env.data, ts: env.ts })),
          standard(env.signature),
        )
      )
        throw Error();
    } catch {
      throw err("SDK_RESPONSE_SIGNATURE_INVALID");
    }
    if (env.nonce !== nonce || env.data?.request_nonce !== nonce)
      throw err("SDK_RESPONSE_NONCE_INVALID");
    if (Math.abs(Number(env.ts) - this.now()) > 300)
      throw err("SDK_RESPONSE_TIMESTAMP_INVALID");
    if (env.code !== "OK") {const e=new AuthGoError(env.code,"服务器拒绝请求",true);e.latestVersion=env.data.latest_version||"";e.latestEntitledVersion=env.data.latest_entitled_version||"";throw e;}
    return [env.data, challenge];
  }
  grant(ticket) {
    try {
      const p = ticket.split(".");
      if (p.length !== 2) throw Error();
      const raw = unb64(p[0]);
      if (
        !verifySignature(
          this.public,
          raw.length ? Buffer.concat([buf("authgo-ticket-v2\0"), raw]) : raw,
          unb64(p[1]),
        )
      )
        throw Error();
      const g = parse(raw);
      if (
        Number(g.v) !== 2 ||
        g.app_key !== this.config.app_key ||
        g.status !== "active" ||
        Number(g.license_id) <= 0 ||
        g.device_hash !== sha(this.fp) ||
        unb64(g.challenge).length !== 32 ||
        Number(g.next_check_in) < 1 ||
        Number(g.next_check_in) > 86400 ||
        date(g.grace_until) < date(g.issued_at)
      )
        throw Error();
      return g;
    } catch {
      throw err("SDK_RESPONSE_SIGNATURE_INVALID", "票据无效");
    }
  }
  validate(ticket) {
    this.ensureInstance();
    const g = this.grant(ticket),
      now = this.now();
    if (this.state.refused) throw err("SDK_NOT_ACTIVATED");
    if (now + 300 < Number(this.state.observed || 0))
      throw err("SDK_CLOCK_ROLLBACK");
    if (g.starts_at && now < date(g.starts_at))
      throw err("LICENSE_NOT_STARTED");
    if (now >= date(g.expires_at)) throw err("LICENSE_EXPIRED");
    if (g.floating && (!g.lease_expires_at || now >= date(g.lease_expires_at)) && !(ticket === this.offlineTicket && now < this.offlineUntil))
      throw err("LEASE_EXPIRED");
    if (
      now < date(g.grace_until) ||
      (ticket === this.onlineTicket && now < this.onlineUntil)
    )
      return g;
    throw err("SDK_GRACE_EXPIRED");
    return g;
  }
  async fallback(cause) {
    let g;
    try {
      if (this.state.refused || !this.state.ticket) throw Error();
      g = this.grant(this.state.ticket);
      if (sha(unb64(this.state.seed)) !== g.unlock_hash) throw Error();
    } catch {
      throw cause;
    }
    if (g.is_trial) throw err("SDK_GRACE_EXPIRED", "试用需要稳定联网");
    const now = this.now();
    if (now + 300 < Number(this.state.observed || 0))
      throw err("SDK_CLOCK_ROLLBACK");
    this.state.observed = Math.max(
      Math.floor(now),
      Number(this.state.observed || 0),
    );
    this.save();
    if (g.starts_at && now < date(g.starts_at))
      throw err("LICENSE_NOT_STARTED");
    if (now >= date(g.expires_at)) throw err("LICENSE_EXPIRED");
    const end = Math.min(date(g.grace_until), date(g.expires_at));
    this.offlineTicket=this.state.ticket;this.offlineUntil=end;
    this.saveWarning();
    if (now < end)
      return new Result(
        this,
        g,
        this.state.ticket,
        unb64(this.state.seed),
        "grace",
        end,
        String(cause),
      );
    throw new AuthGoError("SDK_GRACE_EXPIRED", "", false, cause);
  }
  validGrantTime(g) {
    const now = this.now();
    if (g.starts_at && now < date(g.starts_at))
      throw err("LICENSE_NOT_STARTED");
    if (now >= date(g.expires_at)) throw err("LICENSE_EXPIRED");
    if (g.floating && (!g.lease_expires_at || now >= date(g.lease_expires_at)))
      throw err("LEASE_EXPIRED");
  }
  async _guardCheck(key) {
    if (key) return this.check(key);
    key = this.state.trial_key || "";
    if (!key) {
      const [data, challenge] = await this.request("trial", {device_fingerprint:this.fp});
      if(data.challenge !== challenge) throw err("SDK_RESPONSE_NONCE_INVALID");
      key=data.license_key || ""; validateKey(key);
      this.state.trial_key=key; this.saveWarning();
    }
    return this.check(key);
  }
  async authorization(op, key) {
    try {
      const result = await this._authorization(op, key);
      if (op === "deactivate") {
        this.payloadReady = false;
        payloadKeys.clearPayloadKeys(this);
      } else if (result) payloadKeys.recordPayloadResult(this, result);
      return result;
    } catch (error) {
      if (error.refusal) {
        this.payloadReady = false;
        payloadKeys.clearPayloadKeys(this);
      }
      throw error;
    }
  }
  unlockPayload(payload) { return this.exclusive(() => payloadKeys.unlockPayload(this, payload)); }
  _unlockPayloadMaterial(payload) { return this.exclusive(() => payloadKeys.unlockPayloadMaterial(this, payload)); }
  savePayloadKey(payload, result, key) { return this.exclusive(() => payloadKeys.savePayloadKey(this, payloadKeys.coercePayload(payload), result, key)); }
  loadPayloadKey(payload, result) { return this.exclusive(() => payloadKeys.loadPayloadKey(this, payloadKeys.coercePayload(payload), result)); }
  clearPayloadKeys() { return this.exclusive(() => payloadKeys.clearPayloadKeys(this)); }
  rememberPayloadReplacement() {
    replacedInstances.add(this.instanceKey());
    this.offlineUntil = this.onlineUntil = 0;
  }
  async _authorization(op, key) {
    if (key !== undefined) validateKey(key);
    this.ensureInstance(op === "activate" ? key : undefined);
    if(op === "verify" && this.state.ticket) {try{const g=this.grant(this.state.ticket);if(g.floating && this.now()>=date(g.lease_expires_at))op="heartbeat";}catch{}}
    const previous = { ...this.state };
    if (op === "activate") {
      if (key !== this.state.key) {
        const { observed, trial_key } = this.state;
        this.state = {
          trial_key: trial_key || "",
          observed: observed || 0,
        };
      }
      this.state.key = key;
    } else if (!this.state.token) throw err("SDK_NOT_ACTIVATED");
    try {
      const body = this.body();
      if (op === "deactivate") delete body.instance_session;
      if (op === "activate") body.activation_token = "";
      const [d, ch] = await this.request(op, body);
      if (op === "deactivate") {
        if (!d.deactivated) throw err("SDK_RESPONSE_INVALID");
        Object.assign(this.state, {
          token: "",
          ticket: "",
          seed: "",
          refused: true,
        });
        this.save();
        return;
      }
      if (!d.license_id || !d.next_check_in) throw err("SDK_RESPONSE_INVALID");
      const g = this.grant(d.ticket),
        seed = unb64(d.unlock_seed);
      if (
        String(g.license_id) !== String(d.license_id) ||
        String(g.next_check_in) !== String(d.next_check_in)
      )
        throw err("SDK_RESPONSE_INVALID");
      if (g.challenge !== ch) throw err("SDK_RESPONSE_NONCE_INVALID");
      if (Math.abs(date(g.issued_at) - this.now()) > 300)
        throw err("SDK_RESPONSE_TIMESTAMP_INVALID");
      if (seed.length !== 32 || sha(seed) !== g.unlock_hash)
        throw err("SDK_RESPONSE_SIGNATURE_INVALID");
      this.validGrantTime(g);
      if (op === "activate") {
        if (!/^act_[A-Za-z0-9_-]{43}$/.test(d.activation_token))
          throw err("SDK_RESPONSE_INVALID");
        this.state.token = d.activation_token;
      }
      this.offlineTicket="";this.offlineUntil=0;
      this.onlineTicket = d.ticket;
      this.onlineUntil = this.now() + Number(g.next_check_in);
      delete this.state.status; delete this.state.availability; delete this.state.guard;
      Object.assign(this.state, {
        ticket: d.ticket,
        heartbeat_interval: heartbeatInterval(g, d.heartbeat_interval),
        seed: d.unlock_seed,
        refused: false,
        observed: Math.max(Math.floor(this.now()), date(g.issued_at)),
      });
      this.saveWarning();
      this.validate(d.ticket);
      return new Result(
        this,
        g,
        d.ticket,
        seed,
        "online",
        Math.min(
          Math.max(date(g.grace_until), this.onlineUntil),
          date(g.expires_at),
          g.floating ? date(g.lease_expires_at) : Infinity,
        ),
      );
    } catch (e) {
      if (!(e instanceof AuthGoError)) e = err("SDK_RESPONSE_INVALID");
      if(e.authenticated && e.code==="INSTANCE_REPLACED") {this.state=previous;replacedInstances.add(this.instanceKey(op==="activate"?key:undefined));this.offlineUntil=this.onlineUntil=0;throw e;}
      if (op === "activate" && previous.key !== key) {
        this.state = previous;
        throw e;
      }
      if (op === "activate" && e.refusal) {
        this.state.token = "";
        this.revokeCache();
        throw e;
      }
      if (["verify", "heartbeat"].includes(op)) {
        this.onlineUntil = 0;
        if (e.refusal) {
          this.revokeCache();
          throw e;
        }
        return this.fallback(e);
      }
      throw e;
    }
  }
  check(key) {
    return this.exclusive(() =>
      this.authorization(
        key === this.state.key && this.state.token ? "verify" : "activate",
        key,
      ),
    );
  }
  activate(key) {
    return this.exclusive(() => this.authorization("activate", key));
  }
  verify() {
    return this.exclusive(() => this.authorization("verify"));
  }
  heartbeat() {
    return this.exclusive(() => this.authorization("heartbeat"));
  }
  deactivate() {
    return this.exclusive(() => this.authorization("deactivate"));
  }
  instanceKey(key=this.state.key||"") { return this.endpoint+"\0"+this.config.app_key+"\0"+this.fp+"\0"+this.config.public_key+"\0"+key+"\0"+processSession; }
  ensureInstance(key) { if(replacedInstances.has(this.instanceKey(key)))throw err("INSTANCE_REPLACED"); }
  releaseSeat() { return this.exclusive(async()=>{
    if(!this.state.ticket || !this.grant(this.state.ticket).floating)return;
    try{await this.request("release-seat",this.body());}catch(e){
      if(e.refusal){this.payloadReady=false;payloadKeys.clearPayloadKeys(this);}
      if(e.authenticated && e.code==="INSTANCE_REPLACED"){replacedInstances.add(this.instanceKey());this.onlineUntil=this.offlineUntil=0;}
      else if(e.refusal)this.revokeCache();throw e;
    }
  }); }
  async announcements() {
    return (await this.request("announcement"))[0].items;
  }
  checkUpdate(currentVersion) {
    return this.exclusive(async () => {
      if (!this.state.token) throw err("SDK_NOT_ACTIVATED");
      const d = (
        await this.request("update.check", {
          ...this.body(),
          current_version: currentVersion,
          client_version: currentVersion,
        })
      )[0];
      return Object.fromEntries(Object.entries(d).filter(([key]) => ["available", "docker_image", "docker_pull", "version", "changelog", "mandatory", "published_at", "maintenance_until", "latest_entitled_version", "renewal_required"].includes(key)));
    });
  }
}

export { Codes } from "./codes.js";

export { EXIT_LICENSE, startGuard } from "./guard.js";

export { decryptPayloadFile, payloadCipherSize } from "./sealed.js";
