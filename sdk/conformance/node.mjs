import readline from "node:readline";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client, AuthGoError, httpRequest } from "../node/index.js";
let client,
  result,
  update,
  clock = Date.now() / 1000;
for await (const line of readline.createInterface({ input: process.stdin })) {
  let out = { code: "OK" };
  try {
    const p = JSON.parse(line);
    switch (p.op) {
      case "init":
        clock = p.time || Date.now() / 1000;
        client = new Client(p.config, {
          fingerprint: p.automatic ? undefined : (p.fingerprint || "a".repeat(64)),
          cacheDir:
            p.cache_dir || fs.mkdtempSync(path.join(os.tmpdir(), "authgo-")),
          version: p.unversioned ? "" : (p.version || "1.0.0"),
          clock: () => clock,
          transport: (...args) =>
            httpRequest(...args, {}),
        });
        out.status = "ready";
        break;
      case "clock":
        clock += p.seconds;
        break;
      case "check":
      case "activate":
        result = await client[p.op](p.key);
        out.status = result.status;
        break;
      case "verify":
      case "heartbeat":
        result = await client[p.op]();
        out.status = result.status;
        break;
      case "guard_check": result=await client._guardCheck(p.key||"");out.status=result.status;break;
      case "trial_info":out.is_trial=result.isTrial;break;
      case "release_seat": await client.releaseSeat();break;
      case "entitlement":out.maintenance_until=result.maintenanceUntil;out.latest_entitled_version=result.latestEntitledVersion;break;
      case "validate": client.validate(result.ticket());break;
      case "identity": out.fingerprint=client.fp;break;
      case "cache_warning": out.cache_warning=!!result.cacheWarning;break;
      case "deactivate":
        await client.deactivate();
        break;
      case "announcements":
        out.count = (await client.announcements()).length;
        break;
      case "check_update":
        update = await client.checkUpdate(p.version || "1.0.0");
        out.available = update.available;
        out.version = update.version || "";
        out.docker_image = update.docker_image || ""; out.docker_pull = update.docker_pull || "";
        break;
      default:
        throw Error("unsupported");
    }
  } catch (e) {
    out = {
      ...(e.latestVersion ? {latest_version:e.latestVersion}:{}),
      ...(e.code === "MAINTENANCE_EXPIRED" ? {latest_entitled_version:e.latestEntitledVersion}:{}),
      code: e instanceof AuthGoError ? e.code : "RUNNER_ERROR",
      ...(e instanceof AuthGoError ? {} : { detail: e.constructor.name }),
    };
  }
  console.log(JSON.stringify(out));
}
