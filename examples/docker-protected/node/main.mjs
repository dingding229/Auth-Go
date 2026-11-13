import http from "node:http";
import { startGuard, EXIT_LICENSE, canonical } from "./sdk/index.js";

const CONFIG = null;
const VERSION = null;
let stopping = false, wake, guard;
const stopped = new Promise(resolve => { wake = resolve; });
for (const name of ["SIGTERM", "SIGINT"]) process.on(name, () => { stopping = true; wake(); });
async function run() {
  let server;
  try {
    guard = await startGuard({ config: CONFIG, version: VERSION });
    if (stopping) return 0;
    const core = await guard.requireSealed("core");
    server = http.createServer((_, response) => {
      try {
        response.setHeader("Content-Type", "application/json");
        response.end(canonical(core(guard)));
      } catch {
        response.writeHead(503); response.end("license unavailable\n");
      }
    });
    const index = process.argv.indexOf("-listen");
    const [host, port] = index >= 0 ? process.argv[index + 1].split(":") : ["", "8080"];
    await new Promise((resolve, reject) => {
      server.once("error", reject); server.listen(Number(port), host || "0.0.0.0", resolve);
    });
    console.log(`HTTP已启动 version=${VERSION}`);
    await Promise.race([stopped, guard.done]);
    return stopping ? 0 : EXIT_LICENSE;
  } catch (error) {
    console.error(`授权验证失败: ${error}`);
    return EXIT_LICENSE;
  } finally {
    if (server) { server.close(); server.closeAllConnections(); }
    if (guard) try { await guard.close(); } catch (error) { console.error(`释放席位: ${error}`); }
  }
}
process.exit(await run());
