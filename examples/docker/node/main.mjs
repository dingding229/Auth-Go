import http from "node:http";
import { startGuard, EXIT_LICENSE, canonical } from "authgo";
import build from "./authgo-build.json" with { type: "json" };

let stopping = false, wake, guard;
const stopped = new Promise(resolve => { wake = resolve; });
for (const name of ["SIGTERM", "SIGINT"]) process.on(name, () => { stopping = true; wake(); if (!guard) process.exit(0); });
async function run() {
  try { guard = await startGuard({ config: build.config, version: build.version, onChange(r,e) {
    console.log(e ? `授权检查: ${e}` : `授权状态: ${r.status}`);
    if (r?.cacheWarning) console.log(`缓存提示: ${r.cacheWarning}`);
  } }); } catch (e) { console.error(`授权验证失败: ${e}`); return EXIT_LICENSE; }
  if (guard.result().isTrial) console.log("当前为试用");
  if (guard.result().cacheWarning) console.log(`缓存提示: ${guard.result().cacheWarning}`);
  const server = http.createServer((_,res) => {
    try { guard.require(""); res.setHeader("Content-Type","application/json"); res.end(canonical({features:guard.result().features})); }
    catch { res.writeHead(403); res.end("license unavailable\n"); }
  });
  const addr = process.argv[process.argv.indexOf("-listen")+1];
  const [host,port] = process.argv.includes("-listen") ? addr.split(":") : ["", "8080"];
  try {
    await new Promise((resolve,reject) => { server.once("error",reject);server.listen(Number(port),host || "0.0.0.0",resolve); });
    console.log(`HTTP已启动 version=${build.version}`);
    await Promise.race([stopped,guard.done]);
    if (!stopping && guard.error) { console.error(`授权已失效: ${guard.error}`); return EXIT_LICENSE; }
    return 0;
  } finally {
    // Bound business HTTP shutdown independently of the SDK's five-second close.
    server.close(); server.closeAllConnections();
    try { await guard.close(); } catch(e) { console.error(`释放席位: ${e}`); }
  }
}
// The application owns exit, so an uncooperative HTTP transport cannot keep PID1 alive.
process.exit(await run());
