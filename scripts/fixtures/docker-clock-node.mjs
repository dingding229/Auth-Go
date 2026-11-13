// Test image ONLY; not copied by the production example's Dockerfile.
import { startGuard, EXIT_LICENSE } from "authgo";
import build from "./authgo-build.json" with { type: "json" };
let advance = false;
const keepAlive = setInterval(() => {}, 1000);
try {
  const guard = await startGuard({ config: build.config, version: build.version,
    clock: () => Date.now()/1000 + (advance ? 72*3600+1 : 0),
    onChange(result,error) {
      if(result?.status === "grace") advance = true;
      console.log(`clock agent: ${error ?? result.status}`);
    }
  });
  console.log("clock ready"); await guard.done;
  console.log(`clock stopped: ${guard.error}`);
  try { await guard.close(); } catch {}
} catch (error) { console.error(`clock startup: ${error}`); }
clearInterval(keepAlive);process.exitCode = EXIT_LICENSE;
