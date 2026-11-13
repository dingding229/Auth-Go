import fs from "node:fs";
let source = fs.readFileSync("/src/example/main.mjs", "utf8");
source = source.replace("const CONFIG = null;", `const CONFIG = ${JSON.stringify(process.env.AUTHGO_CONFIG)};`);
source = source.replace("const VERSION = null;", `const VERSION = ${JSON.stringify(process.env.VERSION)};`);
fs.mkdirSync("/launcher");
fs.writeFileSync("/launcher/main.mjs", source);
