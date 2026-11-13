// Node 22 _compile experiment; also exercised from ESM and CommonJS hosts.
import assert from "node:assert/strict";
import Module from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
const filename = fileURLToPath(
  new URL("../__authgo_experiment__.cjs", import.meta.url),
);
const instance = new Module(filename);
instance.filename = filename;
instance.paths = Module._nodeModulePaths(path.dirname(filename));
instance._compile(
  'exports.name = require("./package.json").name; exports.builtin = require.resolve("node:fs"); module.exports.answer = 42;',
  filename,
);
assert.equal(instance.exports.name, "authgo");
assert.equal(instance.exports.answer, 42);
assert.equal(instance.exports.builtin, "node:fs");
const replacement = new Module(filename);
replacement.filename = filename;
replacement._compile("module.exports = x => x + 1", filename);
assert.equal(replacement.exports(41), 42);
const failure = new Module(filename);
assert.throws(
  () => failure._compile('throw new TypeError("experiment failure")', filename),
  { name: "TypeError", message: "experiment failure" },
);
console.log(
  JSON.stringify({
    node: process.versions.node,
    compile_arity: instance._compile.length,
    commonjs_exports: "PASS",
    require_resolution: "PASS",
    exception: "PASS",
  }),
);
