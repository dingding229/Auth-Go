// @vitest-environment node
import { afterEach, expect, it } from "vitest";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { checkDist } from "../scripts/test-dist.mjs";

const folders: string[] = [];
async function fixture(files: Record<string, string>, manifest: unknown) {
  const root = await mkdtemp(path.join(tmpdir(), "authgo-dist-test-"));
  folders.push(root);
  await mkdir(path.join(root, "assets"));
  await mkdir(path.join(root, ".vite"));
  for (const [name, text] of Object.entries(files))
    await writeFile(path.join(root, name), text);
  await writeFile(
    path.join(root, ".vite/manifest.json"),
    JSON.stringify(manifest),
  );
  await writeFile(
    path.join(root, "index.html"),
    '<div id="app"></div><script type="module" src="/assets/entry.js"></script>',
  );
  return root;
}
afterEach(async () => {
  await Promise.all(
    folders
      .splice(0)
      .map((folder) => rm(folder, { recursive: true, force: true })),
  );
});

it("通过实际静态依赖DAG，允许合法的路由动态回边", async () => {
  const root = await fixture(
    {
      "assets/entry.js":
        "import './vendor.js'; export const ready = true; export const load = () => import('./lazy.js');",
      "assets/vendor.js": "export const value = 1;",
      "assets/lazy.js":
        "import {ready} from './entry.js'; export default ready;",
    },
    {
      "index.html": {
        file: "assets/entry.js",
        isEntry: true,
        imports: ["vendor"],
        dynamicImports: ["lazy"],
      },
      vendor: { file: "assets/vendor.js" },
      lazy: { file: "assets/lazy.js", imports: ["index.html"] },
    },
  );
  const result = await checkDist(root);
  expect(result.modules).toBe(3);
  expect(result.dynamicImports).toBe(1);
  expect(result.staticImports).toBe(2);
});

it("拒绝manifest中UI分片的静态循环", async () => {
  const root = await fixture(
    {
      "assets/entry.js": "import './ui-a.js';",
      "assets/ui-a.js": "import './ui-b.js';",
      "assets/ui-b.js": "import './ui-a.js';",
    },
    {
      "index.html": { file: "assets/entry.js", isEntry: true, imports: ["a"] },
      a: { file: "assets/ui-a.js", imports: ["b"] },
      b: { file: "assets/ui-b.js", imports: ["a"] },
    },
  );
  await expect(checkDist(root)).rejects.toThrow(/manifest.*静态分片循环/);
});

it("即使manifest漏报，也从真实生成JS检出初始化环", async () => {
  const root = await fixture(
    {
      "assets/entry.js": "import './ui-a.js';",
      "assets/ui-a.js": "export { b } from './ui-b.js'; export const a = 1;",
      "assets/ui-b.js": "import { a } from './ui-a.js'; export const b = a;",
    },
    { "index.html": { file: "assets/entry.js", isEntry: true } },
  );
  await expect(checkDist(root)).rejects.toThrow(/实际 JS.*静态分片循环/);
});

it("拒绝丢失的字面量动态分片", async () => {
  const root = await fixture(
    { "assets/entry.js": "export const load = () => import('./missing.js');" },
    { "index.html": { file: "assets/entry.js", isEntry: true } },
  );
  await expect(checkDist(root)).rejects.toThrow(
    "缺少产物文件：assets/missing.js",
  );
});

it("拒绝不存在的manifest引用", async () => {
  const root = await fixture(
    { "assets/entry.js": "export const ok = 1;" },
    {
      "index.html": {
        file: "assets/entry.js",
        isEntry: true,
        imports: ["missing"],
      },
    },
  );
  await expect(checkDist(root)).rejects.toThrow("manifest 引用不存在");
});

it("拒绝HTML与构建入口不一致", async () => {
  const root = await fixture(
    {
      "assets/entry.js": "export const ok = 1;",
      "assets/other.js": "export const ok = 2;",
    },
    { "index.html": { file: "assets/other.js", isEntry: true } },
  );
  await expect(checkDist(root)).rejects.toThrow("HTML 入口与 manifest 不一致");
});

it("拒绝越出dist的分片路径", async () => {
  const root = await fixture(
    { "assets/entry.js": "import '../../outside.js';" },
    { "index.html": { file: "assets/entry.js", isEntry: true } },
  );
  await expect(checkDist(root)).rejects.toThrow("依赖越出构建目录");
});
