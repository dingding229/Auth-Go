// Run from the repository root. Snapshot the actual protected examples for the wizard.
import { readdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
const root = resolve(import.meta.dirname, "../.."),
  templates = {};
for (const name of [
  "go",
  "python",
  "node",
  "java",
  "csharp",
  "php",
  "rust",
  "php-fpm",
  "php-apache",
]) {
  const directory = `examples/docker-protected/${name}`,
    files = {};
  async function walk(base = "") {
    for (const entry of await readdir(resolve(root, directory, base), {
      withFileTypes: true,
    })) {
      if (
        ["target", "bin", "obj", "node_modules", "__pycache__"].includes(
          entry.name,
        )
      )
        continue;
      const path = base ? `${base}/${entry.name}` : entry.name;
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile())
        files[path] = await readFile(resolve(root, directory, path), "utf8");
    }
  }
  await walk();
  templates[name] = { directory, files };
}
await writeFile(
  resolve(root, "web/src/lib/protected-templates.json"),
  JSON.stringify(templates, null, 2) + "\n",
);
