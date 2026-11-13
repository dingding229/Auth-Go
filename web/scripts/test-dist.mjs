import assert from 'node:assert/strict'
import { readFile, readdir, realpath, stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { init, parse } from 'es-module-lexer'

const defaultDist = fileURLToPath(
  new URL('../dist/', import.meta.url),
)
const jsFile = (name) => /\.(?:m?js|cjs)$/.test(name)

function localPath(name, importer = '') {
  assert.equal(typeof name, 'string', `无效的分片路径：${String(name)}`)
  assert(
    !/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(name),
    `产物包含外部依赖：${name}`,
  )
  const pathname = decodeURIComponent(name.split(/[?#]/)[0])
  const relative = pathname.startsWith('/')
    ? pathname.slice(1)
    : path.posix.join(path.posix.dirname(importer), pathname)
  const normalized = path.posix.normalize(relative)
  assert(
    !path.posix.isAbsolute(normalized) &&
      normalized !== '..' &&
      !normalized.startsWith('../'),
    `依赖越出构建目录：${name}`,
  )
  assert(!normalized.includes('\\'), `无效的依赖路径：${name}`)
  return normalized
}

async function requireFile(root, name) {
  const filename = path.resolve(root, name)
  const resolved = await realpath(filename).catch(() => {
    throw new Error(`缺少产物文件：${name}`)
  })
  const relative = path.relative(root, resolved)
  assert(
    relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    `产物符号链接越出构建目录：${name}`,
  )
  const info = await stat(resolved)
  assert(info.isFile() && info.size > 0, `产物不是非空文件：${name}`)
  return info
}

async function walk(root, directory = 'assets') {
  const output = []
  for (const entry of await readdir(path.join(root, directory), {
    withFileTypes: true,
  })) {
    const name = `${directory}/${entry.name}`
    if (entry.isDirectory()) output.push(...(await walk(root, name)))
    else {
      const info = await requireFile(root, name)
      output.push({ file: name, bytes: info.size })
    }
  }
  return output.sort((a, b) => a.file.localeCompare(b.file, 'en'))
}

export function assertAcyclic(graph, label) {
  const states = new Map()
  const stack = []
  function visit(file) {
    if (states.get(file) === 2) return
    if (states.get(file) === 1) {
      const cycle = [...stack.slice(stack.indexOf(file)), file]
      throw new Error(`${label} 存在静态分片循环：\n  ${cycle.join('\n  -> ')}`)
    }
    states.set(file, 1)
    stack.push(file)
    for (const dependency of graph.get(file) ?? []) visit(dependency)
    stack.pop()
    states.set(file, 2)
  }
  for (const file of graph.keys()) visit(file)
}

// Read the actual emitted modules as well as the manifest: metadata alone can
// miss a bundler/plugin-generated import. Dynamic edges are not eager init edges.
export async function checkJavaScript(dist) {
  const root = await realpath(dist)
  const assets = await walk(root)
  const graph = new Map()
  let staticImports = 0,
    dynamicImports = 0,
    computedImports = 0
  await init
  for (const asset of assets.filter((item) => jsFile(item.file))) {
    const source = await readFile(path.join(root, asset.file), 'utf8')
    const [imports] = parse(source, asset.file)
    const dependencies = new Set()

    for (const item of imports) {
      assert(
        ['static', 'reexport-star', 'dynamic', 'import-meta'].includes(
          item.type,
        ),
        'ES 模块解析器返回了不支持的记录格式',
      )
      if (item.type === 'import-meta') continue
      const dynamic = item.type === 'dynamic'
      if (dynamic && (item.specifier === undefined || item.glob)) {
        computedImports++
        continue
      }
      assert.equal(
        typeof item.specifier,
        'string',
        `无法识别静态依赖：${asset.file}`,
      )
      assert(
        item.specifier.startsWith('.') || item.specifier.startsWith('/'),
        `分片含未打包的裸模块依赖：${asset.file} -> ${item.specifier}`,
      )
      const target = localPath(item.specifier, asset.file)
      await requireFile(root, target)
      if (!dynamic) {
        staticImports++
        if (jsFile(target)) dependencies.add(target)
      } else dynamicImports++
    }

    graph.set(asset.file, dependencies)
  }
  assert(graph.size > 0, '构建目录没有 JavaScript 分片')
  assertAcyclic(graph, '实际 JS import 图')
  return {
    assets,
    modules: graph.size,
    staticImports,
    dynamicImports,
    computedImports,
  }
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
function list(value, field) {
  if (value === undefined) return []
  assert(
    Array.isArray(value) && value.every((item) => typeof item === 'string'),
    `manifest.${field} 必须是字符串数组`,
  )
  return value
}

export async function checkDist(dist = defaultDist) {
  const root = await realpath(dist)
  const manifestFile = path.join(root, '.vite/manifest.json')
  const manifest = JSON.parse(
    await readFile(manifestFile, 'utf8').catch(() => {
      throw new Error('缺少 Vite manifest，请先运行 npm run build')
    }),
  )
  assert(
    object(manifest) && Object.keys(manifest).length > 0,
    'Vite manifest 为空或格式不正确',
  )
  const graph = new Map(),
    entryFiles = new Set()
  for (const [key, chunk] of Object.entries(manifest)) {
    assert(
      object(chunk) && typeof chunk.file === 'string',
      `manifest 条目无效：${key}`,
    )
    const file = localPath(chunk.file)
    await requireFile(root, file)
    if (chunk.isEntry) entryFiles.add(file)
    if (!graph.has(file)) graph.set(file, new Set())
    for (const [kind, refs] of [
      ['imports', chunk.imports],
      ['dynamicImports', chunk.dynamicImports],
    ]) {
      for (const reference of list(refs, kind)) {
        const target = manifest[reference]
        assert(
          object(target) && typeof target.file === 'string',
          `manifest 引用不存在：${key} -> ${reference}`,
        )
        const dependency = localPath(target.file)
        await requireFile(root, dependency)
        if (kind === 'imports' && dependency !== file)
          graph.get(file).add(dependency)
      }
    }
    for (const extra of [
      ...list(chunk.css, 'css'),
      ...list(chunk.assets, 'assets'),
    ])
      await requireFile(root, localPath(extra))
  }
  assert(entryFiles.size > 0, 'manifest 没有应用入口')
  assertAcyclic(graph, 'manifest 静态 import 图')

  const html = await readFile(path.join(root, 'index.html'), 'utf8')
  const attribute = (tag, key) =>
    new RegExp(`\\b${key}=["']([^"']+)["']`, 'i').exec(tag)?.[1]
  let scripts = 0
  for (const match of html.matchAll(/<script\b[^>]*>/gi)) {
    const tag = match[0]
    if (attribute(tag, 'type') !== 'module') continue
    const source = attribute(tag, 'src')
    assert(source, 'index.html 的 module 入口缺少 src')
    const file = localPath(source)
    await requireFile(root, file)
    assert(entryFiles.has(file), `HTML 入口与 manifest 不一致：${file}`)
    scripts++
  }
  assert(scripts > 0, 'index.html 没有可执行的 module 入口')
  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    const tag = match[0],
      rel = attribute(tag, 'rel')
    if (rel === 'stylesheet' || rel === 'modulepreload') {
      const href = attribute(tag, 'href')
      assert(href, `index.html 的 ${rel} 缺少 href`)
      await requireFile(root, localPath(href))
    }
  }
  const result = await checkJavaScript(root)
  return { ...result, entries: entryFiles.size, root }
}

async function main() {
  const result = await checkDist(process.argv[2] ?? defaultDist)
  console.log(
    `PASS: manifest / HTML 入口与资源完整（${result.entries} 个入口）`,
  )
  console.log(
    `PASS: ${result.modules} 个实际 JS 分片，${result.staticImports} 条静态依赖，无静态循环`,
  )
  console.log(
    `PASS: ${result.dynamicImports} 条字面量动态依赖目标存在（不作为初始化环）`,
  )
  if (result.computedImports)
    console.log(
      `注意：${result.computedImports} 条计算型 import() 无法静态解析，需在浏览器中运行`,
    )
  console.log(
    '检查级别：构建产物静态冒烟，未执行浏览器 JavaScript 或 DOM 初始化。',
  )
  console.log('\n分片清单（文件名\t字节\tKiB）：')
  for (const item of result.assets)
    console.log(
      `${item.file}\t${item.bytes}\t${(item.bytes / 1024).toFixed(2)}`,
    )
}

if (
  process.argv[1] &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  main().catch((error) => {
    console.error(`FAIL: ${error.message}`)
    process.exitCode = 1
  })
}
