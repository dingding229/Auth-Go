// Real Chromium + production dist + native Worker/DecompressionStream.
// API RESPONSES ARE EXPLICIT MOCK FIXTURES: this is NOT an auth-backend E2E test.
// Parent runs this script after building dist; no dependency installation/build here.
// AUTHGO_PLAYWRIGHT points to the externally provisioned temporary Playwright module.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdir, open, readFile, writeFile} from 'node:fs/promises';
import {basename, extname, resolve, sep} from 'node:path';
import {createHash} from 'node:crypto';
import {deflateRawSync} from 'node:zlib';
import {fileURLToPath} from 'node:url';

const dist = fileURLToPath(new URL('../dist/', import.meta.url));
const runtimeHtml = async () => {
  const html = await readFile(resolve(dist, 'index.html'), 'utf8');
  return html.replace('</head>', '<script id="authgo-runtime" type="application/json">{"admin_path":"/admin"}</script></head>');
};
const repo = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const out = process.env.AUTHGO_SCREENSHOTS ? resolve(process.env.AUTHGO_SCREENSHOTS) : resolve(repo, '.authgo-watermark-trace-ui');
const exportRoot = process.env.AUTHGO_WATERMARK_E2E_OUT ? resolve(process.env.AUTHGO_WATERMARK_E2E_OUT) : (process.env.AUTHGO_EXPORT_ROOT ? resolve(process.env.AUTHGO_EXPORT_ROOT) : '');
assert.ok(exportRoot, '请先运行 python3 scripts/test-watermark-e2e.py，并设置 AUTHGO_WATERMARK_E2E_OUT');
const fixtureRoot = resolve(out, 'test-only-fixtures');
const TAG = '0123456789abcdef0123456789abcdef';
const WM = 'b7'.repeat(32);
const SLOT = Buffer.from(TAG + WM);
const otherTag = 'fedcba9876543210fedcba9876543210';
const defaultTags = [{key_id: 'pk_historical_runtime', tag: TAG}, {key_id: 'pk_current_fixture', tag: otherTag}];
const manifest = JSON.parse(await readFile(resolve(exportRoot, 'browser-inputs.json'), 'utf8'));
for (const row of manifest) {
  assert.equal(typeof row.key_id, 'string');
  assert.match(String(row.tag), /^[0-9a-f]{32}$/);
  assert.match(String(row.watermark), /^(?!0{64}$)[0-9a-f]{64}$/);
}
const realTags = [...new Map(manifest.map(row => [row.key_id + ':' + row.tag, {key_id: row.key_id, tag: row.tag}])).values()];
const fullTags = [...new Map([...defaultTags, ...realTags].map(item => [item.key_id + ':' + item.tag, item])).values()];
const allowedWatermarks = new Set([WM, ...manifest.map(row => row.watermark)]);
const allowedBodies = [...allowedWatermarks].map(watermark => Buffer.from(JSON.stringify({watermark})));
const widths = [1440, 1024, 375, 320];
const reports = {
  label: 'MOCK-API / genuine runtime-export inputs / real production Chromium Worker',
  scope: 'NOT real auth-backend E2E; API identity, authorization lookup and trial source metadata are synthetic fixtures.',
  startedAt: new Date().toISOString(), status: 'RUNNING', dist, exportRoot,
  inputs: [], cases: [], viewports: [], screenshots: [], sharedVectors: [],
};
const network = [], errors = [], privacyViolations = [], names = new Set(), fragments = [];
let expectedWatermark, lastExpectedWatermark;
let server, browser, currentPage, origin;
await mkdir(out, {recursive: true});

function rememberName(path) {
  const name = basename(path);
  names.add(name); names.add(encodeURIComponent(name));
}
function rememberFragments(label, bytes) {
  // Exact binary and UTF-8 slices, not a fuzzy text heuristic. Exclude anything
  // already in the explicitly permitted watermark-only JSON body.
  for (const offset of new Set([0, 16, Math.max(0, Math.floor(bytes.length / 2) - 16), Math.max(0, bytes.length - 48)])) {
    const part = bytes.subarray(offset, Math.min(bytes.length, offset + 32));
    if (part.length < 16 || allowedBodies.some(body => body.includes(part))) continue;
    fragments.push({label, bytes: Buffer.from(part)});
  }
}
function occurrences(bytes, needle = SLOT) {
  const positions = [];
  for (let offset = bytes.indexOf(needle); offset >= 0; offset = bytes.indexOf(needle, offset + 1)) positions.push(offset);
  return positions;
}
function inspectPrivacy(row, bytes) {
  const url = decodeURIComponent(row.url), metadata = Buffer.from(JSON.stringify({url, method: row.method, headers: row.headers}));
  for (const name of names) {
    if (row.url.includes(name) || url.includes(name) || (row.postData || '').includes(name)) {
      privacyViolations.push({request: row.number, reason: 'filename transferred', name});
    }
  }
  for (const fragment of fragments) {
    if (bytes.includes(fragment.bytes) || metadata.includes(fragment.bytes) ||
        row.url.includes(fragment.bytes.toString('base64')) ||
        (row.postData || '').includes(fragment.bytes.toString('base64')) ||
        (row.postData || '').includes(fragment.bytes.toString('hex'))) {
      privacyViolations.push({request: row.number, reason: 'export/fixture fragment transferred', input: fragment.label});
    }
  }
  if (/multipart\/form-data|application\/octet-stream/i.test(row.headers['content-type'] || '')) {
    privacyViolations.push({request: row.number, reason: 'upload content type'});
  }
  // No file upload on ANY endpoint, not merely the trace endpoint. All fixture
  // writes in this test are trace requests with exactly the one permitted field.
  if (bytes.length && !(new URL(row.url).pathname === '/api/v1/admin/applications/7/watermark-trace' && allowedBodies.some(body => bytes.equals(body)))) {
    privacyViolations.push({request: row.number, reason: 'non-watermark request body'});
  }
}
function captureRequest(request, width) {
  const bytes = request.postDataBuffer() || Buffer.alloc(0);
  const row = {
    number: network.length + 1, width, url: request.url(), method: request.method(),
    headers: request.headers(), postData: request.postData(),
    postDataBase64: bytes.length ? bytes.toString('base64') : null,
  };
  network.push(row); inspectPrivacy(row, bytes);
}
async function persist() {
  await writeFile(resolve(out, 'results.json'), JSON.stringify(reports, null, 2) + '\n');
  await writeFile(resolve(out, 'network.json'), JSON.stringify({
    label: reports.label, capturesAllContextRequests: true, requests: network,
    checks: {filenames: [...names], exactFragmentSamples: fragments.length, watermarkOnlyBody: {watermark: WM}},
    privacyViolations,
  }, null, 2) + '\n');
  await writeFile(resolve(out, 'errors.json'), JSON.stringify(errors, null, 2) + '\n');
}
function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return (value ^ 0xffffffff) >>> 0;
}
function zip(entries) {
  // Test-only ZIP assembly with Node stdlib: real deflate-raw, CRC and sizes.
  // These archives wrap genuine exports; no production ZIP dependency is added.
  let offset = 0;
  const bodies = [], directory = [];
  for (const entry of entries) {
    const name = Buffer.from(entry.name), raw = entry.data;
    const method = entry.method ?? 8, flags = entry.flags ?? 0;
    const data = method === 8 ? deflateRawSync(raw) : raw, crc = crc32(raw);
    const local = Buffer.alloc(30), central = Buffer.alloc(46);
    local.writeUInt32LE(0x04034b50); local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6); local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    central.writeUInt32LE(0x02014b50); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8); central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28); central.writeUInt32LE(offset, 42);
    bodies.push(local, name, data); directory.push(central, name);
    offset += local.length + name.length + data.length;
  }
  const cd = Buffer.concat(directory), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...bodies, cd, end]);
}
async function fixture(name, data, provenance) {
  const path = resolve(fixtureRoot, name);
  assert.ok(path.startsWith(fixtureRoot + sep));
  await writeFile(path, data); rememberName(path); rememberFragments(name, data);
  reports.inputs.push({path, bytes: data.length, sha256: createHash('sha256').update(data).digest('hex'), provenance, testOnly: true});
  return path;
}
function observed(result) {
  const {status, watermark, count, slots, zeros, complete} = result;
  return {status, ...(watermark === undefined ? {} : {watermark}), count, slots, zeros, complete};
}

try {
  assert.equal(process.platform, 'linux', 'This script requires Linux.');
  await readFile(resolve(dist, 'index.html')); // Require the parent's real, existing production build.
  const rows = language => manifest.filter(row => row.language === language && !row.is_trial);
  const ordered = [];
  const javaByLicense = new Map();
  for (const row of rows('java')) {
    const key = String(row.license_id);
    if (!javaByLicense.has(key)) javaByLicense.set(key, []);
    javaByLicense.get(key).push(row);
  }
  const javaGroup = [...javaByLicense.values()].find(group => group.length >= 2);
  assert.ok(javaGroup, 'E2E 输出缺少同一授权的两个 Java 真实导出');
  for (const language of ['java', 'csharp', 'python', 'go', 'node', 'rust', 'php']) {
    const candidates = rows(language);
    assert.ok(candidates.length, 'E2E 输出缺少 '+language+' 真实导出');
    ordered.push(language === 'java' ? javaGroup[0] : candidates[0]);
    if (language === 'java') ordered.push(javaGroup[1]);
  }
  await mkdir(fixtureRoot, {recursive: true});
  const genuine = [];
  for (const row of ordered) {
    const label = row.language + ' ' + row.variant;
    const path = resolve(row.file), bytes = await readFile(path);
    assert.ok(path.startsWith(resolve(exportRoot) + sep));
    assert.equal(occurrences(bytes, Buffer.from(row.tag + row.watermark)).length, row.expected_total_slots, label + ': real export slot count differs from E2E manifest');
    rememberName(path); rememberFragments(label, bytes);
    genuine.push({...row, label, path, bytes});
    reports.inputs.push({path, label, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'),
      provenance: 'Genuine process/loaded-code export from the preceding E2E run.', testOnly: false});
  }
  const javaPrimary = genuine.find(row => row.language === 'java');
  const javaSecondary = genuine.filter(row => row.language === 'java')[1];
  assert.ok(javaPrimary && javaSecondary);
  const javaSlot = Buffer.from(javaPrimary.tag + javaPrimary.watermark);
  const damaged = Buffer.from(javaPrimary.bytes);
  const damagedExpected = {status: 'found', count: javaPrimary.expected_consistent_slots - 4, slots: javaPrimary.expected_total_slots - 4, zeros: 0, complete: true};
  for (const position of occurrences(damaged, javaSlot).slice(0, 4)) damaged[position] = 120; // x invalidates ONLY four tag prefixes.
  assert.ok(javaPrimary.expected_total_slots >= 4, 'Java export must contain at least four slots for the damage case');
  assert.equal(occurrences(damaged, javaSlot).length, javaPrimary.expected_total_slots - 4);
  const halfPath = await fixture('derived-test-only-half-damaged.class', damaged, 'Test-only copy of Java runtime export; the first four tag prefixes deliberately damaged.');
  const zipPath = await fixture('derived-test-only-runtime-exports.zip', zip([
    {name: 'classes/Business.class', data: javaPrimary.bytes},
    {name: 'classes/Business-2.class', data: javaSecondary.bytes},
  ]), 'Deflated ZIP wrapping two unchanged genuine Java exports from the same license.');
  const inner = zip([{name: 'watermark/Business.class', data: javaSecondary.bytes}]);
  const nestedPath = await fixture('derived-test-only-nested-runtime.jar', zip([
    {name: 'BOOT-INF/classes/Export.class', data: javaPrimary.bytes},
    {name: 'BOOT-INF/lib/business.jar', data: inner},
  ]), 'Deflated nested JAR wrapping both unchanged genuine Java exports.');
  const zeroPath = await fixture('synthetic-test-only-zero.bin', Buffer.from(Array(javaPrimary.expected_total_slots).fill(TAG + '0'.repeat(64)).join('|')), 'Synthetic all-zero slot fixture; not a genuine export.');
  const nonePath = await fixture('synthetic-test-only-no-slot.bin', Buffer.from('LOCAL-ONLY-NO-SLOT-PRIVACY-CANARY-watermark-not-business-code'), 'Synthetic no-slot fixture.');
  const ambiguousPath = await fixture('synthetic-test-only-ambiguous.bin', Buffer.from(TAG + WM + '|' + TAG + 'c3'.repeat(32)), 'Synthetic equal-frequency nonzero values.');
  const partialPath = await fixture('derived-test-only-partial.zip', zip([
    {name: 'verified-runtime.class', data: javaPrimary.bytes},
    {name: 'unsupported-compression.bin', data: Buffer.from('LOCAL-ONLY-UNSUPPORTED-ENTRY-CANARY-watermark'), method: 99},
  ]), 'Verified genuine entry followed by unsupported compression; partial must preserve only the prior verified entry.');
  const encryptedPath = await fixture('synthetic-test-only-encrypted.zip', zip([
    {name: 'encrypted.class', data: javaPrimary.bytes, flags: 1},
  ]), 'Test-only encrypted-flag fixture, not an actual encrypted archive; must be rejected before attribution.');
  const cancelPath = resolve(fixtureRoot, 'synthetic-test-only-cancel-large.bin');
  const sparse = await open(cancelPath, 'w');
  try {
    await sparse.truncate(256 * 1024 * 1024);
    await sparse.write(SLOT, 0, SLOT.length, 256 * 1024 * 1024 - SLOT.length);
  } finally { await sparse.close(); }
  rememberName(cancelPath); rememberFragments('cancel canary slot', SLOT);
  reports.inputs.push({path: cancelPath, bytes: 256 * 1024 * 1024, provenance: 'Test-only sparse zero-prefix file with one final slot; gives the user a genuine cancellable stream, not a delayed/mock Worker.', testOnly: true});
  // Required parent-owned data. fileURLToPath avoids treating a file URL as a Vite asset import.
  const vectorPath = resolve(repo, 'sdk/vectors/watermark.json');
  const vectors = JSON.parse(await readFile(vectorPath, 'utf8'));
  rememberName('shared-vector-local-only.bin');
  assert.equal(vectors.v, 1); assert.equal(vectors.scan.length, 22);
  for (const vector of vectors.scan) rememberFragments('shared vector ' + vector.name, Buffer.from(vector.bytes_b64, 'base64'));
  reports.sharedVectorFile = vectorPath;

  server = createServer(async (req, res) => {
    try {
      const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
      const path = resolve(dist, '.' + (pathname === '/' ? '/index.html' : pathname));
      if (!path.startsWith(resolve(dist) + sep)) { res.writeHead(403).end(); return; }
      let bytes, servedPath = path;
      try { bytes = await readFile(path); }
      catch (error) {
        if (error.code !== 'ENOENT' || extname(path)) { res.writeHead(404).end(); return; }
        servedPath = resolve(dist, 'index.html'); bytes = await readFile(servedPath);
      }
      res.setHeader('cache-control', 'no-store');
      res.setHeader('content-type', ({'.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.html': 'text/html; charset=utf-8', '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon'})[extname(servedPath)] || 'application/octet-stream');
      res.end(extname(servedPath) === '.html' ? await runtimeHtml() : bytes);
    } catch (error) {
      errors.push({kind: 'static-server', message: error.message});
      res.writeHead(500).end();
    }
  });
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  origin = 'http://127.0.0.1:' + server.address().port;
  const {chromium} = await import(process.env.AUTHGO_PLAYWRIGHT || 'playwright');
  browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
  reports.browserVersion = browser.version(); reports.origin = origin;

  for (const width of widths) {
    const context = await browser.newContext({viewport: {width, height: 1000}, isMobile: width < 768, hasTouch: width < 768,
      timezoneId: 'Asia/Shanghai', permissions: ['clipboard-read', 'clipboard-write'], serviceWorkers: 'block'});
    context.on('request', request => captureRequest(request, width));
    await context.addInitScript(() => {
      globalThis.sessionStorage.setItem('authgo.admin.access', 'watermark-mock-api-public-test');
      globalThis.sessionStorage.setItem('authgo.admin.refresh', 'watermark-mock-api-public-test');
      globalThis.sessionStorage.setItem('authgo.admin.user', JSON.stringify({id: 1, username: '模拟接口测试管理员'}));
    });
    const page = await context.newPage(); currentPage = page; page.setDefaultTimeout(20_000);
    const pageErrors = [], workerURLs = [];
    page.on('pageerror', error => { pageErrors.push(error.message); errors.push({width, kind: 'pageerror', message: error.message}); });
    page.on('console', message => { if (message.type() === 'error') errors.push({width, kind: 'browser-console', message: message.text()}); });
    page.on('requestfailed', request => errors.push({width, kind: 'requestfailed', url: request.url(), message: request.failure()?.errorText}));
    page.on('worker', worker => workerURLs.push(worker.url())); // Observe only; do NOT replace or mock Worker.
    const software = {id: 7, name: 'watermark 水印追查 · 模拟 API', app_key: 'app_watermark_fixture', docker_image: 'example-org/example-app',
      status: 'active', next_check_in: 3600, grace_hours: 72, heartbeat_interval: 60};
    const trialSources = [
      {ip: '192.0.2.41', instance_id: 'fixture-trial-instance-a', created_at: '2026-11-09T00:00:00Z'},
      {ip: '2001:db8:1234:5678:90ab:cdef:1234:5678', instance_id: 'fixture-trial-instance-ipv6-long-id', created_at: '2026-11-09T00:05:00Z'},
    ];
    const trial = {found: true, license_id: '91', user_id: '23', user_name: '水印追查模拟客户（非真实授权）', is_trial: true,
      source_ip: trialSources[0].ip, created_at: '2026-11-09T00:00:00Z', key_id: 'pk_historical_runtime', sources: trialSources};
    const api = {tags: fullTags, tagReads: 0, posts: [], failTags: false, failTrace: false, unknown: false, routeErrors: [], licenseReads: 0, userReads: 0};
    let expectedPosts = 0;
    await context.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url());
      if (url.pathname.startsWith('/api/v1/')) {
        try {
          const path = url.pathname.replace(/^\/api\/v1(?:\/admin)?/, '');
          let data = {items: [], total: 0}, status = 200, code = 'OK', message = '';
          if (path === '/auth/me') data = {id: 1, username: '模拟接口测试管理员'};
          else if (path === '/status') data = {initialized: true, setup_required: false};
          else if (path === '/applications/7') data = software;
          else if (path === '/applications') data = {items: [software], total: 1};
          else if (path === '/system/settings') data = {site_name: 'watermark MOCK-API TEST', public_url: 'https://auth.example.com', tools_image: '', tools_version: ''};
          else if (path === '/applications/7/payload-keys') data = {items: [
            {key_id: 'pk_current_fixture', public_key: 'a'.repeat(43), is_current: true, created_at: '2026-11-09T00:00:00Z'},
            {key_id: 'pk_historical_runtime', public_key: 'b'.repeat(43), is_current: false, created_at: '2026-11-08T00:00:00Z'},
          ]};
          else if (path === '/applications/7/watermark-tags') {
            assert.equal(request.method(), 'GET'); assert.equal(url.search, ''); api.tagReads++;
            if (api.failTags) { api.failTags = false; status = 503; code = 'SERVICE_UNAVAILABLE'; message = '模拟软件标记读取失败'; }
            else data = {items: api.tags};
          } else if (path === '/applications/7/watermark-trace') {
            assert.equal(request.method(), 'POST'); assert.equal(url.search, '', 'No trace query parameters');
            assert.match(request.headers()['content-type'] || '', /^application\/json(?:;|$)/i);
            assert.doesNotMatch(request.headers()['content-type'] || '', /multipart|octet-stream/i);
            const payload = request.postDataJSON();
            assert.deepEqual(Object.keys(payload), ['watermark'], 'Only the expected watermark field may leave the browser');
            assert.equal(typeof payload.watermark, 'string');
            assert.ok(allowedWatermarks.has(payload.watermark), 'Watermark is not in the allowed set');
            assert.equal(payload.watermark, expectedWatermark, 'Trace request used a watermark different from the selected export');
            assert.ok(allowedBodies.some(body => request.postDataBuffer().equals(body)), 'No whitespace-wrapped payload, filename, binary or fragments');
            api.posts.push({url: request.url(), method: request.method(), data: request.postDataJSON()});
            if (api.failTrace) { api.failTrace = false; status = 503; code = 'SERVICE_UNAVAILABLE'; message = '模拟来源查询失败'; }
            else data = api.unknown ? {found: false} : trial;
          } else if (path === '/licenses/91') {
            api.licenseReads++; data = {id: 91, app_id: 7, app_name: software.name, user_id: 23, key: 'SYNTHETIC-NOT-A-REAL-AUTH-CODE',
              status: 'active', type: 'trial', is_trial: true, verify_methods: ['KEY'], validity_rule: 'perpetual', max_activations: 1,
              active_activations: 0, features: {}, metadata: {}, source_ip: trial.source_ip};
          } else if (path === '/users/23') {
            api.userReads++; data = {id: 23, name: trial.user_name, email: 'watermark-fixture@example.invalid', status: 'active', has_portal_password: false};
          }
          if (request.method() !== 'GET') assert.equal(path, '/applications/7/watermark-trace', 'Unexpected API write');
          await route.fulfill({status, contentType: 'application/json', body: JSON.stringify({code, message, data})});
        } catch (error) {
          api.routeErrors.push(error.message); errors.push({width, kind: 'mock-route-contract', message: error.message});
          await route.fulfill({status: 400, contentType: 'application/json', body: JSON.stringify({code: 'TEST_CONTRACT_FAILED', message: error.message, data: {}})});
        }
        return;
      }
      if (url.origin !== origin) {
        api.routeErrors.push('Unexpected external request: ' + request.url());
        await route.abort('blockedbyclient'); return;
      }
      await route.continue();
    });
    const trace = page.locator('.watermark-trace');
    const input = trace.locator('input[type="file"]');
    const counts = trace.locator('.trace-result > p').filter({hasText: '一致非零槽位'});
    async function ready() {
      await input.waitFor({state: 'visible'});
      await page.waitForFunction(() => globalThis.document.querySelector('.watermark-trace input[type="file"]')?.disabled === false);
    }
    async function fits(label) {
      await page.evaluate(() => globalThis.document.fonts.ready);
      const size = await page.evaluate(() => {
        const root = globalThis.document.querySelector('.watermark-trace');
        const visible = element => !!(element.getClientRects().length && globalThis.getComputedStyle(element).visibility !== 'hidden');
        const problems = [...root.querySelectorAll('input,button,summary,progress,.trace-result,.trace-drop,.copy-field,.key-value-item dd,.trace-sources li')]
          .filter(visible).map(element => {
            const r = element.getBoundingClientRect();
            return {tag: element.tagName, text: element.textContent?.trim().slice(0, 48), left: r.left, right: r.right,
              client: element.clientWidth, scroll: element.scrollWidth, overflowX: globalThis.getComputedStyle(element).overflowX};
          }).filter(item => item.left < -1 || item.right > globalThis.innerWidth + 1 ||
            (item.scroll > item.client + 1 && !['hidden', 'clip', 'auto', 'scroll'].includes(item.overflowX)));
        return {width: globalThis.innerWidth, document: globalThis.document.documentElement.scrollWidth, problems};
      });
      assert.ok(size.document <= size.width, width + '/' + label + ': document overflow ' + JSON.stringify(size));
      assert.deepEqual(size.problems, [], width + '/' + label + ': visible control/content overflow');
      reports.cases.push({width, case: 'layout/' + label, status: 'PASS', measurements: size});
    }
    async function capture(label) {
      await fits(label);
      const focus = label === 'manual-copy-trial-sources' ? trace.locator('.trace-manual') : trace.locator('.trace-result').last();
      await focus.scrollIntoViewIfNeeded();
      for (const fullPage of [true, false]) {
        const filename = `watermark-${width}-${label}${fullPage ? '' : '-viewport'}.png`;
        await page.screenshot({path: resolve(out, filename), fullPage}); reports.screenshots.push(filename);
      }
    }
    async function assertCount(expected) {
      const text = `一致非零槽位 ${expected.count} / 全部槽位 ${expected.slots} · 零值槽位 ${expected.zeros} · ${expected.complete ? '扫描完整' : '扫描不完整'}`;
      await page.waitForFunction(expectedText => {
        const p = [...globalThis.document.querySelectorAll('.watermark-trace .trace-result > p')].find(p => p.textContent.includes('一致非零槽位'));
        return p?.textContent.replace(/\s+/g, ' ').trim() === expectedText;
      }, text);
      assert.equal((await counts.innerText()).replace(/\s+/g, ' ').trim(), text);
    }
    async function selected(path, expected, label) {
      await ready();
      if (expected.status === 'found') { assert.match(expected.watermark, /^(?!0{64}$)[0-9a-f]{64}$/); expectedWatermark = expected.watermark; lastExpectedWatermark = expected.watermark; }
      const before = api.posts.length, tagReads = api.tagReads;
      const started = page.waitForEvent('worker');
      await input.setInputFiles(path); await started;
      await assertCount(expected);
      if (expected.status === 'found') {
        expectedPosts++;
        await trace.getByRole('heading', {name: /已找到授权来源/}).waitFor();
        assert.equal(api.posts.length, before + 1, label + ': one auto-query');
        assert.equal(await trace.locator('a[href="/admin/licenses/91"]').count(), 1);
        assert.equal(await trace.locator('a[href="/admin/users/23"]').count(), 1);
        await trace.getByText('试用来源记录', {exact: true}).waitFor();
        await trace.getByText('来源 IP：' + trialSources[1].ip, {exact: true}).waitFor();
      } else {
        const states = {zero: '没有水印，可能是用密钥直接解出的', none: '文件里没有水印', ambiguous: '来源有歧义', partial: '文件未扫描完'};
        await trace.getByText(states[expected.status], {exact: false}).waitFor();
        assert.equal(api.posts.length, before, label + ': incomplete/zero/none/ambiguous must not POST');
      }
      assert.ok(api.tagReads > tagReads, label + ': selection must refresh tags before Worker');
      assert.equal(await trace.locator('.scan-progress').count(), 0);
      await fits(label);
      reports.cases.push({width, case: label, status: 'PASS', expected, input: path, genuineExportInput: genuine.some(item => item.path === path)});
    }

    await page.goto(origin + '/admin/applications/7?tab=payload-keys'); await ready();
    assert.equal(await page.getByRole('tab', {name: '打包密钥', exact: true}).getAttribute('aria-selected'), 'true');
    assert.equal(await trace.locator('input[type="checkbox"]').count(), 0);
    const fileId = await input.getAttribute('id'); assert.equal(await trace.locator(`label[for="${fileId}"]`).count(), 1);
    assert.ok((await trace.innerText()).includes('不上传文件、文件名或内容片段'));
    for (const item of genuine) await selected(item.path, {status: 'found', watermark: item.watermark, count: item.expected_consistent_slots, slots: item.expected_total_slots, zeros: 0, complete: true}, item.label);
    await capture('genuine-runtime-trial');
    // Click actual route links. The destination metadata is also explicitly mocked.
    const licenseResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/admin/licenses/91' && response.status() === 200);
    await trace.locator('a[href="/admin/licenses/91"]').click();
    await page.waitForURL(origin + '/admin/licenses/91'); await licenseResponse;
    assert.ok(api.licenseReads > 0); await page.goBack(); await ready();
    damagedExpected.watermark = javaPrimary.watermark; await selected(halfPath, damagedExpected, 'damaged-half genuine export copy');
    await selected(zipPath, {status: 'found', watermark: javaPrimary.watermark, count: javaPrimary.expected_consistent_slots + javaSecondary.expected_consistent_slots, slots: javaPrimary.expected_total_slots + javaSecondary.expected_total_slots, zeros: 0, complete: true}, 'deflated ZIP of two same-license Java exports');
    await selected(nestedPath, {status: 'found', watermark: javaPrimary.watermark, count: javaPrimary.expected_consistent_slots + javaSecondary.expected_consistent_slots, slots: javaPrimary.expected_total_slots + javaSecondary.expected_total_slots, zeros: 0, complete: true}, 'deflated nested JAR of same-license Java exports');
    await capture('nested-jar');
    await selected(zeroPath, {status: 'zero', count: 0, slots: javaPrimary.expected_total_slots, zeros: javaPrimary.expected_total_slots, complete: true}, 'all-zero cannot identify auth');
    await selected(nonePath, {status: 'none', count: 0, slots: 0, zeros: 0, complete: true}, 'no-slot');
    await selected(ambiguousPath, {status: 'ambiguous', count: 1, slots: 2, zeros: 0, complete: true}, 'ambiguous nonzero tie');
    await selected(encryptedPath, {status: 'partial', count: 0, slots: 0, zeros: 0, complete: false}, 'encrypted flag is partial');
    await selected(partialPath, {status: 'partial', count: javaPrimary.expected_consistent_slots, slots: javaPrimary.expected_total_slots, zeros: 0, complete: false}, 'partial preserves prior verified export');
    await capture('partial-no-query');

    const candidates = trace.locator('summary').filter({hasText: '查看非零候选水印'});
    await candidates.focus(); await page.keyboard.press('Enter');
    assert.equal(await candidates.locator('..').getAttribute('open'), '');
    await trace.getByRole('button', {name: '复制候选水印', exact: true}).click();
    await trace.locator('.copy-feedback').filter({hasText: '已复制'}).waitFor();
    assert.equal(await page.evaluate(() => globalThis.navigator.clipboard.readText()), lastExpectedWatermark);
    const advanced = trace.locator('summary').filter({hasText: '更多选项：手动查询与软件标记'});
    await advanced.focus(); await page.keyboard.press('Enter');
    assert.equal(await advanced.locator('..').getAttribute('open'), '');
    await trace.locator('.trace-tags').getByText('密钥编号：pk_historical_runtime', {exact: true}).waitFor();
    const manual = trace.locator('.trace-manual input');
    const beforeInvalid = api.posts.length;
    await manual.fill('0'.repeat(64)); await manual.press('Enter');
    await trace.getByRole('alert').filter({hasText: '全 0 水印无法识别'}).waitFor();
    await manual.fill('Z'.repeat(64)); await manual.press('Enter');
    await trace.getByRole('alert').filter({hasText: '小写十六进制'}).waitFor();
    assert.equal(api.posts.length, beforeInvalid);
    expectedWatermark = WM; await manual.fill(WM); await manual.press('Enter'); expectedPosts++;
    await trace.getByRole('heading', {name: /已找到授权来源/}).waitFor(); await capture('manual-copy-trial-sources');
    await trace.locator('a[href="/admin/users/23"]').click(); await page.waitForURL(origin + '/admin/users/23');
    await page.getByRole('heading', {name: trial.user_name, exact: true}).waitFor(); assert.ok(api.userReads > 0);
    await page.goBack(); await ready();
    const advancedAgain = trace.locator('summary').filter({hasText: '更多选项：手动查询与软件标记'});
    if (await advancedAgain.locator('..').getAttribute('open') === null) { await advancedAgain.focus(); await page.keyboard.press('Enter'); }
    api.unknown = true;
    expectedWatermark = WM; await trace.locator('.trace-manual input').fill(WM); await trace.locator('.trace-manual input').press('Enter'); expectedPosts++;
    await trace.getByText('不属于这个软件的授权，或授权已删除', {exact: false}).waitFor(); api.unknown = false;
    reports.cases.push({width, case: 'keyboard manual/zero validation/copy feedback/trial links/unknown authorization', status: 'PASS'});

    api.failTags = true; await page.getByRole('button', {name: '重新读取软件标记', exact: true}).click();
    await trace.getByRole('alert').filter({hasText: '读取软件标记失败'}).waitFor();
    assert.equal(await input.isDisabled(), true);
    await trace.getByRole('alert').filter({hasText: '读取软件标记失败'}).getByRole('button', {name: '重试', exact: true}).click(); await ready();
    api.tags = []; await page.getByRole('button', {name: '重新读取软件标记', exact: true}).click();
    await trace.getByText('还没有软件标记', {exact: false}).waitFor(); assert.equal(await input.isDisabled(), true);
    api.tags = fullTags; await page.getByRole('button', {name: '重新读取软件标记', exact: true}).click(); await ready();
    api.failTrace = true; expectedWatermark = javaPrimary.watermark;
    const failingWorker = page.waitForEvent('worker'); await input.setInputFiles(javaPrimary.path); await failingWorker; expectedPosts++;
    await trace.getByRole('alert').filter({hasText: '查询授权来源失败'}).waitFor();
    await trace.getByRole('alert').filter({hasText: '查询授权来源失败'}).getByRole('button', {name: '重试', exact: true}).click(); expectedPosts++;
    await trace.getByRole('heading', {name: /已找到授权来源/}).waitFor();
    reports.cases.push({width, case: 'tag reload/empty/retry and trace retry', status: 'PASS'});

    const beforeCancel = api.posts.length, cancellingWorker = page.waitForEvent('worker');
    await input.setInputFiles(cancelPath); await cancellingWorker;
    await trace.getByRole('button', {name: '取消扫描', exact: true}).click();
    await trace.getByText('扫描已取消', {exact: false}).waitFor();
    await assertCount({count: 0, slots: 0, zeros: 0, complete: false});
    assert.equal(api.posts.length, beforeCancel); await fits('cancelled genuine streaming operation');
    reports.cases.push({width, case: 'cancel real streaming Worker before final slot', status: 'PASS', complete: false});

    const productionWorker = workerURLs.find(url => /\/assets\/watermark-worker[^/]*\.js(?:\?|$)/.test(url));
    assert.ok(productionWorker, 'The production Worker asset must actually create a Chromium Worker');
    if (width === 1440) {
      // Shared vectors use the SAME built Worker, outside the UI, so vector
      // watermarks (different from WM) never trigger the WM-only mock REST route.
      // cancel_before uses a real module Worker bootstrap that imports the real
      // production handler and delivers scan+cancel synchronously in one task,
      // before the scanner's first await continuation. No scanner/native API is
      // mocked, and no scheduling delay/sleep is used to manufacture cancellation.
      for (const vector of vectors.scan) {
        const before = api.posts.length;
        const result = await page.evaluate(async ({url, vector}) => {
          let bootstrapURL;
          if (vector.cancel_before) {
            bootstrapURL = URL.createObjectURL(new Blob([
              `await import(${JSON.stringify(url)});\n` +
              'const realReceive=self.onmessage;self.onmessage=event=>{realReceive.call(self,event);if(event.data.type==="scan")realReceive.call(self,new MessageEvent("message",{data:{type:"cancel",id:event.data.id}}));};self.postMessage({type:"harness-ready"});',
            ], {type: 'text/javascript'}));
          }
          const worker = new globalThis.Worker(bootstrapURL || url, {type: 'module'});
          try {
            return await new Promise((resolve, reject) => {
              const deadline = setTimeout(() => reject(new Error('Bounded production Worker deadline: ' + vector.name)), 20000);
              const send = () => {
                const bytes = Uint8Array.from(atob(vector.bytes_b64), c => c.charCodeAt(0));
                worker.postMessage({type: 'scan', id: 1, file: new globalThis.File([bytes], 'shared-vector-local-only.bin'), tags: vector.tags});
              };
              worker.onerror = event => { clearTimeout(deadline); reject(new Error(event.message)); };
              worker.onmessageerror = () => { clearTimeout(deadline); reject(new Error('Worker message decode failed')); };
              worker.onmessage = event => {
                if (event.data.type === 'harness-ready') send();
                if (event.data.type === 'result') { clearTimeout(deadline); resolve(event.data.result); }
              };
              if (!vector.cancel_before) send();
            });
          } finally {
            worker.terminate(); if (bootstrapURL) URL.revokeObjectURL(bootstrapURL);
          }
        }, {url: productionWorker, vector});
        assert.deepEqual(observed(result), vector.expected, 'Real browser common vector: ' + vector.name);
        assert.equal(api.posts.length, before, 'Direct Worker vectors must never call REST');
        reports.sharedVectors.push({name: vector.name, status: 'PASS', expected: vector.expected, observed: observed(result),
          chunkSizeNote: 'Native File.stream chunking in Chromium; exact chunk_size=1/64 is covered by the parent-run scanner unit suite.',
          cancellation: vector.cancel_before ? 'Synchronous real-handler scan/cancel adapter before first awaited scan continuation.' : undefined});
      }
      assert.equal(reports.sharedVectors.length, 22);
    }
    assert.deepEqual(api.routeErrors, [], 'Mock API contract violations');
    assert.deepEqual(pageErrors, [], 'Unhandled production browser errors');
    assert.deepEqual(privacyViolations, [], 'File privacy audit');
    assert.equal(api.posts.length, expectedPosts, 'No delayed or duplicate auto-query');
    reports.viewports.push({width, status: 'PASS', api: 'MOCK FIXTURES ONLY', genuineExports: genuine.map(item => item.label),
      workerAsset: productionWorker, realWorkerInstances: workerURLs.length, watermarkOnlyPosts: api.posts.length, tagReads: api.tagReads});
    await persist(); await context.close(); currentPage = undefined;
  }
  assert.equal(reports.screenshots.length, 32);
  reports.status = 'PASS'; reports.finishedAt = new Date().toISOString();
  reports.privacy = {status: 'PASS', requests: network.length, violations: privacyViolations.length,
    assertion: 'All context network URL/method/postData captured; no filename, binary, export fragment, multipart upload or trace query parameters; only {watermark} trace writes.'};
  await persist();
  console.log(JSON.stringify({label: reports.label, status: reports.status, viewports: reports.viewports,
    sharedVectors: reports.sharedVectors.length, screenshots: reports.screenshots.length, results: resolve(out, 'results.json'), network: resolve(out, 'network.json')}));
} catch (error) {
  reports.status = 'FAIL'; reports.finishedAt = new Date().toISOString();
  reports.failure = {message: error.message, stack: error.stack};
  errors.push({kind: 'test-failure', message: error.message, stack: error.stack});
  if (currentPage && !currentPage.isClosed()) {
    try { await currentPage.screenshot({path: resolve(out, 'failure.png'), fullPage: true}); }
    catch (captureError) { errors.push({kind: 'failure-screenshot', message: captureError.message}); }
  }
  await persist(); await writeFile(resolve(out, 'failure.json'), JSON.stringify(reports.failure, null, 2) + '\n');
  throw error;
} finally {
  if (browser) await browser.close();
  if (server?.listening) await new Promise((done, reject) => server.close(error => error ? reject(error) : done()));
}
