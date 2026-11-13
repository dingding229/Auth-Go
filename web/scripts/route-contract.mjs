// Static request analysis, using the existing TypeScript and Vue compilers.
// No UI execution, mock server, Swagger annotations, regex-extracted Go routes,
// or hand-maintained list of backend endpoints participates in this check.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import ts from 'typescript';
import { parse as parseSFC } from '@vue/compiler-sfc';
import { baseParse } from '@vue/compiler-dom';

const UNKNOWN = Symbol('unresolved');
const SEGMENT = ':segment';
const union = (items) => [...new Set(items.flat())];
const kebab = (s) => s.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`).replace(/^-/, '');
const unwrap = (n) => {
  while (n && (ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isNonNullExpression(n) || ts.isSatisfiesExpression(n) || ts.isTypeAssertionExpression(n))) n = n.expression;
  return n;
};
function filesBelow(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const file = path.join(dir, e.name);
    return e.isDirectory() ? filesBelow(file) : [file];
  });
}
export function sourceDigest(root) {
  const files = [...filesBelow(path.join(root, 'server')), ...filesBelow(path.join(root, 'web/src'))]
    .map((p) => path.relative(root, p).split(path.sep).join('/'))
    .filter((p) => p.startsWith('web/src/') || p.endsWith('.go') || p === 'server/internal/webui/routes.json' || p === 'server/go.mod' || p === 'server/go.sum').sort();
  const h = createHash('sha256');
  for (const p of files) h.update(p + '\0').update(fs.readFileSync(path.join(root, p))).update('\0');
  return h.digest('hex');
}
export function readRouteContract(root) {
  const file = path.join(root, 'server/.route-contract.json');
  if (!fs.existsSync(file)) throw new Error('Missing real Gin route table: run the server route-contract test before web npm test.');
  const contract = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (contract.schema !== 2 || contract.source !== sourceDigest(root)) throw new Error('Stale real Gin route table: rerun server go test ./... on the same sources before web npm test.');
  if (!Array.isArray(contract.contexts) || contract.contexts.length !== 2 ||
      contract.contexts[0]?.admin_path !== '/admin' || contract.contexts[1]?.admin_path !== '/route-check')
    throw new Error('Invalid real Gin route contexts: both default and custom admin paths are required');
  for (const context of contract.contexts) {
    if (!Array.isArray(context.routes) || !context.routes.length || context.routes.some((r) =>
        typeof r.method !== 'string' || !/^[A-Z]+$/.test(r.method) || typeof r.path !== 'string' || !r.path.startsWith('/api/')))
      throw new Error('Invalid real Gin route table');
    const prefix = '/api/v1' + context.admin_path + '/';
    if (!context.routes.some((r) => r.path.startsWith(prefix)) ||
        (context.admin_path !== '/admin' && context.routes.some((r) => r.path === '/api/v1/admin' || r.path.startsWith('/api/v1/admin/'))))
      throw new Error('Invalid real Gin dynamic admin prefix');
  }
  return contract.contexts;
}

// A deliberately bounded abstract interpreter. Unknown route structure is an
// error, never a wildcard. Only an ID or an explicitly URI-encoded value can
// stand for ONE parameter segment. Conditions with finite values are evaluated
// separately, preserving method/path correlation (e.g. IP database deletion).
export function extractRequests(sourceFiles, runtime = {}) {
  // A single reviewed runtime reader is an abstract primitive, NOT arbitrary
  // dynamic strings. Pin its implementation so changing it to a hardcoded path,
  // localStorage or a permissive fallback cannot silently pass the audit.
  const trustedRuntimeDigest = '1686172cfba6b34d0a95a077f7d0aa1e8c71495b5ee7b01e86e901c19629bb46';
  const modules = new Map();
  for (const [filename, source] of Object.entries(sourceFiles)) {
    if (!/\.(vue|[cm]?[jt]sx?)$/.test(filename)) throw new Error(`Unsupported source: ${filename}`);
    const file = path.resolve(filename);
    let text = source;
    const bindings = [];
    const uses = [];
    if (file.endsWith('.vue')) {
      const parsed = parseSFC(source, { filename: file });
      if (parsed.errors.length) throw new Error(`${filename}: invalid Vue SFC: ${parsed.errors}`);
      if (parsed.descriptor.script?.src || parsed.descriptor.scriptSetup?.src) throw new Error(`${filename}: external Vue script is not supported`);
      text = [parsed.descriptor.script?.content ?? '', parsed.descriptor.scriptSetup?.content ?? ''].join('\n');
      if (parsed.descriptor.template) {
        const template = baseParse(parsed.descriptor.template.content);
        const walk = (node) => {
          if (node.type === 5) {
            // Vue interpolation is executable render code, just like a bound
            // prop. Keep it in the same lexical module so request imports and
            // wrappers resolve normally; never silently discard {{ ... }}.
            const exp = node.content?.content;
            if (typeof exp !== 'string') throw new Error(`${filename}: unsupported interpolation AST`);
            text += `\n;(${exp});`;
          }
          if (node.type === 1) {
            const props = [];
            for (const p of node.props) {
              if (p.type === 6) props.push([p.name, p.value ? JSON.stringify(p.value.content) : 'true']);
              else if (p.type === 7 && p.exp) {
                const exp = p.exp.content;
                if (p.name === 'on') text += `\n;(()=>{${exp}\n});`;
                else if (p.name === 'for') text += `\n;for (${exp}) {}`;
                else if (p.name !== 'slot') text += `\n;(${exp});`;
                if (p.name === 'bind') { const key = `__route_prop_${bindings.length}`; text += `\nconst ${key}=(${exp});`; bindings.push(key); props.push([p.arg?.isStatic ? p.arg.content : null, key]); }
              }
            }
            uses.push({ tag: kebab(node.tag), props });
          }
          for (const child of node.children ?? []) walk(child);
        };
        walk(template);
      }
    }
    const virtual = file.endsWith('.vue') ? file + '.ts' : file;
    modules.set(virtual, { file, virtual, text, uses });
  }
  const options = { target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler, allowJs: true, noLib: true, types: [] };
  const host = ts.createCompilerHost(options);
  const getSourceFile = host.getSourceFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  host.fileExists = (p) => modules.has(p) || fileExists(p);
  host.getSourceFile = (p, lang, ...rest) => modules.has(p) ? ts.createSourceFile(p, modules.get(p).text, lang, true, ts.ScriptKind.TS) : getSourceFile(p, lang, ...rest);
  host.resolveModuleNames = (names, containing) => names.map((name) => {
    const local = path.resolve(path.dirname(containing), name);
    for (const candidate of [local, local + '.ts', local + '.vue.ts', local + '/index.ts']) if (modules.has(candidate)) return { resolvedFileName: candidate, extension: ts.Extension.Ts };
    return undefined; // External library internals are not frontend source.
  });
  const program = ts.createProgram([...modules.keys()], options, host);
  const checker = program.getTypeChecker();
  for (const m of modules.values()) {
    m.ast = program.getSourceFile(m.virtual);
    // v-for syntax is Vue-specific; its JavaScript "in" form is parsed above.
    const diagnostics = program.getSyntacticDiagnostics(m.ast);
    if (diagnostics.length) throw new Error(`${m.file}: unsupported/invalid syntax: ${diagnostics.map((d) => ts.flattenDiagnosticMessageText(d.messageText, ' ')).join('; ')}`);
  }
  const symbol = (n) => {
    const s = ts.isIdentifier(n) && ts.isShorthandPropertyAssignment(n.parent) && n.parent.name === n
      ? checker.getShorthandAssignmentValueSymbol(n.parent)
      : checker.getSymbolAtLocation(n);
    if (!s || !(s.flags & ts.SymbolFlags.Alias)) return s;
    const target = checker.getAliasedSymbol(s);
    // External declarations are intentionally not loaded. TypeScript can map
    // unrelated unresolved imports to the SAME unknownSymbol. Preserve each
    // local import identity, otherwise an unrelated object's mutation poisons
    // axios (or a caller binding) in another module. Only project imports are
    // resolved to their owning declaration for inter-module request tracing.
    return target?.declarations?.some((d) => modules.has(d.getSourceFile().fileName)) ? target : s;
  };
  const moduleOf = (n) => modules.get(n.getSourceFile().fileName);
  const location = (n) => `${moduleOf(n)?.file ?? n.getSourceFile().fileName}:${n.getSourceFile().getLineAndCharacterOfPosition(n.getStart()).line + 1}`;
  const fail = (n, why) => {
    const chain = [...callStack, `${location(n)} [request expression]`];
    throw new Error(`${location(n)}: ${why}: ${n.getText().slice(0, 220)}\nRequest call chain (outermost first):\n${chain.map((frame, i) => `  ${i + 1}. ${frame}`).join('\n')}`);
  };
  const thunk = (n, env) => ({ n, env });
  const object = (entries) => ({ object: entries });
  const fnValue = (n, env) => ({ fn: n, env });
  const propName = (n) => n && (ts.isIdentifier(n) || ts.isStringLiteral(n) || ts.isNumericLiteral(n)) ? n.text : undefined;
  const writes = new Map();
  const mutatedObjects = new Set();
  for (const m of modules.values()) {
    const collect = (n) => {
      if (ts.isBinaryExpression(n) && n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && n.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
        const left = unwrap(n.left);
        if (ts.isIdentifier(left)) {
          const key = symbol(left);
          writes.set(key, [...(writes.get(key) ?? []), n.operatorToken.kind === ts.SyntaxKind.EqualsToken ? n.right : undefined]);
        } else {
          let base = left;
          while (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base)) base = unwrap(base.expression);
          if (ts.isIdentifier(base)) mutatedObjects.add(symbol(base));
        }
      }
      ts.forEachChild(n, collect);
    };
    collect(m.ast);
  }
  const seenEval = new Set();
  const requests = [];
  const covered = new Set();
  const sinks = new Set();
  const scanned = new Set();
  const activeScan = new Set();
  const callStack = [];
  let steps = 0;
  function tick(n) { if (++steps > 2000000) fail(n, 'analysis budget exceeded (fail closed)'); }
  function resolveValue(v) { return v?.supplied ?? (v && typeof v === 'object' && 'n' in v ? evaluate(v.n, v.env) : [v]); }
  function declaration(n) { return symbol(n)?.valueDeclaration ?? symbol(n)?.declarations?.[0]; }
  function typed(n, env) {
    if (!n) return [UNKNOWN];
    if (ts.isLiteralTypeNode(n)) return evaluate(n.literal, env);
    if (ts.isUnionTypeNode(n)) return union(n.types.map((t) => typed(t, env)));
    if (ts.isTypeLiteralNode(n)) return [object(n.members.filter(ts.isPropertySignature).map((p) => [propName(p.name), { type: p.type, optional: !!p.questionToken, name: propName(p.name), env }]))];
    if (ts.isTypeReferenceNode(n)) {
      const d = declaration(n.typeName);
      if (d && ts.isTypeAliasDeclaration(d)) return typed(d.type, env);
    }
    return [UNKNOWN];
  }
  function property(v, key, at) {
    if (v == null) return [undefined];
    if (v && typeof v === 'object' && v.object) {
      for (let i = v.object.length - 1; i >= 0; --i) {
        const [name, value] = v.object[i];
        if (name === key) {
          if (value?.type) {
            const vals = typed(value.type, value.env);
            if (vals.includes(UNKNOWN) && /^(id|appId|licenseId)$/.test(value.name)) return [SEGMENT];
            return value.optional ? union([vals, undefined]) : vals;
          }
          return resolveValue(value);
        }
        if (name === null) {
          const spread = resolveValue(value);
          const vals = union(spread.map((s) => property(s, key, at)));
          // Known absent spread keys do not shadow earlier fields.
          if (vals.some((x) => x !== undefined)) return vals;
        }
      }
      return [undefined];
    }
    if (v?.transport) return [{ transportMethod: v, method: key }];
    if (v?.axios && key === 'create') return [{ factory: true }];
    if (v === UNKNOWN && /^(id|appId|licenseId)$/.test(key)) return [SEGMENT];
    if (key === 'value') return [v]; // ref/computed are unwrapped by their constructors.
    if (key === 'resource' && v === UNKNOWN && ts.isPropertyAccessExpression(at) && at.expression.getText() === 'f') return resourceValues(at);
    return [UNKNOWN];
  }
  const resourceNodes = [];
  for (const m of modules.values()) {
    const collect = (n) => {
      if (ts.isPropertyAssignment(n) && propName(n.name) === 'resource' && !m.file.includes('/router/')) resourceNodes.push(n.initializer);
      ts.forEachChild(n, collect);
    };
    collect(m.ast);
  }
  function resourceValues(at) {
    if (!resourceNodes.length) fail(at, 'resource selector has no finite field sources');
    const vals = union(resourceNodes.map((n) => evaluate(n, new Map())));
    if (vals.some((v) => typeof v !== 'string' || !v.startsWith('/'))) fail(at, 'resource field must have a finite path');
    return vals;
  }
  function returns(body) {
    if (!ts.isBlock(body)) return [body];
    const result = [];
    const walk = (n) => {
      if (n !== body && ts.isFunctionLike(n)) return;
      if (ts.isReturnStatement(n) && n.expression) result.push(n.expression);
      ts.forEachChild(n, walk);
    };
    walk(body);
    return result;
  }
  function combinations(arrays) { return arrays.reduce((acc, vals) => acc.flatMap((a) => vals.map((v) => [...a, v])), [[]]); }
  function boundEnvs(f, args) {
    const params = f.fn.parameters ?? [];
    const choices = params.map((p, i) => {
      const fallback = () => p.initializer ? evaluate(p.initializer, f.env) : p.questionToken ? [undefined] : typed(p.type, f.env);
      const contract = typed(p.type, f.env);
      const vals = args[i] ? union(args[i].flatMap((v) => v === undefined ? fallback() : v === UNKNOWN && contract.length && !contract.includes(UNKNOWN) ? contract : [v])) : fallback();
      return ts.isIdentifier(p.name) && /^(id|appId|licenseId)$/.test(p.name.text) ? vals.map((v) => v === UNKNOWN ? SEGMENT : v) : vals;
    });
    return combinations(choices).map((vals) => {
      const env = new Map(f.env);
      params.forEach((p, i) => { if (ts.isIdentifier(p.name)) env.set(symbol(p.name), [vals[i]]); });
      return env;
    });
  }
  function invokeValue(f, args, at) {
    if (f.fn.name?.text === 'adminPath' && moduleOf(f.fn)?.file.endsWith('/lib/runtime.ts')) {
      if (createHash('sha256').update(moduleOf(f.fn).text).digest('hex') !== trustedRuntimeDigest)
        fail(at, 'unreviewed trusted runtime reader');
      if (typeof runtime.admin_path !== 'string' || runtime.admin_path.length > 49 ||
          !/^\/[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(runtime.admin_path))
        fail(at, 'missing or invalid trusted HTML runtime admin_path');
      return [runtime.admin_path];
    }
    if (!f.fn.body) return [UNKNOWN];
    const values = [];
    for (const env of boundEnvs(f, args)) {
      for (const ret of returns(f.fn.body)) values.push(...evaluate(ret, env));
    }
    if (values.length > 256) fail(at, 'too many possible return values');
    return values.length ? union(values) : [UNKNOWN];
  }
  function evaluate(node, env = new Map()) {
    const n = unwrap(node);
    if (!n) return [undefined];
    tick(n);
    if (seenEval.has(n)) return [UNKNOWN];
    seenEval.add(n);
    try {
      if (ts.isStringLiteralLike(n) || ts.isNumericLiteral(n)) return [ts.isNumericLiteral(n) ? Number(n.text) : n.text];
      if (n.kind === ts.SyntaxKind.TrueKeyword) return [true];
      if (n.kind === ts.SyntaxKind.FalseKeyword) return [false];
      if (n.kind === ts.SyntaxKind.NullKeyword) return [null];
      if (ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n)) return [fnValue(n, env)];
      if (ts.isAwaitExpression(n)) return evaluate(n.expression, env);
      if (ts.isIdentifier(n)) {
        if (n.text === 'undefined') return [undefined];
        const s = symbol(n);
        const assigned = () => (writes.get(s) ?? []).flatMap((value) => value ? evaluate(value, env) : [UNKNOWN]);
        if (mutatedObjects.has(s)) return [UNKNOWN];
        if (env.has(s)) return union([env.get(s).flatMap(resolveValue), assigned()]);
        const d = declaration(n);
        if (d && ts.isVariableDeclaration(d)) return union([evaluate(d.initializer, env), assigned()]);
        if (d && ts.isFunctionDeclaration(d)) return [fnValue(d, env)];
        if (d && ts.isParameter(d)) {
          const vals = typed(d.type, env);
          return vals.includes(UNKNOWN) && /^(id|appId|licenseId)$/.test(n.text) ? [SEGMENT] : vals;
        }
        const imported = s?.declarations?.find((d) => ts.isImportClause(d));
        if (imported?.parent.moduleSpecifier.text === 'axios') return [{ axios: true }];
        // Unresolved external imports (axios) retain their local import declaration.
        const raw = checker.getSymbolAtLocation(n)?.declarations?.[0];
        if (raw && ts.isImportClause(raw) && raw.parent.moduleSpecifier.text === 'axios') return [{ axios: true }];
        return [UNKNOWN];
      }
      if (ts.isObjectLiteralExpression(n)) return [object(n.properties.map((p) => ts.isSpreadAssignment(p) ? [null, thunk(p.expression, env)] : [propName(p.name), ts.isShorthandPropertyAssignment(p) ? thunk(p.name, env) : ts.isMethodDeclaration(p) ? fnValue(p, env) : thunk(p.initializer, env)]))];
      if (ts.isArrayLiteralExpression(n)) return [{ array: n.elements.map((p) => thunk(p, env)) }];
      if (ts.isPropertyAccessExpression(n)) {
        const d = declaration(n.name);
        if (d && (ts.isFunctionDeclaration(d) || ts.isVariableDeclaration(d)) && modules.has(d.getSourceFile().fileName)) return ts.isFunctionDeclaration(d) ? [fnValue(d, env)] : evaluate(d.initializer, env);
        return union(evaluate(n.expression, env).map((v) => property(v, n.name.text, n)));
      }
      if (ts.isElementAccessExpression(n)) {
        const keys = evaluate(n.argumentExpression, env);
        return union(evaluate(n.expression, env).flatMap((v) => keys.flatMap((key) => key === UNKNOWN && v?.object ? union(v.object.filter(([k]) => k !== null).map(([k]) => property(v, k, n))) : property(v, String(key), n))));
      }
      if (ts.isTemplateExpression(n)) {
        let vals = [n.head.text];
        for (const span of n.templateSpans) vals = combinations([vals, evaluate(span.expression, env)]).map(([a, b]) => a === UNKNOWN || b === UNKNOWN ? UNKNOWN : a + String(b) + span.literal.text);
        return union(vals);
      }
      if (ts.isConditionalExpression(n)) {
        const tests = evaluate(n.condition, env);
        return union(tests.flatMap((v) => v === UNKNOWN ? [...evaluate(n.whenTrue, env), ...evaluate(n.whenFalse, env)] : evaluate(v ? n.whenTrue : n.whenFalse, env)));
      }
      if (ts.isPrefixUnaryExpression(n) && n.operator === ts.SyntaxKind.ExclamationToken) return evaluate(n.operand, env).map((v) => v === UNKNOWN ? UNKNOWN : !v);
      if (ts.isBinaryExpression(n)) {
        const op = n.operatorToken.kind;
        const left = evaluate(n.left, env);
        if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken || op === ts.SyntaxKind.AmpersandAmpersandToken) return union(left.flatMap((v) => v === UNKNOWN ? [UNKNOWN, ...evaluate(n.right, env)] : ((op === ts.SyntaxKind.AmpersandAmpersandToken ? !!v : op === ts.SyntaxKind.QuestionQuestionToken ? v == null : !v) ? evaluate(n.right, env) : [v])));
        return union(combinations([left, evaluate(n.right, env)]).map(([a, b]) => {
          if (a === UNKNOWN || b === UNKNOWN) return UNKNOWN;
          if (op === ts.SyntaxKind.PlusToken) return a + b;
          if (op === ts.SyntaxKind.EqualsEqualsEqualsToken || op === ts.SyntaxKind.EqualsEqualsToken) return a === b;
          if (op === ts.SyntaxKind.ExclamationEqualsEqualsToken || op === ts.SyntaxKind.ExclamationEqualsToken) return a !== b;
          return UNKNOWN;
        }));
      }
      if (ts.isCallExpression(n)) {
        const name = ts.isIdentifier(n.expression) ? n.expression.text : '';
        if (name === 'defineProps') {
          const declared = typed(n.typeArguments?.[0], env);
          if (!env.has('__props')) return declared;
          return env.get('__props').map((actual) => object([
            // A concrete component invocation has a known prop set. Missing
            // optional props are undefined, NOT every value of their declared
            // type. The declaration only constrains supplied unknown values.
            ...actual.object.map(([key, value]) => {
              const supplied = resolveValue(value);
              const contract = union(declared.map((d) => property(d, key, n)));
              // Vue's existing typecheck enforces literal-union prop contracts.
              // Widened v-for locals may use that finite declared domain, never
              // an arbitrary string or a backend-derived route wildcard.
              return [key, supplied.includes(UNKNOWN) && contract.length && !contract.includes(UNKNOWN) && !contract.includes(undefined) ? { n: undefined, env: new Map(), supplied: contract } : value];
            }),
          ]));
        }
        if (name === 'withDefaults') return evaluate(n.arguments[0], env);
        if (['ref', 'shallowRef', 'reactive'].includes(name)) {
          // Reactive state is mutable (including template v-model writes).
          // Its initial value must never prune later request branches.
          return n.typeArguments?.[0] ? typed(n.typeArguments[0], env) : [UNKNOWN];
        }
        if (['toValue', 'unref', 'computed'].includes(name)) {
          return union(evaluate(n.arguments[0], env).flatMap((v) => v?.fn ? invokeValue(v, [], n) : name === 'computed' && v?.object ? property(v, 'get', n).flatMap((g) => g?.fn ? invokeValue(g, [], n) : [UNKNOWN]) : [v]));
        }
        if (name === 'idText') return [SEGMENT];
        if (name === 'encodeURIComponent') return evaluate(n.arguments[0], env).map((v) => v === UNKNOWN || v === SEGMENT ? SEGMENT : encodeURIComponent(String(v)));
        if (name === 'String') return evaluate(n.arguments[0], env).map((v) => v === UNKNOWN ? UNKNOWN : String(v));
        const callees = evaluate(n.expression, env);
        return union(callees.flatMap((f) => {
          if (f?.factory) {
            if (!moduleOf(n).file.endsWith('/lib/http.ts')) fail(n, 'HTTP clients must be created in lib/http.ts');
            return [ { transport: true, base: evaluate(n.arguments[0], env).flatMap((o) => property(o, 'baseURL', n)) } ];
          }
          if (f?.fn) return invokeValue(f, n.arguments.map((a) => evaluate(a, env)), n);
          return [UNKNOWN];
        }));
      }
      return [UNKNOWN];
    } finally { seenEval.delete(n); }
  }
  function directFunction(expression, env) {
    const n = unwrap(expression);
    if (!n) return undefined;
    if (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) return fnValue(n, env);
    const d = declaration(ts.isPropertyAccessExpression(n) ? n.name : n);
    if (!d || !modules.has(d.getSourceFile().fileName)) return undefined;
    if (ts.isFunctionDeclaration(d)) return fnValue(d, env);
    if (ts.isVariableDeclaration(d)) {
      const init = unwrap(d.initializer);
      if (init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init))) return fnValue(init, env);
      if (init && (ts.isIdentifier(init) || ts.isPropertyAccessExpression(init))) return directFunction(init, env);
    }
    return undefined;
  }
  const networkMemo = new Map();
  function networkFunction(f, active = new Set()) {
    if (networkMemo.has(f.fn)) return networkMemo.get(f.fn);
    if (active.has(f.fn)) return false;
    const next = new Set(active).add(f.fn);
    let found = false;
    const walk = (n) => {
      if (ts.isCallExpression(n)) {
        const e = unwrap(n.expression);
        if (ts.isPropertyAccessExpression(e) && ['request', 'post', 'put', 'patch', 'delete', 'get', 'head', 'options'].includes(e.name.text)) {
          if (e.name.text === 'request' || evaluate(e.expression, f.env).some((v) => v?.transport)) found = true;
        }
        const g = directFunction(e, f.env);
        if (g && networkFunction(g, next)) found = true;
      }
      if (!found) ts.forEachChild(n, walk);
    };
    if (f.fn.body) walk(f.fn.body);
    networkMemo.set(f.fn, found);
    return found;
  }
  const contextMemo = new Map();
  function componentContexts(m, active = new Set()) {
    if (contextMemo.has(m)) return contextMemo.get(m);
    if (active.has(m)) throw new Error(`${m.file}: cyclic route-bearing component props`);
    const contexts = [];
    for (const parent of modules.values()) {
      for (const statement of parent.ast.statements) {
        if (!ts.isImportDeclaration(statement) || !statement.importClause?.name || !statement.moduleSpecifier.text.endsWith('.vue')) continue;
        const target = path.resolve(path.dirname(parent.virtual), statement.moduleSpecifier.text) + '.ts';
        if (target !== m.virtual) continue;
        for (const use of parent.uses.filter((u) => u.tag === kebab(statement.importClause.name.text))) {
          for (const env of componentContexts(parent, new Set(active).add(m))) {
            const props = use.props.map(([key, code]) => {
              const camel = key === null ? null : key.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
              const decl = parent.ast.statements.filter(ts.isVariableStatement).flatMap((s) => [...s.declarationList.declarations]).find((d) => ts.isIdentifier(d.name) && d.name.text === code);
              const n = decl?.initializer ?? ts.createSourceFile('literal.ts', `(${code})`, ts.ScriptTarget.ESNext, true).statements[0].expression;
              return [camel, thunk(n, env)];
            });
            contexts.push(new Map([['__props', [object(props)]]]));
          }
        }
      }
    }
    if (!contexts.length) contexts.push(new Map());
    contextMemo.set(m, contexts);
    return contexts;
  }
  function transportCall(n, env, method) {
    const e = unwrap(n.expression);
    if (!ts.isPropertyAccessExpression(e)) fail(n, 'invalid HTTP transport');
    const receivers = evaluate(e.expression, env);
    if (!receivers.every((v) => v?.transport)) {
      const states = receivers.map((v) => v === UNKNOWN ? 'unresolved' : v?.transport ? 'axios-instance' : v?.axios ? 'axios-module' : v === undefined ? 'undefined' : typeof v);
      fail(n, `unresolved HTTP transport (receiver states: ${states.join(', ')})`);
    }
    for (const receiver of receivers) {
      const configs = method === 'request' ? evaluate(n.arguments[0], env) : n.arguments[method === 'get' || method === 'delete' || method === 'head' || method === 'options' ? 1 : 2] ? evaluate(n.arguments[method === 'get' || method === 'delete' || method === 'head' || method === 'options' ? 1 : 2], env) : [object([])];
      for (const config of configs) {
        const urls = method === 'request' ? property(config, 'url', n) : evaluate(n.arguments[0], env);
        const methods = method === 'request' ? property(config, 'method', n).map((v) => v === undefined ? 'GET' : v) : [method.toUpperCase()];
        for (const [base, url, verb] of combinations([receiver.base.map((v) => v === undefined ? '' : v), urls, methods])) {
          if (typeof base !== 'string' || typeof url !== 'string' || typeof verb !== 'string' || url.includes('undefined') || url.includes('Symbol(')) {
            const classify = (value, field) => {
              if (value === UNKNOWN) return '<unresolved>';
              if (value === undefined) return '<undefined>';
              if (value === null) return '<null>';
              if (typeof value !== 'string') return `<${typeof value}>`;
              if (field === 'method') return /^[A-Za-z]{1,20}$/.test(value) ? `string:${value}` : '<non-method-string>';
              // Only relative route structure, never credentials/query/hash or
              // request data, is useful for contract diagnostics.
              if (value === '' || value.startsWith('/')) return `path:${JSON.stringify(value.split(/[?#]/, 1)[0]).slice(0, 240)}`;
              return '<non-relative-path-string>';
            };
            fail(n, `unresolved method/baseURL/path (method=${classify(verb, 'method')}; baseURL=${classify(base, 'baseURL')}; path=${classify(url, 'path')})`);
          }
          if (!url.startsWith('/') || /^[a-z]+:/i.test(url)) fail(n, 'only same-origin finite API paths are supported');
          const full = (base ? base.replace(/\/$/, '') + '/' + url.replace(/^\//, '') : url).split(/[?#]/, 1)[0];
          if (full.includes('//') || full.split('/').some((s) => s.includes(SEGMENT) && s !== SEGMENT)) fail(n, 'dynamic values must occupy exactly one complete route parameter segment');
          requests.push({ method: verb.toUpperCase(), path: full, at: callStack[0] ?? location(n), via: [...callStack, location(n)] });
          covered.add(n);
        }
      }
    }
  }
  function isReplay(n) {
    if (!moduleOf(n)?.file.endsWith('/lib/http.ts') || !ts.isPropertyAccessExpression(n.expression) || n.expression.name.text !== 'request' || n.expression.expression.getText() !== 'client') return false;
    if (n.arguments.length !== 1 || n.arguments[0].getText() !== 'config') fail(n, 'retry must replay the original config');
    const d = declaration(n.arguments[0]);
    if (!d || !ts.isVariableDeclaration(d) || !ts.isConditionalExpression(d.initializer) || d.initializer.whenTrue.getText() !== 'error.config' || d.initializer.whenFalse.getText() !== 'undefined') fail(n, 'retry config must come from the original Axios error');
    covered.add(n);
    return true;
  }
  function scanFunction(f, args, at) {
    if (activeScan.has(f.fn)) fail(at, 'recursive request wrapper cannot be proven finite');
    activeScan.add(f.fn);
    const owner = f.fn.name?.getText() ?? (ts.isVariableDeclaration(f.fn.parent) ? f.fn.parent.name.getText() : '<callback>');
    callStack.push(`${location(at)} -> ${owner} [${location(f.fn)}]`);
    try { for (const env of boundEnvs(f, args)) visit(f.fn.body, env); }
    finally { activeScan.delete(f.fn); callStack.pop(); }
  }
  const incoming = new Set();
  for (const m of modules.values()) {
    const collect = (n) => {
      if (ts.isCallExpression(n)) {
        const f = directFunction(n.expression, new Map());
        if (f) incoming.add(f.fn);
      }
      ts.forEachChild(n, collect);
    };
    collect(m.ast);
  }
  function visit(n, env) {
    if (!n) return;
    tick(n);
    if (ts.isFunctionLike(n) && n.body) {
      // Named wrappers are checked through every real caller, including Vue
      // event expressions. Do not replace a concrete action with `string`.
      if (incoming.has(n) && networkFunction(fnValue(n, env))) return;
      for (const bound of boundEnvs(fnValue(n, env), [])) visit(n.body, bound);
      return;
    }
    if (ts.isConditionalExpression(n)) {
      visit(n.condition, env);
      const tests = evaluate(n.condition, env);
      if (tests.some((v) => v === UNKNOWN || v)) visit(n.whenTrue, env);
      if (tests.some((v) => v === UNKNOWN || !v)) visit(n.whenFalse, env);
      return;
    }
    if (ts.isIfStatement(n)) {
      visit(n.expression, env);
      const tests = evaluate(n.expression, env);
      if (tests.some((v) => v === UNKNOWN || v)) visit(n.thenStatement, env);
      if (tests.some((v) => v === UNKNOWN || !v)) visit(n.elseStatement, env);
      return;
    }
    if (ts.isIdentifier(n) && ['fetch', 'sendBeacon', 'XMLHttpRequest', 'WebSocket', 'EventSource'].includes(n.text)) fail(n, 'network access must use lib/http.ts (including aliases)');
    if (ts.isIdentifier(n) && !moduleOf(n)?.file.endsWith('/lib/http.ts')) {
      const raw = checker.getSymbolAtLocation(n)?.declarations?.[0];
      if (raw && ts.isImportClause(raw) && raw.parent.moduleSpecifier.text === 'axios' && n !== raw.name) {
        const parent = n.parent;
        if (!ts.isPropertyAccessExpression(parent) || parent.expression !== n || !['isCancel', 'isAxiosError'].includes(parent.name.text)) fail(n, 'raw Axios access must stay in lib/http.ts');
      }
    }
    if (ts.isCallExpression(n)) {
      const e = unwrap(n.expression);
      const name = ts.isIdentifier(e) ? e.text : ts.isPropertyAccessExpression(e) ? e.name.text : '';
      if (['fetch', 'sendBeacon'].includes(name)) fail(n, 'network access must use lib/http.ts');
      if (isReplay(n)) return;
      const f = directFunction(e, env);
      if (f && networkFunction(f)) {
        scanFunction(f, n.arguments.map((a) => evaluate(a, env)), n);
        scanned.add(n);
      } else if (ts.isPropertyAccessExpression(e) && ['request', 'get', 'post', 'patch', 'put', 'delete', 'head', 'options'].includes(name)) {
        const vals = evaluate(e.expression, env);
        if (vals.some((v) => v?.transport) || name === 'request') transportCall(n, env, name);
      } else if (ts.isIdentifier(e)) {
        // Bound aliases of transport methods are rejected rather than dropped.
        if (evaluate(e, env).some((v) => v?.transportMethod || v?.axios)) fail(n, 'unbounded/aliased raw transport call');
      }
    }
    ts.forEachChild(n, (child) => visit(child, env));
  }
  for (const m of modules.values()) {
    const collect = (n) => {
      if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
        if (n.expression.name.text === 'request' || (m.file.endsWith('/lib/http.ts') && ['authTransport', 'http', 'portalHttp'].includes(n.expression.expression.getText()) && ['get', 'post', 'patch', 'delete', 'put', 'head', 'options'].includes(n.expression.name.text))) sinks.add(n);
      }
      ts.forEachChild(n, collect);
    };
    collect(m.ast);
    if (m.file.endsWith('/composables/collection.ts') || m.file.endsWith('/composables/admin-detail.ts')) continue;
    for (const env of componentContexts(m)) {
      if (m.file.endsWith('/lib/http.ts')) {
        // Generic exported wrappers are analyzed with their actual caller args.
        // Interceptors and refresh are implementation roots, not fake endpoints.
        for (const statement of m.ast.statements) if (!statement.modifiers?.some((v) => v.kind === ts.SyntaxKind.ExportKeyword)) visit(statement, env);
      } else visit(m.ast, env);
    }
  }
  for (const sink of sinks) if (!covered.has(sink)) fail(sink, 'HTTP request has no analyzed caller (fail closed)');
  if (!requests.length || !scanned.size) throw new Error('No frontend request contracts were extracted');
  return requests;
}

export function compareRequests(requests, routes) {
  const missing = requests.filter((request) => !routes.some((route) => {
    if (request.method !== route.method) return false;
    const wanted = request.path.split('/'), actual = route.path.split('/');
    if (wanted.length !== actual.length) return false;
    return wanted.every((part, i) => actual[i].startsWith(':') ? part.length > 0 : part !== SEGMENT && part === actual[i]);
  }));
  if (missing.length) throw new Error('Frontend requests absent from real Gin routes:\n' + [...new Set(missing.map((r) => `${r.method} ${r.path} (${r.at})`))].sort().join('\n'));
}
export function auditFrontend(root) {
  const contexts = readRouteContract(root);
  const sources = Object.fromEntries(filesBelow(path.join(root, 'web/src')).filter((p) => /\.(vue|[cm]?[jt]sx?)$/.test(p)).map((p) => [p, fs.readFileSync(p, 'utf8')]));
  const audited = contexts.map((context) => {
    const requests = extractRequests(sources, { admin_path: context.admin_path });
    compareRequests(requests, context.routes);
    return { admin_path: context.admin_path, requests, routes: context.routes };
  });
  return { requests: audited.flatMap((context) => context.requests), routes: audited.flatMap((context) => context.routes), contexts: audited };
}
