import JSONBigFactory from "json-bigint";

// Keep json-bigint only for its BigInt-aware serializer. Its native-BigInt
// parser treats long fractions as integers; parse number tokens by syntax here.
const json = JSONBigFactory({ useNativeBigInt: true });
export function parseJSON(value: string): unknown {
  let offset = 0;
  const fail = (): never => {
    throw new SyntaxError(`Invalid JSON at position ${offset}`);
  };
  const whitespace = () => {
    while (/^[\t\n\r ]$/.test(value[offset] || "")) offset++;
  };
  function string(): string {
    const start = offset++;
    while (offset < value.length) {
      const ch = value[offset++];
      if (ch === '"') return JSON.parse(value.slice(start, offset)) as string;
      if (ch === "\\") offset++;
    }
    return fail();
  }
  function read(): unknown {
    whitespace();
    const ch = value[offset];
    if (ch === '"') return string();
    if (ch === "{") {
      offset++;
      const result: Record<string, unknown> = Object.create(null);
      whitespace();
      if (value[offset] === "}") {
        offset++;
        return result;
      }
      while (offset < value.length) {
        whitespace();
        if (value[offset] !== '"') return fail();
        const key = string();
        if (Object.hasOwn(result, key)) return fail();
        whitespace();
        if (value[offset++] !== ":") return fail();
        result[key] = read();
        whitespace();
        const next = value[offset++];
        if (next === "}") return result;
        if (next !== ",") return fail();
      }
      return fail();
    }
    if (ch === "[") {
      offset++;
      const result: unknown[] = [];
      whitespace();
      if (value[offset] === "]") {
        offset++;
        return result;
      }
      while (offset < value.length) {
        result.push(read());
        whitespace();
        const next = value[offset++];
        if (next === "]") return result;
        if (next !== ",") return fail();
      }
      return fail();
    }
    for (const [token, parsed] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (value.startsWith(token, offset)) {
        offset += token.length;
        return parsed;
      }
    }
    const token = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      value.slice(offset),
    )?.[0];
    if (!token) return fail();
    offset += token.length;
    const number = Number(token);
    return !/[.eE]/.test(token) && !Number.isSafeInteger(number)
      ? BigInt(token)
      : number;
  }
  const result = read();
  whitespace();
  if (offset !== value.length) return fail();
  return result;
}
export const stringify = (value: unknown, space?: number): string =>
  json.stringify(value, undefined, space);
export type Row = Record<string, unknown>;
export function record(value: unknown): Row {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Row)
    : {};
}
export function rows(value: unknown): Row[] {
  return Array.isArray(value) ? value.map(record) : [];
}
export function text(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) return value.map(text).join("、") || "—";
  if (typeof value === "object") return stringify(value, 2);
  if (typeof value === "boolean") return value ? "是" : "否";
  return String(value);
}
export function dateText(value: unknown, seconds = false): string {
  if (!value) return "—";
  const d = new Date(String(value));
  if (Number.isNaN(d.getTime())) return "—";
  const p = (v: number) => String(v).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}${seconds ? ":" + p(d.getSeconds()) : ""}`;
}
export const idText = (value: unknown) =>
  value === null || value === undefined ? "" : String(value);
export interface Page {
  items: Row[];
  total: number;
  page?: number;
  page_size?: number;
}
export const cleanParams = (value: Row): Row =>
  Object.fromEntries(
    Object.entries(value).filter(
      ([, v]) => v !== "" && v !== undefined && v !== null,
    ),
  );
