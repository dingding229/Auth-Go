// Display classification only; forwarding trust is decided by the server.
const v4 = /^(?:\d{1,3}|\*)(?:\.(?:\d{1,3}|\*)){3}$/;
const privateV4 =
  /^(?:10|127)\.|^169\.254\.|^192\.168\.|^172\.(?:1[6-9]|2\d|3[01])\./;
const privateV6 = /^(?:::1|f[cd][0-9a-f]{0,2}:.*|fe[89ab][0-9a-f]:.*)$/;
export function internalIP(value: unknown): boolean {
  const raw =
    String(value ?? "")
      .toLowerCase()
      .split("%")[0] ?? "";
  const mapped = raw.startsWith("::ffff:") ? raw.slice(7) : raw;
  if (v4.test(mapped)) return privateV4.test(mapped);
  return raw.includes(":") && privateV6.test(raw);
}

let regions: Intl.DisplayNames | undefined;
let regionConstructor: typeof Intl.DisplayNames | undefined;
export function regionName(
  code: unknown,
  fallback = String(code || ""),
): string {
  const value = String(code || "");
  try {
    if (regionConstructor !== Intl.DisplayNames) {
      regions = undefined;
      regionConstructor = Intl.DisplayNames;
    }
    regions ??= new Intl.DisplayNames("zh-CN", {
      type: "region",
      fallback: "none",
    });
    return regions.of(value) || fallback;
  } catch {
    return fallback;
  }
}
