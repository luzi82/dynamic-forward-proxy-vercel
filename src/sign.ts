export const HEADER_TARGET_HOST = "X-DynamicForwardProxyVercel-Target-Host";
export const HEADER_TIMESTAMP = "X-DynamicForwardProxyVercel-Timestamp";
export const HEADER_SIGNATURE = "X-DynamicForwardProxyVercel-Signature";

export const SKEW_SECONDS = 60;

export function canonicalString(input: {
  timestamp: string;
  targetHost: string;
  method: string;
  pathname: string;
  search: string;
}): string {
  return `${input.timestamp}\n${input.targetHost}\n${input.method}\n${input.pathname}${input.search}`;
}

export async function sign(secret: string, canonical: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical));
  return toHex(new Uint8Array(mac));
}

export function timestampFresh(timestamp: string, nowSeconds: number): boolean {
  if (!/^[0-9]{1,12}$/.test(timestamp)) return false;
  const value = Number(timestamp);
  if (!Number.isSafeInteger(value)) return false;
  return Math.abs(nowSeconds - value) <= SKEW_SECONDS;
}

export async function signaturesMatch(
  secrets: readonly string[],
  canonical: string,
  provided: string,
): Promise<boolean> {
  const wellFormed = /^[0-9a-f]{64}$/.test(provided);
  const candidate = wellFormed ? provided : "0".repeat(64);
  let ok = false;
  for (const secret of secrets) {
    const expected = await sign(secret, canonical);
    ok = (timingSafeEqual(expected, candidate) && wellFormed) || ok;
  }
  return ok;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}
