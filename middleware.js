// src/host.ts
var LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
var DECIMAL = /^[0-9]+$/;
var HEX = /^0x[0-9a-f]+$/;
var BLOCKED_SUFFIXES = [
  "local",
  "localhost",
  "localdomain",
  "internal",
  "intranet",
  "lan",
  "home",
  "corp",
  "home.arpa",
  "google.internal",
  "ec2.internal",
  "cluster.local",
  "svc"
];
var BLOCKED_EXACT = /* @__PURE__ */ new Set([
  "metadata.google.internal",
  "metadata.google.com",
  "metadata.goog",
  "instance-data",
  "kubernetes",
  "kubernetes.default"
]);
function parseAllowlist(raw) {
  if (raw === void 0) return null;
  const hosts = raw.split(",").map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  if (hosts.length === 0) return null;
  return new Set(hosts);
}
function decideHost(host, allowlist) {
  if (!isNameAllowed(host)) return { ok: false, status: 400 };
  if (!allowlist.has(host)) return { ok: false, status: 403 };
  return { ok: true };
}
function isNameAllowed(host) {
  if (host.length === 0 || host.length > 253) return false;
  if (host.includes(":") || host.includes("[") || host.includes("]")) return false;
  if (BLOCKED_EXACT.has(host) || hasBlockedSuffix(host)) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  if (labels.some((label) => !LABEL.test(label))) return false;
  if (labels.every((label) => DECIMAL.test(label) || HEX.test(label))) return false;
  return true;
}
function hasBlockedSuffix(host) {
  return BLOCKED_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

// src/sign.ts
var HEADER_TARGET_HOST = "X-DynamicForwardProxyVercel-Target-Host";
var HEADER_TIMESTAMP = "X-DynamicForwardProxyVercel-Timestamp";
var HEADER_SIGNATURE = "X-DynamicForwardProxyVercel-Signature";
var SKEW_SECONDS = 60;
function canonicalString(input) {
  return `${input.timestamp}
${input.targetHost}
${input.method}
${input.pathname}${input.search}`;
}
async function sign(secret, canonical) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical));
  return toHex(new Uint8Array(mac));
}
function timestampFresh(timestamp, nowSeconds) {
  if (!/^[0-9]{1,12}$/.test(timestamp)) return false;
  const value = Number(timestamp);
  if (!Number.isSafeInteger(value)) return false;
  return Math.abs(nowSeconds - value) <= SKEW_SECONDS;
}
async function signaturesMatch(secrets, canonical, provided) {
  const wellFormed = /^[0-9a-f]{64}$/.test(provided);
  const candidate = wellFormed ? provided : "0".repeat(64);
  let ok = false;
  for (const secret of secrets) {
    const expected = await sign(secret, canonical);
    ok = timingSafeEqual(expected, candidate) && wellFormed || ok;
  }
  return ok;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function toHex(bytes) {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

// src/headers.ts
var HOP_BY_HOP = /* @__PURE__ */ new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade"
]);
var PROXY_HEADERS = /* @__PURE__ */ new Set([
  HEADER_TARGET_HOST.toLowerCase(),
  HEADER_TIMESTAMP.toLowerCase(),
  HEADER_SIGNATURE.toLowerCase()
]);
function forwardedRequestHeaders(incoming, targetHost) {
  const drop = hopByHopNames(incoming);
  drop.add("host");
  drop.add("content-length");
  drop.add("expect");
  for (const name of PROXY_HEADERS) drop.add(name);
  const outgoing = new Headers();
  incoming.forEach((value, key) => {
    if (drop.has(key) || isProxyInfrastructure(key)) return;
    outgoing.append(key, value);
  });
  outgoing.set("host", targetHost);
  return outgoing;
}
function forwardedResponseHeaders(incoming) {
  const drop = hopByHopNames(incoming);
  const outgoing = new Headers();
  incoming.forEach((value, key) => {
    if (drop.has(key)) return;
    outgoing.append(key, value);
  });
  return outgoing;
}
function hopByHopNames(headers) {
  const names = new Set(HOP_BY_HOP);
  const connection = headers.get("connection");
  if (!connection) return names;
  for (const part of connection.split(",")) {
    const name = part.trim().toLowerCase();
    if (name) names.add(name);
  }
  return names;
}
function isProxyInfrastructure(name) {
  return name === "forwarded" || name === "x-real-ip" || name.startsWith("x-forwarded-") || name.startsWith("x-vercel-");
}

// src/proxy.ts
var config = {
  runtime: "nodejs"
};
async function handleProxy(request, deps) {
  const secret = deps.env.DYNAMIC_FORWARD_PROXY_HMAC_SECRET;
  const allowlist = parseAllowlist(deps.env.DYNAMIC_FORWARD_PROXY_HOST_ALLOWLIST);
  if (!secret || !allowlist) return text(500);
  const method = request.method.toUpperCase();
  const targetHost = request.headers.get(HEADER_TARGET_HOST);
  const timestamp = request.headers.get(HEADER_TIMESTAMP);
  const signature = request.headers.get(HEADER_SIGNATURE);
  if (targetHost === null || timestamp === null || signature === null) return text(401);
  const nowSeconds = Math.floor((deps.now?.() ?? Date.now()) / 1e3);
  if (!timestampFresh(timestamp, nowSeconds)) return text(401);
  const url = new URL(request.url);
  const canonical = canonicalString({
    timestamp,
    targetHost,
    method,
    pathname: url.pathname,
    search: url.search
  });
  const secrets = [secret];
  const previous = deps.env.DYNAMIC_FORWARD_PROXY_HMAC_SECRET_PREVIOUS;
  if (previous) secrets.push(previous);
  if (!await signaturesMatch(secrets, canonical, signature)) return text(401);
  if (method === "CONNECT" || method === "TRACE") return text(400);
  const decision = decideHost(targetHost, allowlist);
  if (!decision.ok) return text(decision.status);
  const upstream = new URL(`https://${targetHost}`);
  upstream.pathname = url.pathname;
  upstream.search = url.search;
  const init = {
    method,
    headers: forwardedRequestHeaders(request.headers, targetHost),
    redirect: "manual"
  };
  if (method !== "GET" && method !== "HEAD" && request.body) {
    init.body = request.body;
    init.duplex = "half";
  }
  const upstreamResponse = await deps.fetch(upstream.toString(), init);
  const status = upstreamResponse.status;
  const nullBody = status === 204 || status === 205 || status === 304;
  return new Response(nullBody ? null : upstreamResponse.body, {
    status,
    statusText: upstreamResponse.statusText,
    headers: forwardedResponseHeaders(upstreamResponse.headers)
  });
}
function middleware(request) {
  return handleProxy(request, {
    env: process.env,
    fetch: (input, init) => fetch(input, init)
  });
}
function text(status) {
  return new Response(null, { status });
}
export {
  config,
  middleware as default,
  handleProxy
};
