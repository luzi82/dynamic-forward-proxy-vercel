import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import { forwardedRequestHeaders, forwardedResponseHeaders } from "../src/headers.ts";
import { canonicalString, sign } from "../src/sign.ts";
import { handleProxy, type ProxyEnv } from "../src/proxy.ts";
import {
  HEADER_SIGNATURE,
  HEADER_TARGET_HOST,
  HEADER_TIMESTAMP,
} from "../src/sign.ts";

const SECRET = "test-secret";
const ALLOW = "api.example.com, cdn.example.com";

test("sign matches node crypto HMAC-SHA256", async () => {
  const canonical = canonicalString({
    timestamp: "1700000000",
    targetHost: "api.example.com",
    method: "POST",
    pathname: "/v1/items",
    search: "?x=1",
  });
  const expected = createHmac("sha256", SECRET).update(canonical).digest("hex");
  assert.equal(await sign(SECRET, canonical), expected);
});

test("rejects a wrong secret, an expired timestamp, and swapped method, path, or host", async () => {
  const { fetchImpl, calls } = mockFetch();
  const env = baseEnv();
  const deps = { env, fetch: fetchImpl, now: fixedNow };

  const wrongSecret = await signedRequest({ secret: "other-secret" });
  assert.equal((await handleProxy(wrongSecret, deps)).status, 401);

  const expired = await signedRequest();
  assert.equal(
    (await handleProxy(expired, { ...deps, now: () => 1_700_000_061_000 })).status,
    401,
  );

  const swappedMethod = await signedRequest({ method: "POST", signMethod: "GET" });
  assert.equal((await handleProxy(swappedMethod, deps)).status, 401);

  const swappedPath = await signedRequest({ path: "/other", signPath: "/v1/items?x=1" });
  assert.equal((await handleProxy(swappedPath, deps)).status, 401);

  const swappedHost = await signedRequest({ host: "cdn.example.com", signHost: "api.example.com" });
  assert.equal((await handleProxy(swappedHost, deps)).status, 401);

  const edge = await signedRequest({ timestamp: "1699999940" });
  assert.equal((await handleProxy(edge, deps)).status, 200);

  assert.equal(calls.length, 1);
});

test("accepts the previous secret inside the 60 second window", async () => {
  const { fetchImpl, calls } = mockFetch();
  const request = await signedRequest({ secret: "old-secret" });
  const response = await handleProxy(request, {
    env: { ...baseEnv(), DYNAMIC_FORWARD_PROXY_HMAC_SECRET_PREVIOUS: "old-secret" },
    fetch: fetchImpl,
    now: () => 1_700_000_000_000,
  });
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
});

test("rejects names that are uppercase, IP, metadata, or blocked suffixes", async () => {
  const { fetchImpl, calls } = mockFetch();
  const hosts = [
    "API.example.com",
    "127.0.0.1",
    "0x7f.0x0.0x0.0x1",
    "metadata.google.internal",
    "metadata.google.com",
    "metadata.goog",
    "instance-data",
    "kubernetes",
    "kubernetes.default",
    "localhost",
    "foo.local",
    "foo.internal",
    "foo.svc",
    "api.example.com:443",
    "api.example.com.",
  ];
  for (const host of hosts) {
    const request = await signedRequest({ host });
    assert.equal(
      (await handleProxy(request, {
        env: baseEnv(`${ALLOW},${host}`),
        fetch: fetchImpl,
        now: fixedNow,
      })).status,
      400,
      host,
    );
  }
  assert.equal(calls.length, 0);
});

test("allowlist hit forwards, a miss is 403, and an empty list is 500", async () => {
  const hit = mockFetch();
  const request = await signedRequest({ path: "/v1/items?x=1" });
  const response = await handleProxy(request, { env: baseEnv(), fetch: hit.fetchImpl, now: fixedNow });
  assert.equal(response.status, 200);
  assert.equal(hit.calls[0]?.url, "https://api.example.com/v1/items?x=1");
  assert.equal(hit.calls[0]?.init.redirect, "manual");

  const miss = mockFetch();
  const other = await signedRequest({ host: "other.example.com" });
  assert.equal((await handleProxy(other, { env: baseEnv(), fetch: miss.fetchImpl, now: fixedNow })).status, 403);
  assert.equal(miss.calls.length, 0);

  const empty = mockFetch();
  const blocked = await handleProxy(request, {
    env: { ...baseEnv(), DYNAMIC_FORWARD_PROXY_HOST_ALLOWLIST: " , " },
    fetch: empty.fetchImpl,
  });
  assert.equal(blocked.status, 500);
  assert.equal(empty.calls.length, 0);
});

test("an intranet name stays rejected when it is written in the allowlist", async () => {
  const { fetchImpl, calls } = mockFetch();
  const request = await signedRequest({ host: "metadata.google.internal" });
  const response = await handleProxy(request, {
    env: { ...baseEnv(), DYNAMIC_FORWARD_PROXY_HOST_ALLOWLIST: "metadata.google.internal" },
    fetch: fetchImpl,
    now: fixedNow,
  });
  assert.equal(response.status, 400);
  assert.equal(calls.length, 0);
});

test("strips proxy, hop-by-hop, and forwarded headers before the upstream request", () => {
  const incoming = new Headers();
  incoming.append("authorization", "Bearer token");
  incoming.append("cookie", "a=b");
  incoming.append("content-type", "application/json");
  incoming.append("x-forwarded-for", "203.0.113.5");
  incoming.append("x-vercel-id", "abc");
  incoming.append("x-real-ip", "203.0.113.5");
  incoming.append("forwarded", "for=203.0.113.5");
  incoming.append(HEADER_TARGET_HOST, "api.example.com");
  incoming.append(HEADER_TIMESTAMP, "1700000000");
  incoming.append(HEADER_SIGNATURE, "ab".repeat(32));
  incoming.append("connection", "close, x-custom");
  incoming.append("x-custom", "drop-me");
  incoming.append("content-length", "12");

  const outgoing = forwardedRequestHeaders(incoming, "api.example.com");
  assert.equal(outgoing.get("authorization"), "Bearer token");
  assert.equal(outgoing.get("cookie"), "a=b");
  assert.equal(outgoing.get("content-type"), "application/json");
  assert.equal(outgoing.get("host"), "api.example.com");
  for (const name of [
    "x-forwarded-for",
    "x-vercel-id",
    "x-real-ip",
    "forwarded",
    HEADER_TARGET_HOST,
    HEADER_TIMESTAMP,
    HEADER_SIGNATURE,
    "connection",
    "x-custom",
    "content-length",
  ]) {
    assert.equal(outgoing.get(name), null, name);
  }
});

test("strips hop-by-hop response headers and keeps location and set-cookie", () => {
  const incoming = new Headers();
  incoming.append("content-type", "text/plain");
  incoming.append("connection", "close");
  incoming.append("transfer-encoding", "chunked");
  incoming.append("location", "https://api.example.com/next");
  incoming.append("set-cookie", "a=1");
  incoming.append("set-cookie", "b=2");

  const outgoing = forwardedResponseHeaders(incoming);
  assert.equal(outgoing.get("content-type"), "text/plain");
  assert.equal(outgoing.get("location"), "https://api.example.com/next");
  assert.deepEqual(outgoing.getSetCookie(), ["a=1", "b=2"]);
  assert.equal(outgoing.get("connection"), null);
  assert.equal(outgoing.get("transfer-encoding"), null);
});

test("streams the request body and asks fetch not to follow redirects", async () => {
  const { fetchImpl, calls } = mockFetch(new Response("upstream-body", { status: 201, statusText: "Created" }));
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("hello"));
      controller.close();
    },
  });
  const request = await signedRequest({ method: "POST", body });
  const response = await handleProxy(request, { env: baseEnv(), fetch: fetchImpl, now: fixedNow });

  assert.equal(response.status, 201);
  assert.equal(response.statusText, "Created");
  assert.equal(await response.text(), "upstream-body");
  assert.equal(calls[0]?.init.redirect, "manual");
  assert.equal(calls[0]?.init.duplex, "half");
  assert.ok(calls[0]?.init.body instanceof ReadableStream);
  assert.notEqual(typeof calls[0]?.init.body, "string");
  assert.equal(request.bodyUsed, false);
});

test("GET does not forward a body", async () => {
  const { fetchImpl, calls } = mockFetch();
  const request = await signedRequest();
  await handleProxy(request, { env: baseEnv(), fetch: fetchImpl, now: fixedNow });
  assert.equal(calls[0]?.init.body, undefined);
  assert.equal(calls[0]?.init.method, "GET");
});

test("signed CONNECT and TRACE are rejected before fetch", async () => {
  for (const method of ["CONNECT", "TRACE"]) {
    const { fetchImpl, calls } = mockFetch();
    const request = withMethod(await signedRequest({ signMethod: method }), method);
    assert.equal((await handleProxy(request, { env: baseEnv(), fetch: fetchImpl, now: fixedNow })).status, 400, method);
    assert.equal(calls.length, 0);
  }
});

test("missing secret is 500 and does not fetch", async () => {
  const { fetchImpl, calls } = mockFetch();
  const request = await signedRequest();
  const response = await handleProxy(request, {
    env: { DYNAMIC_FORWARD_PROXY_HOST_ALLOWLIST: ALLOW },
    fetch: fetchImpl,
  });
  assert.equal(response.status, 500);
  assert.equal(calls.length, 0);
});

function baseEnv(allowlist = ALLOW): ProxyEnv {
  return {
    DYNAMIC_FORWARD_PROXY_HMAC_SECRET: SECRET,
    DYNAMIC_FORWARD_PROXY_HOST_ALLOWLIST: allowlist,
  };
}

function fixedNow(): number {
  return 1_700_000_000_000;
}

function mockFetch(response = new Response("ok", { status: 200 })) {
  const calls: { url: string; init: { method: string; redirect: string; body?: BodyInit | null; duplex?: string; headers: Headers } }[] = [];
  const fetchImpl = async (url: string, init: { method: string; redirect: "manual"; body?: BodyInit | null; duplex?: "half"; headers: Headers }) => {
    calls.push({ url, init });
    return response;
  };
  return { fetchImpl, calls };
}

function withMethod(request: Request, method: string): Request {
  return { method, url: request.url, headers: request.headers, body: request.body } as Request;
}

async function signedRequest(options: {
  path?: string;
  method?: string;
  host?: string;
  timestamp?: string;
  secret?: string;
  body?: BodyInit | null;
  signHost?: string;
  signMethod?: string;
  signPath?: string;
} = {}): Promise<Request> {
  const path = options.path ?? "/v1/items?x=1";
  const method = (options.method ?? "GET").toUpperCase();
  const host = options.host ?? "api.example.com";
  const timestamp = options.timestamp ?? "1700000000";
  const requestUrl = new URL(path, "https://proxy.example");
  const signedUrl = new URL(options.signPath ?? path, "https://proxy.example");
  const signature = await sign(
    options.secret ?? SECRET,
    canonicalString({
      timestamp,
      targetHost: options.signHost ?? host,
      method: options.signMethod ?? method,
      pathname: signedUrl.pathname,
      search: signedUrl.search,
    }),
  );
  const headers = new Headers();
  headers.set(HEADER_TARGET_HOST, host);
  headers.set(HEADER_TIMESTAMP, timestamp);
  headers.set(HEADER_SIGNATURE, signature);
  const init: RequestInit & { duplex?: "half" } = { method, headers };
  if (options.body) {
    init.body = options.body;
    init.duplex = "half";
  }
  return new Request(requestUrl, init);
}
