import { decideHost, parseAllowlist } from "./host.ts";
import { forwardedRequestHeaders, forwardedResponseHeaders } from "./headers.ts";
import {
  HEADER_SIGNATURE,
  HEADER_TARGET_HOST,
  HEADER_TIMESTAMP,
  canonicalString,
  signaturesMatch,
  timestampFresh,
} from "./sign.ts";

export const config = {
  runtime: "nodejs",
};

export interface ProxyEnv {
  DYNAMIC_FORWARD_PROXY_HMAC_SECRET?: string;
  DYNAMIC_FORWARD_PROXY_HMAC_SECRET_PREVIOUS?: string;
  DYNAMIC_FORWARD_PROXY_HOST_ALLOWLIST?: string;
}

interface FetchInit {
  method: string;
  headers: Headers;
  redirect: "manual";
  body?: BodyInit | null;
  duplex?: "half";
}

export async function handleProxy(
  request: Request,
  deps: {
    env: ProxyEnv;
    fetch: (input: string, init: FetchInit) => Promise<Response>;
    now?: () => number;
  },
): Promise<Response> {
  const secret = deps.env.DYNAMIC_FORWARD_PROXY_HMAC_SECRET;
  const allowlist = parseAllowlist(deps.env.DYNAMIC_FORWARD_PROXY_HOST_ALLOWLIST);
  if (!secret || !allowlist) return text(500);

  const method = request.method.toUpperCase();
  const targetHost = request.headers.get(HEADER_TARGET_HOST);
  const timestamp = request.headers.get(HEADER_TIMESTAMP);
  const signature = request.headers.get(HEADER_SIGNATURE);
  if (targetHost === null || timestamp === null || signature === null) return text(401);

  const nowSeconds = Math.floor((deps.now?.() ?? Date.now()) / 1000);
  if (!timestampFresh(timestamp, nowSeconds)) return text(401);

  const url = new URL(request.url);
  const canonical = canonicalString({
    timestamp,
    targetHost,
    method,
    pathname: url.pathname,
    search: url.search,
  });
  const secrets = [secret];
  const previous = deps.env.DYNAMIC_FORWARD_PROXY_HMAC_SECRET_PREVIOUS;
  if (previous) secrets.push(previous);
  if (!(await signaturesMatch(secrets, canonical, signature))) return text(401);

  if (method === "CONNECT" || method === "TRACE") return text(400);

  const decision = decideHost(targetHost, allowlist);
  if (!decision.ok) return text(decision.status);

  const upstream = new URL(`https://${targetHost}`);
  upstream.pathname = url.pathname;
  upstream.search = url.search;

  const init: FetchInit = {
    method,
    headers: forwardedRequestHeaders(request.headers, targetHost),
    redirect: "manual",
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
    headers: forwardedResponseHeaders(upstreamResponse.headers),
  });
}

export default function middleware(request: Request): Promise<Response> {
  return handleProxy(request, {
    env: process.env,
    fetch: (input, init) => fetch(input, init),
  });
}

function text(status: number): Response {
  return new Response(null, { status });
}
