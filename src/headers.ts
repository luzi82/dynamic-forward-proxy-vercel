import { HEADER_SIGNATURE, HEADER_TARGET_HOST, HEADER_TIMESTAMP } from "./sign.ts";

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const PROXY_HEADERS = new Set([
  HEADER_TARGET_HOST.toLowerCase(),
  HEADER_TIMESTAMP.toLowerCase(),
  HEADER_SIGNATURE.toLowerCase(),
]);

export function forwardedRequestHeaders(incoming: Headers, targetHost: string): Headers {
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

export function forwardedResponseHeaders(incoming: Headers): Headers {
  const drop = hopByHopNames(incoming);
  const outgoing = new Headers();
  incoming.forEach((value, key) => {
    if (drop.has(key)) return;
    outgoing.append(key, value);
  });
  return outgoing;
}

function hopByHopNames(headers: Headers): Set<string> {
  const names = new Set(HOP_BY_HOP);
  const connection = headers.get("connection");
  if (!connection) return names;
  for (const part of connection.split(",")) {
    const name = part.trim().toLowerCase();
    if (name) names.add(name);
  }
  return names;
}

function isProxyInfrastructure(name: string): boolean {
  return name === "forwarded" || name === "x-real-ip" || name.startsWith("x-forwarded-") || name.startsWith("x-vercel-");
}
