const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DECIMAL = /^[0-9]+$/;
const HEX = /^0x[0-9a-f]+$/;

const BLOCKED_SUFFIXES = [
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
  "svc",
];

const BLOCKED_EXACT = new Set([
  "metadata.google.internal",
  "metadata.google.com",
  "metadata.goog",
  "instance-data",
  "kubernetes",
  "kubernetes.default",
]);

export type HostDecision = { ok: true } | { ok: false; status: 400 | 403 };

export function parseAllowlist(raw: string | undefined): Set<string> | null {
  if (raw === undefined) return null;
  const hosts = raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (hosts.length === 0) return null;
  return new Set(hosts);
}

export function decideHost(host: string, allowlist: ReadonlySet<string>): HostDecision {
  if (!isNameAllowed(host)) return { ok: false, status: 400 };
  if (!allowlist.has(host)) return { ok: false, status: 403 };
  return { ok: true };
}

export function isNameAllowed(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  if (host.includes(":") || host.includes("[") || host.includes("]")) return false;
  if (BLOCKED_EXACT.has(host) || hasBlockedSuffix(host)) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  if (labels.some((label) => !LABEL.test(label))) return false;
  if (labels.every((label) => DECIMAL.test(label) || HEX.test(label))) return false;
  return true;
}

function hasBlockedSuffix(host: string): boolean {
  return BLOCKED_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}
