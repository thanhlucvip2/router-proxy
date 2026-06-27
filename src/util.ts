import * as ipaddr from 'ipaddr.js';
import { randomBytes } from 'node:crypto';

export function htmlEscape(value: unknown): string {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#x27;');
}

export function shellQuote(value: string): string {
  if (!value) return "''";
  return /^[A-Za-z0-9_/:=-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\"'\"'")}'`;
}

export function normalizeMac(mac: unknown): string {
  return String(mac ?? '').trim().toLowerCase();
}

export function validMac(mac: unknown): boolean {
  const parts = normalizeMac(mac).split(':');
  return parts.length === 6 && parts.every((part) => /^[0-9a-f]{2}$/.test(part));
}

export function ipToBigInt(ip: string): bigint {
  const parsed = ipaddr.parse(ip);
  const bytes = parsed.toByteArray();
  return bytes.reduce((acc, byte) => (acc << 8n) + BigInt(byte), 0n);
}

export function bigIntToIpv4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 255n)).join('.');
}

export function parseIpv4Cidr(cidr: string): { ip: string; prefix: number; mask: string; network: string; broadcast: string; size: bigint } {
  const [rawIp, rawPrefix = '24'] = String(cidr).trim().split('/');
  const ip = ipaddr.parse(rawIp);
  if (ip.kind() !== 'ipv4') throw new Error('LAN CIDR phai la IPv4, vi du 10.42.0.1/24');
  const prefix = Number(rawPrefix);
  if (!Number.isInteger(prefix) || prefix < 1 || prefix > 30) {
    throw new Error('LAN CIDR phai co prefix /1 den /30');
  }
  const ipValue = ipToBigInt(rawIp);
  const maskValue = ((1n << 32n) - 1n) ^ ((1n << BigInt(32 - prefix)) - 1n);
  const networkValue = ipValue & maskValue;
  const size = 1n << BigInt(32 - prefix);
  const broadcastValue = networkValue + size - 1n;
  return {
    ip: ip.toString(),
    prefix,
    mask: bigIntToIpv4(maskValue),
    network: `${bigIntToIpv4(networkValue)}/${prefix}`,
    broadcast: bigIntToIpv4(broadcastValue),
    size,
  };
}

export function ipInCidr(ip: string, cidr: string): boolean {
  try {
    const parsed = ipaddr.parse(ip);
    const range = ipaddr.parseCIDR(cidr);
    return parsed.match(range);
  } catch {
    return false;
  }
}

export function normalizeIpv4(value: unknown): string {
  const parsed = ipaddr.parse(String(value ?? '').trim());
  if (parsed.kind() !== 'ipv4') throw new Error('Dia chi phai la IPv4');
  return parsed.toString();
}

export function ipSortKey(value: string): number[] {
  return String(value).split('.').map((part) => Number(part) || 0);
}

export function compareIp(a: string, b: string): number {
  const left = ipSortKey(a);
  const right = ipSortKey(b);
  for (let idx = 0; idx < Math.max(left.length, right.length); idx += 1) {
    const diff = (left[idx] ?? 0) - (right[idx] ?? 0);
    if (diff) return diff;
  }
  return 0;
}

export function formValue(body: any, key: string, fallback = ''): string {
  const value = body?.[key];
  if (Array.isArray(value)) return String(value[0] ?? fallback);
  return String(value ?? fallback);
}

export function randomToken(bytes = 24): string {
  return randomBytes(bytes).toString('base64url');
}
