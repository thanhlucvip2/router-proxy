import { createConnection, createServer, Socket } from 'node:net';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { UpstreamProxy } from './types';

function formatProxyHost(host: string): string {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

function formatHostPort(host: string, port: number): string {
  return `${formatProxyHost(host)}:${port}`;
}

function parseHostPort(value: string, defaultPort: number): [string, number] {
  const raw = value.trim();
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end !== -1) {
      const host = raw.slice(1, end);
      const rest = raw.slice(end + 1);
      if (rest.startsWith(':') && /^\d+$/.test(rest.slice(1))) return [host, Number(rest.slice(1))];
      return [host, defaultPort];
    }
  }
  if ((raw.match(/:/g) || []).length === 1) {
    const [host, port] = raw.split(':');
    if (/^\d+$/.test(port)) return [host, Number(port)];
  }
  return [raw, defaultPort];
}

function parseHttpTarget(data: Buffer, defaultPort: number): [string, number] | null {
  const text = data.toString('latin1');
  const lineEnd = text.indexOf('\r\n');
  if (lineEnd === -1) return null;
  const parts = text.slice(0, lineEnd).split(/\s+/);
  const method = String(parts[0] || '').toUpperCase();
  if (!['GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT'].includes(method)) return null;
  if (method === 'CONNECT' && parts[1]) return parseHostPort(parts[1], defaultPort);
  for (const line of text.slice(lineEnd + 2).split('\r\n')) {
    if (!line) break;
    const idx = line.indexOf(':');
    if (idx > 0 && line.slice(0, idx).toLowerCase() === 'host') return parseHostPort(line.slice(idx + 1), defaultPort);
  }
  return null;
}

function parseTlsSni(data: Buffer): string | null {
  try {
    if (data.length < 5 || data[0] !== 22) return null;
    const recordLen = data.readUInt16BE(3);
    if (data.length < Math.min(5 + recordLen, 64)) return null;
    let pos = 5;
    if (data[pos] !== 1) return null;
    const handshakeLen = data.readUIntBE(pos + 1, 3);
    const end = Math.min(data.length, pos + 4 + handshakeLen);
    pos += 4 + 2 + 32;
    if (pos >= end) return null;
    pos += 1 + data[pos];
    if (pos + 2 > end) return null;
    pos += 2 + data.readUInt16BE(pos);
    if (pos >= end) return null;
    pos += 1 + data[pos];
    if (pos + 2 > end) return null;
    const extensionsLen = data.readUInt16BE(pos);
    pos += 2;
    const extensionsEnd = Math.min(end, pos + extensionsLen);
    while (pos + 4 <= extensionsEnd) {
      const extType = data.readUInt16BE(pos);
      const extLen = data.readUInt16BE(pos + 2);
      pos += 4;
      const extEnd = pos + extLen;
      if (extType === 0 && pos + 2 <= extEnd) {
        const listLen = data.readUInt16BE(pos);
        let namePos = pos + 2;
        const listEnd = Math.min(extEnd, namePos + listLen);
        while (namePos + 3 <= listEnd) {
          const nameType = data[namePos];
          const nameLen = data.readUInt16BE(namePos + 1);
          namePos += 3;
          if (nameType === 0 && namePos + nameLen <= listEnd) return data.subarray(namePos, namePos + nameLen).toString('utf8');
          namePos += nameLen;
        }
      }
      pos = extEnd;
    }
  } catch {
    return null;
  }
  return null;
}

function normalizeSocketIp(value: unknown): string {
  const ip = String(value || '');
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function conntrackCommand(): string[] {
  if (typeof process.geteuid === 'function' && process.geteuid() === 0) return ['conntrack', '-L', '-p', 'tcp'];
  return ['sudo', '-n', 'conntrack', '-L', '-p', 'tcp'];
}

function parseConntrackTokens(line: string): Record<string, string>[] {
  const groups: Record<string, string>[] = [];
  let current: Record<string, string> = {};
  for (const item of line.trim().split(/\s+/)) {
    const idx = item.indexOf('=');
    if (idx <= 0) continue;
    const key = item.slice(0, idx);
    const value = item.slice(idx + 1);
    if (key === 'src' && Object.keys(current).length) {
      groups.push(current);
      current = {};
    }
    current[key] = value;
  }
  if (Object.keys(current).length) groups.push(current);
  return groups;
}

function originalDestination(client: Socket, listenPort: number): [string, number] | null {
  const clientIp = normalizeSocketIp(client.remoteAddress);
  const clientPort = Number(client.remotePort || 0);
  if (!clientIp || !clientPort) return null;
  const command = conntrackCommand();
  const result = spawnSync(command[0], command.slice(1), { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  if (result.status !== 0) return null;
  for (const line of String(result.stdout || '').split('\n')) {
    if (!line.includes(`src=${clientIp}`) || !line.includes(`sport=${clientPort}`)) continue;
    const groups = parseConntrackTokens(line);
    const original = groups[0] || {};
    const reply = groups[1] || {};
    if (original.src !== clientIp || Number(original.sport) !== clientPort) continue;
    if (listenPort && Number(reply.sport) !== listenPort) continue;
    const host = original.dst || '';
    const port = Number(original.dport || 0);
    if (host && Number.isInteger(port) && port > 0 && port <= 65535) return [host, port];
  }
  return null;
}

function connectHttpProxy(proxy: UpstreamProxy, targetHost: string, targetPort: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const upstream = createConnection({ host: proxy.host, port: Number(proxy.port), timeout: 12000 });
    upstream.once('error', reject);
    upstream.once('connect', () => {
      const hostHeader = formatHostPort(targetHost, targetPort);
      const lines = [`CONNECT ${hostHeader} HTTP/1.1`, `Host: ${hostHeader}`, 'Proxy-Connection: keep-alive'];
      if (proxy.login) {
        const token = Buffer.from(`${proxy.login}:${proxy.password || ''}`).toString('base64');
        lines.push(`Proxy-Authorization: Basic ${token}`);
      }
      upstream.write(`${lines.join('\r\n')}\r\n\r\n`);
    });
    let response = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      response = Buffer.concat([response, chunk]);
      if (!response.includes('\r\n\r\n') && response.length < 16384) return;
      upstream.off('data', onData);
      const status = response.toString('latin1').split('\r\n', 1)[0] || '';
      if (!status.includes(' 200 ')) {
        upstream.destroy();
        reject(new Error(status || 'proxy connect failed'));
        return;
      }
      const bodyStart = response.indexOf('\r\n\r\n') + 4;
      const extra = response.subarray(bodyStart);
      if (extra.length) upstream.unshift(extra);
      upstream.setTimeout(0);
      resolve(upstream);
    };
    upstream.on('data', onData);
  });
}

async function detectTarget(client: Socket, listenPort: number): Promise<[string, number, Buffer]> {
  let original: [string, number] | null | undefined;
  const getOriginal = () => {
    if (original === undefined) original = originalDestination(client, listenPort);
    return original;
  };
  const chunks: Buffer[] = [];
  const started = Date.now();
  while (Date.now() - started < 5000) {
    const chunk = await new Promise<Buffer>((resolve) => {
      const timer = setTimeout(() => resolve(Buffer.alloc(0)), 200);
      client.once('data', (data) => {
        clearTimeout(timer);
        resolve(data);
      });
    });
    if (!chunk.length) break;
    chunks.push(chunk);
    const data = Buffer.concat(chunks);
    const http = parseHttpTarget(data, 80);
    if (http) return [http[0], http[1], data];
    const sni = parseTlsSni(data);
    if (sni) return [sni, 443, data];
    if (data.includes('\r\n\r\n') || data.length >= 4096) break;
  }
  const fallback = getOriginal();
  if (fallback) return [fallback[0], fallback[1], Buffer.concat(chunks)];
  return ['', 443, Buffer.concat(chunks)];
}

export function runDomainProxyWorker(configPath: string): void {
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  const proxy: UpstreamProxy = config.proxy;
  const listenIp = config.listen_ip;
  const listenPort = Number(config.listen_port);
  const server = createServer(async (client) => {
    let upstream: Socket | null = null;
    let targetHost = '';
    let targetPort = 0;
    try {
      const [host, port, initialData] = await detectTarget(client, listenPort);
      targetHost = host;
      targetPort = port;
      if (!targetHost) {
        client.destroy();
        return;
      }
      upstream = await connectHttpProxy(proxy, targetHost, targetPort);
      if (initialData.length) upstream.write(initialData);
      client.pipe(upstream);
      upstream.pipe(client);
    } catch (error: any) {
      const peer = `${normalizeSocketIp(client.remoteAddress)}:${client.remotePort || ''}`;
      const target = targetHost ? ` target=${targetHost}:${targetPort}` : '';
      process.stderr.write(`domain-proxy client ${peer}${target}: ${error?.message || error}\n`);
      client.destroy();
      upstream?.destroy();
    }
  });
  server.listen(listenPort, listenIp, () => {
    process.stderr.write(`domain-proxy listening on ${listenIp}:${listenPort}\n`);
  });
}
