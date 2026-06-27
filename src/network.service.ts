import { Injectable } from '@nestjs/common';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import * as ipaddr from 'ipaddr.js';
import {
  DEFAULT_BRIDGE_IF,
  DEFAULT_LAN_CIDR,
  DNSMASQ_CONF,
  DNSMASQ_LEASES,
  DNSMASQ_PID,
  GUARD_CHAIN,
  HOSTAPD_CONF,
  HOSTAPD_PID,
  NETWORKD_PREFIX,
  NETWORKD_RUNTIME_DIR,
  PRIVATE_NETS,
  PROXY_CHAIN,
  PROXY_LOCAL_BASE,
  PROXY_TEST_URLS,
  PROXY_TYPES,
  PROXY_V4_GUARD_CHAIN,
  PROXY_V6_GUARD_CHAIN,
  REDSOCKS_CONF,
  REDSOCKS_PID,
  STATE_DIR,
  UDP_GUARD_PORTS,
  WEB_PID,
  WIFI_5_CENTER_SEG0,
} from './constants';
import { StateService } from './state.service';
import { HotspotConfig, ProxyFamily, RouterState, UpstreamProxy } from './types';
import { bigIntToIpv4, compareIp, ipInCidr, ipToBigInt, normalizeMac, normalizeIpv4, parseIpv4Cidr, shellQuote, validMac } from './util';
import { SystemService } from './system.service';

@Injectable()
export class NetworkService {
  wanIf = '';
  baseLanIf = '';
  private proxyApplyTimer: NodeJS.Timeout | null = null;
  private proxyApplyLanIf = '';
  private proxyApplyFlushIps = new Set<string>();

  constructor(
    private readonly system: SystemService,
    private readonly state: StateService,
  ) {}

  setRuntime(wanIf: string, baseLanIf: string): void {
    this.wanIf = wanIf;
    this.baseLanIf = baseLanIf;
  }

  interfaceList(value: unknown): string[] {
    const raw = Array.isArray(value) ? value : String(value || '').replaceAll(',', ' ').split(/\s+/);
    const items: string[] = [];
    for (const item of raw) {
      const name = String(item || '').trim();
      if (name && !items.includes(name)) items.push(name);
    }
    return items;
  }

  primaryInterface(value: unknown): string {
    return this.interfaceList(value)[0] || '';
  }

  allInterfaceNames(): string[] {
    const rows = this.system.readJsonCommand(['ip', '-j', 'link']);
    return rows.map((row: any) => row.ifname).filter((name: string) => name && name !== 'lo');
  }

  interfaceExists(ifname: string): boolean {
    return this.allInterfaceNames().includes(ifname);
  }

  requireInterface(ifname: string, role: string): void {
    const names = this.allInterfaceNames();
    if (!names.includes(ifname)) {
      throw new Error(`${role} interface ${JSON.stringify(ifname)} khong ton tai. Interfaces hien co: ${names.join(', ') || 'none'}`);
    }
  }

  linkNames(): string[] {
    return this.allInterfaceNames().filter((name) => !name.startsWith('docker') && !name.startsWith('br-') && !name.startsWith('veth'));
  }

  wirelessInterfaces(): string[] {
    const names = this.linkNames().filter((name) => existsSync(`/sys/class/net/${name}/wireless`));
    if (names.length || !this.system.commandExists('iw')) return names;
    const out = this.system.sh(['iw', 'dev'], false);
    for (const raw of out.split('\n')) {
      const line = raw.trim();
      if (line.startsWith('Interface ')) {
        const ifname = line.split(/\s+/, 2)[1]?.trim();
        if (ifname && !names.includes(ifname)) names.push(ifname);
      }
    }
    return names;
  }

  detectWan(): string {
    const route = this.system.sh(['ip', 'route', 'show', 'default'], false);
    for (const line of route.split('\n')) {
      const parts = line.trim().split(/\s+/);
      const idx = parts.indexOf('dev');
      if (idx >= 0 && parts[idx + 1]) return parts[idx + 1];
    }
    return '';
  }

  detectLan(wanIf: string): string {
    const candidates = this.linkNames().filter((name) => name !== wanIf);
    const down = candidates.filter((name) => this.system.sh(['ip', '-br', 'link', 'show', name], false).includes(' DOWN '));
    return (down[0] || candidates[0] || '');
  }

  cidrParts(cidr: string): [string, string, string] {
    const parsed = parseIpv4Cidr(cidr);
    return [parsed.ip, parsed.mask, parsed.network];
  }

  dhcpRangeFor(lanCidr: string): [string, string, string] {
    const parsed = parseIpv4Cidr(lanCidr);
    const ipValue = ipToBigInt(parsed.ip);
    const [networkIp, prefixText] = parsed.network.split('/');
    const networkValue = ipToBigInt(networkIp);
    const broadcastValue = networkValue + parsed.size - 1n;
    let first = networkValue + 1n;
    let last = broadcastValue - 1n;
    if (first > last) throw new Error('LAN CIDR qua nho, khong co dia chi DHCP kha dung');
    let start: bigint;
    let end: bigint;
    if (parsed.size > 512n) {
      start = first > networkValue + 257n ? first : networkValue + 257n;
      end = last < broadcastValue - 257n ? last : broadcastValue - 257n;
    } else {
      start = first > networkValue + 50n ? first : networkValue + 50n;
      end = last < networkValue + 200n ? last : networkValue + 200n;
    }
    if (start > end) {
      start = first;
      end = last;
    }
    if (start === ipValue) start += 1n;
    if (end === ipValue) end -= 1n;
    if (start > end) throw new Error('Khong tao duoc DHCP range khac IP gateway');
    return [bigIntToIpv4(start), bigIntToIpv4(end), parsed.mask || prefixText];
  }

  normalizeLanCidr(value: unknown): string {
    let cidr = String(value || '').trim();
    if (!cidr) throw new Error('LAN CIDR khong duoc de trong');
    if (!cidr.includes('/')) cidr += '/24';
    const parsed = parseIpv4Cidr(cidr);
    if (parsed.ip === parsed.network.split('/')[0] || parsed.ip === parsed.broadcast) {
      throw new Error('IP gateway khong duoc la network/broadcast address');
    }
    this.dhcpRangeFor(`${parsed.ip}/${parsed.prefix}`);
    return `${parsed.ip}/${parsed.prefix}`;
  }

  activeLanIf(baseLanIf = this.baseLanIf, state?: RouterState): string {
    const hotspot = this.state.normalizedHotspot(state || this.state.loadState());
    const lanMembers = this.interfaceList(baseLanIf);
    if (lanMembers.length > 1) return DEFAULT_BRIDGE_IF;
    if (hotspot.enabled && hotspot.ifname) return DEFAULT_BRIDGE_IF;
    return this.primaryInterface(baseLanIf);
  }

  currentMac(ifname: string): string {
    try {
      return readFileSync(`/sys/class/net/${ifname}/address`, 'utf8').trim();
    } catch {
      return '';
    }
  }

  randomLocalMac(): string {
    const bytes = Array.from(randomBytes(6));
    bytes[0] = (bytes[0] | 0x02) & 0xfe;
    return bytes.map((value) => value.toString(16).padStart(2, '0')).join(':');
  }

  rotateInterfaceMac(ifname: string): [string, string] {
    if (!ifname || ifname === 'lo') throw new Error('Interface khong hop le');
    const oldMac = this.currentMac(ifname);
    const newMac = this.randomLocalMac();
    this.system.sudo(['ip', 'link', 'set', 'dev', ifname, 'down']);
    this.system.sudo(['ip', 'link', 'set', 'dev', ifname, 'address', newMac]);
    this.system.sudo(['ip', 'link', 'set', 'dev', ifname, 'up']);
    if (this.system.commandExists('networkctl')) this.system.sudo(['networkctl', 'renew', ifname], false);
    if (this.system.commandExists('nmcli')) this.system.sh(['nmcli', 'device', 'reapply', ifname], false);
    return [oldMac, newMac];
  }

  setNmManaged(ifname: string, managed: boolean): void {
    if (ifname && this.system.commandExists('nmcli')) {
      this.system.sudo(['nmcli', 'device', 'set', ifname, 'managed', managed ? 'yes' : 'no'], false);
    }
  }

  networkdConfigPath(ifname: string): string {
    const safe = ifname.replace(/[^A-Za-z0-9._-]/g, '_');
    return join(NETWORKD_RUNTIME_DIR, `${NETWORKD_PREFIX}-${safe}.network`);
  }

  setNetworkdUnmanaged(ifnames: unknown, unmanaged: boolean): void {
    const names = this.interfaceList(ifnames);
    if (!names.length || !this.system.commandExists('networkctl') || !existsSync(NETWORKD_RUNTIME_DIR)) return;
    for (const ifname of names) {
      const path = this.networkdConfigPath(ifname);
      if (unmanaged) this.system.sudoWriteText(path, `[Match]\nName=${ifname}\n\n[Link]\nUnmanaged=yes\n`);
      else this.system.sudo(['rm', '-f', path], false);
    }
    this.system.sudo(['networkctl', 'reload'], false);
    for (const ifname of names) this.system.sudo(['networkctl', 'reconfigure', ifname], false);
  }

  writeDnsmasqConf(lanIf: string, lanCidr: string): void {
    const [lanIp] = this.cidrParts(lanCidr);
    const [dhcpStart, dhcpEnd, netmask] = this.dhcpRangeFor(lanCidr);
    const state = this.state.loadState();
    const reservations: string[] = [];
    for (const [rawMac, rawIp] of Object.entries(state.dhcp_reservations || {}).sort()) {
      const mac = normalizeMac(rawMac);
      try {
        const ip = this.state.normalizeDhcpReservationIp(rawIp, lanCidr);
        if (validMac(mac) && ip) reservations.push(`dhcp-host=${mac},${ip}`);
      } catch {
        // ignore stale reservations
      }
    }
    writeFileSync(
      DNSMASQ_CONF,
      [
        `interface=${lanIf}`,
        'bind-interfaces',
        'except-interface=lo',
        `dhcp-range=${dhcpStart},${dhcpEnd},${netmask},12h`,
        `dhcp-option=3,${lanIp}`,
        `dhcp-option=6,${lanIp}`,
        'server=1.1.1.1',
        'server=8.8.8.8',
        'domain-needed',
        'bogus-priv',
        ...reservations,
        `dhcp-leasefile=${DNSMASQ_LEASES}`,
        `pid-file=${DNSMASQ_PID}`,
        '',
      ].join('\n'),
    );
  }

  startDnsmasq(lanIf: string, lanCidr: string): void {
    this.system.requireCommands(['dnsmasq']);
    this.system.stopPid(DNSMASQ_PID);
    this.writeDnsmasqConf(lanIf, lanCidr);
    this.system.sudo(['dnsmasq', `--conf-file=${DNSMASQ_CONF}`], true);
  }

  writeHostapdConf(config: HotspotConfig, bridgeIf = ''): void {
    const band = this.state.wifiBand(config.band) || '2.4';
    let channel = Number(config.channel || this.state.defaultChannelForBand(band));
    if (!this.state.validChannelsForBand(band).includes(channel)) channel = this.state.defaultChannelForBand(band);
    const lines = [`interface=${config.ifname}`, 'driver=nl80211'];
    if (bridgeIf) lines.push(`bridge=${bridgeIf}`);
    lines.push(`ssid=${config.ssid}`, `country_code=${this.state.normalizeWifiCountry(config.country)}`, 'ieee80211d=1');
    if (band === '5') {
      const ht40 = [36, 44, 149, 157].includes(channel) ? '[HT40+]' : '[HT40-]';
      lines.push(
        'hw_mode=a',
        `channel=${channel}`,
        'ieee80211n=1',
        `ht_capab=${ht40}[SHORT-GI-20][SHORT-GI-40]`,
        'ieee80211ac=1',
        'ieee80211h=1',
        'vht_oper_chwidth=1',
        `vht_oper_centr_freq_seg0_idx=${WIFI_5_CENTER_SEG0[channel]}`,
        'vht_capab=[MAX-MPDU-11454][SHORT-GI-80]',
      );
    } else {
      lines.push('hw_mode=g', `channel=${channel}`, 'ieee80211n=1');
    }
    lines.push('wmm_enabled=1', 'auth_algs=1', 'wpa=2', `wpa_passphrase=${config.password}`, 'wpa_key_mgmt=WPA-PSK', 'rsn_pairwise=CCMP', '');
    writeFileSync(HOSTAPD_CONF, lines.join('\n'));
    spawnSync('chmod', ['600', HOSTAPD_CONF]);
  }

  stopHostapdProcesses(): void {
    const rows = this.system.sh(['ps', '-eo', 'pid,args'], false);
    for (const line of rows.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.includes('hostapd') || !trimmed.includes(HOSTAPD_CONF)) continue;
      const pid = trimmed.split(/\s+/, 1)[0];
      this.system.sudo(['kill', '-TERM', pid], false);
      this.system.sudo(['kill', '-KILL', pid], false);
    }
    rmSync(HOSTAPD_PID, { force: true });
  }

  stopHotspot(config?: HotspotConfig): void {
    const hotspot = config || this.state.normalizedHotspot(this.state.loadState());
    this.system.stopPid(HOSTAPD_PID);
    this.stopHostapdProcesses();
    this.setNmManaged(hotspot.ifname, true);
    if (hotspot.ifname) this.system.sudo(['ip', 'link', 'set', 'dev', hotspot.ifname, 'nomaster'], false);
  }

  startHotspot(config: HotspotConfig, bridgeIf = ''): void {
    const hotspot = this.state.normalizedHotspot({ hotspot: config });
    if (!hotspot.enabled) {
      this.stopHotspot(hotspot);
      return;
    }
    this.system.requireCommands(['hostapd', 'ip']);
    this.requireInterface(hotspot.ifname, 'WiFi');
    this.stopHotspot(hotspot);
    this.writeHostapdConf(hotspot, bridgeIf);
    if (this.system.commandExists('iw')) this.system.sudo(['iw', 'reg', 'set', hotspot.country], false);
    this.system.sudo(['systemctl', 'stop', 'hostapd'], false);
    if (this.system.commandExists('rfkill')) this.system.sudo(['rfkill', 'unblock', 'wifi'], false);
    if (this.system.commandExists('nmcli')) this.system.sudo(['nmcli', 'device', 'disconnect', hotspot.ifname], false);
    this.setNmManaged(hotspot.ifname, false);
    if (this.system.commandExists('iw')) this.system.sudo(['iw', 'dev', hotspot.ifname, 'set', 'power_save', 'off'], false);
    this.system.sudo(['ip', 'link', 'set', hotspot.ifname, 'up'], false);
    this.system.sudo(['hostapd', '-B', '-P', HOSTAPD_PID, HOSTAPD_CONF]);
    for (let idx = 0; idx < 15; idx += 1) {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
      if (this.system.pidAlive(HOSTAPD_PID)) return;
    }
    throw new Error('hostapd khong khoi dong duoc');
  }

  ensureRouter(wanIf: string, lanIf: string, lanCidr: string): string {
    this.system.requireCommands(['ip', 'iptables', 'sysctl', 'dnsmasq']);
    this.requireInterface(wanIf, 'WAN');
    this.requireInterface(lanIf, 'LAN');
    const [lanIp] = this.cidrParts(lanCidr);
    this.system.sudo(['ip', 'link', 'set', lanIf, 'up']);
    this.system.sudo(['ip', 'addr', 'flush', 'dev', lanIf]);
    this.system.sudo(['ip', 'addr', 'add', lanCidr, 'dev', lanIf]);
    this.system.sudo(['sysctl', '-w', 'net.ipv4.ip_forward=1']);
    this.system.deleteExistingRule(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', wanIf, '-j', 'MASQUERADE']);
    this.system.sudo(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', wanIf, '-j', 'MASQUERADE']);
    for (const rule of [
      ['FORWARD', '-i', lanIf, '-o', wanIf, '-j', 'ACCEPT'],
      ['FORWARD', '-i', wanIf, '-o', lanIf, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
    ]) {
      this.system.deleteExistingRule(['iptables', '-D', ...rule]);
      this.system.sudo(['iptables', '-A', ...rule]);
    }
    this.startDnsmasq(lanIf, lanCidr);
    return lanIp;
  }

  removeRouterRules(wanIf: string, lanIf: string): void {
    if (!lanIf) return;
    this.iptablesProxyReset(lanIf);
    this.system.deleteExistingRule(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', wanIf, '-j', 'MASQUERADE']);
    for (const rule of [
      ['FORWARD', '-i', lanIf, '-o', wanIf, '-j', 'ACCEPT'],
      ['FORWARD', '-i', wanIf, '-o', lanIf, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
    ]) {
      this.system.deleteExistingRule(['iptables', '-D', ...rule]);
    }
  }

  clearLanAddresses(ifname: string): void {
    if (ifname) this.system.sudo(['ip', 'addr', 'flush', 'dev', ifname], false);
  }

  ensureLanBridge(baseLanIf: string, wifiIf: string, bridgeIf: string, lanCidr: string): void {
    this.system.requireCommands(['ip']);
    const members = this.interfaceList(baseLanIf);
    if (!members.length) throw new Error('Chua cau hinh LAN interface');
    for (const member of members) this.requireInterface(member, 'LAN');
    if (wifiIf) this.requireInterface(wifiIf, 'WiFi');
    if (!this.interfaceExists(bridgeIf)) this.system.sudo(['ip', 'link', 'add', 'name', bridgeIf, 'type', 'bridge']);
    this.setNetworkdUnmanaged([bridgeIf, ...members, wifiIf], true);
    this.system.sudo(['ip', 'link', 'set', 'dev', bridgeIf, 'type', 'bridge', 'stp_state', '1'], false);
    for (const member of members) {
      this.setNmManaged(member, false);
      this.clearLanAddresses(member);
      this.system.sudo(['ip', 'link', 'set', 'dev', member, 'nomaster'], false);
      this.system.sudo(['ip', 'link', 'set', 'dev', member, 'master', bridgeIf]);
      this.system.sudo(['ip', 'link', 'set', 'dev', member, 'up']);
    }
    if (wifiIf) {
      this.setNmManaged(wifiIf, false);
      this.clearLanAddresses(wifiIf);
    }
    this.system.sudo(['ip', 'link', 'set', 'dev', bridgeIf, 'up']);
  }

  teardownLanBridge(baseLanIf: string, bridgeIf: string, wifiIf = ''): void {
    const networkdIfnames = [bridgeIf, ...this.interfaceList(baseLanIf), wifiIf];
    for (const member of this.interfaceList(baseLanIf)) {
      if (this.interfaceExists(member)) {
        this.system.sudo(['ip', 'link', 'set', 'dev', member, 'nomaster'], false);
        this.setNmManaged(member, true);
      }
    }
    if (wifiIf && this.interfaceExists(wifiIf)) this.setNmManaged(wifiIf, true);
    if (this.interfaceExists(bridgeIf)) {
      this.system.sudo(['ip', 'link', 'set', 'dev', bridgeIf, 'down'], false);
      this.system.sudo(['ip', 'link', 'del', 'dev', bridgeIf], false);
    }
    this.setNetworkdUnmanaged(networkdIfnames, false);
  }

  applyRouterStack(wanIf: string, baseLanIf: string, lanCidr: string): string {
    this.setRuntime(wanIf, baseLanIf);
    const state = this.state.loadState();
    const hotspot = this.state.normalizedHotspot(state);
    const lanIf = this.activeLanIf(baseLanIf, state);
    const bridgeWifiIf = hotspot.enabled ? hotspot.ifname : '';
    const staleLanIfs = [...this.interfaceList(baseLanIf), hotspot.ifname].filter(Boolean);
    if (lanIf === DEFAULT_BRIDGE_IF) this.ensureLanBridge(baseLanIf, bridgeWifiIf, lanIf, lanCidr);
    else {
      this.stopHotspot(hotspot);
      this.teardownLanBridge(baseLanIf, DEFAULT_BRIDGE_IF, hotspot.ifname);
    }
    for (const staleIf of Array.from(new Set(staleLanIfs))) if (staleIf !== lanIf) this.removeRouterRules(wanIf, staleIf);
    this.ensureRouter(wanIf, lanIf, lanCidr);
    if (hotspot.enabled) this.startHotspot(hotspot, lanIf === DEFAULT_BRIDGE_IF ? lanIf : '');
    else this.stopHotspot(hotspot);
    this.applyProxyRules(lanIf);
    return lanIf;
  }

  stopRouter(wanIf: string, lanIf: string, baseLanIf = ''): void {
    this.stopHotspot();
    this.removeRouterRules(wanIf, lanIf);
    this.system.stopPid(REDSOCKS_PID);
    this.stopRedsocksProcesses();
    this.stopDomainProxyWorkers();
    this.system.stopPid(DNSMASQ_PID);
    if (lanIf === DEFAULT_BRIDGE_IF) {
      const hotspot = this.state.normalizedHotspot(this.state.loadState());
      this.teardownLanBridge(baseLanIf, DEFAULT_BRIDGE_IF, hotspot.ifname);
    }
  }

  proxyIpVersion(proxy: Partial<UpstreamProxy>): '4' | '6' {
    const version = String(proxy.ip_version || '4').toLowerCase().replace(/^ipv/, '');
    return version === '6' ? '6' : '4';
  }

  proxyIpLabel(proxy: Partial<UpstreamProxy>): string {
    return this.proxyIpVersion(proxy) === '6' ? 'IPv6' : 'IPv4';
  }

  parseProxyIpVersion(value: unknown): '4' | '6' {
    const version = String(value || '4').trim().toLowerCase().replace(/^ipv/, '');
    if (version !== '4' && version !== '6') throw new Error('Proxy IP phai la IPv4 hoac IPv6');
    return version;
  }

  normalizeProxyType(value: unknown): UpstreamProxy['type'] {
    const type = String(value || '').trim().toLowerCase();
    if (type === 'sock5') return 'socks5';
    if ((PROXY_TYPES as readonly string[]).includes(type)) return type as UpstreamProxy['type'];
    throw new Error('Proxy type khong hop le');
  }

  normalizeProxyHost(host: string): string {
    const value = host.trim();
    return value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
  }

  formatProxyHost(host: string): string {
    return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  }

  formatHostPort(host: string, port: number | string): string {
    return `${this.formatProxyHost(String(host))}:${port}`;
  }

  parseProxyUrl(value: string, ipVersion = '4'): UpstreamProxy {
    const raw = value.trim();
    if (!raw) throw new Error('Proxy URL dang trong');
    const parsed = new URL(raw.includes('://') ? raw : `socks5://${raw}`);
    const type = this.normalizeProxyType(parsed.protocol.slice(0, -1));
    if (!parsed.hostname || !parsed.port) throw new Error('Can dung dang socks5://host:port, http://host:port hoac https://host:port');
    return {
      type,
      host: parsed.hostname,
      port: Number(parsed.port),
      login: decodeURIComponent(parsed.username || ''),
      password: decodeURIComponent(parsed.password || ''),
      ip_version: this.parseProxyIpVersion(ipVersion),
    };
  }

  parseProxyForm(data: Record<string, any>): UpstreamProxy {
    const ipVersion = this.parseProxyIpVersion(data.ip_version);
    const proxyUrl = String(data.url || '').trim();
    if (proxyUrl) return this.parseProxyUrl(proxyUrl, ipVersion);
    const type = this.normalizeProxyType(data.type);
    const host = this.normalizeProxyHost(String(data.host || ''));
    const port = Number(String(data.port || '').trim());
    if (!host) throw new Error('Host proxy dang trong');
    if (/\s/.test(host)) throw new Error('Host proxy khong duoc co khoang trang');
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Port proxy phai nam trong 1-65535');
    return { type, host, port, login: String(data.login || '').trim(), password: String(data.password || ''), ip_version: ipVersion };
  }

  parseProxyBulkLine(line: string, lineNumber: number, ipVersion = '4'): UpstreamProxy {
    const parts = line.trim().split(':');
    if (parts.length < 3) {
      throw new Error(`Dong ${lineNumber}: can dung dang type:host:port:user:pass:ipv4`);
    }
    const [rawType, rawHost, rawPort, rawLogin = '', ...restParts] = parts;
    let lineIpVersion = ipVersion;
    let passwordParts = restParts;
    const lastPart = restParts.at(-1);
    if (lastPart && /^(ipv)?[46]$/i.test(lastPart.trim())) {
      lineIpVersion = lastPart;
      passwordParts = restParts.slice(0, -1);
    }
    const type = this.normalizeProxyType(rawType);
    const host = this.normalizeProxyHost(rawHost || '');
    const port = Number(rawPort || '');
    if (!host) throw new Error(`Dong ${lineNumber}: host proxy dang trong`);
    if (/\s/.test(host)) throw new Error(`Dong ${lineNumber}: host proxy khong duoc co khoang trang`);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Dong ${lineNumber}: port proxy phai nam trong 1-65535`);
    }
    return {
      type,
      host,
      port,
      login: rawLogin.trim(),
      password: passwordParts.join(':'),
      ip_version: this.parseProxyIpVersion(lineIpVersion),
    };
  }

  parseProxyBulk(value: unknown, ipVersion = '4'): UpstreamProxy[] {
    const proxies: UpstreamProxy[] = [];
    const lines = String(value || '').split(/\r?\n/);
    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      proxies.push(this.parseProxyBulkLine(trimmed, idx + 1, ipVersion));
    });
    return proxies;
  }

  proxyUrl(proxy: UpstreamProxy): string {
    let auth = '';
    if (proxy.login) {
      auth = encodeURIComponent(proxy.login);
      if (proxy.password) auth += `:${encodeURIComponent(proxy.password)}`;
      auth += '@';
    }
    const scheme = proxy.type === 'socks5' ? 'socks5h' : proxy.type === 'socks4' ? 'socks4a' : 'http';
    return `${scheme}://${auth}${this.formatHostPort(proxy.host, proxy.port)}`;
  }

  proxyKey(proxy: UpstreamProxy): string {
    const auth = proxy.login ? `${proxy.login}@` : '';
    return `${proxy.type}://${auth}${this.formatHostPort(proxy.host, proxy.port)} [${this.proxyIpLabel(proxy)}]`;
  }

  proxyIdentity(proxy: UpstreamProxy): string {
    return JSON.stringify([proxy.type, proxy.host, Number(proxy.port), proxy.login, proxy.password, this.proxyIpVersion(proxy)]);
  }

  proxyPort(index: number): number {
    return PROXY_LOCAL_BASE + index;
  }

  checkProxy(index: number): Promise<{ ok: boolean; detail: string; ip: string; ping_ms: number | null }> {
    const proxies = this.state.loadState().proxies || [];
    if (index < 0 || index >= proxies.length) throw new Error('Proxy index khong hop le');
    const proxy = proxies[index];
    return new Promise((resolve) => {
      const child = spawn('curl', ['-sS', '--max-time', '12', '-w', '\n%{time_total}', '-x', this.proxyUrl(proxy), PROXY_TEST_URLS[this.proxyIpVersion(proxy)]], {
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      const append = (current: string, chunk: Buffer): string => (current + chunk.toString('utf8')).slice(0, 4096);
      child.stdout?.on('data', (chunk: Buffer) => {
        stdout = append(stdout, chunk);
      });
      child.stderr?.on('data', (chunk: Buffer) => {
        stderr = append(stderr, chunk);
      });
      child.on('error', (error) => {
        resolve({ ok: false, detail: error.message, ip: '', ping_ms: null });
      });
      child.on('close', (code, signal) => {
        const lines = stdout.trim().split(/\r?\n/);
        const timeText = lines.length > 1 ? lines.pop() || '' : '';
        const body = lines.join('\n').trim();
        const seconds = Number(timeText);
        const pingMs = Number.isFinite(seconds) ? Math.round(seconds * 1000) : null;
        const err = stderr.trim();
        resolve(code === 0 && body ? { ok: true, detail: body, ip: body, ping_ms: pingMs } : { ok: false, detail: err || `curl exit ${code ?? signal}`, ip: '', ping_ms: pingMs });
      });
    });
  }

  confQuote(value: string): string {
    return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
  }

  redsocksType(proxyType: string): string {
    return proxyType === 'http' || proxyType === 'https' ? 'http-connect' : proxyType;
  }

  useDomainProxy(proxy: UpstreamProxy): boolean {
    return this.proxyIpVersion(proxy) === '6' && ['http', 'https'].includes(proxy.type);
  }

  redsocksConfText(proxies: UpstreamProxy[], localIp = '127.0.0.1'): string {
    const blocks = ['base {', '  log_debug = off;', '  log_info = on;', '  log = stderr;', '  daemon = on;', '  redirector = iptables;', '}', ''];
    proxies.forEach((proxy, idx) => {
      if (this.useDomainProxy(proxy)) return;
      blocks.push('redsocks {', `  local_ip = ${localIp};`, `  local_port = ${this.proxyPort(idx)};`, `  ip = ${proxy.host};`, `  port = ${proxy.port};`, `  type = ${this.redsocksType(proxy.type)};`);
      if (proxy.login) blocks.push(`  login = "${this.confQuote(proxy.login)}";`);
      if (proxy.password) blocks.push(`  password = "${this.confQuote(proxy.password)}";`);
      blocks.push('}', '');
    });
    return blocks.join('\n');
  }

  writeRedsocksConf(proxies: UpstreamProxy[], localIp = '127.0.0.1'): void {
    writeFileSync(REDSOCKS_CONF, this.redsocksConfText(proxies, localIp));
  }

  stopRedsocksProcesses(): void {
    const rows = this.system.sh(['ps', '-eo', 'pid,args'], false);
    for (const line of rows.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.includes('redsocks') || !trimmed.includes(REDSOCKS_CONF)) continue;
      const pid = trimmed.split(/\s+/, 1)[0];
      this.system.sudo(['kill', '-TERM', pid], false);
      this.system.sudo(['kill', '-KILL', pid], false);
    }
    rmSync(REDSOCKS_PID, { force: true });
  }

  startRedsocks(proxies: UpstreamProxy[], localIp = '127.0.0.1'): void {
    this.system.requireCommands(['redsocks']);
    if (!proxies.some((proxy) => !this.useDomainProxy(proxy))) {
      writeFileSync(REDSOCKS_CONF, '');
      this.system.stopPid(REDSOCKS_PID);
      this.stopRedsocksProcesses();
      return;
    }
    const configText = this.redsocksConfText(proxies, localIp);
    if (this.system.pidAlive(REDSOCKS_PID) && this.system.readFile(REDSOCKS_CONF, '') === configText) return;
    this.system.stopPid(REDSOCKS_PID);
    this.stopRedsocksProcesses();
    writeFileSync(REDSOCKS_CONF, configText);
    this.system.sudo(['systemctl', 'stop', 'redsocks'], false);
    this.system.sudo(['redsocks', '-t', '-c', REDSOCKS_CONF]);
    this.system.sudo(['redsocks', '-c', REDSOCKS_CONF, '-p', REDSOCKS_PID]);
    for (let idx = 0; idx < 10; idx += 1) {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
      if (this.system.pidAlive(REDSOCKS_PID)) return;
    }
    throw new Error('redsocks khong khoi dong duoc');
  }

  domainProxyPidFile(port: number): string {
    return join(STATE_DIR, `domain_proxy_${port}.pid`);
  }

  domainProxyConfFile(port: number): string {
    return join(STATE_DIR, `domain_proxy_${port}.json`);
  }

  domainProxyLogFile(port: number): string {
    return join(STATE_DIR, `domain_proxy_${port}.log`);
  }

  stopDomainProxyWorkers(): void {
    for (const file of spawnSync('sh', ['-c', `ls ${shellQuote(STATE_DIR)}/domain_proxy_*.pid 2>/dev/null || true`], { encoding: 'utf8' }).stdout.split(/\s+/).filter(Boolean)) {
      this.system.stopPid(file);
    }
    const rows = this.system.sh(['ps', '-eo', 'pid,args'], false);
    for (const line of rows.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.includes('--domain-proxy-worker')) continue;
      const pid = trimmed.split(/\s+/, 1)[0];
      if (!Number(pid)) continue;
      this.system.sudo(['kill', '-TERM', pid], false);
      this.system.sudo(['kill', '-KILL', pid], false);
    }
  }

  domainProxyPidFiles(): string[] {
    return spawnSync('sh', ['-c', `ls ${shellQuote(STATE_DIR)}/domain_proxy_*.pid 2>/dev/null || true`], { encoding: 'utf8' }).stdout.split(/\s+/).filter(Boolean);
  }

  domainProxyPortFromPidFile(file: string): number {
    const match = basename(file).match(/^domain_proxy_(\d+)\.pid$/);
    return match ? Number(match[1]) : 0;
  }

  startDomainProxyWorkers(proxies: UpstreamProxy[], localIp: string): void {
    const desiredPorts = new Set<number>();
    proxies.forEach((proxy, idx) => {
      if (this.useDomainProxy(proxy)) desiredPorts.add(this.proxyPort(idx));
    });
    for (const file of this.domainProxyPidFiles()) {
      const port = this.domainProxyPortFromPidFile(file);
      if (!desiredPorts.has(port)) this.system.stopPid(file);
    }
    proxies.forEach((proxy, idx) => {
      if (!this.useDomainProxy(proxy)) return;
      const port = this.proxyPort(idx);
      const config = { listen_ip: localIp, listen_port: port, proxy };
      const confFile = this.domainProxyConfFile(port);
      const configText = `${JSON.stringify(config, null, 2)}\n`;
      if (this.system.pidAlive(this.domainProxyPidFile(port)) && this.system.readFile(confFile, '') === configText) return;
      this.system.stopPid(this.domainProxyPidFile(port));
      writeFileSync(confFile, configText);
      spawnSync('chmod', ['600', confFile]);
      const logFd = spawnSync('sh', ['-c', `: >> ${shellQuote(this.domainProxyLogFile(port))}`]);
      void logFd;
      const child = spawn(process.execPath, [join(__dirname, 'main.js'), '--domain-proxy-worker', confFile], {
        detached: true,
        stdio: ['ignore', 'ignore', 'ignore'],
      });
      child.unref();
      writeFileSync(this.domainProxyPidFile(port), String(child.pid));
    });
  }

  dnsGuardReset(lanIf: string): void {
    for (const proto of ['udp', 'tcp']) {
      this.system.deleteExistingRule(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-i', lanIf, '-p', proto, '--dport', '53', '-j', 'REDIRECT', '--to-ports', '53']);
    }
  }

  filterGuardReset(lanIf: string): void {
    this.system.deleteExistingRule(['iptables', '-D', 'FORWARD', '-i', lanIf, '-j', GUARD_CHAIN]);
    this.system.sudo(['iptables', '-F', GUARD_CHAIN], false);
    this.system.sudo(['iptables', '-X', GUARD_CHAIN], false);
  }

  applyDnsGuard(lanIf: string): void {
    this.dnsGuardReset(lanIf);
    for (const proto of ['udp', 'tcp']) {
      this.system.sudo(['iptables', '-t', 'nat', '-I', 'PREROUTING', '1', '-i', lanIf, '-p', proto, '--dport', '53', '-j', 'REDIRECT', '--to-ports', '53']);
    }
  }

  applyFilterGuard(lanIf: string): void {
    this.filterGuardReset(lanIf);
    this.system.sudo(['iptables', '-N', GUARD_CHAIN], false);
    this.system.sudo(['iptables', '-F', GUARD_CHAIN]);
    this.system.sudo(['iptables', '-A', GUARD_CHAIN, '-p', 'tcp', '--dport', '853', '-j', 'REJECT', '--reject-with', 'tcp-reset']);
    this.system.sudo(['iptables', '-A', GUARD_CHAIN, '-p', 'udp', '--dport', '853', '-j', 'REJECT', '--reject-with', 'icmp-port-unreachable']);
    for (const net of PRIVATE_NETS) this.system.sudo(['iptables', '-A', GUARD_CHAIN, '-d', net, '-j', 'REJECT', '--reject-with', 'icmp-port-unreachable']);
    this.system.sudo(['iptables', '-A', GUARD_CHAIN, '-j', 'RETURN']);
    this.system.sudo(['iptables', '-I', 'FORWARD', '1', '-i', lanIf, '-j', GUARD_CHAIN]);
  }

  listClientIps(lanIf: string, lanCidr: string): string[] {
    const clients = new Set<string>();
    if (existsSync(DNSMASQ_LEASES)) {
      for (const line of readFileSync(DNSMASQ_LEASES, 'utf8').split('\n')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3 && ipInCidr(parts[2], lanCidr)) clients.add(parts[2]);
      }
    }
    const rows = this.system.readJsonCommand(['ip', '-j', 'neigh']);
    for (const row of rows) {
      const ip = row.dst || '';
      if (row.dev === lanIf && ip && !ip.includes(':') && ipInCidr(ip, lanCidr)) clients.add(ip);
    }
    return Array.from(clients).sort(compareIp);
  }

  flushClientConntrack(clientIps: Iterable<string>): void {
    if (!this.system.commandExists('conntrack')) return;
    for (const ip of Array.from(new Set(clientIps)).sort(compareIp)) {
      this.system.sudo(['conntrack', '-D', '-s', ip], false);
      this.system.sudo(['conntrack', '-D', '-d', ip], false);
    }
  }

  applyProxyRulesSoon(lanIf: string, flushIps: Iterable<string> = []): void {
    this.proxyApplyLanIf = lanIf;
    for (const ip of flushIps) this.proxyApplyFlushIps.add(ip);
    if (this.proxyApplyTimer) clearTimeout(this.proxyApplyTimer);
    this.proxyApplyTimer = setTimeout(() => {
      const targetLanIf = this.proxyApplyLanIf;
      const targetFlushIps = Array.from(this.proxyApplyFlushIps);
      this.proxyApplyTimer = null;
      this.proxyApplyFlushIps.clear();
      try {
        this.applyProxyRules(targetLanIf, targetFlushIps);
      } catch (error: any) {
        console.error(`apply proxy rules failed: ${error?.message || error}`);
      }
    }, 150);
  }

  iptablesProxyReset(lanIf: string): void {
    this.dnsGuardReset(lanIf);
    this.filterGuardReset(lanIf);
    this.system.deleteExistingRule(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-i', lanIf, '-p', 'tcp', '-j', PROXY_CHAIN]);
    for (const cmd of [
      ['iptables', '-t', 'nat', '-F', PROXY_CHAIN],
      ['iptables', '-t', 'nat', '-X', PROXY_CHAIN],
      ['iptables', '-F', PROXY_V4_GUARD_CHAIN],
      ['iptables', '-X', PROXY_V4_GUARD_CHAIN],
      ['ip6tables', '-F', PROXY_V6_GUARD_CHAIN],
      ['ip6tables', '-X', PROXY_V6_GUARD_CHAIN],
    ]) this.system.sudo(cmd, false);
    this.system.deleteExistingRule(['iptables', '-D', 'FORWARD', '-i', lanIf, '-j', PROXY_V4_GUARD_CHAIN]);
    this.system.deleteExistingRule(['ip6tables', '-D', 'FORWARD', '-i', lanIf, '-j', 'REJECT']);
    this.system.deleteExistingRule(['ip6tables', '-D', 'FORWARD', '-i', lanIf, '-j', PROXY_V6_GUARD_CHAIN]);
    const state = this.state.loadState();
    const natRules = this.system.sh(['iptables', '-t', 'nat', '-S', 'PREROUTING'], false);
    const forwardRules = this.system.sh(['iptables', '-S', 'FORWARD'], false);
    const hasLegacyDirectProxy = natRules.includes(`--to-ports ${PROXY_LOCAL_BASE}`);
    const hasLegacyUdpGuards = UDP_GUARD_PORTS.some((port) => forwardRules.includes(`--dport ${port}`)) || forwardRules.includes('-p udp -j REJECT');
    if (hasLegacyDirectProxy || hasLegacyUdpGuards) {
      const clientIps = [...Object.keys(state.assignments || {}), ...this.listClientIps(lanIf, state.lan_cidr || DEFAULT_LAN_CIDR)];
      for (const clientIp of clientIps) {
        if (hasLegacyDirectProxy) this.system.deleteExistingRule(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-i', lanIf, '-s', clientIp, '-p', 'tcp', '-j', 'REDIRECT', '--to-ports', String(PROXY_LOCAL_BASE)]);
        if (hasLegacyUdpGuards) {
          this.system.deleteExistingRule(['iptables', '-D', 'FORWARD', '-s', clientIp, '-p', 'udp', '-j', 'REJECT', '--reject-with', 'icmp-port-unreachable']);
          for (const ports of UDP_GUARD_PORTS) {
            this.system.deleteExistingRule(['iptables', '-D', 'FORWARD', '-s', clientIp, '-p', 'udp', '-m', 'udp', '--dport', ports, '-j', 'REJECT', '--reject-with', 'icmp-port-unreachable']);
          }
        }
      }
    }
  }

  clientMacMap(lanIf: string, lanCidr: string, state: RouterState): Record<string, string> {
    const mapping: Record<string, string> = {};
    const add = (ip: string, mac: string) => {
      const cleanMac = normalizeMac(mac);
      if (validMac(cleanMac) && ipInCidr(ip, lanCidr)) mapping[ip] = cleanMac;
    };
    if (existsSync(DNSMASQ_LEASES)) {
      for (const line of readFileSync(DNSMASQ_LEASES, 'utf8').split('\n')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3) add(parts[2], parts[1]);
      }
    }
    for (const row of this.system.readJsonCommand(['ip', '-j', 'neigh'])) {
      if (row.dev === lanIf && row.dst && !String(row.dst).includes(':')) add(row.dst, row.lladdr || '');
    }
    for (const [mac, ip] of Object.entries(state.dhcp_reservations || {})) if (!mapping[ip]) add(ip, mac);
    for (const entry of Object.values(state.device_presence || {})) if (entry && typeof entry === 'object' && !mapping[entry.ip]) add(entry.ip, entry.mac);
    return mapping;
  }

  proxyFamily(value: unknown): ProxyFamily {
    const family = String(value || 'all').trim().toLowerCase().replace(/^ipv/, '');
    if (!['all', '4', '6'].includes(family)) throw new Error('Chi ho tro all, IPv4 hoac IPv6');
    return family as ProxyFamily;
  }

  proxyFamilyLabel(value: unknown): string {
    const family = this.proxyFamily(value);
    return family === '4' ? 'IPv4' : family === '6' ? 'IPv6' : 'All';
  }

  eligibleProxyIndexes(proxies: UpstreamProxy[], family: ProxyFamily): number[] {
    return proxies.map((proxy, idx) => ({ proxy, idx })).filter(({ proxy }) => family === 'all' || this.proxyIpVersion(proxy) === family).map(({ idx }) => idx);
  }

  normalizeAssignmentIps(lanCidr: string, ips: Iterable<string>): string[] {
    const clients = new Set<string>();
    for (const ip of ips) if (ipInCidr(ip, lanCidr)) clients.add(ip);
    return Array.from(clients).sort(compareIp);
  }

  assignmentClientIps(lanIf: string, lanCidr: string, state: RouterState, extraIps: Iterable<string> = []): string[] {
    return this.normalizeAssignmentIps(lanCidr, [...this.listClientIps(lanIf, lanCidr), ...Object.keys(state.assignments || {}), ...extraIps]);
  }

  proxyLoadCounts(assignments: Record<string, any>, indexes: Iterable<number>): Record<number, number> {
    const counts: Record<number, number> = {};
    for (const idx of indexes) counts[idx] = 0;
    for (const value of Object.values(assignments || {})) {
      const idx = Number(value);
      if (Number.isInteger(idx) && idx in counts) counts[idx] += 1;
    }
    return counts;
  }

  stableProxyIndexForClient(clientIp: string, indexes: number[]): number {
    const digest = createHash('sha1').update(clientIp).digest();
    return indexes[digest.readUInt32BE(0) % indexes.length];
  }

  assignClientsToProxies(state: RouterState, clients: Iterable<string>, familyValue: unknown): { count: number; proxyCount: number } {
    const family = this.proxyFamily(familyValue);
    const indexes = this.eligibleProxyIndexes(state.proxies || [], family);
    if (!indexes.length) throw new Error(`Khong co proxy ${this.proxyFamilyLabel(family)} de gan`);
    state.assignments ||= {};
    let count = 0;
    for (const clientIp of clients) {
      state.assignments[clientIp] = this.stableProxyIndexForClient(clientIp, indexes);
      count += 1;
    }
    if (state.load_balance) state.load_balance.enabled = false;
    return { count, proxyCount: indexes.length };
  }

  applyProxyRules(lanIf: string, flushIps?: Iterable<string>): void {
    const state = this.state.loadState();
    const proxies = state.proxies || [];
    const assignments = state.assignments || {};
    const lanCidr = state.lan_cidr || DEFAULT_LAN_CIDR;
    const clientIps = new Set([...Object.keys(assignments), ...this.listClientIps(lanIf, lanCidr)]);
    const flushTargets = flushIps === undefined ? clientIps : new Set(flushIps);
    const macByIp = this.clientMacMap(lanIf, lanCidr, state);
    const [lanIp] = this.cidrParts(lanCidr);
    let wanIp = '';
    for (const row of this.system.readJsonCommand(['ip', '-j', 'addr'])) {
      if (row.ifname === this.wanIf) {
        const info = (row.addr_info || []).find((item: any) => item.family === 'inet');
        wanIp = info?.local || '';
      }
    }
    this.iptablesProxyReset(lanIf);
    this.applyDnsGuard(lanIf);
    this.applyFilterGuard(lanIf);
    if (!proxies.length || !Object.keys(assignments).length) {
      this.system.stopPid(REDSOCKS_PID);
      this.stopRedsocksProcesses();
      this.stopDomainProxyWorkers();
      this.flushClientConntrack(flushTargets);
      return;
    }
    this.startRedsocks(proxies, lanIp);
    this.startDomainProxyWorkers(proxies, lanIp);
    const natRules = ['*nat', `:${PROXY_CHAIN} - [0:0]`, `-F ${PROXY_CHAIN}`];
    const v4FilterRules = ['*filter', `:${PROXY_V4_GUARD_CHAIN} - [0:0]`, `-F ${PROXY_V4_GUARD_CHAIN}`];
    const v6FilterRules = ['*filter', `:${PROXY_V6_GUARD_CHAIN} - [0:0]`, `-F ${PROXY_V6_GUARD_CHAIN}`];
    for (const net of PRIVATE_NETS) natRules.push(`-A ${PROXY_CHAIN} -d ${net} -j RETURN`);
    for (const localTarget of [lanIp, wanIp].filter(Boolean)) natRules.push(`-A ${PROXY_CHAIN} -d ${localTarget} -j RETURN`);
    for (const [clientIp, proxyIdx] of Object.entries(assignments)) {
      const idx = Number(proxyIdx);
      if (!Number.isInteger(idx) || idx < 0 || idx >= proxies.length) continue;
      try {
        ipaddr.parse(clientIp);
      } catch {
        continue;
      }
      const proxy = proxies[idx];
      try {
        if (ipaddr.parse(proxy.host).kind() !== 'ipv6') {
          natRules.push(`-A ${PROXY_CHAIN} -s ${clientIp} -p tcp -d ${proxy.host} --dport ${Number(proxy.port)} -j RETURN`);
        }
      } catch {
        // Hostname proxy endpoints are allowed, but skipped in restore batches to avoid blocking on DNS.
      }
      if (this.proxyIpVersion(proxy) === '6') {
        v4FilterRules.push(`-A ${PROXY_V4_GUARD_CHAIN} -s ${clientIp} -j REJECT --reject-with icmp-port-unreachable`);
      } else {
        const mac = macByIp[clientIp];
        if (mac) v6FilterRules.push(`-A ${PROXY_V6_GUARD_CHAIN} -m mac --mac-source ${mac} -j REJECT`);
      }
      for (const ports of UDP_GUARD_PORTS) {
        v4FilterRules.push(`-A ${PROXY_V4_GUARD_CHAIN} -s ${clientIp} -p udp -m udp --dport ${ports} -j REJECT --reject-with icmp-port-unreachable`);
      }
      natRules.push(`-A ${PROXY_CHAIN} -s ${clientIp} -p tcp -j REDIRECT --to-ports ${this.proxyPort(idx)}`);
    }
    natRules.push(`-A ${PROXY_CHAIN} -j RETURN`, 'COMMIT', '');
    v4FilterRules.push(`-A ${PROXY_V4_GUARD_CHAIN} -j RETURN`, 'COMMIT', '');
    v6FilterRules.push(`-A ${PROXY_V6_GUARD_CHAIN} -j RETURN`, 'COMMIT', '');
    this.system.sudoInput(['iptables-restore', '-n'], natRules.join('\n'));
    this.system.sudoInput(['iptables-restore', '-n'], v4FilterRules.join('\n'));
    this.system.sudoInput(['ip6tables-restore', '-n'], v6FilterRules.join('\n'), false);
    this.system.sudo(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', lanIf, '-p', 'tcp', '-j', PROXY_CHAIN]);
    this.system.sudo(['iptables', '-I', 'FORWARD', '1', '-i', lanIf, '-j', PROXY_V4_GUARD_CHAIN]);
    this.system.sudo(['ip6tables', '-I', 'FORWARD', '1', '-i', lanIf, '-j', PROXY_V6_GUARD_CHAIN], false);
    this.flushClientConntrack(flushTargets);
  }

  removeProxy(index: number, lanIf: string): void {
    const state = this.state.loadState();
    if (index < 0 || index >= state.proxies.length) return;
    state.proxies.splice(index, 1);
    const assignments: Record<string, number> = {};
    for (const [ip, rawIdx] of Object.entries(state.assignments || {})) {
      const idx = Number(rawIdx);
      if (idx === index) continue;
      assignments[ip] = idx > index ? idx - 1 : idx;
    }
    state.assignments = assignments;
    this.state.saveState(state);
    this.applyProxyRules(lanIf, Object.keys(assignments));
  }

  stopWebServer(): void {
    const targets = new Set<number>();
    try {
      const pid = Number(readFileSync(WEB_PID, 'utf8').trim());
      if (pid) targets.add(pid);
    } catch {
      // ignore
    }
    const rows = this.system.sh(['ps', '-eo', 'pid,args'], false);
    for (const line of rows.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const [pidText, ...args] = trimmed.split(/\s+/);
      if (args.some((arg) => basename(arg) === 'main.js' || basename(arg) === 'router_manager.py' || arg.includes('ts-node'))) {
        const pid = Number(pidText);
        if (pid && pid !== process.pid) targets.add(pid);
      }
    }
    targets.delete(process.pid);
    for (const pid of targets) {
      this.system.sudo(['kill', '-TERM', String(pid)], false);
      this.system.sudo(['kill', '-KILL', String(pid)], false);
    }
    rmSync(WEB_PID, { force: true });
  }

  removeDnsmasqLeasesForMac(macValue: string): string[] {
    const mac = normalizeMac(macValue);
    if (!mac || !existsSync(DNSMASQ_LEASES)) return [];
    const kept: string[] = [];
    const removed: string[] = [];
    for (const line of readFileSync(DNSMASQ_LEASES, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3 && normalizeMac(parts[1]) === mac) removed.push(parts[2]);
      else kept.push(line);
    }
    if (removed.length) this.system.sudoWriteText(DNSMASQ_LEASES, kept.length ? `${kept.join('\n')}\n` : '');
    return removed;
  }

  flushClientNetworkState(lanIf: string, ips: string[]): void {
    const cleanIps = ips.filter((ip) => {
      try {
        return ipaddr.parse(ip).kind() === 'ipv4';
      } catch {
        return false;
      }
    });
    if (!lanIf || !cleanIps.length) return;
    this.flushClientConntrack(cleanIps);
    for (const ip of Array.from(new Set(cleanIps)).sort(compareIp)) this.system.sudo(['ip', 'neigh', 'del', ip, 'dev', lanIf], false);
  }

  wifiStationDetails(wifiIf: string): Record<string, any> {
    const stations: Record<string, any> = {};
    if (!wifiIf || !this.system.commandExists('iw')) return stations;
    const out = this.system.sh(['iw', 'dev', wifiIf, 'station', 'dump'], false);
    let current = '';
    for (const raw of out.split('\n')) {
      const line = raw.trim();
      if (line.startsWith('Station ')) {
        current = normalizeMac(line.split(/\s+/)[1] || '');
        if (current) stations[current] = { mac: current, interface: wifiIf };
      } else if (current && line.includes(':')) {
        const [key, ...rest] = line.split(':');
        stations[current][key.trim().replaceAll(' ', '_')] = rest.join(':').trim();
      }
    }
    return stations;
  }

  disconnectWifiClient(macValue: string, wifiIf: string): boolean {
    const mac = normalizeMac(macValue);
    if (!mac || !wifiIf) return false;
    if (this.system.commandExists('iw') && !(mac in this.wifiStationDetails(wifiIf))) return false;
    if (this.system.commandExists('iw') && this.system.sudoSuccess(['iw', 'dev', wifiIf, 'station', 'del', mac])) return true;
    if (this.system.commandExists('hostapd_cli')) return this.system.sudoSuccess(['hostapd_cli', '-i', wifiIf, 'deauthenticate', mac]);
    return false;
  }

  refreshDhcpClient(mac: string, lanIf: string, candidateIps: string[] = []): string {
    const state = this.state.loadState();
    const hotspot = this.state.normalizedHotspot(state);
    const reservationIp = state.dhcp_reservations[normalizeMac(mac)] || '';
    this.flushClientNetworkState(lanIf, [...candidateIps, reservationIp].filter(Boolean));
    if (this.disconnectWifiClient(mac, hotspot.ifname)) return 'DHCP binding changed; lease cleared and WiFi client reconnected to get the new IP';
    return 'DHCP binding changed; lease cleared. Client will get the new IP on next reconnect/renew';
  }
}
