import { Injectable } from '@nestjs/common';
import { existsSync, readFileSync } from 'node:fs';
import {
  DEFAULT_BRIDGE_IF,
  DEFAULT_LAN_CIDR,
  DNSMASQ_LEASES,
  DNSMASQ_PID,
  HOSTAPD_PID,
  OFFLINE_NEIGH_STATES,
  ONLINE_NEIGH_STATES,
  REDSOCKS_PID,
} from './constants';
import { NetworkService } from './network.service';
import { StateService } from './state.service';
import { RouterState } from './types';
import { compareIp, ipInCidr, normalizeMac } from './util';
import { SystemService } from './system.service';

@Injectable()
export class StatusService {
  constructor(
    private readonly system: SystemService,
    private readonly state: StateService,
    private readonly network: NetworkService,
  ) {}

  timestampNow(): number {
    return Math.floor(Date.now() / 1000);
  }

  formatTimestamp(value: unknown): string {
    const ts = Number(value);
    if (!Number.isFinite(ts) || ts <= 0) return '';
    const date = new Date(ts * 1000);
    const pad = (item: number) => String(item).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  }

  devicePresenceKey(row: any): string {
    return normalizeMac(row.mac || '') || String(row.ip || '').trim();
  }

  rowIsOnline(row: any, wifiStations: Record<string, any>, fdbPorts: Record<string, string>): [boolean, string] {
    const mac = normalizeMac(row.mac || '');
    if (mac && mac in wifiStations) return [true, 'wifi station'];
    if (mac && mac in fdbPorts) return [true, 'bridge fdb'];
    const states = new Set<string>((row.neigh_state || []).map((item: any) => String(item).toUpperCase()));
    if ([...states].some((item) => ONLINE_NEIGH_STATES.has(item))) return [true, [...states].sort().join('/')];
    if ([...states].some((item) => OFFLINE_NEIGH_STATES.has(item))) return [false, [...states].sort().join('/')];
    return [false, [...states].sort().join('/') || row.source || 'unknown'];
  }

  updateDevicePresence(state: RouterState, rows: any[], wifiStations: Record<string, any>, fdbPorts: Record<string, string>): boolean {
    state.device_presence ||= {};
    const now = this.timestampNow();
    let changed = false;
    for (const row of rows) {
      const key = this.devicePresenceKey(row);
      if (!key) continue;
      const [online, reason] = this.rowIsOnline(row, wifiStations, fdbPorts);
      const entry = state.device_presence[key] && typeof state.device_presence[key] === 'object' ? state.device_presence[key] : {};
      const wasOnline = Boolean(entry.online);
      const updates = online
        ? {
            online: true,
            ip: row.ip || '',
            mac: normalizeMac(row.mac || ''),
            hostname: row.hostname || '',
            connection: row.connection || '',
            interface: row.interface || '',
            first_seen: entry.first_seen || now,
            last_seen: now,
            disconnected_at: '',
            reason,
          }
        : {
            online: false,
            ip: row.ip || entry.ip || '',
            mac: normalizeMac(row.mac || entry.mac || ''),
            hostname: row.hostname || entry.hostname || '',
            connection: row.connection || entry.connection || '',
            interface: row.interface || entry.interface || '',
            first_seen: entry.first_seen || now,
            last_seen: entry.last_seen || '',
            disconnected_at: entry.disconnected_at || (wasOnline || Object.keys(entry).length ? now : ''),
            reason,
          };
      if (JSON.stringify(entry) !== JSON.stringify(updates)) {
        state.device_presence[key] = updates;
        changed = true;
      }
      row.online = online;
      row.presence_reason = reason;
      row.last_seen_at = state.device_presence[key].last_seen || '';
      row.disconnected_at = state.device_presence[key].disconnected_at || '';
      row.last_seen_text = this.formatTimestamp(row.last_seen_at);
      row.disconnected_text = this.formatTimestamp(row.disconnected_at);
    }
    return changed;
  }

  bridgeFdbPorts(bridgeIf: string): Record<string, string> {
    const ports: Record<string, string> = {};
    if (!bridgeIf || !this.system.commandExists('bridge') || !this.network.interfaceExists(bridgeIf)) return ports;
    let rows: any[] = [];
    try {
      rows = JSON.parse(this.system.sh(['bridge', '-j', 'fdb', 'show', 'br', bridgeIf], false) || '[]');
    } catch {
      rows = [];
    }
    for (const row of rows) {
      const mac = normalizeMac(row.mac || '');
      if (!mac || mac.startsWith('01:') || mac.startsWith('33:33:')) continue;
      const flags = new Set(row.flags || []);
      if (flags.has('self') || row.state === 'permanent') continue;
      if (row.ifname) ports[mac] = row.ifname;
    }
    return ports;
  }

  classifyClient(macValue: string, lanIf: string, baseLanIf: string, wifiIf: string, wifiStations: Record<string, any>, fdbPorts: Record<string, string>): any {
    const mac = normalizeMac(macValue);
    const lanMembers = this.network.interfaceList(baseLanIf);
    const lanLabel = (ifname: string) => (ifname === 'enp8s0' ? 'LAN1' : ifname === 'enp3s0f0' ? 'LAN2' : 'LAN');
    const lanDetail = (ifname: string) => (ifname && ifname !== lanLabel(ifname) ? ifname : '');
    if (mac && mac in wifiStations) return { connection: 'WIFI', interface: wifiIf, detail: wifiStations[mac].signal || '' };
    const port = fdbPorts[mac] || '';
    if (port === wifiIf) return { connection: 'WIFI', interface: wifiIf, detail: '' };
    if (lanMembers.includes(port)) return { connection: lanLabel(port), interface: port, detail: lanDetail(port) };
    if (port && this.interfaceKind(port) === 'ethernet') return { connection: lanLabel(port), interface: port, detail: lanDetail(port) };
    if (lanIf === wifiIf) return { connection: 'WIFI', interface: wifiIf, detail: '' };
    if (lanMembers.includes(lanIf)) return { connection: lanLabel(lanIf), interface: lanIf, detail: lanDetail(lanIf) };
    if (this.interfaceKind(lanIf) === 'ethernet') return { connection: lanLabel(lanIf), interface: lanIf, detail: lanDetail(lanIf) };
    return { connection: 'Unknown', interface: port || lanIf, detail: '' };
  }

  listLeases(lanIf: string, lanCidr: string, baseLanIf = '', wifiIf = ''): any[] {
    const wifiStations = this.network.wifiStationDetails(wifiIf);
    const fdbPorts = this.bridgeFdbPorts(lanIf === DEFAULT_BRIDGE_IF ? lanIf : '');
    const leases: Record<string, any> = {};
    if (existsSync(DNSMASQ_LEASES)) {
      for (const line of readFileSync(DNSMASQ_LEASES, 'utf8').split('\n')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4 && ipInCidr(parts[2], lanCidr)) {
          const [expires, mac, ip, hostname] = parts;
          leases[ip] = { ip, mac, hostname: hostname === '*' ? '' : hostname, expires, source: 'dhcp' };
        }
      }
    }
    for (const row of this.system.readJsonCommand(['ip', '-j', 'neigh'])) {
      const ip = row.dst || '';
      if (row.dev !== lanIf || !ip || ip.includes(':') || !ipInCidr(ip, lanCidr)) continue;
      const neighState = Array.isArray(row.state) ? row.state : row.state ? [row.state] : [];
      leases[ip] ||= { ip, mac: row.lladdr || '', hostname: '', expires: '', source: 'arp' };
      if (row.lladdr && !leases[ip].mac) leases[ip].mac = row.lladdr;
      leases[ip].neigh_state = neighState;
    }
    return Object.values(leases)
      .map((row) => ({ ...row, ...this.classifyClient(row.mac || '', lanIf, baseLanIf, wifiIf, wifiStations, fdbPorts) }))
      .sort((a, b) => compareIp(a.ip, b.ip));
  }

  interfaceKind(ifname: string): string {
    if (existsSync(`/sys/class/net/${ifname}/bridge`)) return 'bridge';
    if (existsSync(`/sys/class/net/${ifname}/wireless`)) return 'wifi';
    if (ifname.startsWith('docker') || ifname.startsWith('br-') || ifname.startsWith('veth')) return 'virtual';
    if (existsSync(`/sys/class/net/${ifname}/device`)) return 'ethernet';
    return 'virtual';
  }

  networkCards(wanIf: string, baseLanIf: string, activeIf: string, hotspot: any): any[] {
    const rows = this.system.readJsonCommand(['ip', '-j', 'addr']);
    const lanMembers = this.network.interfaceList(baseLanIf);
    return rows
      .filter((row) => row.ifname && row.ifname !== 'lo')
      .map((row) => {
        const roles: string[] = [];
        if (row.ifname === wanIf) roles.push('WAN');
        if (lanMembers.includes(row.ifname)) roles.push('LAN port');
        if (row.ifname === activeIf) roles.push('Gateway');
        if (row.ifname === hotspot.ifname) roles.push('WiFi AP');
        if (row.master === activeIf) roles.push(`member of ${activeIf}`);
        const addresses = (row.addr_info || []).filter((info: any) => info.local && info.prefixlen !== undefined).map((info: any) => `${info.local}/${info.prefixlen}`);
        return {
          name: row.ifname,
          kind: this.interfaceKind(row.ifname),
          state: row.operstate || '',
          mac: row.address || '',
          master: row.master || '',
          role: roles.join(', ') || '-',
          addresses,
        };
      });
  }

  commandStatus(wanIf: string, baseLanIf: string): any {
    const state = this.state.loadState();
    const lanCidr = state.lan_cidr || DEFAULT_LAN_CIDR;
    const hotspot = this.state.normalizedHotspot(state);
    const lanIf = this.network.activeLanIf(baseLanIf, state);
    const [lanIp, , lanNetwork] = this.network.cidrParts(lanCidr);
    const wifiStations = this.network.wifiStationDetails(hotspot.ifname);
    const fdbPorts = this.bridgeFdbPorts(lanIf === DEFAULT_BRIDGE_IF ? lanIf : '');
    const leases = this.listLeases(lanIf, lanCidr, baseLanIf, hotspot.ifname);
    let changed = this.updateDevicePresence(state, leases, wifiStations, fdbPorts);
    state.hidden_offline_devices ||= {};
    for (const row of leases) {
      const key = this.devicePresenceKey(row);
      if (key && row.online && key in state.hidden_offline_devices) {
        delete state.hidden_offline_devices[key];
        changed = true;
      }
    }
    const visibleLeases = leases.filter((row) => !(this.devicePresenceKey(row) in state.hidden_offline_devices && !row.online));
    if (changed) this.state.saveState(state);
    return {
      wan_if: wanIf,
      base_lan_if: baseLanIf,
      lan_if: lanIf,
      wan_mac: this.network.currentMac(wanIf),
      lan_mac: this.network.currentMac(lanIf),
      lan_ip: lanIp,
      lan_network: lanNetwork,
      dhcp_range: this.network.dhcpRangeFor(lanCidr),
      interfaces: this.system.sh(['ip', '-br', 'addr'], false),
      routes: this.system.sh(['ip', 'route'], false),
      ip_forward: this.system.readFile('/proc/sys/net/ipv4/ip_forward', '').trim(),
      dnsmasq: this.system.pidAlive(DNSMASQ_PID),
      hostapd: this.system.pidAlive(HOSTAPD_PID),
      redsocks: this.system.pidAlive(REDSOCKS_PID),
      leases: visibleLeases,
      network_cards: this.networkCards(wanIf, baseLanIf, lanIf, hotspot),
      wifi_stations: Object.values(wifiStations),
      wifi_interfaces: this.network.wirelessInterfaces(),
      state: this.state.publicState(state),
    };
  }
}
