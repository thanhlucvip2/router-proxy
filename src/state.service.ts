import { Injectable } from '@nestjs/common';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import * as ipaddr from 'ipaddr.js';
import {
  ADMIN_PASSWORD_FILE,
  CONFIG_FILE,
  DEFAULT_ADMIN_USER,
  DEFAULT_LAN_CIDR,
  DEFAULT_WIFI_BAND,
  DEFAULT_WIFI_CHANNEL,
  DEFAULT_WIFI_COUNTRY,
  DEFAULT_WIFI_SSID,
  SESSION_FILE,
  STATE_DIR,
  STATE_FILE,
  WIFI_24_CHANNELS,
  WIFI_5_CHANNELS,
} from './constants';
import { DeviceGroup, HotspotConfig, RouterState } from './types';
import { ipInCidr, normalizeMac, parseIpv4Cidr, randomToken, validMac } from './util';

@Injectable()
export class StateService {
  ensureStateDir(): void {
    mkdirSync(STATE_DIR, { recursive: true });
  }

  wifiBand(value: unknown): '2.4' | '5' | '' {
    const cleaned = String(value ?? '').trim().toLowerCase().replace('ghz', '').replaceAll(' ', '');
    if (['2.4', '2', '24', '2g', 'b', 'g', 'n'].includes(cleaned)) return '2.4';
    if (['5', '5g', 'a', 'ac', 'ax'].includes(cleaned)) return '5';
    return '';
  }

  wifiBandLabel(value: unknown): string {
    return this.wifiBand(value) === '5' ? '5 GHz fast' : '2.4 GHz compatible';
  }

  defaultChannelForBand(band: unknown): number {
    return this.wifiBand(band) === '5' ? 36 : DEFAULT_WIFI_CHANNEL;
  }

  validChannelsForBand(band: unknown): number[] {
    return this.wifiBand(band) === '5' ? WIFI_5_CHANNELS : WIFI_24_CHANNELS;
  }

  normalizeWifiCountry(value: unknown): string {
    const country = String(value || DEFAULT_WIFI_COUNTRY).trim().toUpperCase();
    return /^[A-Z]{2}$/.test(country) ? country : DEFAULT_WIFI_COUNTRY;
  }

  defaultHotspot(): HotspotConfig {
    return {
      enabled: false,
      ifname: '',
      ssid: DEFAULT_WIFI_SSID,
      password: '',
      band: DEFAULT_WIFI_BAND,
      country: DEFAULT_WIFI_COUNTRY,
      channel: DEFAULT_WIFI_CHANNEL,
    };
  }

  defaultState(): RouterState {
    return {
      proxies: [],
      assignments: {},
      device_names: {},
      device_groups: [],
      dhcp_reservations: {},
      lan_cidr: DEFAULT_LAN_CIDR,
      hotspot: this.defaultHotspot(),
      device_presence: {},
      hidden_offline_devices: {},
    };
  }

  readConfigWithKeys(): { config: any; keys: Set<string> } {
    if (!existsSync(CONFIG_FILE)) return { config: { dhcp_bindings: {}, device_groups: [] }, keys: new Set() };
    const data = JSON.parse(readFileSync(CONFIG_FILE, 'utf8'));
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('config.json phai la JSON object');
    return { config: { dhcp_bindings: {}, device_groups: [], ...data }, keys: new Set(Object.keys(data)) };
  }

  writeConfig(config: any): void {
    const tmp = `${CONFIG_FILE}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(config, null, 2)}\n`);
    renameSync(tmp, CONFIG_FILE);
  }

  normalizeDhcpReservationIp(value: unknown, lanCidr: string): string {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    const ip = ipaddr.parse(raw);
    if (ip.kind() !== 'ipv4') throw new Error('DHCP IP phai la IPv4');
    if (!ipInCidr(ip.toString(), lanCidr)) throw new Error(`DHCP IP phai nam trong LAN ${lanCidr}`);
    const parsed = parseIpv4Cidr(lanCidr);
    const networkAddress = parsed.network.split('/')[0];
    const broadcast = parsed.broadcast;
    const gateway = parsed.ip;
    if ([networkAddress, broadcast, gateway].includes(ip.toString())) {
      throw new Error('DHCP IP khong duoc la gateway/network/broadcast');
    }
    return ip.toString();
  }

  configBindingMaps(config: any, lanCidr: string): { names: Record<string, string>; reservations: Record<string, string> } {
    const bindings = config?.dhcp_bindings;
    const entries = Array.isArray(bindings)
      ? bindings.map((entry: any) => [entry?.mac, entry])
      : bindings && typeof bindings === 'object'
        ? Object.entries(bindings)
        : [];
    const names: Record<string, string> = {};
    const reservations: Record<string, string> = {};
    for (const [rawMac, rawEntry] of entries) {
      const mac = normalizeMac(rawMac);
      if (!validMac(mac)) continue;
      const entry: any = rawEntry && typeof rawEntry === 'object' ? rawEntry : { ip_address: rawEntry };
      const name = String(entry.name ?? '').trim().slice(0, 64);
      if (name) names[mac] = name;
      try {
        const ip = this.normalizeDhcpReservationIp(entry.ip_address ?? entry.ip ?? entry.dhcp_ip ?? '', lanCidr);
        if (ip) reservations[mac] = ip;
      } catch {
        // Invalid config entries are ignored to match the old dashboard behavior.
      }
    }
    return { names, reservations };
  }

  normalizeDeviceGroupIps(value: unknown): string[] {
    const rawItems = typeof value === 'string' ? value.replaceAll(',', '\n').split('\n') : Array.isArray(value) ? value : [];
    const ips: string[] = [];
    for (const item of rawItems) {
      try {
        const ip = ipaddr.parse(String(item ?? '').trim()).toString();
        if (!ips.includes(ip)) ips.push(ip);
      } catch {
        // skip invalid IPs
      }
    }
    return ips;
  }

  normalizeDeviceGroups(rawGroups: unknown): DeviceGroup[] {
    if (!Array.isArray(rawGroups)) return [];
    const groups: DeviceGroup[] = [];
    const seenIds = new Set<string>();
    const groupedIps = new Set<string>();
    for (const item of rawGroups) {
      if (!item || typeof item !== 'object') continue;
      const row: any = item;
      const id = String(row.id ?? '').trim().slice(0, 48);
      if (!id || seenIds.has(id)) continue;
      const ips = this.normalizeDeviceGroupIps(row.ips).filter((ip) => {
        if (groupedIps.has(ip)) return false;
        groupedIps.add(ip);
        return true;
      });
      if (!ips.length) continue;
      seenIds.add(id);
      groups.push({
        id,
        name: String(row.name ?? '').trim().slice(0, 64) || 'Group',
        ips,
        collapsed: Boolean(row.collapsed),
      });
    }
    return groups;
  }

  normalizedHotspot(state: Partial<RouterState> | any): HotspotConfig {
    const raw = state?.hotspot && typeof state.hotspot === 'object' ? state.hotspot : {};
    const config: any = { ...this.defaultHotspot(), ...raw };
    config.enabled = Boolean(config.enabled);
    config.ifname = String(config.ifname ?? '').trim();
    config.ssid = String(config.ssid ?? '').trim() || DEFAULT_WIFI_SSID;
    config.password = String(config.password ?? '');
    config.band = this.wifiBand(config.band) || DEFAULT_WIFI_BAND;
    config.country = this.normalizeWifiCountry(config.country);
    let channel = Number(config.channel);
    if (!Number.isInteger(channel)) channel = this.defaultChannelForBand(config.band);
    if (!this.validChannelsForBand(config.band).includes(channel)) channel = this.defaultChannelForBand(config.band);
    config.channel = channel;
    return config as HotspotConfig;
  }

  applyConfigToState(state: RouterState): RouterState {
    if (!existsSync(CONFIG_FILE)) return state;
    const { config, keys } = this.readConfigWithKeys();
    const { names, reservations } = this.configBindingMaps(config, state.lan_cidr || DEFAULT_LAN_CIDR);
    state.device_names = names;
    state.dhcp_reservations = reservations;
    if (keys.has('device_groups')) state.device_groups = this.normalizeDeviceGroups(config.device_groups);
    else this.saveDeviceGroupsConfig(state);
    return state;
  }

  loadState(): RouterState {
    this.ensureStateDir();
    if (!existsSync(STATE_FILE)) return this.applyConfigToState(this.defaultState());
    const state = { ...this.defaultState(), ...JSON.parse(readFileSync(STATE_FILE, 'utf8')) } as RouterState;
    state.device_groups = this.normalizeDeviceGroups(state.device_groups);
    state.hotspot = this.normalizedHotspot(state);
    state.device_presence ||= {};
    state.hidden_offline_devices ||= {};
    return this.applyConfigToState(state);
  }

  publicState(state: RouterState): RouterState {
    const data = JSON.parse(JSON.stringify(state));
    for (const proxy of data.proxies || []) if (proxy.password) proxy.password = '********';
    if (data.hotspot?.password) data.hotspot.password = '********';
    return data;
  }

  saveState(state: RouterState): void {
    this.ensureStateDir();
    const tmp = `${STATE_FILE}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`);
    renameSync(tmp, STATE_FILE);
  }

  saveDeviceGroupsConfig(state: RouterState): void {
    const { config } = this.readConfigWithKeys();
    config.device_groups = this.normalizeDeviceGroups(state.device_groups);
    this.writeConfig(config);
  }

  saveDhcpBindingsConfig(state: RouterState): void {
    const { config } = this.readConfigWithKeys();
    const names = Object.fromEntries(Object.entries(state.device_names || {}).filter(([mac]) => validMac(mac)));
    const reservations = Object.fromEntries(Object.entries(state.dhcp_reservations || {}).filter(([mac]) => validMac(mac)));
    const macs = Array.from(new Set([...Object.keys(names), ...Object.keys(reservations)])).sort((a, b) => {
      const ipA = reservations[a] || '';
      const ipB = reservations[b] || '';
      return ipA.localeCompare(ipB, undefined, { numeric: true }) || String(names[a] || '').localeCompare(String(names[b] || '')) || a.localeCompare(b);
    });
    config.dhcp_bindings = {};
    for (const mac of macs) {
      const entry: any = {};
      if (names[mac]) entry.name = String(names[mac]).trim().slice(0, 64);
      if (reservations[mac]) entry.ip_address = String(reservations[mac]).trim();
      if (Object.keys(entry).length) config.dhcp_bindings[mac] = entry;
    }
    this.writeConfig(config);
  }

  loadOrCreateAdminPassword(): string {
    this.ensureStateDir();
    const envPassword = String(process.env.ROUTER_ADMIN_PASSWORD || '').trim();
    if (envPassword) {
      writeFileSync(ADMIN_PASSWORD_FILE, `${envPassword}\n`);
      chmodSync(ADMIN_PASSWORD_FILE, 0o600);
      return envPassword;
    }
    if (existsSync(ADMIN_PASSWORD_FILE)) return readFileSync(ADMIN_PASSWORD_FILE, 'utf8').trim();
    const password = randomToken(18);
    writeFileSync(ADMIN_PASSWORD_FILE, `${password}\n`);
    chmodSync(ADMIN_PASSWORD_FILE, 0o600);
    return password;
  }

  loadOrCreateSessionToken(): string {
    this.ensureStateDir();
    if (existsSync(SESSION_FILE)) return readFileSync(SESSION_FILE, 'utf8').trim();
    const token = randomToken(32);
    writeFileSync(SESSION_FILE, `${token}\n`);
    chmodSync(SESSION_FILE, 0o600);
    return token;
  }

  defaultAdminUser(): string {
    return DEFAULT_ADMIN_USER;
  }
}
