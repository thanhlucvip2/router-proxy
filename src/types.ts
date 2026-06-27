export type ProxyType = 'http' | 'https' | 'socks5' | 'socks4';
export type ProxyIpVersion = '4' | '6';
export type ProxyFamily = 'all' | '4' | '6';

export interface UpstreamProxy {
  type: ProxyType;
  host: string;
  port: number;
  login: string;
  password: string;
  ip_version: ProxyIpVersion;
}

export interface HotspotConfig {
  enabled: boolean;
  ifname: string;
  ssid: string;
  password: string;
  band: '2.4' | '5';
  country: string;
  channel: number;
}

export interface DeviceGroup {
  id: string;
  name: string;
  ips: string[];
  collapsed: boolean;
}

export interface RouterState {
  proxies: UpstreamProxy[];
  assignments: Record<string, number>;
  device_names: Record<string, string>;
  device_groups: DeviceGroup[];
  dhcp_reservations: Record<string, string>;
  lan_cidr: string;
  hotspot: HotspotConfig;
  device_presence: Record<string, any>;
  hidden_offline_devices: Record<string, number>;
  load_balance?: { enabled: boolean; family: ProxyFamily };
}

export interface RuntimeOptions {
  wan: string;
  lan: string;
  lanCidr: string;
  host: string;
  port: number;
  adminUser: string;
}
