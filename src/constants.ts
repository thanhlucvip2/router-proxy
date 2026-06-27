import { join } from 'node:path';

export const BASE_DIR = join(__dirname, '..');
export const STATE_DIR = join(BASE_DIR, 'state');
export const CONFIG_FILE = join(BASE_DIR, 'config.json');
export const STATE_FILE = join(STATE_DIR, 'router_state.json');
export const DNSMASQ_CONF = join(STATE_DIR, 'dnsmasq.conf');
export const DNSMASQ_LEASES = join(STATE_DIR, 'dnsmasq.leases');
export const DNSMASQ_PID = join(STATE_DIR, 'dnsmasq.pid');
export const HOSTAPD_CONF = join(STATE_DIR, 'hostapd.conf');
export const HOSTAPD_PID = join(STATE_DIR, 'hostapd.pid');
export const REDSOCKS_CONF = join(STATE_DIR, 'redsocks.conf');
export const REDSOCKS_PID = join(STATE_DIR, 'redsocks.pid');
export const WEB_PID = join(STATE_DIR, 'router_manager.pid');
export const ADMIN_PASSWORD_FILE = join(STATE_DIR, 'admin_password.txt');
export const SESSION_FILE = join(STATE_DIR, 'session_token.txt');
export const NETWORKD_RUNTIME_DIR = '/run/systemd/network';
export const NETWORKD_PREFIX = '00-router-manager';

export const DEFAULT_LAN_CIDR = '10.42.0.1/21';
export const DEFAULT_BRIDGE_IF = 'br-router';
export const DEFAULT_WIFI_SSID = 'RouterWiFi';
export const DEFAULT_WIFI_CHANNEL = 6;
export const DEFAULT_WIFI_BAND = '2.4';
export const DEFAULT_WIFI_COUNTRY = 'US';
export const DEFAULT_ADMIN_USER = 'admin';
export const PROXY_CHAIN = 'ROUTER_PROXY';
export const GUARD_CHAIN = 'ROUTER_GUARD';
export const PROXY_V4_GUARD_CHAIN = 'ROUTER_PROXY_V4_GUARD';
export const PROXY_V6_GUARD_CHAIN = 'ROUTER_PROXY_V6_GUARD';
export const PROXY_LOCAL_BASE = 23450;
export const PROXY_TYPES = ['http', 'https', 'socks5', 'socks4'] as const;
export const PROXY_TEST_URLS: Record<'4' | '6', string> = {
  '4': 'https://api.ipify.org',
  '6': 'https://api6.ipify.org',
};
export const PROXY_ASSIGN_FAMILIES = ['all', '4', '6'] as const;
export const UDP_GUARD_PORTS = ['443', '3478:3481', '5349', '19302:19309'];
export const ONLINE_NEIGH_STATES = new Set(['REACHABLE', 'DELAY', 'PROBE', 'STALE']);
export const OFFLINE_NEIGH_STATES = new Set(['FAILED', 'INCOMPLETE']);
export const WIFI_24_CHANNELS = Array.from({ length: 13 }, (_v, idx) => idx + 1);
export const WIFI_5_CHANNELS = [36, 40, 44, 48, 149, 153, 157, 161];
export const WIFI_5_CENTER_SEG0: Record<number, number> = {
  36: 42,
  40: 42,
  44: 42,
  48: 42,
  149: 155,
  153: 155,
  157: 155,
  161: 155,
};
export const PRIVATE_NETS = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '224.0.0.0/4',
  '240.0.0.0/4',
];
