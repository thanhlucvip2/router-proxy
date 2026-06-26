#!/usr/bin/env python3
import argparse
import base64
import hashlib
import html
import ipaddress
import json
import os
import select
import shlex
import shutil
import signal
import socket
import secrets
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse


BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = BASE_DIR / "state"
CONFIG_FILE = BASE_DIR / "config.json"
STATE_FILE = STATE_DIR / "router_state.json"
DNSMASQ_CONF = STATE_DIR / "dnsmasq.conf"
DNSMASQ_LEASES = STATE_DIR / "dnsmasq.leases"
DNSMASQ_PID = STATE_DIR / "dnsmasq.pid"
HOSTAPD_CONF = STATE_DIR / "hostapd.conf"
HOSTAPD_PID = STATE_DIR / "hostapd.pid"
REDSOCKS_CONF = STATE_DIR / "redsocks.conf"
REDSOCKS_PID = STATE_DIR / "redsocks.pid"
DOMAIN_PROXY_PREFIX = "domain_proxy"
WEB_PID = STATE_DIR / "router_manager.pid"
ADMIN_PASSWORD_FILE = STATE_DIR / "admin_password.txt"
SESSION_FILE = STATE_DIR / "session_token.txt"
NETWORKD_RUNTIME_DIR = Path("/run/systemd/network")
NETWORKD_PREFIX = "00-router-manager"

DEFAULT_LAN_CIDR = "10.42.0.1/21"
DEFAULT_BRIDGE_IF = "br-router"
DEFAULT_WIFI_SSID = "RouterWiFi"
DEFAULT_WIFI_CHANNEL = 6
DEFAULT_WIFI_BAND = "2.4"
DEFAULT_WIFI_COUNTRY = "US"
DEFAULT_ADMIN_USER = "admin"
PROXY_CHAIN = "ROUTER_PROXY"
GUARD_CHAIN = "ROUTER_GUARD"
PROXY_V4_GUARD_CHAIN = "ROUTER_PROXY_V4_GUARD"
PROXY_V6_GUARD_CHAIN = "ROUTER_PROXY_V6_GUARD"
PROXY_LOCAL_BASE = 23450
PROXY_TYPES = ("http", "https", "socks5", "socks4")
PROXY_TEST_URLS = {
    "4": "https://api.ipify.org",
    "6": "https://api6.ipify.org",
}
BALANCE_FAMILIES = ("all", "4", "6")
UDP_GUARD_PORTS = ("443", "3478:3481", "5349", "19302:19309")
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
ONLINE_NEIGH_STATES = {"REACHABLE", "DELAY", "PROBE", "STALE"}
OFFLINE_NEIGH_STATES = {"FAILED", "INCOMPLETE"}
WIFI_24_CHANNELS = tuple(range(1, 14))
WIFI_5_CHANNELS = (36, 40, 44, 48, 149, 153, 157, 161)
WIFI_5_CENTER_SEG0 = {
    36: 42,
    40: 42,
    44: 42,
    48: 42,
    149: 155,
    153: 155,
    157: 155,
    161: 155,
}
PRIVATE_NETS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


def wifi_band(value):
    cleaned = str(value or "").strip().lower().replace("ghz", "").replace(" ", "")
    if cleaned in ("2.4", "2", "24", "2g", "b", "g", "n"):
        return "2.4"
    if cleaned in ("5", "5g", "a", "ac", "ax"):
        return "5"
    return ""


def wifi_band_label(value):
    return "5 GHz fast" if wifi_band(value) == "5" else "2.4 GHz compatible"


def default_channel_for_band(band):
    return 36 if wifi_band(band) == "5" else DEFAULT_WIFI_CHANNEL


def valid_channels_for_band(band):
    return WIFI_5_CHANNELS if wifi_band(band) == "5" else WIFI_24_CHANNELS


def ht40_capab_for_channel(channel):
    return "[HT40+]" if channel in (36, 44, 149, 157) else "[HT40-]"


def normalize_wifi_country(value):
    country = str(value or DEFAULT_WIFI_COUNTRY).strip().upper()
    if len(country) == 2 and country.isalpha():
        return country
    return DEFAULT_WIFI_COUNTRY


def sh(cmd, check=True, capture=True):
    result = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"{' '.join(cmd)} failed: {detail}")
    return (result.stdout or "").strip()


def sudo(cmd, check=True, capture=True):
    if os.geteuid() == 0:
        return sh(cmd, check=check, capture=capture)
    return sh(["sudo", "-n", *cmd], check=check, capture=capture)


def sudo_success(cmd):
    actual = cmd if os.geteuid() == 0 else ["sudo", "-n", *cmd]
    return subprocess.run(actual, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def sudo_write_text(path, text):
    path = Path(path)
    if os.geteuid() == 0:
        path.write_text(text)
        return
    result = subprocess.run(
        ["sudo", "-n", "tee", str(path)],
        input=text,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Khong ghi duoc {path}: {(result.stderr or '').strip()}")


def delete_existing_rule(cmd):
    for _ in range(50):
        if not sudo_success(cmd):
            return


def require_commands(names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        install = "sudo apt-get update && sudo apt-get install -y dnsmasq-base redsocks iptables conntrack hostapd iw"
        raise RuntimeError(f"Thieu lenh: {', '.join(missing)}. Cai bang: {install}")


def all_interface_names():
    out = sh(["ip", "-j", "link"])
    rows = json.loads(out)
    return [row["ifname"] for row in rows if row["ifname"] != "lo"]


def interface_exists(ifname):
    return ifname in all_interface_names()


def require_interface(ifname, role):
    names = all_interface_names()
    if ifname not in names:
        shown = ", ".join(names) or "none"
        raise RuntimeError(f"{role} interface {ifname!r} khong ton tai. Interfaces hien co: {shown}")


def interface_list(value):
    if isinstance(value, (list, tuple)):
        raw_items = value
    else:
        raw_items = str(value or "").replace(",", " ").split()
    items = []
    for item in raw_items:
        name = str(item).strip()
        if name and name not in items:
            items.append(name)
    return items


def primary_interface(value):
    items = interface_list(value)
    return items[0] if items else ""


def default_hotspot():
    return {
        "enabled": False,
        "ifname": "",
        "ssid": DEFAULT_WIFI_SSID,
        "password": "",
        "band": DEFAULT_WIFI_BAND,
        "country": DEFAULT_WIFI_COUNTRY,
        "channel": DEFAULT_WIFI_CHANNEL,
    }


def default_state():
    return {
        "proxies": [],
        "assignments": {},
        "device_names": {},
        "device_groups": [],
        "dhcp_reservations": {},
        "lan_cidr": DEFAULT_LAN_CIDR,
        "hotspot": default_hotspot(),
    }


def default_config():
    return {
        "dhcp_bindings": {},
        "device_groups": [],
    }


def read_config_file_with_keys():
    if not CONFIG_FILE.exists():
        return default_config(), set()
    data = json.loads(CONFIG_FILE.read_text())
    if not isinstance(data, dict):
        raise ValueError("config.json phai la JSON object")
    keys = set(data)
    config = default_config()
    config.update(data)
    return config, keys


def read_config_file():
    config, _keys = read_config_file_with_keys()
    return config


def write_config_file(config):
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, indent=2))
    tmp.replace(CONFIG_FILE)


def config_binding_maps(config, lan_cidr):
    bindings = config.get("dhcp_bindings", {})
    if isinstance(bindings, list):
        entries = ((entry.get("mac", ""), entry) for entry in bindings if isinstance(entry, dict))
    elif isinstance(bindings, dict):
        entries = bindings.items()
    else:
        entries = []
    names = {}
    reservations = {}
    for raw_mac, raw_entry in entries:
        mac = normalize_mac(raw_mac)
        if not valid_mac(mac):
            continue
        entry = raw_entry if isinstance(raw_entry, dict) else {"ip_address": raw_entry}
        name = str(entry.get("name", "")).strip()[:64]
        if name:
            names[mac] = name
        raw_ip = entry.get("ip_address", entry.get("ip", entry.get("dhcp_ip", "")))
        try:
            ip_address = normalize_dhcp_reservation_ip(raw_ip, lan_cidr)
        except ValueError:
            ip_address = ""
        if ip_address:
            reservations[mac] = ip_address
    return names, reservations


def apply_config_to_state(state):
    if not CONFIG_FILE.exists():
        return state
    config, config_keys = read_config_file_with_keys()
    names, reservations = config_binding_maps(config, state.get("lan_cidr", DEFAULT_LAN_CIDR))
    state["device_names"] = names
    state["dhcp_reservations"] = reservations
    if "device_groups" in config_keys:
        state["device_groups"] = normalize_device_groups(config.get("device_groups", []))
    else:
        save_device_groups_config(state)
    return state


def save_device_groups_config(state):
    config = read_config_file()
    config["device_groups"] = normalize_device_groups(state.get("device_groups", []))
    write_config_file(config)


def save_dhcp_bindings_config(state):
    config = read_config_file()
    names = {normalize_mac(mac): name for mac, name in state.get("device_names", {}).items() if valid_mac(mac)}
    reservations = {
        normalize_mac(mac): ip_address
        for mac, ip_address in state.get("dhcp_reservations", {}).items()
        if valid_mac(mac)
    }
    bindings = {}
    def binding_sort_key(mac):
        try:
            ip_key = int(ipaddress.ip_address(reservations.get(mac, "")))
        except ValueError:
            ip_key = 0
        return (ip_key, names.get(mac, ""), mac)

    for mac in sorted(set(names) | set(reservations), key=binding_sort_key):
        entry = {}
        if names.get(mac):
            entry["name"] = str(names[mac]).strip()[:64]
        if reservations.get(mac):
            entry["ip_address"] = str(reservations[mac]).strip()
        if entry:
            bindings[mac] = entry
    config["dhcp_bindings"] = bindings
    write_config_file(config)


def normalized_hotspot(state):
    raw = state.get("hotspot", {})
    config = default_hotspot()
    if isinstance(raw, dict):
        for key in config:
            if key in raw:
                config[key] = raw[key]
    config["enabled"] = bool(config.get("enabled"))
    config["ifname"] = str(config.get("ifname", "")).strip()
    config["ssid"] = str(config.get("ssid", "")).strip() or DEFAULT_WIFI_SSID
    config["password"] = str(config.get("password", ""))
    config["band"] = wifi_band(config.get("band")) or DEFAULT_WIFI_BAND
    config["country"] = normalize_wifi_country(config.get("country"))
    try:
        channel = int(config.get("channel", DEFAULT_WIFI_CHANNEL))
    except (TypeError, ValueError):
        channel = default_channel_for_band(config["band"])
    if channel not in valid_channels_for_band(config["band"]):
        channel = default_channel_for_band(config["band"])
    config["channel"] = channel
    return config


def normalize_device_group_ips(value):
    ips = []
    if isinstance(value, str):
        raw_items = value.replace(",", "\n").splitlines()
    elif isinstance(value, list):
        raw_items = value
    else:
        raw_items = []
    for item in raw_items:
        raw_ip = str(item or "").strip()
        if not raw_ip:
            continue
        try:
            ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            continue
        if ip not in ips:
            ips.append(ip)
    return ips


def normalize_device_groups(raw_groups):
    groups = []
    seen_ids = set()
    grouped_ips = set()
    if not isinstance(raw_groups, list):
        return groups
    for item in raw_groups:
        if not isinstance(item, dict):
            continue
        group_id = str(item.get("id", "")).strip()[:48]
        if not group_id or group_id in seen_ids:
            continue
        ips = []
        for ip in normalize_device_group_ips(item.get("ips", [])):
            if ip in grouped_ips:
                continue
            ips.append(ip)
            grouped_ips.add(ip)
        if not ips:
            continue
        seen_ids.add(group_id)
        groups.append(
            {
                "id": group_id,
                "name": str(item.get("name", "")).strip()[:64] or "Group",
                "ips": ips,
                "collapsed": bool(item.get("collapsed")),
            }
        )
    return groups


def load_state():
    STATE_DIR.mkdir(exist_ok=True)
    if not STATE_FILE.exists():
        return apply_config_to_state(default_state())
    state = json.loads(STATE_FILE.read_text())
    state.setdefault("proxies", [])
    state.setdefault("assignments", {})
    state.setdefault("device_names", {})
    state["device_groups"] = normalize_device_groups(state.get("device_groups", []))
    state.setdefault("dhcp_reservations", {})
    state.setdefault("lan_cidr", DEFAULT_LAN_CIDR)
    state.setdefault("device_presence", {})
    state.setdefault("hidden_offline_devices", {})
    state["hotspot"] = normalized_hotspot(state)
    apply_config_to_state(state)
    return state


def public_state(state):
    data = json.loads(json.dumps(state))
    for proxy in data.get("proxies", []):
        if proxy.get("password"):
            proxy["password"] = "********"
    hotspot = data.get("hotspot", {})
    if hotspot.get("password"):
        hotspot["password"] = "********"
    return data


def save_state(state):
    STATE_DIR.mkdir(exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(STATE_FILE)


def websocket_accept_key(client_key):
    digest = hashlib.sha1((client_key + WEBSOCKET_GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def websocket_frame(payload, opcode=0x1):
    if isinstance(payload, str):
        payload = payload.encode()
    length = len(payload)
    header = bytearray([0x80 | opcode])
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.extend([126, (length >> 8) & 0xFF, length & 0xFF])
    else:
        header.extend(
            [
                127,
                (length >> 56) & 0xFF,
                (length >> 48) & 0xFF,
                (length >> 40) & 0xFF,
                (length >> 32) & 0xFF,
                (length >> 24) & 0xFF,
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            ]
        )
    return bytes(header) + payload


def websocket_send_json(conn, data):
    conn.sendall(websocket_frame(json.dumps(data, separators=(",", ":"))))


def websocket_recv_exact(conn, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def websocket_read_message(conn):
    try:
        header = websocket_recv_exact(conn, 2)
    except socket.timeout:
        return None
    if not header:
        return {"type": "close"}
    first, second = header
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        extended = websocket_recv_exact(conn, 2)
        if not extended:
            return {"type": "close"}
        length = int.from_bytes(extended, "big")
    elif length == 127:
        extended = websocket_recv_exact(conn, 8)
        if not extended:
            return {"type": "close"}
        length = int.from_bytes(extended, "big")
    mask = websocket_recv_exact(conn, 4) if masked else b""
    payload = websocket_recv_exact(conn, length) if length else b""
    if payload is None:
        return {"type": "close"}
    if masked and mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    if opcode == 0x8:
        return {"type": "close"}
    if opcode == 0x9:
        return {"type": "ping", "payload": payload}
    if opcode != 0x1:
        return None
    try:
        return {"type": "text", "text": payload.decode()}
    except UnicodeDecodeError:
        return None


def load_or_create_admin_password():
    STATE_DIR.mkdir(exist_ok=True)
    password = os.environ.get("ROUTER_ADMIN_PASSWORD", "").strip()
    if password:
        ADMIN_PASSWORD_FILE.write_text(password + "\n")
        ADMIN_PASSWORD_FILE.chmod(0o600)
        return password
    if ADMIN_PASSWORD_FILE.exists():
        return ADMIN_PASSWORD_FILE.read_text().strip()
    password = secrets.token_urlsafe(18)
    ADMIN_PASSWORD_FILE.write_text(password + "\n")
    ADMIN_PASSWORD_FILE.chmod(0o600)
    return password


def load_or_create_session_token():
    STATE_DIR.mkdir(exist_ok=True)
    if SESSION_FILE.exists():
        return SESSION_FILE.read_text().strip()
    token = secrets.token_urlsafe(32)
    SESSION_FILE.write_text(token + "\n")
    SESSION_FILE.chmod(0o600)
    return token


def link_names():
    out = sh(["ip", "-j", "link"])
    rows = json.loads(out)
    return [row["ifname"] for row in rows if row["ifname"] != "lo" and not row["ifname"].startswith(("docker", "br-", "veth"))]


def wireless_interfaces():
    names = []
    for name in link_names():
        if Path(f"/sys/class/net/{name}/wireless").exists():
            names.append(name)
    if names or shutil.which("iw") is None:
        return names
    out = sh(["iw", "dev"], check=False)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            ifname = line.split(None, 1)[1].strip()
            if ifname and ifname not in names:
                names.append(ifname)
    return names


def detect_wan():
    route = sh(["ip", "route", "show", "default"], check=False)
    for line in route.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return ""


def detect_lan(wan):
    candidates = [name for name in link_names() if name != wan]
    down = []
    for name in candidates:
        row = sh(["ip", "-br", "link", "show", name], check=False)
        if " DOWN " in f" {row} ":
            down.append(name)
    return (down or candidates or [""])[0]


def cidr_parts(cidr):
    iface = ipaddress.ip_interface(cidr)
    if iface.version != 4:
        raise ValueError("LAN CIDR phai la IPv4, vi du 10.42.0.1/24")
    network = iface.network
    return str(iface.ip), str(network.netmask), str(network)


def dhcp_range_for(lan_cidr):
    iface = ipaddress.ip_interface(lan_cidr)
    if iface.version != 4:
        raise ValueError("LAN CIDR phai la IPv4")
    network = iface.network
    gateway = int(iface.ip)
    first = int(network.network_address) + 1
    last = int(network.broadcast_address) - 1
    if first > last:
        raise ValueError("LAN CIDR qua nho, khong co dia chi DHCP kha dung")
    if network.num_addresses > 512:
        start = max(first, int(network.network_address) + 257)
        end = min(last, int(network.broadcast_address) - 257)
    else:
        start = max(first, int(network.network_address) + 50)
        end = min(last, int(network.network_address) + 200)
    if start > end:
        start, end = first, last
    if start == gateway:
        start += 1
    if end == gateway:
        end -= 1
    if start > end:
        raise ValueError("Khong tao duoc DHCP range khac IP gateway")
    return str(ipaddress.ip_address(start)), str(ipaddress.ip_address(end)), str(network.netmask)


def normalize_lan_cidr(value):
    value = str(value or "").strip()
    if not value:
        raise ValueError("LAN CIDR khong duoc de trong")
    if "/" not in value:
        value += "/24"
    iface = ipaddress.ip_interface(value)
    if iface.version != 4:
        raise ValueError("LAN CIDR phai la IPv4, vi du 10.42.7.1/24 hoac 10.42.0.1/16")
    network = iface.network
    if iface.ip == network.network_address or iface.ip == network.broadcast_address:
        raise ValueError("IP gateway khong duoc la network/broadcast address")
    dhcp_range_for(iface.with_prefixlen)
    return iface.with_prefixlen


def prune_lan_scoped_state(state, lan_cidr):
    lan_net = ipaddress.ip_interface(lan_cidr).network
    assignments = {}
    for client_ip, proxy_idx in state.get("assignments", {}).items():
        try:
            if ipaddress.ip_address(client_ip) in lan_net:
                assignments[client_ip] = proxy_idx
        except ValueError:
            continue
    state["assignments"] = assignments
    reservations = {}
    for mac, client_ip in state.get("dhcp_reservations", {}).items():
        mac = normalize_mac(mac)
        try:
            if mac and ipaddress.ip_address(client_ip) in lan_net:
                reservations[mac] = client_ip
        except ValueError:
            continue
    state["dhcp_reservations"] = reservations
    groups = []
    for group in normalize_device_groups(state.get("device_groups", [])):
        ips = []
        for client_ip in group.get("ips", []):
            try:
                if ipaddress.ip_address(client_ip) in lan_net:
                    ips.append(client_ip)
            except ValueError:
                continue
        if ips:
            group["ips"] = ips
            groups.append(group)
    state["device_groups"] = groups


def normalize_dhcp_reservation_ip(value, lan_cidr):
    value = str(value or "").strip()
    if not value:
        return ""
    ip = ipaddress.ip_address(value)
    if ip.version != 4:
        raise ValueError("DHCP IP phai la IPv4")
    iface = ipaddress.ip_interface(lan_cidr)
    network = iface.network
    if ip not in network:
        raise ValueError(f"DHCP IP phai nam trong LAN {network}")
    if ip in (network.network_address, network.broadcast_address, iface.ip):
        raise ValueError("DHCP IP khong duoc la gateway/network/broadcast")
    return str(ip)


def current_mac(ifname):
    try:
        return Path(f"/sys/class/net/{ifname}/address").read_text().strip()
    except OSError:
        return ""


def random_local_mac():
    values = [secrets.randbits(8) for _ in range(6)]
    values[0] = (values[0] | 0x02) & 0xFE
    return ":".join(f"{value:02x}" for value in values)


def renew_interface(ifname):
    if shutil.which("networkctl"):
        sudo(["networkctl", "renew", ifname], check=False)
    if shutil.which("nmcli"):
        sh(["nmcli", "device", "reapply", ifname], check=False)


def set_nm_managed(ifname, managed):
    if ifname and shutil.which("nmcli"):
        sudo(["nmcli", "device", "set", ifname, "managed", "yes" if managed else "no"], check=False)


def networkd_config_path(ifname):
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in ifname)
    return NETWORKD_RUNTIME_DIR / f"{NETWORKD_PREFIX}-{safe}.network"


def set_networkd_unmanaged(ifnames, unmanaged):
    names = interface_list(ifnames)
    if not names or not shutil.which("networkctl") or not NETWORKD_RUNTIME_DIR.exists():
        return
    for ifname in names:
        path = networkd_config_path(ifname)
        if unmanaged:
            sudo_write_text(path, f"[Match]\nName={ifname}\n\n[Link]\nUnmanaged=yes\n")
        else:
            sudo(["rm", "-f", str(path)], check=False)
    sudo(["networkctl", "reload"], check=False)
    for ifname in names:
        sudo(["networkctl", "reconfigure", ifname], check=False)


def rotate_interface_mac(ifname):
    if not ifname or ifname == "lo":
        raise ValueError("Interface khong hop le")
    old_mac = current_mac(ifname)
    new_mac = random_local_mac()
    sudo(["ip", "link", "set", "dev", ifname, "down"])
    sudo(["ip", "link", "set", "dev", ifname, "address", new_mac])
    sudo(["ip", "link", "set", "dev", ifname, "up"])
    renew_interface(ifname)
    return old_mac, new_mac


def pid_alive(pid_file):
    try:
        pid = int(Path(pid_file).read_text().strip())
    except (FileNotFoundError, ValueError):
        return False
    cmd = ["kill", "-0", str(pid)]
    if os.geteuid() != 0:
        cmd = ["sudo", "-n", *cmd]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def stop_pid(pid_file):
    try:
        pid = int(Path(pid_file).read_text().strip())
    except (FileNotFoundError, ValueError):
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        sudo(["kill", f"-{sig.name.removeprefix('SIG')}", str(pid)], check=False)
        for _ in range(10):
            time.sleep(0.1)
            if not pid_alive(pid_file):
                break
        if not pid_alive(pid_file):
            break
    Path(pid_file).unlink(missing_ok=True)


def process_alive(pid):
    return sudo_success(["kill", "-0", str(pid)])


def signal_process(pid, sig):
    sudo(["kill", f"-{sig.name.removeprefix('SIG')}", str(pid)], check=False)


def active_lan_if(base_lan_if, state=None):
    hotspot = normalized_hotspot(state or load_state())
    lan_members = interface_list(base_lan_if)
    if len(lan_members) > 1:
        return DEFAULT_BRIDGE_IF
    if hotspot["enabled"] and hotspot["ifname"]:
        return DEFAULT_BRIDGE_IF
    return primary_interface(base_lan_if)


def validate_hostapd_text(value, label):
    if any(ch in value for ch in ("\n", "\r", "\0")):
        raise ValueError(f"{label} khong duoc co ky tu xuong dong")
    return value


def parse_hotspot_form(data, existing_state, wan_if):
    current = normalized_hotspot(existing_state)
    ifname = data.get("ifname", "").strip()
    if not ifname:
        raise ValueError("Chua chon card WiFi")
    require_interface(ifname, "WiFi")
    if ifname == wan_if:
        raise ValueError("Card WiFi hotspot khong duoc trung voi WAN")
    wifi_names = wireless_interfaces()
    if wifi_names and ifname not in wifi_names:
        shown = ", ".join(wifi_names)
        raise ValueError(f"{ifname!r} khong phai WiFi interface. WiFi hien co: {shown}")
    ssid = validate_hostapd_text(data.get("ssid", "").strip(), "Ten WiFi")
    if not ssid:
        raise ValueError("Ten WiFi dang trong")
    if len(ssid.encode("utf-8")) > 32:
        raise ValueError("Ten WiFi toi da 32 byte")
    password = data.get("password", "")
    if not password and current.get("password"):
        password = current["password"]
    password = validate_hostapd_text(password, "Password WiFi")
    if len(password) < 8 or len(password) > 63:
        raise ValueError("Password WiFi phai tu 8 den 63 ky tu")
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in password):
        raise ValueError("Password WiFi chi ho tro ASCII in duoc")
    band = wifi_band(data.get("band", current.get("band", DEFAULT_WIFI_BAND)))
    if not band:
        raise ValueError("Band WiFi chi ho tro 2.4 hoac 5 GHz")
    country = str(data.get("country", current.get("country", DEFAULT_WIFI_COUNTRY))).strip().upper()
    if len(country) != 2 or not country.isalpha():
        raise ValueError("Country code WiFi phai gom 2 chu cai, vi du US")
    channel_raw = str(data.get("channel", "")).strip()
    try:
        channel = int(channel_raw) if channel_raw else int(current.get("channel", default_channel_for_band(band)))
    except (TypeError, ValueError):
        channel = default_channel_for_band(band)
    if channel not in valid_channels_for_band(band):
        if channel_raw and wifi_band(current.get("band")) == band:
            allowed = ", ".join(str(item) for item in valid_channels_for_band(band))
            raise ValueError(f"Kenh WiFi {wifi_band_label(band)} chi ho tro: {allowed}")
        channel = default_channel_for_band(band)
    return {
        "enabled": True,
        "ifname": ifname,
        "ssid": ssid,
        "password": password,
        "band": band,
        "country": country,
        "channel": channel,
    }


def write_hostapd_conf(config, bridge_if=""):
    band = wifi_band(config.get("band")) or DEFAULT_WIFI_BAND
    country = normalize_wifi_country(config.get("country"))
    channel = int(config.get("channel", default_channel_for_band(band)))
    if channel not in valid_channels_for_band(band):
        channel = default_channel_for_band(band)
    lines = [
        f"interface={config['ifname']}",
        "driver=nl80211",
    ]
    if bridge_if:
        lines.append(f"bridge={bridge_if}")
    lines.extend(
        [
            f"ssid={config['ssid']}",
            f"country_code={country}",
            "ieee80211d=1",
        ]
    )
    if band == "5":
        center_seg0 = WIFI_5_CENTER_SEG0[channel]
        lines.extend(
            [
                "hw_mode=a",
                f"channel={channel}",
                "ieee80211n=1",
                f"ht_capab={ht40_capab_for_channel(channel)}[SHORT-GI-20][SHORT-GI-40]",
                "ieee80211ac=1",
                "ieee80211h=1",
                "vht_oper_chwidth=1",
                f"vht_oper_centr_freq_seg0_idx={center_seg0}",
                "vht_capab=[MAX-MPDU-11454][SHORT-GI-80]",
            ]
        )
    else:
        lines.extend(
            [
                "hw_mode=g",
                f"channel={channel}",
                "ieee80211n=1",
            ]
        )
    lines.extend(
        [
            "wmm_enabled=1",
            "auth_algs=1",
            "wpa=2",
            f"wpa_passphrase={config['password']}",
            "wpa_key_mgmt=WPA-PSK",
            "rsn_pairwise=CCMP",
            "",
        ]
    )
    HOSTAPD_CONF.write_text("\n".join(lines))
    HOSTAPD_CONF.chmod(0o600)


def stop_hostapd_processes():
    proc_rows = sh(["ps", "-eo", "pid,args"], check=False)
    conf_path = str(HOSTAPD_CONF)
    for line in proc_rows.splitlines():
        line = line.strip()
        if not line or "hostapd" not in line or conf_path not in line:
            continue
        pid_text, _, _ = line.partition(" ")
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        for sig in (signal.SIGTERM, signal.SIGKILL):
            sudo(["kill", f"-{sig.name.removeprefix('SIG')}", str(pid)], check=False)
            for _ in range(10):
                time.sleep(0.1)
                if not sudo_success(["kill", "-0", str(pid)]):
                    break
            if not sudo_success(["kill", "-0", str(pid)]):
                break
    HOSTAPD_PID.unlink(missing_ok=True)


def stop_hotspot(config=None):
    if config is None:
        config = normalized_hotspot(load_state())
    elif isinstance(config, dict) and "hotspot" in config:
        config = normalized_hotspot(config)
    else:
        config = normalized_hotspot({"hotspot": config})
    stop_pid(HOSTAPD_PID)
    stop_hostapd_processes()
    set_nm_managed(config.get("ifname"), True)
    if config.get("ifname"):
        sudo(["ip", "link", "set", "dev", config["ifname"], "nomaster"], check=False)


def start_hotspot(config, bridge_if=""):
    config = normalized_hotspot({"hotspot": config})
    if not config["enabled"]:
        stop_hotspot(config)
        return
    require_commands(["hostapd", "ip"])
    require_interface(config["ifname"], "WiFi")
    stop_hotspot(config)
    write_hostapd_conf(config, bridge_if)
    if shutil.which("iw"):
        sudo(["iw", "reg", "set", config["country"]], check=False)
    sudo(["systemctl", "stop", "hostapd"], check=False)
    if shutil.which("rfkill"):
        sudo(["rfkill", "unblock", "wifi"], check=False)
    if shutil.which("nmcli"):
        sudo(["nmcli", "device", "disconnect", config["ifname"]], check=False)
    set_nm_managed(config["ifname"], False)
    if shutil.which("iw"):
        sudo(["iw", "dev", config["ifname"], "set", "power_save", "off"], check=False)
    sudo(["ip", "link", "set", config["ifname"], "up"], check=False)
    sudo(["hostapd", "-B", "-P", str(HOSTAPD_PID), str(HOSTAPD_CONF)])
    for _ in range(15):
        time.sleep(0.2)
        if pid_alive(HOSTAPD_PID):
            return
    raise RuntimeError("hostapd khong khoi dong duoc")


def stop_redsocks_processes():
    proc_rows = sh(["ps", "-eo", "pid,args"], check=False)
    conf_path = str(REDSOCKS_CONF)
    for line in proc_rows.splitlines():
        line = line.strip()
        if not line or "redsocks" not in line or conf_path not in line:
            continue
        pid_text, _, _ = line.partition(" ")
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        for sig in (signal.SIGTERM, signal.SIGKILL):
            sudo(["kill", f"-{sig.name.removeprefix('SIG')}", str(pid)], check=False)
            for _ in range(10):
                time.sleep(0.1)
                if not sudo_success(["kill", "-0", str(pid)]):
                    break
            if not sudo_success(["kill", "-0", str(pid)]):
                break
    REDSOCKS_PID.unlink(missing_ok=True)


def domain_proxy_pid_file(port):
    return STATE_DIR / f"{DOMAIN_PROXY_PREFIX}_{port}.pid"


def domain_proxy_conf_file(port):
    return STATE_DIR / f"{DOMAIN_PROXY_PREFIX}_{port}.json"


def domain_proxy_log_file(port):
    return STATE_DIR / f"{DOMAIN_PROXY_PREFIX}_{port}.log"


def stop_domain_proxy_workers():
    for pid_file in STATE_DIR.glob(f"{DOMAIN_PROXY_PREFIX}_*.pid"):
        stop_pid(pid_file)
    proc_rows = sh(["ps", "-eo", "pid,args"], check=False)
    script_path = str(Path(__file__).resolve())
    for line in proc_rows.splitlines():
        line = line.strip()
        if "--domain-proxy-worker" not in line:
            continue
        pid_text, _, args = line.partition(" ")
        try:
            argv = shlex.split(args)
            pid = int(pid_text)
        except (ValueError, IndexError):
            continue
        if not argv or Path(argv[0]).name not in ("python", "python3"):
            continue
        if len(argv) < 2:
            continue
        try:
            if str(Path(argv[1]).resolve()) != script_path:
                continue
        except OSError:
            continue
        for sig in (signal.SIGTERM, signal.SIGKILL):
            sudo(["kill", f"-{sig.name.removeprefix('SIG')}", str(pid)], check=False)
            for _ in range(10):
                time.sleep(0.1)
                if not sudo_success(["kill", "-0", str(pid)]):
                    break
            if not sudo_success(["kill", "-0", str(pid)]):
                break
    for path in STATE_DIR.glob(f"{DOMAIN_PROXY_PREFIX}_*.pid"):
        path.unlink(missing_ok=True)


def stop_web_server():
    targets = set()
    try:
        pid = int(WEB_PID.read_text().strip())
        targets.add(pid)
    except (FileNotFoundError, ValueError):
        pass
    proc_rows = sh(["ps", "-eo", "pid,args"], check=False)
    script_path = str(Path(__file__).resolve())
    for line in proc_rows.splitlines():
        line = line.strip()
        if not line:
            continue
        pid_text, _, args = line.partition(" ")
        try:
            argv = shlex.split(args)
        except ValueError:
            continue
        if not argv or not Path(argv[0]).name.startswith("python"):
            continue
        script_args = argv[1:]
        is_this_script = False
        for item in script_args:
            if item == "router_manager.py":
                is_this_script = True
                break
            try:
                if str(Path(item).resolve()) == script_path:
                    is_this_script = True
                    break
            except OSError:
                continue
        if not is_this_script:
            continue
        try:
            targets.add(int(pid_text))
        except ValueError:
            continue
    targets.discard(os.getpid())
    for pid in targets:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if not process_alive(pid):
                break
            signal_process(pid, sig)
            for _ in range(20):
                time.sleep(0.1)
                if not process_alive(pid):
                    break
            if not process_alive(pid):
                break
    WEB_PID.unlink(missing_ok=True)


def write_dnsmasq_conf(lan_if, lan_cidr):
    lan_ip, _, _ = cidr_parts(lan_cidr)
    dhcp_start, dhcp_end, netmask = dhcp_range_for(lan_cidr)
    state = load_state()
    reservation_lines = []
    for mac, client_ip in sorted(state.get("dhcp_reservations", {}).items()):
        mac = normalize_mac(mac)
        try:
            client_ip = normalize_dhcp_reservation_ip(client_ip, lan_cidr)
        except ValueError:
            continue
        if mac and client_ip:
            reservation_lines.append(f"dhcp-host={mac},{client_ip}")
    DNSMASQ_CONF.write_text(
        "\n".join(
            [
                f"interface={lan_if}",
                "bind-interfaces",
                "except-interface=lo",
                f"dhcp-range={dhcp_start},{dhcp_end},{netmask},12h",
                f"dhcp-option=3,{lan_ip}",
                f"dhcp-option=6,{lan_ip}",
                "server=1.1.1.1",
                "server=8.8.8.8",
                "domain-needed",
                "bogus-priv",
                *reservation_lines,
                f"dhcp-leasefile={DNSMASQ_LEASES}",
                f"pid-file={DNSMASQ_PID}",
                "",
            ]
        )
    )


def start_dnsmasq(lan_if, lan_cidr):
    require_commands(["dnsmasq"])
    stop_pid(DNSMASQ_PID)
    write_dnsmasq_conf(lan_if, lan_cidr)
    sudo(["dnsmasq", "--conf-file=" + str(DNSMASQ_CONF)], capture=True)


def ensure_router(wan_if, lan_if, lan_cidr):
    require_commands(["ip", "iptables", "sysctl", "dnsmasq"])
    require_interface(wan_if, "WAN")
    require_interface(lan_if, "LAN")
    lan_ip, _, _ = cidr_parts(lan_cidr)
    sudo(["ip", "link", "set", lan_if, "up"])
    sudo(["ip", "addr", "flush", "dev", lan_if])
    sudo(["ip", "addr", "add", lan_cidr, "dev", lan_if])
    sudo(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    delete_existing_rule(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", wan_if, "-j", "MASQUERADE"])
    sudo(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wan_if, "-j", "MASQUERADE"])

    for rule in (
        ["FORWARD", "-i", lan_if, "-o", wan_if, "-j", "ACCEPT"],
        ["FORWARD", "-i", wan_if, "-o", lan_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ):
        delete_existing_rule(["iptables", "-D", *rule])
        sudo(["iptables", "-A", *rule])

    start_dnsmasq(lan_if, lan_cidr)
    return lan_ip


def remove_router_rules(wan_if, lan_if):
    if not lan_if:
        return
    iptables_proxy_reset(lan_if)
    delete_existing_rule(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", wan_if, "-j", "MASQUERADE"])
    for rule in (
        ["FORWARD", "-i", lan_if, "-o", wan_if, "-j", "ACCEPT"],
        ["FORWARD", "-i", wan_if, "-o", lan_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ):
        delete_existing_rule(["iptables", "-D", *rule])


def clear_lan_addresses(ifname, lan_cidr):
    if not ifname:
        return
    sudo(["ip", "addr", "flush", "dev", ifname], check=False)


def ensure_lan_bridge(base_lan_if, wifi_if, bridge_if, lan_cidr):
    require_commands(["ip"])
    lan_members = interface_list(base_lan_if)
    if not lan_members:
        raise RuntimeError("Chua cau hinh LAN interface")
    for member in lan_members:
        require_interface(member, "LAN")
    if wifi_if:
        require_interface(wifi_if, "WiFi")
    if not interface_exists(bridge_if):
        sudo(["ip", "link", "add", "name", bridge_if, "type", "bridge"])
    set_networkd_unmanaged([bridge_if, *lan_members, wifi_if], True)
    sudo(["ip", "link", "set", "dev", bridge_if, "type", "bridge", "stp_state", "1"], check=False)
    for member in lan_members:
        set_nm_managed(member, False)
        clear_lan_addresses(member, lan_cidr)
        sudo(["ip", "link", "set", "dev", member, "nomaster"], check=False)
        sudo(["ip", "link", "set", "dev", member, "master", bridge_if])
        sudo(["ip", "link", "set", "dev", member, "up"])
    if wifi_if:
        set_nm_managed(wifi_if, False)
        clear_lan_addresses(wifi_if, lan_cidr)
    sudo(["ip", "link", "set", "dev", bridge_if, "up"])


def teardown_lan_bridge(base_lan_if, bridge_if, wifi_if=""):
    networkd_ifnames = [bridge_if, *interface_list(base_lan_if), wifi_if]
    for member in interface_list(base_lan_if):
        if interface_exists(member):
            sudo(["ip", "link", "set", "dev", member, "nomaster"], check=False)
            set_nm_managed(member, True)
    if wifi_if and interface_exists(wifi_if):
        set_nm_managed(wifi_if, True)
    if interface_exists(bridge_if):
        sudo(["ip", "link", "set", "dev", bridge_if, "down"], check=False)
        sudo(["ip", "link", "del", "dev", bridge_if], check=False)
    set_networkd_unmanaged(networkd_ifnames, False)


def apply_router_stack(wan_if, base_lan_if, lan_cidr):
    state = load_state()
    hotspot = normalized_hotspot(state)
    lan_if = active_lan_if(base_lan_if, state)
    bridge_wifi_if = hotspot["ifname"] if hotspot["enabled"] else ""
    stale_lan_ifs = interface_list(base_lan_if)
    if hotspot["ifname"]:
        stale_lan_ifs.append(hotspot["ifname"])
    if lan_if == DEFAULT_BRIDGE_IF:
        ensure_lan_bridge(base_lan_if, bridge_wifi_if, lan_if, lan_cidr)
    else:
        stop_hotspot(hotspot)
        teardown_lan_bridge(base_lan_if, DEFAULT_BRIDGE_IF, hotspot.get("ifname", ""))
    for stale_if in dict.fromkeys(stale_lan_ifs):
        if stale_if and stale_if != lan_if:
            remove_router_rules(wan_if, stale_if)
    ensure_router(wan_if, lan_if, lan_cidr)
    if hotspot["enabled"]:
        start_hotspot(hotspot, lan_if if lan_if == DEFAULT_BRIDGE_IF else "")
    else:
        stop_hotspot(hotspot)
    apply_proxy_rules(lan_if)
    return lan_if


def stop_router(wan_if, lan_if, base_lan_if=""):
    stop_hotspot()
    remove_router_rules(wan_if, lan_if)
    stop_pid(REDSOCKS_PID)
    stop_redsocks_processes()
    stop_domain_proxy_workers()
    stop_pid(DNSMASQ_PID)
    if lan_if == DEFAULT_BRIDGE_IF:
        state = load_state()
        hotspot = normalized_hotspot(state)
        teardown_lan_bridge(base_lan_if, DEFAULT_BRIDGE_IF, hotspot.get("ifname", ""))


def normalize_mac(mac):
    return str(mac or "").strip().lower()


def valid_mac(mac):
    parts = normalize_mac(mac).split(":")
    return len(parts) == 6 and all(len(part) == 2 and all(ch in "0123456789abcdef" for ch in part) for part in parts)


def remove_dnsmasq_leases_for_mac(mac):
    mac = normalize_mac(mac)
    if not mac or not DNSMASQ_LEASES.exists():
        return []
    lines = DNSMASQ_LEASES.read_text().splitlines()
    kept = []
    removed_ips = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and normalize_mac(parts[1]) == mac:
            removed_ips.append(parts[2])
            continue
        kept.append(line)
    if removed_ips:
        text = "\n".join(kept)
        if text:
            text += "\n"
        sudo_write_text(DNSMASQ_LEASES, text)
    return removed_ips


def flush_client_network_state(lan_if, ips):
    if not lan_if:
        return
    clean_ips = []
    for ip in ips:
        try:
            parsed = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            continue
        if parsed.version == 4:
            clean_ips.append(str(parsed))
    if not clean_ips:
        return
    flush_client_conntrack(clean_ips)
    for ip in sorted(set(clean_ips), key=ip_sort_key):
        sudo(["ip", "neigh", "del", ip, "dev", lan_if], check=False)


def disconnect_wifi_client(mac, wifi_if):
    mac = normalize_mac(mac)
    if not mac or not wifi_if:
        return False
    if shutil.which("iw") and mac not in wifi_station_details(wifi_if):
        return False
    if shutil.which("iw") and sudo_success(["iw", "dev", wifi_if, "station", "del", mac]):
        return True
    if shutil.which("hostapd_cli"):
        return sudo_success(["hostapd_cli", "-i", wifi_if, "deauthenticate", mac])
    return False


def refresh_dhcp_client(mac, lan_if, candidate_ips=None):
    mac = normalize_mac(mac)
    state = load_state()
    hotspot = normalized_hotspot(state)
    reservation_ip = state.get("dhcp_reservations", {}).get(mac, "")
    ips = set(candidate_ips or [])
    if reservation_ip:
        ips.add(reservation_ip)
    flush_client_network_state(lan_if, ips)
    if disconnect_wifi_client(mac, hotspot.get("ifname", "")):
        return "DHCP binding changed; lease cleared and WiFi client reconnected to get the new IP"
    return "DHCP binding changed; lease cleared. Client will get the new IP on next reconnect/renew"


def wifi_station_details(wifi_if):
    stations = {}
    if not wifi_if or shutil.which("iw") is None:
        return stations
    out = sh(["iw", "dev", wifi_if, "station", "dump"], check=False)
    current = None
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if line.startswith("Station "):
            parts = line.split()
            current = normalize_mac(parts[1] if len(parts) > 1 else "")
            if current:
                stations[current] = {"mac": current, "interface": wifi_if}
            continue
        if not current or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().replace(" ", "_")
        stations[current][key] = value.strip()
    return stations


def bridge_fdb_ports(bridge_if):
    ports = {}
    if not bridge_if or shutil.which("bridge") is None or not interface_exists(bridge_if):
        return ports
    out = sh(["bridge", "-j", "fdb", "show", "br", bridge_if], check=False)
    try:
        rows = json.loads(out or "[]")
    except json.JSONDecodeError:
        rows = []
    for row in rows:
        mac = normalize_mac(row.get("mac", ""))
        if not mac or mac.startswith(("01:", "33:33:")):
            continue
        flags = set(row.get("flags", []))
        if "self" in flags or row.get("state") == "permanent":
            continue
        if row.get("ifname"):
            ports[mac] = row["ifname"]
    return ports


def timestamp_now():
    return int(time.time())


def format_timestamp(value):
    try:
        ts = int(float(value))
    except (TypeError, ValueError):
        return ""
    if ts <= 0:
        return ""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def device_presence_key(row):
    mac = normalize_mac(row.get("mac", ""))
    return mac or str(row.get("ip", "")).strip()


def row_is_online(row, wifi_stations, fdb_ports):
    mac = normalize_mac(row.get("mac", ""))
    if mac and mac in wifi_stations:
        return True, "wifi station"
    if mac and mac in fdb_ports:
        return True, "bridge fdb"
    states = {str(item).upper() for item in row.get("neigh_state", [])}
    if states & ONLINE_NEIGH_STATES:
        return True, "/".join(sorted(states))
    if states & OFFLINE_NEIGH_STATES:
        return False, "/".join(sorted(states))
    return False, "/".join(sorted(states)) or row.get("source", "unknown")


def update_device_presence(state, rows, wifi_stations, fdb_ports):
    presence = state.setdefault("device_presence", {})
    now = timestamp_now()
    changed = False
    for row in rows:
        key = device_presence_key(row)
        if not key:
            continue
        online, reason = row_is_online(row, wifi_stations, fdb_ports)
        entry = presence.get(key, {})
        if not isinstance(entry, dict):
            entry = {}
        was_online = bool(entry.get("online", False))
        if online:
            updates = {
                "online": True,
                "ip": row.get("ip", ""),
                "mac": normalize_mac(row.get("mac", "")),
                "hostname": row.get("hostname", ""),
                "connection": row.get("connection", ""),
                "interface": row.get("interface", ""),
                "first_seen": entry.get("first_seen") or now,
                "last_seen": now,
                "disconnected_at": "",
                "reason": reason,
            }
        else:
            disconnected_at = entry.get("disconnected_at") or (now if was_online or not entry else "")
            updates = {
                "online": False,
                "ip": row.get("ip", entry.get("ip", "")),
                "mac": normalize_mac(row.get("mac", entry.get("mac", ""))),
                "hostname": row.get("hostname", entry.get("hostname", "")),
                "connection": row.get("connection", entry.get("connection", "")),
                "interface": row.get("interface", entry.get("interface", "")),
                "first_seen": entry.get("first_seen") or now,
                "last_seen": entry.get("last_seen") or "",
                "disconnected_at": disconnected_at,
                "reason": reason,
            }
        if entry != updates:
            presence[key] = updates
            changed = True
        row["online"] = online
        row["presence_reason"] = reason
        row["last_seen_at"] = presence[key].get("last_seen", "")
        row["disconnected_at"] = presence[key].get("disconnected_at", "")
        row["last_seen_text"] = format_timestamp(row["last_seen_at"])
        row["disconnected_text"] = format_timestamp(row["disconnected_at"])
    return changed


def classify_client(mac, lan_if, base_lan_if, wifi_if, wifi_stations=None, fdb_ports=None):
    mac = normalize_mac(mac)
    wifi_stations = wifi_stations or {}
    fdb_ports = fdb_ports or {}
    lan_members = interface_list(base_lan_if)
    if mac and mac in wifi_stations:
        station = wifi_stations[mac]
        detail = station.get("signal", "")
        return {"connection": "WiFi", "interface": wifi_if, "detail": detail}
    port = fdb_ports.get(mac, "")
    if port == wifi_if:
        return {"connection": "WiFi", "interface": wifi_if, "detail": ""}
    if port in lan_members:
        return {"connection": "LAN", "interface": port, "detail": ""}
    if lan_if == wifi_if:
        return {"connection": "WiFi", "interface": wifi_if, "detail": ""}
    if lan_if in lan_members:
        return {"connection": "LAN", "interface": lan_if, "detail": ""}
    return {"connection": "Unknown", "interface": port or lan_if, "detail": ""}


def annotate_client(row, lan_if, base_lan_if, wifi_if, wifi_stations, fdb_ports):
    row.update(classify_client(row.get("mac", ""), lan_if, base_lan_if, wifi_if, wifi_stations, fdb_ports))
    return row


def list_leases(lan_if, lan_cidr, base_lan_if="", wifi_if=""):
    lan_net = ipaddress.ip_interface(lan_cidr).network
    wifi_stations = wifi_station_details(wifi_if)
    fdb_ports = bridge_fdb_ports(lan_if if lan_if == DEFAULT_BRIDGE_IF else "")
    leases = {}
    if DNSMASQ_LEASES.exists():
        for line in DNSMASQ_LEASES.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                expires, mac, ip, hostname = parts[:4]
                if ipaddress.ip_address(ip) not in lan_net:
                    continue
                leases[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname if hostname != "*" else "",
                    "expires": expires,
                    "source": "dhcp",
                }
    neigh = sh(["ip", "-j", "neigh"], check=False)
    try:
        rows = json.loads(neigh or "[]")
    except json.JSONDecodeError:
        rows = []
    for row in rows:
        ip = row.get("dst", "")
        lladdr = row.get("lladdr", "")
        if not ip or ":" in ip:
            continue
        if row.get("dev") != lan_if or ipaddress.ip_address(ip) not in lan_net:
            continue
        neigh_state = row.get("state", [])
        if isinstance(neigh_state, str):
            neigh_state = [neigh_state]
        if ip not in leases:
            leases[ip] = {"ip": ip, "mac": lladdr, "hostname": "", "expires": "", "source": "arp"}
        elif lladdr and not leases[ip].get("mac"):
            leases[ip]["mac"] = lladdr
        leases[ip]["neigh_state"] = neigh_state
    rows = [
        annotate_client(row, lan_if, base_lan_if, wifi_if, wifi_stations, fdb_ports)
        for row in leases.values()
    ]
    return sorted(rows, key=lambda x: tuple(int(p) for p in x["ip"].split(".")))


def interface_kind(ifname):
    if Path(f"/sys/class/net/{ifname}/bridge").exists():
        return "bridge"
    if Path(f"/sys/class/net/{ifname}/wireless").exists():
        return "wifi"
    if ifname.startswith(("docker", "br-", "veth")):
        return "virtual"
    if Path(f"/sys/class/net/{ifname}/device").exists():
        return "ethernet"
    return "virtual"


def network_cards(wan_if, base_lan_if, active_if, hotspot):
    addr_rows = json.loads(sh(["ip", "-j", "addr"], check=False) or "[]")
    lan_members = interface_list(base_lan_if)
    rows = []
    for row in addr_rows:
        ifname = row.get("ifname", "")
        if not ifname or ifname == "lo":
            continue
        roles = []
        if ifname == wan_if:
            roles.append("WAN")
        if ifname in lan_members:
            roles.append("LAN port")
        if ifname == active_if:
            roles.append("Gateway")
        if ifname == hotspot.get("ifname"):
            roles.append("WiFi AP")
        if row.get("master") == active_if:
            roles.append(f"member of {active_if}")
        addresses = []
        for info in row.get("addr_info", []):
            local = info.get("local", "")
            prefixlen = info.get("prefixlen")
            if local and prefixlen is not None:
                addresses.append(f"{local}/{prefixlen}")
        rows.append(
            {
                "name": ifname,
                "kind": interface_kind(ifname),
                "state": row.get("operstate", ""),
                "mac": row.get("address", ""),
                "master": row.get("master", ""),
                "role": ", ".join(roles) or "-",
                "addresses": addresses,
            }
        )
    return rows


def proxy_key(proxy):
    auth = f"{proxy.get('login', '')}@" if proxy.get("login") else ""
    return f"{proxy['type']}://{auth}{format_host_port(proxy['host'], proxy['port'])} [{proxy_ip_label(proxy)}]"


def proxy_ip_version(proxy):
    version = str(proxy.get("ip_version", "4")).lower().removeprefix("ipv")
    return version if version in ("4", "6") else "4"


def proxy_ip_label(proxy):
    return "IPv6" if proxy_ip_version(proxy) == "6" else "IPv4"


def balance_family(value):
    family = str(value or "all").strip().lower().removeprefix("ipv")
    if family not in BALANCE_FAMILIES:
        raise ValueError("Load balance chi ho tro all, IPv4 hoac IPv6")
    return family


def balance_family_label(family):
    family = balance_family(family)
    if family == "4":
        return "IPv4"
    if family == "6":
        return "IPv6"
    return "All"


def load_balance_config(state):
    config = state.get("load_balance", {})
    try:
        family = balance_family(config.get("family", "all"))
    except ValueError:
        family = "all"
    return {"enabled": bool(config.get("enabled", False)), "family": family}


def proxy_auth_label(proxy):
    if proxy.get("login") and proxy.get("password"):
        return "user/pass"
    if proxy.get("login"):
        return "user only"
    return "none"


def is_ipv6_literal(value):
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def shell_quote(value):
    return shlex.quote(value)


def proxy_identity(proxy):
    return (
        proxy.get("type", ""),
        proxy.get("host", ""),
        int(proxy.get("port", 0)),
        proxy.get("login", ""),
        proxy.get("password", ""),
        proxy_ip_version(proxy),
    )


def proxy_port(index):
    return PROXY_LOCAL_BASE + index


def parse_proxy_ip_version(value):
    version = str(value or "4").strip().lower().removeprefix("ipv")
    if version not in ("4", "6"):
        raise ValueError("Proxy IP phai la IPv4 hoac IPv6")
    return version


def normalize_proxy_host(host):
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def format_proxy_host(host):
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def format_host_port(host, port):
    return f"{format_proxy_host(str(host))}:{port}"


def parse_proxy_url(value, ip_version="4"):
    value = value.strip()
    if not value:
        raise ValueError("Proxy URL dang trong")
    parsed = urlparse(value if "://" in value else "socks5://" + value)
    if parsed.scheme not in PROXY_TYPES:
        raise ValueError("Chi ho tro http, https, socks5, socks4")
    if not parsed.hostname or not parsed.port:
        raise ValueError("Can dung dang socks5://host:port, http://host:port hoac https://host:port")
    return {
        "type": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "login": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
        "ip_version": parse_proxy_ip_version(ip_version),
    }


def parse_proxy_form(data):
    ip_version = parse_proxy_ip_version(data.get("ip_version", "4"))
    proxy_url = data.get("url", "").strip()
    if proxy_url:
        return parse_proxy_url(proxy_url, ip_version)
    proxy_type = data.get("type", "").strip().lower()
    host = normalize_proxy_host(data.get("host", ""))
    port_value = data.get("port", "").strip()
    if proxy_type not in PROXY_TYPES:
        raise ValueError("Proxy type khong hop le")
    if not host:
        raise ValueError("Host proxy dang trong")
    if any(ch.isspace() for ch in host):
        raise ValueError("Host proxy khong duoc co khoang trang")
    try:
        port = int(port_value)
    except ValueError:
        raise ValueError("Port proxy phai la so") from None
    if port < 1 or port > 65535:
        raise ValueError("Port proxy phai nam trong 1-65535")
    return {
        "type": proxy_type,
        "host": host,
        "port": port,
        "login": data.get("login", "").strip(),
        "password": data.get("password", ""),
        "ip_version": ip_version,
    }


def proxy_url(proxy):
    auth = ""
    if proxy.get("login"):
        auth = quote(proxy["login"], safe="")
        if proxy.get("password"):
            auth += ":" + quote(proxy["password"], safe="")
        auth += "@"
    proxy_type = proxy.get("type", "http")
    scheme = {"socks5": "socks5h", "socks4": "socks4a"}.get(proxy_type, "http")
    return f"{scheme}://{auth}{format_host_port(proxy['host'], proxy['port'])}"


def check_proxy(index):
    state = load_state()
    proxies = state.get("proxies", [])
    if index < 0 or index >= len(proxies):
        raise ValueError("Proxy index khong hop le")
    proxy = proxies[index]
    cmd = [
        "curl",
        "-sS",
        "--max-time",
        "12",
        "-x",
        proxy_url(proxy),
        PROXY_TEST_URLS[proxy_ip_version(proxy)],
    ]
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    body = (result.stdout or "").strip()
    err = (result.stderr or "").strip()
    if result.returncode == 0 and body:
        return {"ok": True, "detail": body}
    return {"ok": False, "detail": err or f"curl exit {result.returncode}"}


def conf_quote(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def redsocks_type(proxy_type):
    if proxy_type in ("http", "https"):
        return "http-connect"
    return proxy_type


def use_domain_proxy(proxy):
    return proxy_ip_version(proxy) == "6" and proxy.get("type") in ("http", "https")


def parse_host_port(value, default_port):
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            host = value[1:end]
            rest = value[end + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, default_port
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return value, default_port


def parse_http_target(data, default_port):
    try:
        text = data.decode("iso-8859-1", "ignore")
    except UnicodeDecodeError:
        return None
    line_end = text.find("\r\n")
    if line_end == -1:
        return None
    first_line = text[:line_end]
    parts = first_line.split()
    if not parts:
        return None
    method = parts[0].upper()
    methods = {"GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
    if method not in methods:
        return None
    if method == "CONNECT" and len(parts) >= 2:
        return parse_host_port(parts[1], default_port)
    for line in text[line_end + 2 :].split("\r\n"):
        if not line:
            break
        key, sep, value = line.partition(":")
        if sep and key.lower() == "host":
            return parse_host_port(value, default_port)
    return None


def parse_tls_sni(data):
    try:
        if len(data) < 5 or data[0] != 22:
            return None
        record_len = int.from_bytes(data[3:5], "big")
        if len(data) < min(5 + record_len, 64):
            return None
        pos = 5
        if data[pos] != 1:
            return None
        handshake_len = int.from_bytes(data[pos + 1 : pos + 4], "big")
        end = min(len(data), pos + 4 + handshake_len)
        pos += 4 + 2 + 32
        if pos >= end:
            return None
        session_len = data[pos]
        pos += 1 + session_len
        if pos + 2 > end:
            return None
        cipher_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2 + cipher_len
        if pos >= end:
            return None
        compression_len = data[pos]
        pos += 1 + compression_len
        if pos + 2 > end:
            return None
        extensions_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        extensions_end = min(end, pos + extensions_len)
        while pos + 4 <= extensions_end:
            ext_type = int.from_bytes(data[pos : pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            ext_end = pos + ext_len
            if ext_type == 0 and pos + 2 <= ext_end:
                list_len = int.from_bytes(data[pos : pos + 2], "big")
                name_pos = pos + 2
                list_end = min(ext_end, name_pos + list_len)
                while name_pos + 3 <= list_end:
                    name_type = data[name_pos]
                    name_len = int.from_bytes(data[name_pos + 1 : name_pos + 3], "big")
                    name_pos += 3
                    if name_type == 0 and name_pos + name_len <= list_end:
                        return data[name_pos : name_pos + name_len].decode("idna")
                    name_pos += name_len
            pos = ext_end
    except (IndexError, UnicodeError):
        return None
    return None


def original_dst(client):
    try:
        data = client.getsockopt(socket.SOL_IP, 80, 16)
        port = struct.unpack_from("!H", data, 2)[0]
        host = socket.inet_ntoa(data[4:8])
        return host, port
    except OSError:
        return "", 443


def detect_domain_proxy_target(client, listen_port=None):
    original_host, original_port = original_dst(client)
    if listen_port and original_port == listen_port:
        original_port = 443
    client.settimeout(5)
    data = b""
    deadline = time.time() + 5
    while time.time() < deadline and len(data) < 16384:
        try:
            data = client.recv(16384, socket.MSG_PEEK)
        except socket.timeout:
            break
        if not data:
            break
        http_target = parse_http_target(data, original_port)
        if http_target:
            return http_target
        sni = parse_tls_sni(data)
        if sni:
            return sni, original_port
        if b"\r\n\r\n" in data or len(data) >= 4096:
            break
        time.sleep(0.05)
    return original_host, original_port


def connect_http_proxy(proxy, target_host, target_port):
    upstream = socket.create_connection((proxy["host"], int(proxy["port"])), timeout=12)
    host_header = format_host_port(target_host, target_port)
    lines = [
        f"CONNECT {host_header} HTTP/1.1",
        f"Host: {host_header}",
        "Proxy-Connection: keep-alive",
    ]
    if proxy.get("login"):
        token = f"{proxy.get('login', '')}:{proxy.get('password', '')}".encode()
        lines.append("Proxy-Authorization: Basic " + base64.b64encode(token).decode("ascii"))
    payload = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    upstream.sendall(payload)
    response = b""
    upstream.settimeout(12)
    while b"\r\n\r\n" not in response and len(response) < 16384:
        chunk = upstream.recv(4096)
        if not chunk:
            break
        response += chunk
    status_line = response.split(b"\r\n", 1)[0]
    if b" 200 " not in status_line:
        raise RuntimeError(status_line.decode("iso-8859-1", "ignore") or "proxy connect failed")
    upstream.settimeout(None)
    return upstream


def relay_sockets(left, right):
    sockets = [left, right]
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 300)
            if errored:
                return
            if not readable:
                return
            for sock in readable:
                data = sock.recv(65536)
                if not data:
                    return
                (right if sock is left else left).sendall(data)
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass


def handle_domain_proxy_client(client, addr, proxy, listen_port=None):
    target_host = ""
    target_port = 0
    try:
        target_host, target_port = detect_domain_proxy_target(client, listen_port)
        if not target_host:
            return
        upstream = connect_http_proxy(proxy, target_host, target_port)
        relay_sockets(client, upstream)
    except Exception as exc:
        target = f" target={target_host}:{target_port}" if target_host else ""
        sys.stderr.write(f"domain-proxy client {addr}{target}: {exc}\n")
        try:
            client.close()
        except OSError:
            pass


def run_domain_proxy_worker(config_path):
    config = json.loads(Path(config_path).read_text())
    proxy = config["proxy"]
    listen_ip = config["listen_ip"]
    listen_port = int(config["listen_port"])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_ip, listen_port))
    server.listen(256)
    sys.stderr.write(f"domain-proxy listening on {listen_ip}:{listen_port}\n")
    while True:
        client, addr = server.accept()
        thread = threading.Thread(
            target=handle_domain_proxy_client,
            args=(client, addr, proxy, listen_port),
            daemon=True,
        )
        thread.start()


def start_domain_proxy_workers(proxies, local_ip):
    stop_domain_proxy_workers()
    for idx, proxy in enumerate(proxies):
        if not use_domain_proxy(proxy):
            continue
        port = proxy_port(idx)
        config = {
            "listen_ip": local_ip,
            "listen_port": port,
            "proxy": proxy,
        }
        conf_file = domain_proxy_conf_file(port)
        conf_file.write_text(json.dumps(config, indent=2, sort_keys=True))
        conf_file.chmod(0o600)
        log_file = domain_proxy_log_file(port)
        log = log_file.open("ab")
        try:
            proc = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--domain-proxy-worker", str(conf_file)],
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
        finally:
            log.close()
        domain_proxy_pid_file(port).write_text(str(proc.pid))
        for _ in range(10):
            time.sleep(0.1)
            if pid_alive(domain_proxy_pid_file(port)):
                break


def write_redsocks_conf(proxies, local_ip="127.0.0.1"):
    proxy_items = [(idx, proxy) for idx, proxy in enumerate(proxies) if not use_domain_proxy(proxy)]
    blocks = [
        "base {",
        "  log_debug = off;",
        "  log_info = on;",
        "  log = stderr;",
        "  daemon = on;",
        "  redirector = iptables;",
        "}",
        "",
    ]
    for idx, proxy in proxy_items:
        blocks.extend(
            [
                "redsocks {",
                f"  local_ip = {local_ip};",
                f"  local_port = {proxy_port(idx)};",
                f"  ip = {proxy['host']};",
                f"  port = {proxy['port']};",
                f"  type = {redsocks_type(proxy['type'])};",
            ]
        )
        if proxy.get("login"):
            blocks.append(f"  login = \"{conf_quote(proxy['login'])}\";")
        if proxy.get("password"):
            blocks.append(f"  password = \"{conf_quote(proxy['password'])}\";")
        blocks.extend(["}", ""])
    REDSOCKS_CONF.write_text("\n".join(blocks))


def start_redsocks(proxies, local_ip="127.0.0.1"):
    require_commands(["redsocks"])
    stop_pid(REDSOCKS_PID)
    stop_redsocks_processes()
    if not any(not use_domain_proxy(proxy) for proxy in proxies):
        REDSOCKS_CONF.write_text("")
        return
    write_redsocks_conf(proxies, local_ip)
    sudo(["systemctl", "stop", "redsocks"], check=False)
    sudo(["redsocks", "-t", "-c", str(REDSOCKS_CONF)])
    sudo(["redsocks", "-c", str(REDSOCKS_CONF), "-p", str(REDSOCKS_PID)])
    for _ in range(10):
        time.sleep(0.1)
        if pid_alive(REDSOCKS_PID):
            return
    raise RuntimeError("redsocks khong khoi dong duoc")


def dns_guard_reset(lan_if):
    for proto in ("udp", "tcp"):
        delete_existing_rule(
            [
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-i",
                lan_if,
                "-p",
                proto,
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-ports",
                "53",
            ]
        )


def filter_guard_reset(lan_if):
    delete_existing_rule(["iptables", "-D", "FORWARD", "-i", lan_if, "-j", GUARD_CHAIN])
    sudo(["iptables", "-F", GUARD_CHAIN], check=False)
    sudo(["iptables", "-X", GUARD_CHAIN], check=False)


def apply_dns_guard(lan_if):
    dns_guard_reset(lan_if)
    for proto in ("udp", "tcp"):
        sudo(
            [
                "iptables",
                "-t",
                "nat",
                "-I",
                "PREROUTING",
                "1",
                "-i",
                lan_if,
                "-p",
                proto,
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-ports",
                "53",
            ]
        )


def apply_filter_guard(lan_if):
    filter_guard_reset(lan_if)
    sudo(["iptables", "-N", GUARD_CHAIN], check=False)
    sudo(["iptables", "-F", GUARD_CHAIN])
    sudo(["iptables", "-A", GUARD_CHAIN, "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"])
    sudo(["iptables", "-A", GUARD_CHAIN, "-p", "udp", "--dport", "853", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"])
    for net in PRIVATE_NETS:
        sudo(["iptables", "-A", GUARD_CHAIN, "-d", net, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"])
    sudo(["iptables", "-A", GUARD_CHAIN, "-j", "RETURN"])
    sudo(["iptables", "-I", "FORWARD", "1", "-i", lan_if, "-j", GUARD_CHAIN])


def iptables_proxy_reset(lan_if):
    dns_guard_reset(lan_if)
    filter_guard_reset(lan_if)
    delete_existing_rule(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", lan_if, "-p", "tcp", "-j", PROXY_CHAIN])
    sudo(["iptables", "-t", "nat", "-F", PROXY_CHAIN], check=False)
    sudo(["iptables", "-t", "nat", "-X", PROXY_CHAIN], check=False)
    delete_existing_rule(["iptables", "-D", "FORWARD", "-i", lan_if, "-j", PROXY_V4_GUARD_CHAIN])
    sudo(["iptables", "-F", PROXY_V4_GUARD_CHAIN], check=False)
    sudo(["iptables", "-X", PROXY_V4_GUARD_CHAIN], check=False)
    delete_existing_rule(["ip6tables", "-D", "FORWARD", "-i", lan_if, "-j", "REJECT"])
    delete_existing_rule(["ip6tables", "-D", "FORWARD", "-i", lan_if, "-j", PROXY_V6_GUARD_CHAIN])
    sudo(["ip6tables", "-F", PROXY_V6_GUARD_CHAIN], check=False)
    sudo(["ip6tables", "-X", PROXY_V6_GUARD_CHAIN], check=False)
    state = load_state()
    for client_ip in list(state.get("assignments", {}).keys()) + list_client_ips(lan_if, state.get("lan_cidr", DEFAULT_LAN_CIDR)):
        delete_existing_rule(
            [
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-i",
                lan_if,
                "-s",
                client_ip,
                "-p",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                str(PROXY_LOCAL_BASE),
            ]
        )
        delete_existing_rule(
            [
                "iptables",
                "-D",
                "FORWARD",
                "-s",
                client_ip,
                "-p",
                "udp",
                "-j",
                "REJECT",
                "--reject-with",
                "icmp-port-unreachable",
            ]
        )
        for ports in UDP_GUARD_PORTS:
            delete_existing_rule(
                [
                    "iptables",
                    "-D",
                    "FORWARD",
                    "-s",
                    client_ip,
                    "-p",
                    "udp",
                    "-m",
                    "udp",
                    "--dport",
                    ports,
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "icmp-port-unreachable",
                ]
            )
        delete_existing_rule(
            [
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-i",
                lan_if,
                "-s",
                client_ip,
                "-d",
                "103.82.39.178",
                "-p",
                "tcp",
                "--dport",
                "53031",
                "-j",
                "RETURN",
            ]
        )


def flush_client_conntrack(client_ips):
    if not client_ips or shutil.which("conntrack") is None:
        return
    for client_ip in sorted(set(client_ips)):
        sudo(["conntrack", "-D", "-s", client_ip], check=False)
        sudo(["conntrack", "-D", "-d", client_ip], check=False)


def list_client_ips(lan_if, lan_cidr):
    lan_net = ipaddress.ip_interface(lan_cidr).network
    clients = set()
    if DNSMASQ_LEASES.exists():
        for line in DNSMASQ_LEASES.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[2]
                try:
                    if ipaddress.ip_address(ip) in lan_net:
                        clients.add(ip)
                except ValueError:
                    continue
    neigh = sh(["ip", "-j", "neigh"], check=False)
    try:
        rows = json.loads(neigh or "[]")
    except json.JSONDecodeError:
        rows = []
    for row in rows:
        ip = row.get("dst", "")
        if row.get("dev") != lan_if or not ip or ":" in ip:
            continue
        try:
            if ipaddress.ip_address(ip) in lan_net:
                clients.add(ip)
        except ValueError:
            continue
    return sorted(clients)


def client_mac_map(lan_if, lan_cidr, state=None):
    lan_net = ipaddress.ip_interface(lan_cidr).network
    mapping = {}

    def add(ip, mac):
        ip = str(ip or "").strip()
        mac = normalize_mac(mac)
        if not valid_mac(mac):
            return
        try:
            if ipaddress.ip_address(ip) not in lan_net:
                return
        except ValueError:
            return
        mapping[ip] = mac

    if DNSMASQ_LEASES.exists():
        for line in DNSMASQ_LEASES.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                add(parts[2], parts[1])

    neigh = sh(["ip", "-j", "neigh"], check=False)
    try:
        rows = json.loads(neigh or "[]")
    except json.JSONDecodeError:
        rows = []
    for row in rows:
        ip = row.get("dst", "")
        if row.get("dev") == lan_if and ip and ":" not in ip:
            add(ip, row.get("lladdr", ""))

    state = state or {}
    for mac, ip in state.get("dhcp_reservations", {}).items():
        if str(ip or "").strip() not in mapping:
            add(ip, mac)
    for entry in state.get("device_presence", {}).values():
        if isinstance(entry, dict):
            ip = str(entry.get("ip", "")).strip()
            if ip not in mapping:
                add(ip, entry.get("mac", ""))

    return {ip: mac for ip, mac in mapping.items() if valid_mac(mac)}


def ip_sort_key(value):
    return tuple(int(part) for part in value.split("."))


def eligible_proxy_indexes(proxies, family):
    family = balance_family(family)
    return [
        idx
        for idx, proxy in enumerate(proxies)
        if family == "all" or proxy_ip_version(proxy) == family
    ]


def balance_client_ips(lan_if, lan_cidr, state):
    lan_net = ipaddress.ip_interface(lan_cidr).network
    clients = set(list_client_ips(lan_if, lan_cidr))
    for ip in state.get("assignments", {}):
        try:
            if ipaddress.ip_address(ip) in lan_net:
                clients.add(ip)
        except ValueError:
            continue
    return sorted(clients, key=ip_sort_key)


def proxy_load_counts(assignments, indexes):
    counts = {idx: 0 for idx in indexes}
    for value in assignments.values():
        try:
            idx = int(value)
        except (TypeError, ValueError):
            continue
        if idx in counts:
            counts[idx] += 1
    return counts


def rebalance_devices(state, lan_if, family):
    family = balance_family(family)
    proxies = state.get("proxies", [])
    indexes = eligible_proxy_indexes(proxies, family)
    if not indexes:
        raise ValueError(f"Khong co proxy {balance_family_label(family)} de can bang")
    lan_cidr = state.get("lan_cidr", DEFAULT_LAN_CIDR)
    clients = balance_client_ips(lan_if, lan_cidr, state)
    assignments = state.setdefault("assignments", {})
    for pos, client_ip in enumerate(clients):
        assignments[client_ip] = indexes[pos % len(indexes)]
    return len(clients)


def auto_balance_devices(state, lan_if):
    config = load_balance_config(state)
    if not config["enabled"]:
        return 0
    proxies = state.get("proxies", [])
    indexes = eligible_proxy_indexes(proxies, config["family"])
    if not indexes:
        return 0
    lan_cidr = state.get("lan_cidr", DEFAULT_LAN_CIDR)
    clients = balance_client_ips(lan_if, lan_cidr, state)
    assignments = state.setdefault("assignments", {})
    counts = proxy_load_counts(assignments, indexes)
    changed = 0
    for client_ip in clients:
        try:
            current = int(assignments.get(client_ip))
        except (TypeError, ValueError):
            current = None
        if current in indexes:
            continue
        target = min(indexes, key=lambda idx: (counts[idx], idx))
        assignments[client_ip] = target
        counts[target] += 1
        changed += 1
    return changed


def apply_proxy_rules(lan_if):
    state = load_state()
    if auto_balance_devices(state, lan_if):
        save_state(state)
    proxies = state.get("proxies", [])
    assignments = state.get("assignments", {})
    lan_cidr = state.get("lan_cidr", DEFAULT_LAN_CIDR)
    client_ips = set(assignments.keys()) | set(list_client_ips(lan_if, lan_cidr))
    mac_by_ip = client_mac_map(lan_if, lan_cidr, state)
    lan_ip, _, _ = cidr_parts(lan_cidr)
    wan_ip = ""
    addr_rows = json.loads(sh(["ip", "-j", "addr"], check=False) or "[]")
    for row in addr_rows:
        if row.get("ifname") == Handler.wan_if:
            for info in row.get("addr_info", []):
                if info.get("family") == "inet":
                    wan_ip = info.get("local", "")
                    break
    iptables_proxy_reset(lan_if)
    apply_dns_guard(lan_if)
    apply_filter_guard(lan_if)
    if not proxies or not assignments:
        stop_pid(REDSOCKS_PID)
        stop_redsocks_processes()
        stop_domain_proxy_workers()
        flush_client_conntrack(client_ips)
        return
    start_redsocks(proxies, lan_ip)
    start_domain_proxy_workers(proxies, lan_ip)
    sudo(["iptables", "-t", "nat", "-N", PROXY_CHAIN], check=False)
    sudo(["iptables", "-t", "nat", "-F", PROXY_CHAIN])
    sudo(["iptables", "-N", PROXY_V4_GUARD_CHAIN], check=False)
    sudo(["iptables", "-F", PROXY_V4_GUARD_CHAIN])
    sudo(["ip6tables", "-N", PROXY_V6_GUARD_CHAIN], check=False)
    sudo(["ip6tables", "-F", PROXY_V6_GUARD_CHAIN], check=False)
    for net in PRIVATE_NETS:
        sudo(["iptables", "-t", "nat", "-A", PROXY_CHAIN, "-d", net, "-j", "RETURN"])
    for local_target in filter(None, [lan_ip, wan_ip]):
        sudo(["iptables", "-t", "nat", "-A", PROXY_CHAIN, "-d", local_target, "-j", "RETURN"])
    for client_ip, proxy_idx in assignments.items():
        if proxy_idx is None:
            continue
        try:
            idx = int(proxy_idx)
            ipaddress.ip_address(client_ip)
            if idx < 0 or idx >= len(proxies):
                continue
        except ValueError:
            continue
        proxy = proxies[idx]
        proxy_version = proxy_ip_version(proxy)
        # Let explicit connections to the upstream proxy pass, avoiding accidental loops.
        if not is_ipv6_literal(proxy["host"]):
            sudo(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    PROXY_CHAIN,
                    "-s",
                    client_ip,
                    "-p",
                    "tcp",
                    "-d",
                    proxy["host"],
                    "--dport",
                    str(proxy["port"]),
                    "-j",
                    "RETURN",
                ]
            )
        if proxy_version == "6":
            sudo(
                [
                    "iptables",
                    "-A",
                    PROXY_V4_GUARD_CHAIN,
                    "-s",
                    client_ip,
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "icmp-port-unreachable",
                ]
            )
        else:
            client_mac = mac_by_ip.get(client_ip, "")
            if client_mac:
                sudo(
                    [
                        "ip6tables",
                        "-A",
                        PROXY_V6_GUARD_CHAIN,
                        "-m",
                        "mac",
                        "--mac-source",
                        client_mac,
                        "-j",
                        "REJECT",
                    ],
                    check=False,
                )
        delete_existing_rule(
            [
                "iptables",
                "-D",
                "FORWARD",
                "-s",
                client_ip,
                "-p",
                "udp",
                "-j",
                "REJECT",
                "--reject-with",
                "icmp-port-unreachable",
            ]
        )
        for ports in UDP_GUARD_PORTS:
            sudo(
                [
                    "iptables",
                    "-I",
                    "FORWARD",
                    "1",
                    "-s",
                    client_ip,
                    "-p",
                    "udp",
                    "-m",
                    "udp",
                    "--dport",
                    ports,
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "icmp-port-unreachable",
                ]
            )
        sudo(
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                PROXY_CHAIN,
                "-s",
                client_ip,
                "-p",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                str(proxy_port(idx)),
            ]
        )
    sudo(["iptables", "-t", "nat", "-A", PROXY_CHAIN, "-j", "RETURN"])
    sudo(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", lan_if, "-p", "tcp", "-j", PROXY_CHAIN])
    sudo(["iptables", "-A", PROXY_V4_GUARD_CHAIN, "-j", "RETURN"])
    sudo(["iptables", "-I", "FORWARD", "1", "-i", lan_if, "-j", PROXY_V4_GUARD_CHAIN])
    sudo(["ip6tables", "-A", PROXY_V6_GUARD_CHAIN, "-j", "RETURN"], check=False)
    sudo(["ip6tables", "-I", "FORWARD", "1", "-i", lan_if, "-j", PROXY_V6_GUARD_CHAIN], check=False)
    flush_client_conntrack(client_ips)


def remove_proxy(index, lan_if):
    state = load_state()
    proxies = state.get("proxies", [])
    if index < 0 or index >= len(proxies):
        return
    proxies.pop(index)
    new_assignments = {}
    for ip, idx in state.get("assignments", {}).items():
        idx = int(idx)
        if idx == index:
            continue
        new_assignments[ip] = idx - 1 if idx > index else idx
    state["proxies"] = proxies
    state["assignments"] = new_assignments
    save_state(state)
    apply_proxy_rules(lan_if)


def command_status(wan_if, lan_if):
    state = load_state()
    lan_cidr = state.get("lan_cidr", DEFAULT_LAN_CIDR)
    base_lan_if = lan_if
    hotspot = normalized_hotspot(state)
    lan_if = active_lan_if(base_lan_if, state)
    lan_ip, _, lan_network = cidr_parts(lan_cidr)
    wifi_stations = wifi_station_details(hotspot.get("ifname", ""))
    fdb_ports = bridge_fdb_ports(lan_if if lan_if == DEFAULT_BRIDGE_IF else "")
    leases = list_leases(lan_if, lan_cidr, base_lan_if, hotspot.get("ifname", ""))
    changed = update_device_presence(state, leases, wifi_stations, fdb_ports)
    hidden = state.setdefault("hidden_offline_devices", {})
    for row in leases:
        key = device_presence_key(row)
        if key and row.get("online") and key in hidden:
            hidden.pop(key, None)
            changed = True
    visible_leases = [
        row
        for row in leases
        if not (device_presence_key(row) in hidden and not row.get("online"))
    ]
    if changed:
        save_state(state)
    return {
        "wan_if": wan_if,
        "base_lan_if": base_lan_if,
        "lan_if": lan_if,
        "wan_mac": current_mac(wan_if),
        "lan_mac": current_mac(lan_if),
        "lan_ip": lan_ip,
        "lan_network": lan_network,
        "dhcp_range": dhcp_range_for(lan_cidr),
        "interfaces": sh(["ip", "-br", "addr"], check=False),
        "routes": sh(["ip", "route"], check=False),
        "ip_forward": Path("/proc/sys/net/ipv4/ip_forward").read_text().strip(),
        "dnsmasq": pid_alive(DNSMASQ_PID),
        "hostapd": pid_alive(HOSTAPD_PID),
        "redsocks": pid_alive(REDSOCKS_PID),
        "leases": visible_leases,
        "network_cards": network_cards(wan_if, base_lan_if, lan_if, hotspot),
        "wifi_stations": list(wifi_stations.values()),
        "wifi_interfaces": wireless_interfaces(),
        "state": public_state(state),
    }


def render_page(data, message="", proxy_check=None, device_filter="online", device_sort="ip", sort_dir="asc"):
    state = data["state"]
    proxies = state.get("proxies", [])
    assignments = state.get("assignments", {})
    device_names = state.get("device_names", {})
    device_groups = normalize_device_groups(state.get("device_groups", []))
    dhcp_reservations = state.get("dhcp_reservations", {})
    lan_cidr = state.get("lan_cidr", DEFAULT_LAN_CIDR)
    device_presence = state.get("device_presence", {})
    hotspot = normalized_hotspot(state)
    load_balance = load_balance_config(state)
    wifi_names = list(data.get("wifi_interfaces", []))
    if hotspot["ifname"] and hotspot["ifname"] not in wifi_names:
        wifi_names.insert(0, hotspot["ifname"])
    selected_wifi = hotspot["ifname"] or (wifi_names[0] if wifi_names else "")
    wifi_options = "".join(f'<option value="{html.escape(name)}">' for name in wifi_names)
    hotspot_running = bool(data.get("hostapd"))
    hotspot_label = "Running" if hotspot_running else ("Configured" if hotspot["enabled"] else "Off")
    hotspot_password_placeholder = "configured" if hotspot.get("password") else "8-63 chars"
    band_options = []
    for value, label in (("2.4", "2.4 GHz"), ("5", "5 GHz fast")):
        selected = " selected" if hotspot["band"] == value else ""
        band_options.append(f'<option value="{value}"{selected}>{label}</option>')
    leases = {lease["ip"]: lease for lease in data["leases"]}
    for assigned_ip in assignments:
        leases.setdefault(
            assigned_ip,
            {
                "ip": assigned_ip,
                "mac": "",
                "hostname": "",
                "expires": "",
                "source": "manual",
                "connection": "Unknown",
                "interface": data["lan_if"],
                "detail": "",
                "online": False,
                "presence_reason": "manual",
                "last_seen_text": "",
                "disconnected_text": format_timestamp(device_presence.get(assigned_ip, {}).get("disconnected_at")),
            },
        )
    leases = [leases[ip] for ip in sorted(leases, key=lambda value: tuple(int(p) for p in value.split(".")))]
    online_count = sum(1 for lease in leases if lease.get("online"))
    offline_count = len(leases) - online_count
    interface_counts = {}
    for lease in leases:
        ifname = str(lease.get("interface", "")).strip()
        if ifname:
            interface_counts[ifname] = interface_counts.get(ifname, 0) + 1
    card_order = {card.get("name", ""): idx for idx, card in enumerate(data.get("network_cards", []))}
    device_interface_tabs = sorted(
        interface_counts,
        key=lambda name: (card_order.get(name, len(card_order)), name),
    )
    valid_device_filters = {"all", "online", "offline"} | {f"if:{name}" for name in device_interface_tabs}
    device_filter = device_filter if device_filter in valid_device_filters else "online"
    sort_columns = {
        "ip": "IP",
        "name": "Name",
        "mac": "MAC",
        "hostname": "Hostname",
        "connection": "Connection",
        "status": "Status",
        "proxy": "Proxy",
    }
    device_sort = device_sort if device_sort in sort_columns else "ip"
    sort_dir = sort_dir if sort_dir in {"asc", "desc"} else "asc"

    def ip_sort_value(value):
        try:
            addr = ipaddress.ip_address(value)
            return (addr.version, int(addr))
        except ValueError:
            return (99, str(value))

    def assigned_proxy_label(lease):
        current = assignments.get(lease.get("ip", ""), "")
        if current == "":
            return "direct/nat"
        try:
            idx = int(current)
        except (TypeError, ValueError):
            return str(current).lower()
        if 0 <= idx < len(proxies):
            return proxy_key(proxies[idx]).lower()
        return str(current).lower()

    def device_name(lease):
        mac = normalize_mac(lease.get("mac", ""))
        return str(device_names.get(mac, "")).strip()

    def device_sort_value(lease):
        if device_sort == "ip":
            return ip_sort_value(lease.get("ip", ""))
        if device_sort == "name":
            return device_name(lease).lower()
        if device_sort == "mac":
            return lease.get("mac", "").lower()
        if device_sort == "hostname":
            return lease.get("hostname", "").lower()
        if device_sort == "connection":
            return (
                lease.get("connection", "").lower(),
                lease.get("interface", "").lower(),
                lease.get("detail", "").lower(),
            )
        if device_sort == "status":
            return (
                0 if lease.get("online") else 1,
                lease.get("last_seen_text", "") if lease.get("online") else lease.get("disconnected_text", ""),
            )
        if device_sort == "proxy":
            return assigned_proxy_label(lease)
        return ip_sort_value(lease.get("ip", ""))

    if device_filter == "all":
        filtered_leases = list(leases)
    elif device_filter in {"online", "offline"}:
        filtered_leases = [
            lease
            for lease in leases
            if bool(lease.get("online")) == (device_filter == "online")
        ]
    elif device_filter.startswith("if:"):
        filter_ifname = device_filter[3:]
        filtered_leases = [lease for lease in leases if str(lease.get("interface", "")).strip() == filter_ifname]
    else:
        filtered_leases = []
    filtered_leases = sorted(
        filtered_leases,
        key=lambda lease: (device_sort_value(lease), ip_sort_value(lease.get("ip", ""))),
        reverse=sort_dir == "desc",
    )
    if device_filter == "all":
        device_empty_text = "Chua co thiet bi."
    elif device_filter == "online":
        device_empty_text = "Chua co thiet bi online."
    elif device_filter == "offline":
        device_empty_text = "Chua co thiet bi offline."
    elif device_filter.startswith("if:"):
        device_empty_text = f"Chua co thiet bi tren {device_filter[3:]}."
    else:
        device_empty_text = "Chua co thiet bi."
    tab_sort_query = f"&sort={quote(device_sort)}&dir={quote(sort_dir)}"

    def device_tab(key, label, count):
        active_class = "active" if device_filter == key else ""
        return (
            f'<a data-device-nav="1" class="{active_class}" href="/?devices={quote(key)}{tab_sort_query}">'
            f'{html.escape(label)} <span>{count}</span></a>'
        )

    device_tab_items = [
        device_tab("all", "All", len(leases)),
        device_tab("online", "Online", online_count),
        device_tab("offline", "Offline", offline_count),
    ]
    for ifname in device_interface_tabs:
        device_tab_items.append(device_tab(f"if:{ifname}", ifname, interface_counts[ifname]))
    device_tabs = f"""
        <div class="device-tabs">
          {''.join(device_tab_items)}
        </div>
    """
    device_headers = [
        '<th class="select-col"><input type="checkbox" data-device-checkall aria-label="Select all devices"></th>'
    ]
    for key, label in sort_columns.items():
        next_dir = "desc" if device_sort == key and sort_dir == "asc" else "asc"
        marker = "^" if device_sort == key and sort_dir == "asc" else ("v" if device_sort == key else "")
        active_class = " active" if device_sort == key else ""
        device_headers.append(
            f'<th><a data-device-nav="1" class="sort-link{active_class}" href="/?devices={quote(device_filter)}&sort={quote(key)}&dir={quote(next_dir)}">'
            f'{html.escape(label)}<span>{marker}</span></a></th>'
        )
    device_headers.append("<th>Action</th>")
    card_rows = []
    for card in data.get("network_cards", []):
        addresses = ", ".join(card.get("addresses", [])) or "-"
        master = f"master: {card.get('master')}" if card.get("master") else ""
        card_rows.append(
            f"""
            <tr>
              <td><strong>{html.escape(card['name'])}</strong><span>{html.escape(card.get('kind', ''))}</span></td>
              <td>{html.escape(card.get('role', '-'))}</td>
              <td>{html.escape(card.get('state', ''))}</td>
              <td>{html.escape(card.get('mac', ''))}</td>
              <td>{html.escape(addresses)}<span>{html.escape(master)}</span></td>
            </tr>
            """
        )
    proxy_options = ["<option value=''>Direct/NAT</option>"]
    for idx, proxy in enumerate(proxies):
        proxy_options.append(
            f"<option value='{idx}'>{html.escape(proxy_key(proxy))} -> localhost:{proxy_port(idx)}</option>"
        )
    def render_device_row(lease, group_id="", collapsed=False):
        ip = lease["ip"]
        current = assignments.get(ip, "")
        options = []
        for opt in proxy_options:
            if current != "" and f"value='{current}'" in opt:
                options.append(opt.replace("<option", "<option selected", 1))
            elif current == "" and "value=''" in opt:
                options.append(opt.replace("<option", "<option selected", 1))
            else:
                options.append(opt)
        connection_detail = " ".join(filter(None, [lease.get("interface", ""), lease.get("detail", "")]))
        mac = normalize_mac(lease.get("mac", ""))
        name_value = device_name(lease)
        dhcp_ip = dhcp_reservations.get(mac, "")
        binding_ip = dhcp_ip or ip
        name_display = name_value or "-"
        online = bool(lease.get("online"))
        status_class = "status-online" if online else "status-offline"
        status_label = "Online" if online else "Offline"
        status_time = lease.get("last_seen_text", "") if online else lease.get("disconnected_text", "")
        status_time_label = "Last seen" if online else "Disconnected"
        status_detail = " ".join(filter(None, [status_time_label if status_time else "", status_time]))
        status_reason = lease.get("presence_reason", "")
        row_attrs = ' class="device-row"'
        if group_id:
            row_attrs += f' data-group-member="{html.escape(group_id)}"'
        if collapsed:
            row_attrs += " hidden"
        return (
            f"""
			            <tr{row_attrs}>
			              <td class="select-col">
			                <input
		                  type="checkbox"
		                  data-device-select
		                  data-ip="{html.escape(ip)}"
		                  data-mac="{html.escape(mac)}"
		                  aria-label="Select {html.escape(ip)}"
		                >
		              </td>
		              <td><strong>{html.escape(ip)}</strong><span>{html.escape(lease.get('source',''))}</span></td>
		              <td><strong>{html.escape(name_display)}</strong>{f'<span>DHCP {html.escape(dhcp_ip)}</span>' if dhcp_ip else ''}</td>
		              <td>{html.escape(lease.get('mac',''))}</td>
              <td>{html.escape(lease.get('hostname',''))}</td>
              <td><strong>{html.escape(lease.get('connection','Unknown'))}</strong><span>{html.escape(connection_detail)}</span></td>
              <td>
                <span class="status-badge {status_class}"><span class="status-dot"></span>{html.escape(status_label)}</span>
                <span>{html.escape(status_detail or status_reason)}</span>
              </td>
	              <td>
	                <form method="post" action="/assign">
	                  <input type="hidden" name="ip" value="{html.escape(ip)}">
	                  <select name="proxy">{''.join(options)}</select>
	                  <button>Save</button>
	                </form>
	              </td>
	              <td>
	                <button
	                  type="button"
	                  class="neutral"
	                  data-device-edit
	                  data-mac="{html.escape(mac)}"
	                  data-name="{html.escape(name_value)}"
	                  data-dhcp="{html.escape(dhcp_ip)}"
	                  data-binding-ip="{html.escape(binding_ip)}"
	                  data-ip="{html.escape(ip)}"
	                  {'disabled' if not mac else ''}
	                >Edit</button>
	              </td>
		            </tr>
	            """
        )

    row_by_ip = {lease["ip"]: render_device_row(lease) for lease in filtered_leases}
    lease_by_ip = {lease["ip"]: lease for lease in filtered_leases}
    device_rows = []
    grouped_visible_ips = set()
    for group in device_groups:
        group_id = group["id"]
        group_ips = [ip for ip in group.get("ips", []) if ip in row_by_ip]
        if not group_ips:
            continue
        grouped_visible_ips.update(group_ips)
        online_in_group = sum(1 for ip in group_ips if lease_by_ip[ip].get("online"))
        collapsed = bool(group.get("collapsed"))
        expanded = "false" if collapsed else "true"
        toggle_label = "Mo" if collapsed else "Thu gon"
        device_word = "device" if len(group_ips) == 1 else "devices"
        device_rows.append(
            f"""
            <tr class="device-group-row" data-device-group="{html.escape(group_id)}" data-collapsed="{'1' if collapsed else '0'}">
              <td colspan="9">
                <div class="device-group-head">
                  <button type="button" class="group-toggle" data-group-toggle data-group-id="{html.escape(group_id)}" aria-expanded="{expanded}">{html.escape(toggle_label)}</button>
                  <div class="device-group-title">
                    <strong>{html.escape(group.get('name', 'Group'))}</strong>
                    <span>{len(group_ips)} {device_word} | {online_in_group} online</span>
                  </div>
                  <form method="post" action="/device-group/delete">
                    <input type="hidden" name="id" value="{html.escape(group_id)}">
                    <button type="submit" class="neutral group-delete">Bo group</button>
                  </form>
                </div>
              </td>
            </tr>
            """
        )
        for ip in group_ips:
            device_rows.append(render_device_row(lease_by_ip[ip], group_id, collapsed))
    for lease in filtered_leases:
        if lease["ip"] not in grouped_visible_ips:
            device_rows.append(row_by_ip[lease["ip"]])
    proxy_rows = []
    load_counts = proxy_load_counts(assignments, range(len(proxies)))
    for idx, proxy in enumerate(proxies):
        check_label = ""
        if proxy_check and proxy_check.get("index") == idx:
            status = "Live" if proxy_check.get("ok") else "Die"
            detail = proxy_check.get("detail", "")
            cls = "ok" if proxy_check.get("ok") else "bad"
            check_label = f'<span class="{cls}">{html.escape(status)}: {html.escape(detail)}</span>'
        proxy_rows.append(
            f"""
            <tr>
              <td>
                <strong>{html.escape(proxy['type'].upper())}</strong>
                <span>{html.escape(format_host_port(proxy['host'], proxy['port']))}</span>
              </td>
              <td>{proxy_ip_label(proxy)}</td>
              <td>{html.escape(proxy_auth_label(proxy))}</td>
              <td>{proxy_port(idx)}</td>
              <td>{load_counts.get(idx, 0)}</td>
              <td>
                {check_label}
                <form method="post" action="/proxy/check">
                  <input type="hidden" name="index" value="{idx}">
                  <button class="neutral">Check</button>
                </form>
                <form method="post" action="/proxy/delete">
                  <input type="hidden" name="index" value="{idx}">
                  <button class="danger">Delete</button>
                </form>
              </td>
            </tr>
            """
        )
    assign_options = ["<option value=''>Direct/NAT</option>"]
    for idx, proxy in enumerate(proxies):
        assign_options.append(f"<option value='{idx}'>{html.escape(proxy_key(proxy))}</option>")
    family_options = []
    for value in BALANCE_FAMILIES:
        selected = " selected" if load_balance["family"] == value else ""
        family_options.append(f"<option value='{value}'{selected}>{balance_family_label(value)}</option>")
    load_rows = []
    for idx, proxy in enumerate(proxies):
        load_rows.append(
            f"""
            <tr>
              <td>{idx}</td>
              <td>{html.escape(proxy_key(proxy))}</td>
              <td>{proxy_ip_label(proxy)}</td>
              <td>{load_counts.get(idx, 0)}</td>
            </tr>
            """
        )
    return f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ubuntu Router Manager</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --ink: #1f2937;
      --muted: #687385;
      --line: #d8dde6;
      --accent: #0f766e;
      --accent-2: #2563eb;
      --danger: #b91c1c;
      --soft: #eef2f7;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, sans-serif;
      background: var(--bg);
      color: var(--ink);
    }}
    header {{
      padding: 20px 28px 12px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-start;
    }}
    h1 {{ margin: 0 0 6px; font-size: 24px; letter-spacing: 0; }}
    a {{ color: var(--accent-2); text-decoration: none; font-weight: 700; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 22px; display: grid; gap: 18px; }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }}
    h2 {{ font-size: 17px; margin: 0 0 14px; }}
      .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }}
    .metric {{ border: 1px solid var(--line); border-radius: 8px; padding: 12px; min-height: 74px; }}
    .metric b {{ display: block; font-size: 13px; color: var(--muted); margin-bottom: 4px; }}
    .ok {{ color: var(--accent); font-weight: 700; }}
	    .bad {{ color: var(--danger); font-weight: 700; }}
	    .actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
	    table {{ width: 100%; border-collapse: collapse; }}
	    th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: middle; }}
	    th {{ color: var(--muted); font-size: 13px; font-weight: 700; }}
	    td span {{ display: block; color: var(--muted); font-size: 12px; margin-top: 2px; }}
	    .select-col {{ width: 34px; min-width: 34px; text-align: center; }}
	    .select-col input {{ width: 18px; height: 18px; min-height: 18px; padding: 0; accent-color: var(--accent-2); cursor: pointer; }}
	    .status-badge {{
      display: inline-flex;
      align-items: center;
      gap: 7px;
      min-height: 26px;
      padding: 4px 9px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 800;
      margin-top: 0;
    }}
    .status-dot {{
      width: 9px;
      height: 9px;
      border-radius: 999px;
      margin-top: 0;
      background: currentColor;
    }}
	    .status-online {{ color: #047857; background: #d1fae5; }}
	    .status-offline {{ color: #b91c1c; background: #fee2e2; }}
	    .device-tabs {{
	      display: inline-flex;
	      align-items: center;
	      flex-wrap: wrap;
	      gap: 4px;
	      padding: 4px;
	      margin-bottom: 12px;
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      background: var(--soft);
	    }}
	    .device-tabs a {{
	      display: inline-flex;
	      align-items: center;
	      gap: 7px;
	      min-height: 34px;
	      padding: 7px 12px;
	      border-radius: 6px;
	      color: var(--muted);
	      font-size: 13px;
	      font-weight: 800;
	    }}
	    .device-tabs a.active {{
	      color: white;
	      background: var(--accent);
	    }}
		    .device-tabs span {{
		      margin: 0;
		      color: inherit;
		      font-size: 12px;
		      font-weight: 800;
		    }}
		    .device-toolbar {{
		      display: flex;
		      align-items: center;
		      justify-content: space-between;
		      gap: 12px;
		      flex-wrap: wrap;
		      margin-bottom: 12px;
		    }}
		    .device-toolbar .device-tabs {{
		      margin-bottom: 0;
		    }}
			    .bulk-copy {{
			      position: relative;
			      display: inline-flex;
			      align-items: center;
			      gap: 8px;
			      flex-wrap: wrap;
			    }}
			    .bulk-copy[hidden] {{
			      display: none;
			    }}
			    .group-action {{
			      background: var(--accent);
			    }}
			    .device-group-row td {{
			      padding: 10px 8px;
			      background: #f8fafc;
			    }}
			    .device-group-head {{
			      display: flex;
			      align-items: center;
			      justify-content: space-between;
			      gap: 12px;
			      min-height: 46px;
			      padding: 6px 8px;
			      border: 1px solid var(--line);
			      border-radius: 8px;
			      background: linear-gradient(180deg, #ffffff 0%, #f4f7fb 100%);
			    }}
			    .device-group-title {{
			      flex: 1;
			      min-width: 160px;
			    }}
			    .device-group-title strong {{
			      display: block;
			      font-size: 15px;
			    }}
			    .device-group-title span {{
			      margin-top: 3px;
			    }}
			    .group-toggle {{
			      min-width: 78px;
			      background: #0f766e;
			    }}
			    .group-delete {{
			      min-width: 82px;
			    }}
			    .group-modal-count {{
			      color: var(--muted);
			      font-size: 12px;
			      font-weight: 800;
			    }}
			    .bulk-copy-menu {{
		      position: absolute;
		      top: calc(100% + 6px);
		      right: 0;
		      z-index: 10;
		      min-width: 138px;
		      display: grid;
		      gap: 4px;
		      padding: 6px;
		      border: 1px solid var(--line);
		      border-radius: 8px;
		      background: var(--panel);
		      box-shadow: 0 12px 32px rgba(15, 23, 42, 0.16);
		    }}
		    .bulk-copy-menu[hidden] {{
		      display: none;
		    }}
		    .bulk-copy-menu button {{
		      justify-content: flex-start;
		      min-height: 34px;
		      width: 100%;
		      border-radius: 6px;
		      background: transparent;
		      color: var(--ink);
		      text-align: left;
		    }}
		    .bulk-copy-menu button:hover {{
		      background: var(--soft);
		    }}
		    .sort-link {{
	      display: inline-flex;
	      align-items: center;
	      gap: 6px;
	      color: var(--muted);
	      font-weight: 800;
	    }}
	    .sort-link.active {{
	      color: var(--ink);
	    }}
	    .sort-link span {{
	      min-width: 10px;
	      margin: 0;
	      color: inherit;
	      font-size: 11px;
	      line-height: 1;
	    }}
	    .socket-status {{
	      align-self: center;
	      min-height: 26px;
	      padding: 5px 9px;
	      border-radius: 999px;
	      background: #fee2e2;
	      color: #991b1b;
	      font-size: 12px;
	      font-weight: 800;
	    }}
	    .socket-status.live {{
	      background: #d1fae5;
	      color: #047857;
	    }}
	    form {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 0; }}
	    .modal {{
	      position: fixed;
	      inset: 0;
	      z-index: 20;
	      display: grid;
	      place-items: center;
	      padding: 18px;
	      background: rgba(15, 23, 42, 0.38);
	    }}
	    .modal[hidden] {{ display: none; }}
	    .modal-panel {{
	      width: min(100%, 460px);
	      background: var(--panel);
	      border: 1px solid var(--line);
	      border-radius: 8px;
	      padding: 18px;
	      box-shadow: 0 22px 48px rgba(15, 23, 42, 0.22);
	    }}
	    .modal-panel h3 {{ margin: 0 0 14px; font-size: 17px; }}
	    .modal-panel form {{ display: grid; gap: 12px; }}
	    .modal-panel label {{ display: grid; gap: 6px; color: var(--muted); font-size: 12px; font-weight: 800; }}
	    .modal-panel input {{ width: 100%; min-width: 0; }}
	    .modal-actions {{ display: flex; gap: 8px; justify-content: flex-end; }}
    input, select {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 10px;
      min-height: 38px;
      background: white;
      color: var(--ink);
    }}
    input[type=text] {{ min-width: min(100%, 320px); }}
    input[type=number] {{ width: 120px; }}
    .proxy-form {{
      display: grid;
      grid-template-columns: minmax(110px, 130px) minmax(100px, 120px) minmax(180px, 1fr) minmax(90px, 120px) minmax(150px, 1fr) minmax(150px, 1fr) auto;
      gap: 8px;
      align-items: end;
    }}
    .proxy-form label {{ display: grid; gap: 5px; color: var(--muted); font-size: 12px; font-weight: 700; }}
    .proxy-form input, .proxy-form select {{ width: 100%; min-width: 0; }}
    .hotspot-form {{
      display: grid;
      grid-template-columns: minmax(130px, 170px) minmax(110px, 130px) minmax(180px, 1fr) minmax(170px, 1fr) minmax(80px, 100px) minmax(90px, 120px) auto;
      gap: 8px;
      align-items: end;
    }}
    .hotspot-form label {{ display: grid; gap: 5px; color: var(--muted); font-size: 12px; font-weight: 700; }}
    .hotspot-form input, .hotspot-form select {{ width: 100%; min-width: 0; }}
    .url-form {{ margin-top: 10px; padding-top: 12px; border-top: 1px solid var(--line); }}
    button {{
      border: 0;
      border-radius: 6px;
      min-height: 38px;
      padding: 9px 13px;
      background: var(--accent-2);
      color: white;
      font-weight: 700;
      cursor: pointer;
    }}
	    button.primary {{ background: var(--accent); }}
	    button.danger {{ background: var(--danger); }}
	    button.neutral {{ background: #4b5563; }}
	    input:disabled, select:disabled {{
	      color: var(--muted);
	      background: #f8fafc;
	      cursor: not-allowed;
	    }}
	    button:disabled {{
	      opacity: 0.45;
	      cursor: not-allowed;
	    }}
    pre {{
      overflow: auto;
      padding: 12px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: #101827;
      color: #dbeafe;
      max-height: 240px;
    }}
    .msg {{ padding: 10px 12px; border-radius: 8px; background: #e0f2fe; border: 1px solid #bae6fd; }}
	    @media (max-width: 720px) {{
	      header {{ padding: 18px; }}
	      header {{ display: block; }}
	      main {{ padding: 14px; }}
	      table, thead, tbody, th, td, tr {{ display: block; }}
	      thead {{ display: none; }}
	      tr {{ border-bottom: 1px solid var(--line); padding: 8px 0; }}
	      td {{ border-bottom: 0; padding: 6px 0; }}
	      td.select-col {{ width: auto; min-width: 0; text-align: left; padding-bottom: 2px; }}
	      td.select-col input {{ width: 18px; }}
	      form {{ align-items: stretch; }}
	      select, button, input {{ width: 100%; }}
	      .proxy-form {{ grid-template-columns: 1fr; }}
      .hotspot-form {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Ubuntu Router Manager</h1>
      <div>WAN: <strong>{html.escape(data['wan_if'])}</strong> | LAN out: <strong>{html.escape(data['lan_if'])}</strong> | Gateway: <strong>{html.escape(data['lan_ip'])}</strong></div>
	    </div>
	    <div class="actions">
	      <button type="button" class="neutral" data-refresh-status>Refresh</button>
	      <span class="socket-status" data-socket-status>Offline</span>
	      <a href="/api/status">JSON</a>
	      <a href="/logout">Logout</a>
	    </div>
  </header>
  <main>
    {f'<div class="msg">{html.escape(message)}</div>' if message else ''}
    <section>
      <h2>Router</h2>
      <div class="grid">
        <div class="metric"><b>DHCP/NAT</b><span class="{ 'ok' if data['dnsmasq'] else 'bad' }">{'Running' if data['dnsmasq'] else 'Stopped'}</span></div>
        <div class="metric"><b>WiFi Hotspot</b><span class="{ 'ok' if hotspot_running else 'bad' }">{html.escape(hotspot_label)}</span></div>
        <div class="metric"><b>IP Forward</b><span class="{ 'ok' if data['ip_forward'] == '1' else 'bad' }">{html.escape(data['ip_forward'])}</span></div>
        <div class="metric"><b>Proxy Engine</b><span class="{ 'ok' if data['redsocks'] else 'bad' }">{'Running' if data['redsocks'] else 'Stopped'}</span></div>
        <div class="metric"><b>LAN CIDR</b><span>{html.escape(lan_cidr)}</span></div>
        <div class="metric"><b>DHCP Range</b><span>{html.escape(data['dhcp_range'][0])} - {html.escape(data['dhcp_range'][1])}</span></div>
        <div class="metric"><b>WAN MAC</b><span>{html.escape(data['wan_mac'])}</span></div>
        <div class="metric"><b>LAN MAC</b><span>{html.escape(data['lan_mac'])}</span></div>
	        <div class="metric"><b>DNS/WebRTC Guard</b><span class="ok">Enabled</span></div>
        <div class="metric"><b>LAN Isolation</b><span class="ok">Enabled</span></div>
      </div>
	      <div class="actions" style="margin-top:14px">
	        <form method="post" action="/setup"><button class="primary">Apply LAN Router Config</button></form>
	        <form method="post" action="/lan/save">
	          <input type="text" name="lan_cidr" value="{html.escape(lan_cidr)}" placeholder="10.42.7.1/24 or 10.42.0.1/16">
	          <button class="neutral">Save LAN CIDR</button>
	        </form>
	        <form method="post" action="/mac/rotate">
          <input type="hidden" name="target" value="wan">
          <button class="neutral">Rotate WAN MAC</button>
        </form>
        <form method="post" action="/mac/rotate">
          <input type="hidden" name="target" value="lan">
          <button class="neutral">Rotate LAN MAC</button>
        </form>
        <form method="post" action="/stop"><button class="danger">Stop Test Router</button></form>
      </div>
    </section>
    <section>
      <h2>WiFi Hotspot</h2>
      <div class="grid">
        <div class="metric"><b>Interface</b><span>{html.escape(hotspot['ifname'] or selected_wifi or 'none')}</span></div>
        <div class="metric"><b>SSID</b><span>{html.escape(hotspot['ssid'])}</span></div>
        <div class="metric"><b>Band</b><span>{html.escape(wifi_band_label(hotspot['band']))}</span></div>
        <div class="metric"><b>Channel</b><span>{html.escape(str(hotspot['channel']))}</span></div>
        <div class="metric"><b>Country</b><span>{html.escape(hotspot['country'])}</span></div>
        <div class="metric"><b>LAN Output</b><span>{html.escape(data['lan_if'])}</span></div>
      </div>
      <form method="post" action="/hotspot/save" style="margin-top:14px">
        <div class="hotspot-form">
          <label>WiFi Card
            <input type="text" name="ifname" list="wifi-ifaces" value="{html.escape(selected_wifi)}" placeholder="wlan0">
            <datalist id="wifi-ifaces">{wifi_options}</datalist>
          </label>
          <label>Band
            <select name="band">{''.join(band_options)}</select>
          </label>
          <label>Ten WiFi
            <input type="text" name="ssid" maxlength="32" value="{html.escape(hotspot['ssid'])}" placeholder="RouterWiFi">
          </label>
          <label>Password
            <input type="password" name="password" autocomplete="new-password" placeholder="{html.escape(hotspot_password_placeholder)}">
          </label>
          <label>Country
            <input type="text" name="country" maxlength="2" value="{html.escape(hotspot['country'])}">
          </label>
          <label>Channel
            <input type="number" name="channel" min="1" max="161" value="{html.escape(str(hotspot['channel']))}">
          </label>
          <button class="primary">Start Hotspot</button>
        </div>
      </form>
      <div class="actions" style="margin-top:12px">
        <form method="post" action="/hotspot/stop"><button class="danger">Stop Hotspot</button></form>
      </div>
    </section>
    <section>
      <h2>Network Cards</h2>
      <table>
        <thead><tr><th>Interface</th><th>Role</th><th>State</th><th>MAC</th><th>Addresses</th></tr></thead>
        <tbody>{''.join(card_rows) if card_rows else '<tr><td colspan="5">Khong doc duoc card mang.</td></tr>'}</tbody>
      </table>
    </section>
		    <section>
		      <h2>Devices</h2>
			      <div class="device-toolbar">
			        {device_tabs}
			        <div class="bulk-copy" data-bulk-copy hidden>
			          <button type="button" class="group-action" data-group-create-open>Tao group</button>
			          <button type="button" class="neutral" data-copy-toggle>Copy</button>
			          <div class="bulk-copy-menu" data-copy-menu hidden>
		            <button type="button" data-copy-selected="dhcp">Copy DHCP</button>
		            <button type="button" data-copy-selected="mac">Copy MAC</button>
		          </div>
		        </div>
		      </div>
		      <table>
		        <thead><tr>{''.join(device_headers)}</tr></thead>
		        <tbody>{''.join(device_rows) if device_rows else f'<tr><td colspan="9">{device_empty_text}</td></tr>'}</tbody>
		      </table>
		      <form method="post" action="/assign" style="margin-top:14px">
		        <input type="text" name="ip" placeholder="Gan thu cong IP, vi du 10.42.0.50">
		        <select name="proxy">{''.join(assign_options)}</select>
		        <button>Assign IP</button>
		      </form>
		    </section>
    <section>
      <h2>Load Balance</h2>
      <div class="grid">
        <div class="metric"><b>Auto Balance</b><span class="{ 'ok' if load_balance['enabled'] else 'bad' }">{'Enabled' if load_balance['enabled'] else 'Off'}</span></div>
        <div class="metric"><b>Pool</b><span>{balance_family_label(load_balance['family'])}</span></div>
        <div class="metric"><b>Devices</b><span>{len(assignments)}</span></div>
        <div class="metric"><b>Proxies</b><span>{len(proxies)}</span></div>
      </div>
      <div class="actions" style="margin-top:14px">
        <form method="post" action="/balance/apply">
          <select name="family">{''.join(family_options)}</select>
          <button class="primary">Balance Now</button>
        </form>
        <form method="post" action="/balance/auto">
          <input type="hidden" name="action" value="enable">
          <select name="family">{''.join(family_options)}</select>
          <button>Enable Auto</button>
        </form>
        <form method="post" action="/balance/auto">
          <input type="hidden" name="action" value="disable">
          <button class="neutral">Disable Auto</button>
        </form>
      </div>
      <table style="margin-top:12px">
        <thead><tr><th>#</th><th>Proxy</th><th>IP</th><th>Devices</th></tr></thead>
        <tbody>{''.join(load_rows) if load_rows else '<tr><td colspan="4">Chua co proxy de can bang tai.</td></tr>'}</tbody>
      </table>
    </section>
    <section>
      <h2>Proxy</h2>
      <form method="post" action="/proxy/add">
        <div class="proxy-form">
          <label>Type
            <select name="type">
              <option value="http">HTTP</option>
              <option value="https">HTTPS</option>
              <option value="socks5" selected>SOCKS5</option>
              <option value="socks4">SOCKS4</option>
            </select>
          </label>
          <label>Proxy IP
            <select name="ip_version">
              <option value="4">IPv4</option>
              <option value="6">IPv6</option>
            </select>
          </label>
          <label>Host
            <input type="text" name="host" placeholder="proxy.example.com">
          </label>
          <label>Port
            <input type="number" name="port" min="1" max="65535" placeholder="1080">
          </label>
          <label>Username
            <input type="text" name="login" autocomplete="username" placeholder="optional">
          </label>
          <label>Password
            <input type="password" name="password" autocomplete="current-password" placeholder="optional">
          </label>
          <button>Add Proxy</button>
        </div>
      </form>
      <form class="url-form" method="post" action="/proxy/add">
        <input type="text" name="url" placeholder="Hoac dan URL: socks5://user:pass@host:port">
        <select name="ip_version">
          <option value="4">IPv4</option>
          <option value="6">IPv6</option>
        </select>
        <button>Add Proxy</button>
      </form>
      <table style="margin-top:12px">
        <thead><tr><th>Upstream proxy</th><th>Proxy IP</th><th>Auth</th><th>Local port</th><th>Load</th><th>Action</th></tr></thead>
        <tbody>{''.join(proxy_rows) if proxy_rows else '<tr><td colspan="6">Chua co proxy. Thiet bi hien dang di Direct/NAT.</td></tr>'}</tbody>
      </table>
    </section>
	    <section>
	      <h2>System</h2>
	      <pre>{html.escape(data['interfaces'])}</pre>
	      <pre>{html.escape(data['routes'])}</pre>
	    </section>
		  </main>
		  <div class="modal" data-group-modal hidden>
		    <div class="modal-panel">
		      <h3>Tao Device Group</h3>
		      <form method="post" action="/device-group/create" data-group-form>
		        <input type="hidden" name="ips" data-group-ips>
		        <label>Ten group
		          <input type="text" name="name" maxlength="64" data-group-name placeholder="Vi du: Samsung Box">
		        </label>
			        <div class="group-modal-count" data-group-count>0 devices da chon</div>
			        <div class="modal-actions">
			          <button type="button" class="neutral" data-group-modal-close>Huy</button>
			          <button class="primary">Tao</button>
		        </div>
		      </form>
		    </div>
		  </div>
		  <div class="modal" data-device-modal hidden>
	    <div class="modal-panel">
	      <h3>DHCP Binding</h3>
	      <form method="post" action="/device/edit">
	        <input type="hidden" name="mac" data-modal-mac-hidden>
	        <label>Name
	          <input type="text" name="name" maxlength="64" data-modal-name placeholder="Name">
	        </label>
	        <label>MAC Address
	          <input type="text" data-modal-mac readonly>
	        </label>
	        <label>IP Address
	          <input type="text" name="ip_address" data-modal-ip-address placeholder="Vi du 10.42.0.56">
	        </label>
	        <div class="modal-actions">
	          <button type="button" class="neutral" data-modal-close>Cancel</button>
	          <button>Apply</button>
	        </div>
	      </form>
	    </div>
	  </div>
	  <script>
	    (() => {{
		      let socket = null;
		      let retryTimer = null;
		      let pendingHtml = null;
		      let selectedDeviceIps = new Set();
			      let state = new URLSearchParams(window.location.search);
			      const socketStatus = () => document.querySelector('[data-socket-status]');
			      const hasFocusedEditor = () => Boolean(document.querySelector('input:focus, select:focus, textarea:focus'));
		      const deviceBoxes = () => Array.from(document.querySelectorAll('[data-device-select]'));
		      const selectedDeviceBoxes = () => deviceBoxes().filter((box) => box.checked);
			      const copyMenu = () => document.querySelector('[data-copy-menu]');
			      const deviceModal = () => document.querySelector('[data-device-modal]');
			      const groupModal = () => document.querySelector('[data-group-modal]');
		      const updateBulkCopy = () => {{
		        const boxes = deviceBoxes();
		        const selected = selectedDeviceBoxes();
		        const checkAll = document.querySelector('[data-device-checkall]');
		        if (checkAll) {{
		          checkAll.checked = boxes.length > 0 && selected.length === boxes.length;
		          checkAll.indeterminate = selected.length > 0 && selected.length < boxes.length;
		        }}
		        const bulk = document.querySelector('[data-bulk-copy]');
		        if (bulk) bulk.hidden = selected.length === 0;
		        const toggle = document.querySelector('[data-copy-toggle]');
		        if (toggle) toggle.textContent = selected.length ? 'Copy (' + selected.length + ')' : 'Copy';
		        if (!selected.length && copyMenu()) copyMenu().hidden = true;
		      }};
		      const restoreBulkSelection = () => {{
		        deviceBoxes().forEach((box) => {{
		          box.checked = selectedDeviceIps.has(box.dataset.ip || '');
		        }});
		        updateBulkCopy();
		      }};
		      const copyText = async (text) => {{
		        if (navigator.clipboard && window.isSecureContext) {{
		          await navigator.clipboard.writeText(text);
		          return;
		        }}
		        const area = document.createElement('textarea');
		        area.value = text;
		        area.setAttribute('readonly', '');
		        area.style.position = 'fixed';
		        area.style.left = '-9999px';
		        document.body.appendChild(area);
		        area.select();
		        document.execCommand('copy');
		        area.remove();
		      }};
		      const copySelectedDevices = async (mode) => {{
		        const values = selectedDeviceBoxes()
		          .map((box) => mode === 'mac' ? box.dataset.mac || '' : box.dataset.ip || '')
		          .filter(Boolean);
		        if (!values.length) return;
		        await copyText(values.join('\\n'));
		        const menu = copyMenu();
		        if (menu) menu.hidden = true;
		        const toggle = document.querySelector('[data-copy-toggle]');
		        if (toggle) {{
		          const original = toggle.textContent;
		          toggle.textContent = 'Copied';
		          setTimeout(updateBulkCopy, 900);
		        }}
		      }};
			      const closeDeviceModal = () => {{
			        const modal = deviceModal();
			        if (modal) modal.hidden = true;
		      }};
	      const openDeviceModal = (button) => {{
	        const modal = deviceModal();
		        if (!modal) return;
		        modal.querySelector('[data-modal-mac-hidden]').value = button.dataset.mac || '';
		        modal.querySelector('[data-modal-mac]').value = button.dataset.mac || '';
		        modal.querySelector('[data-modal-name]').value = button.dataset.name || '';
		        modal.querySelector('[data-modal-ip-address]').value = button.dataset.bindingIp || button.dataset.ip || '';
			        modal.hidden = false;
			        modal.querySelector('[data-modal-name]').focus();
		      }};
		      const selectedGroupIps = () => selectedDeviceBoxes()
		        .map((box) => box.dataset.ip || '')
		        .filter(Boolean);
		      const closeGroupModal = () => {{
		        const modal = groupModal();
		        if (modal) modal.hidden = true;
		      }};
		      const openGroupModal = () => {{
		        const ips = selectedGroupIps();
		        if (!ips.length) return;
		        const modal = groupModal();
		        if (!modal) return;
		        modal.querySelector('[data-group-ips]').value = ips.join('\\n');
		        modal.querySelector('[data-group-count]').textContent = ips.length + (ips.length === 1 ? ' device da chon' : ' devices da chon');
		        modal.hidden = false;
		        modal.querySelector('[data-group-name]').focus();
		      }};
			      const setGroupCollapsed = (groupId, collapsed) => {{
			        const groupRow = Array.from(document.querySelectorAll('[data-device-group]')).find((row) => row.dataset.deviceGroup === groupId);
			        if (groupRow) groupRow.dataset.collapsed = collapsed ? '1' : '0';
			        Array.from(document.querySelectorAll('[data-group-member]')).filter((row) => row.dataset.groupMember === groupId).forEach((row) => {{
			          row.hidden = collapsed;
			        }});
			        const toggle = Array.from(document.querySelectorAll('[data-group-toggle]')).find((button) => button.dataset.groupId === groupId);
		        if (toggle) {{
		          toggle.textContent = collapsed ? 'Mo' : 'Thu gon';
		          toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
		        }}
		      }};
				      const applyDashboard = (html) => {{
				        const main = document.querySelector('main');
				        if (main) {{
			          main.outerHTML = html;
			          restoreBulkSelection();
			        }}
		      }};
	      const filters = () => ({{
	        devices: state.get('devices') || 'online',
	        sort: state.get('sort') || 'ip',
	        dir: state.get('dir') || 'asc',
	      }});
	      const setSocketStatus = (live) => {{
	        const el = socketStatus();
	        if (!el) return;
	        el.textContent = live ? 'Live' : 'Offline';
	        el.classList.toggle('live', live);
	      }};
	      const socketUrl = () => {{
	        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
	        const params = new URLSearchParams(filters());
	        return `${{protocol}}//${{window.location.host}}/ws/status?${{params.toString()}}`;
	      }};
	      const sendFilters = (force = false) => {{
	        if (!socket || socket.readyState !== WebSocket.OPEN) return;
	        socket.send(JSON.stringify({{type: force ? 'refresh' : 'filters', ...filters()}}));
	      }};
	      const connect = () => {{
	        if (retryTimer) clearTimeout(retryTimer);
	        socket = new WebSocket(socketUrl());
	        socket.addEventListener('open', () => {{
	          setSocketStatus(true);
	          sendFilters(true);
	        }});
	        socket.addEventListener('message', (event) => {{
	          let data = null;
	          try {{
	            data = JSON.parse(event.data);
	          }} catch (_err) {{
	            return;
	          }}
	          if (data.type !== 'dashboard' || !data.html) return;
	          if (hasFocusedEditor()) {{
	            pendingHtml = data.html;
	            return;
	          }}
	          pendingHtml = null;
	          applyDashboard(data.html);
	        }});
	        socket.addEventListener('close', () => {{
	          setSocketStatus(false);
	          retryTimer = setTimeout(connect, 2000);
	        }});
	        socket.addEventListener('error', () => {{
	          setSocketStatus(false);
	          socket.close();
	        }});
	      }};
		      document.addEventListener('click', (event) => {{
		        const nav = event.target.closest('a[data-device-nav]');
		        if (nav) {{
		          event.preventDefault();
		          const url = new URL(nav.href, window.location.href);
		          state = new URLSearchParams(url.search);
		          window.history.replaceState(null, '', `${{url.pathname}}?${{state.toString()}}`);
		          sendFilters(true);
		          return;
		        }}
			        const edit = event.target.closest('[data-device-edit]');
			        if (edit) {{
			          event.preventDefault();
			          openDeviceModal(edit);
			          return;
			        }}
				        const copyToggle = event.target.closest('[data-copy-toggle]');
				        if (copyToggle) {{
			          event.preventDefault();
			          const menu = copyMenu();
			          if (menu) menu.hidden = !menu.hidden;
			          return;
			        }}
			        const copyOption = event.target.closest('[data-copy-selected]');
			        if (copyOption) {{
			          event.preventDefault();
			          copySelectedDevices(copyOption.dataset.copySelected || 'dhcp');
				          return;
				        }}
				        const groupOpen = event.target.closest('[data-group-create-open]');
				        if (groupOpen) {{
				          event.preventDefault();
				          openGroupModal();
				          return;
				        }}
				        const groupToggle = event.target.closest('[data-group-toggle]');
				        if (groupToggle) {{
				          event.preventDefault();
				          const groupId = groupToggle.dataset.groupId || '';
				          const groupRow = Array.from(document.querySelectorAll('[data-device-group]')).find((row) => row.dataset.deviceGroup === groupId);
				          const collapsed = !(groupRow && groupRow.dataset.collapsed === '1');
				          setGroupCollapsed(groupId, collapsed);
				          const params = new URLSearchParams({{id: groupId, collapsed: collapsed ? '1' : '0'}});
				          fetch('/device-group/toggle', {{
				            method: 'POST',
				            headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
				            body: params.toString(),
				          }}).catch(() => {{}});
				          return;
				        }}
				        const close = event.target.closest('[data-modal-close]');
				        if (close) {{
			          event.preventDefault();
		          closeDeviceModal();
		          return;
		        }}
			        const modal = event.target.closest('[data-device-modal]');
			        if (modal && event.target === modal) {{
			          closeDeviceModal();
			          return;
			        }}
			        const groupClose = event.target.closest('[data-group-modal-close]');
			        if (groupClose) {{
			          event.preventDefault();
			          closeGroupModal();
			          return;
			        }}
			        const groupBackdrop = event.target.closest('[data-group-modal]');
			        if (groupBackdrop && event.target === groupBackdrop) {{
			          closeGroupModal();
			          return;
			        }}
		        const refresh = event.target.closest('[data-refresh-status]');
			        if (refresh) {{
			          event.preventDefault();
		          sendFilters(true);
		        }}
		        if (!event.target.closest('[data-bulk-copy]') && copyMenu()) {{
		          copyMenu().hidden = true;
				        }}
				      }});
				      document.addEventListener('submit', (event) => {{
				        const groupForm = event.target.closest('[data-group-form]');
				        if (!groupForm) return;
				        const ips = selectedGroupIps();
				        if (!ips.length) {{
				          event.preventDefault();
				          closeGroupModal();
				          return;
				        }}
				        groupForm.querySelector('[data-group-ips]').value = ips.join('\\n');
				      }});
				      document.addEventListener('change', (event) => {{
		        const checkAll = event.target.closest('[data-device-checkall]');
		        if (checkAll) {{
		          deviceBoxes().forEach((box) => {{
		            box.checked = checkAll.checked;
		            if (box.dataset.ip) {{
		              if (box.checked) selectedDeviceIps.add(box.dataset.ip);
		              else selectedDeviceIps.delete(box.dataset.ip);
			        }}
			      }});
			          updateBulkCopy();
		          return;
		        }}
		        const box = event.target.closest('[data-device-select]');
		        if (box) {{
		          if (box.checked) selectedDeviceIps.add(box.dataset.ip || '');
		          else selectedDeviceIps.delete(box.dataset.ip || '');
		          updateBulkCopy();
		        }}
		      }});
		      document.addEventListener('focusout', () => {{
	        setTimeout(() => {{
	          if (!pendingHtml || hasFocusedEditor()) return;
	          const html = pendingHtml;
	          pendingHtml = null;
	          applyDashboard(html);
	        }}, 0);
		      }});
		      document.addEventListener('keydown', (event) => {{
		        if (event.key === 'Escape') {{
		          closeDeviceModal();
		          closeGroupModal();
		        }}
		      }});
	      window.addEventListener('beforeunload', () => {{
	        if (socket) socket.close();
	      }});
	      connect();
	    }})();
	  </script>
	</body>
	</html>"""


def render_dashboard_fragment(data, device_filter="online", device_sort="ip", sort_dir="asc"):
    page = render_page(
        data,
        device_filter=device_filter,
        device_sort=device_sort,
        sort_dir=sort_dir,
    )
    start = page.index("<main>")
    end = page.index("</main>", start) + len("</main>")
    return page[start:end]


class Handler(BaseHTTPRequestHandler):
    wan_if = ""
    lan_if = ""
    lan_cidr = DEFAULT_LAN_CIDR
    admin_user = DEFAULT_ADMIN_USER
    admin_password = ""
    session_token = ""

    def respond(self, body, status=200, content_type="text/html; charset=utf-8"):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def respond_bytes(self, payload, status=200, content_type="text/html; charset=utf-8", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in extra_headers or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def parse_cookies(self):
        raw = self.headers.get("Cookie", "")
        cookies = {}
        for item in raw.split(";"):
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            cookies[key.strip()] = value.strip()
        return cookies

    def is_authenticated(self):
        if not self.admin_password:
            return True
        token = self.parse_cookies().get("router_session", "")
        return bool(token) and secrets.compare_digest(token, self.session_token)

    def render_login(self, message=""):
        return f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Router Login</title>
  <style>
    :root {{
      --bg: #eef3f8;
      --panel: #ffffff;
      --ink: #16202a;
      --muted: #64748b;
      --line: #d8e1ea;
      --accent: #0f766e;
      --danger: #b91c1c;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: radial-gradient(circle at top left, #d7f3ec 0, transparent 32%), linear-gradient(180deg, #f8fafc 0, #e8eef5 100%);
      font-family: system-ui, -apple-system, Segoe UI, sans-serif;
      color: var(--ink);
      padding: 20px;
    }}
    .panel {{
      width: min(100%, 420px);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 24px;
      box-shadow: 0 18px 40px rgba(15, 23, 42, 0.08);
    }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    p {{ margin: 0 0 18px; color: var(--muted); }}
    form {{ display: grid; gap: 12px; }}
    label {{ display: grid; gap: 6px; font-size: 13px; color: var(--muted); font-weight: 700; }}
    input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 11px 12px;
      min-height: 42px;
      font: inherit;
      color: var(--ink);
      background: white;
    }}
    button {{
      border: 0;
      border-radius: 8px;
      min-height: 42px;
      background: var(--accent);
      color: white;
      font-weight: 700;
      cursor: pointer;
    }}
    .msg {{
      margin-bottom: 14px;
      padding: 10px 12px;
      border-radius: 8px;
      background: #fef2f2;
      color: var(--danger);
      border: 1px solid #fecaca;
    }}
  </style>
</head>
<body>
  <section class="panel">
    <h1>Ubuntu Router Manager</h1>
    <p>Dang nhap de quan ly router va proxy.</p>
    {f'<div class="msg">{html.escape(message)}</div>' if message else ''}
    <form method="post" action="/login">
      <label>Username
        <input type="text" name="username" autocomplete="username" value="{html.escape(self.admin_user)}">
      </label>
      <label>Password
        <input type="password" name="password" autocomplete="current-password">
      </label>
      <button>Login</button>
    </form>
  </section>
</body>
</html>"""

    def redirect_with_cookie(self, location, cookie_value=None, clear_cookie=False):
        self.send_response(303)
        self.send_header("Location", location)
        if clear_cookie:
            self.send_header("Set-Cookie", "router_session=; Path=/; Max-Age=0; SameSite=Lax")
        elif cookie_value is not None:
            self.send_header("Set-Cookie", f"router_session={cookie_value}; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()

    def redirect(self, message=""):
        location = "/" + (f"?msg={quote(message)}" if message else "")
        self.redirect_with_cookie(location)

    def form(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        return {key: values[0] for key, values in parse_qs(body).items()}

    def current_lan_if(self):
        return active_lan_if(self.lan_if)

    def current_lan_cidr(self):
        return load_state().get("lan_cidr", self.lan_cidr or DEFAULT_LAN_CIDR)

    def status_filters(self, query):
        return {
            "device_filter": query.get("devices", ["online"])[0],
            "device_sort": query.get("sort", ["ip"])[0],
            "sort_dir": query.get("dir", ["asc"])[0],
        }

    def handle_status_socket(self, parsed):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self.respond("websocket upgrade required", status=400)
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self.respond("missing websocket key", status=400)
            return

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", websocket_accept_key(key))
        self.end_headers()
        self.close_connection = True

        filters = self.status_filters(parse_qs(parsed.query))
        next_send = 0
        last_html = ""
        self.connection.settimeout(0.2)
        while True:
            try:
                message = websocket_read_message(self.connection)
                force_send = False
                if message and message.get("type") == "close":
                    break
                if message and message.get("type") == "ping":
                    self.connection.sendall(websocket_frame(message.get("payload", b""), opcode=0xA))
                if message and message.get("type") == "text":
                    try:
                        payload = json.loads(message.get("text", "{}"))
                    except json.JSONDecodeError:
                        payload = {}
                    if payload.get("type") in {"filters", "refresh"}:
                        filters = {
                            "device_filter": payload.get("devices", filters["device_filter"]),
                            "device_sort": payload.get("sort", filters["device_sort"]),
                            "sort_dir": payload.get("dir", filters["sort_dir"]),
                        }
                        force_send = True

                now = time.monotonic()
                if force_send or now >= next_send:
                    data = command_status(self.wan_if, self.lan_if)
                    html_fragment = render_dashboard_fragment(data, **filters)
                    if force_send or html_fragment != last_html:
                        websocket_send_json(
                            self.connection,
                            {
                                "type": "dashboard",
                                "html": html_fragment,
                                "ts": timestamp_now(),
                            },
                        )
                        last_html = html_fragment
                    next_send = now + 5
            except (BrokenPipeError, ConnectionResetError, OSError):
                break

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/logout":
            self.redirect_with_cookie("/login?msg=Logged%20out", clear_cookie=True)
            return
        if parsed.path == "/login":
            message = parse_qs(parsed.query).get("msg", [""])[0]
            self.respond(self.render_login(message))
            return
        if not self.is_authenticated():
            self.redirect_with_cookie("/login")
            return
        if parsed.path == "/ws/status":
            self.handle_status_socket(parsed)
            return
        if parsed.path == "/api/status":
            data = command_status(self.wan_if, self.lan_if)
            self.respond(json.dumps(data, indent=2), content_type="application/json")
            return
        query = parse_qs(parsed.query)
        message = query.get("msg", [""])[0]
        device_filter = query.get("devices", ["online"])[0]
        device_sort = query.get("sort", ["ip"])[0]
        sort_dir = query.get("dir", ["asc"])[0]
        try:
            data = command_status(self.wan_if, self.lan_if)
            self.respond(render_page(data, message, device_filter=device_filter, device_sort=device_sort, sort_dir=sort_dir))
        except Exception as exc:
            self.respond(f"<pre>{html.escape(str(exc))}</pre>", status=500)

    def do_HEAD(self):
        if not self.is_authenticated():
            self.send_response(303)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_POST(self):
        if self.path == "/login":
            data = self.form()
            username = data.get("username", "")
            password = data.get("password", "")
            if secrets.compare_digest(username, self.admin_user) and secrets.compare_digest(password, self.admin_password):
                self.redirect_with_cookie("/", cookie_value=self.session_token)
            else:
                self.respond(self.render_login("Sai username hoac password"), status=401)
            return
        if not self.is_authenticated():
            self.redirect_with_cookie("/login")
            return
        try:
            if self.path == "/setup":
                lan_if = apply_router_stack(self.wan_if, self.lan_if, self.current_lan_cidr())
                self.redirect(f"Router config applied on {lan_if}")
                return
            if self.path == "/lan/save":
                data = self.form()
                lan_cidr = normalize_lan_cidr(data.get("lan_cidr", ""))
                state = load_state()
                state["lan_cidr"] = lan_cidr
                prune_lan_scoped_state(state, lan_cidr)
                save_state(state)
                self.lan_cidr = lan_cidr
                Handler.lan_cidr = lan_cidr
                lan_if = apply_router_stack(self.wan_if, self.lan_if, lan_cidr)
                dhcp_start, dhcp_end, _ = dhcp_range_for(lan_cidr)
                self.redirect(f"LAN CIDR saved on {lan_if}: {lan_cidr}; DHCP {dhcp_start} - {dhcp_end}")
                return
            if self.path == "/stop":
                state = load_state()
                lan_if = active_lan_if(self.lan_if, state)
                stop_router(self.wan_if, lan_if, self.lan_if)
                if lan_if != self.lan_if:
                    for stale_if in interface_list(self.lan_if):
                        stop_router(self.wan_if, stale_if, self.lan_if)
                self.redirect("Router stopped")
                return
            if self.path == "/mac/rotate":
                target = self.form().get("target", "")
                if target == "wan":
                    _, new_mac = rotate_interface_mac(self.wan_if)
                    apply_router_stack(self.wan_if, self.lan_if, self.current_lan_cidr())
                    self.redirect(f"WAN MAC rotated: {new_mac}")
                    return
                if target == "lan":
                    _, new_mac = rotate_interface_mac(self.current_lan_if())
                    apply_router_stack(self.wan_if, self.lan_if, self.current_lan_cidr())
                    self.redirect(f"LAN MAC rotated: {new_mac}")
                    return
                raise ValueError("MAC target khong hop le")
            if self.path == "/hotspot/save":
                data = self.form()
                state = load_state()
                old_hotspot = normalized_hotspot(state)
                old_lan_if = active_lan_if(self.lan_if, state)
                new_hotspot = parse_hotspot_form(data, state, self.wan_if)
                if old_hotspot["enabled"] and old_hotspot["ifname"] != new_hotspot["ifname"]:
                    stop_hotspot(old_hotspot)
                state["hotspot"] = new_hotspot
                new_lan_if = active_lan_if(self.lan_if, state)
                if old_lan_if != new_lan_if:
                    stop_router(self.wan_if, old_lan_if, self.lan_if)
                save_state(state)
                lan_if = apply_router_stack(self.wan_if, self.lan_if, self.current_lan_cidr())
                self.redirect(f"WiFi hotspot started on {lan_if}")
                return
            if self.path == "/hotspot/stop":
                state = load_state()
                hotspot = normalized_hotspot(state)
                old_lan_if = active_lan_if(self.lan_if, state)
                was_enabled = hotspot["enabled"]
                hotspot["enabled"] = False
                state["hotspot"] = hotspot
                save_state(state)
                if was_enabled:
                    stop_router(self.wan_if, old_lan_if, self.lan_if)
                    lan_if = apply_router_stack(self.wan_if, self.lan_if, self.current_lan_cidr())
                    self.redirect(f"WiFi hotspot stopped; LAN output {lan_if}")
                    return
                stop_hotspot(hotspot)
                self.redirect("WiFi hotspot stopped")
                return
            if self.path == "/balance/apply":
                data = self.form()
                family = balance_family(data.get("family", "all"))
                state = load_state()
                count = rebalance_devices(state, self.current_lan_if(), family)
                state["load_balance"] = {"enabled": False, "family": family}
                save_state(state)
                apply_proxy_rules(self.current_lan_if())
                self.redirect(f"Balanced {count} devices across {balance_family_label(family)} proxies")
                return
            if self.path == "/balance/auto":
                data = self.form()
                action = data.get("action", "")
                family = balance_family(data.get("family", "all"))
                state = load_state()
                if action == "enable":
                    count = rebalance_devices(state, self.current_lan_if(), family)
                    state["load_balance"] = {"enabled": True, "family": family}
                    save_state(state)
                    apply_proxy_rules(self.current_lan_if())
                    self.redirect(f"Auto balance enabled: {count} devices on {balance_family_label(family)}")
                    return
                if action == "disable":
                    state["load_balance"] = {"enabled": False, "family": family}
                    save_state(state)
                    apply_proxy_rules(self.current_lan_if())
                    self.redirect("Auto balance disabled")
                    return
                raise ValueError("Load balance action khong hop le")
            if self.path == "/proxy/add":
                data = self.form()
                proxy = parse_proxy_form(data)
                state = load_state()
                state.setdefault("proxies", [])
                if proxy_identity(proxy) not in [proxy_identity(item) for item in state["proxies"]]:
                    state["proxies"].append(proxy)
                save_state(state)
                apply_proxy_rules(self.current_lan_if())
                self.redirect("Proxy added")
                return
            if self.path == "/proxy/check":
                idx = int(self.form().get("index", "-1"))
                result = check_proxy(idx)
                data = command_status(self.wan_if, self.lan_if)
                self.respond(render_page(data, "Proxy checked", {"index": idx, **result}))
                return
            if self.path == "/proxy/delete":
                idx = int(self.form().get("index", "-1"))
                remove_proxy(idx, self.current_lan_if())
                self.redirect("Proxy deleted")
                return
            if self.path == "/assign":
                data = self.form()
                client_ip = data.get("ip", "")
                proxy_idx = data.get("proxy", "")
                ipaddress.ip_address(client_ip)
                state = load_state()
                state.setdefault("assignments", {})
                if proxy_idx == "":
                    state["assignments"].pop(client_ip, None)
                else:
                    idx = int(proxy_idx)
                    if idx < 0 or idx >= len(state.get("proxies", [])):
                        raise ValueError("Proxy index khong hop le")
                    state["assignments"][client_ip] = idx
                save_state(state)
                apply_proxy_rules(self.current_lan_if())
                self.redirect("Assignment saved")
                return
            if self.path == "/device-group/create":
                data = self.form()
                name = str(data.get("name", "")).strip()[:64]
                ips = normalize_device_group_ips(data.get("ips", ""))
                if not name:
                    raise ValueError("Ten group khong duoc de trong")
                if not ips:
                    raise ValueError("Chua chon device de tao group")
                state = load_state()
                groups = []
                selected = set(ips)
                for group in normalize_device_groups(state.get("device_groups", [])):
                    group["ips"] = [ip for ip in group.get("ips", []) if ip not in selected]
                    if group["ips"]:
                        groups.append(group)
                groups.append(
                    {
                        "id": f"group-{timestamp_now()}-{secrets.token_hex(4)}",
                        "name": name,
                        "ips": ips,
                        "collapsed": False,
                    }
                )
                state["device_groups"] = groups
                save_device_groups_config(state)
                save_state(state)
                self.redirect(f"Group created: {name}")
                return
            if self.path == "/device-group/toggle":
                data = self.form()
                group_id = str(data.get("id", "")).strip()
                collapsed = str(data.get("collapsed", "")) == "1"
                state = load_state()
                groups = normalize_device_groups(state.get("device_groups", []))
                for group in groups:
                    if group.get("id") == group_id:
                        group["collapsed"] = collapsed
                        break
                state["device_groups"] = groups
                save_device_groups_config(state)
                save_state(state)
                self.respond("ok", content_type="text/plain; charset=utf-8")
                return
            if self.path == "/device-group/delete":
                data = self.form()
                group_id = str(data.get("id", "")).strip()
                state = load_state()
                state["device_groups"] = [
                    group
                    for group in normalize_device_groups(state.get("device_groups", []))
                    if group.get("id") != group_id
                ]
                save_device_groups_config(state)
                save_state(state)
                self.redirect("Group removed")
                return
            if self.path == "/device/name":
                data = self.form()
                mac = normalize_mac(data.get("mac", ""))
                if not mac:
                    raise ValueError("MAC khong hop le")
                name = str(data.get("name", "")).strip()[:64]
                state = load_state()
                names = state.setdefault("device_names", {})
                if name:
                    names[mac] = name
                else:
                    names.pop(mac, None)
                save_dhcp_bindings_config(state)
                save_state(state)
                self.redirect("Device name saved")
                return
            if self.path == "/device/edit":
                data = self.form()
                mac = normalize_mac(data.get("mac", ""))
                if not mac:
                    raise ValueError("MAC khong hop le")
                lan_cidr = self.current_lan_cidr()
                name = str(data.get("name", "")).strip()[:64]
                dhcp_ip = normalize_dhcp_reservation_ip(data.get("ip_address", data.get("dhcp_ip", "")), lan_cidr)
                state = load_state()
                names = state.setdefault("device_names", {})
                reservations = state.setdefault("dhcp_reservations", {})
                reservation_key = next((key for key in reservations if normalize_mac(key) == mac), mac)
                previous_dhcp_ip = reservations.get(reservation_key, "")
                reservation_changed = previous_dhcp_ip != dhcp_ip
                removed_lease_ips = []
                if reservation_key != mac:
                    reservations.pop(reservation_key, None)
                if dhcp_ip:
                    for other_mac, other_ip in reservations.items():
                        if normalize_mac(other_mac) != mac and other_ip == dhcp_ip:
                            raise ValueError(f"DHCP IP {dhcp_ip} da duoc gan cho {other_mac}")
                    reservations[mac] = dhcp_ip
                else:
                    reservations.pop(mac, None)
                if name:
                    names[mac] = name
                else:
                    names.pop(mac, None)
                if reservation_changed:
                    removed_lease_ips = remove_dnsmasq_leases_for_mac(mac)
                save_dhcp_bindings_config(state)
                save_state(state)
                lan_if = self.current_lan_if()
                start_dnsmasq(lan_if, lan_cidr)
                if reservation_changed:
                    refresh_ips = [previous_dhcp_ip, dhcp_ip, *removed_lease_ips]
                    self.redirect(refresh_dhcp_client(mac, lan_if, refresh_ips))
                else:
                    self.redirect("Device updated")
                return
            if self.path == "/assign/clear":
                state = load_state()
                state["assignments"] = {}
                state["load_balance"] = {"enabled": False, "family": load_balance_config(state)["family"]}
                save_state(state)
                apply_proxy_rules(self.current_lan_if())
                self.redirect("All devices set to Direct/NAT")
                return
            if self.path == "/devices/clear-offline":
                data = command_status(self.wan_if, self.lan_if)
                state = load_state()
                hidden = state.setdefault("hidden_offline_devices", {})
                now = timestamp_now()
                count = 0
                for row in data.get("leases", []):
                    key = device_presence_key(row)
                    if key and not row.get("online") and key not in hidden:
                        hidden[key] = now
                        count += 1
                save_state(state)
                self.redirect(f"Cleared {count} offline devices; new active devices will reappear automatically")
                return
            self.respond("not found", status=404)
        except Exception as exc:
            self.respond(f"<pre>{html.escape(str(exc))}</pre>", status=500)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    parser = argparse.ArgumentParser(description="Quick Ubuntu LAN router dashboard")
    parser.add_argument("--wan", default=detect_wan())
    parser.add_argument("--lan", default="")
    parser.add_argument("--lan-cidr", default="")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--apply", action="store_true", help="apply router config before starting web")
    parser.add_argument("--stop", action="store_true", help="stop dnsmasq/redsocks and remove temporary iptables rules")
    parser.add_argument("--replace", action="store_true", help="stop an older router_manager web process before binding")
    parser.add_argument("--admin-user", default=DEFAULT_ADMIN_USER)
    parser.add_argument("--domain-proxy-worker", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if hasattr(args, "domain_proxy_worker"):
        run_domain_proxy_worker(args.domain_proxy_worker)
        return
    args.lan = args.lan or detect_lan(args.wan)
    if not args.wan or not args.lan:
        raise SystemExit("Khong detect duoc WAN/LAN interface")
    if args.stop:
        state = load_state()
        lan_if = active_lan_if(args.lan, state)
        stop_web_server()
        stop_router(args.wan, lan_if, args.lan)
        if lan_if != args.lan:
            for stale_if in interface_list(args.lan):
                stop_router(args.wan, stale_if, args.lan)
        print(f"Stopped router services/rules for WAN={args.wan} LAN={lan_if}")
        return
    if args.replace:
        stop_web_server()
    state = load_state()
    lan_cidr = normalize_lan_cidr(args.lan_cidr or state.get("lan_cidr", DEFAULT_LAN_CIDR))
    state["lan_cidr"] = lan_cidr
    save_state(state)
    Handler.wan_if = args.wan
    Handler.lan_if = args.lan
    Handler.lan_cidr = lan_cidr
    Handler.admin_user = args.admin_user
    Handler.admin_password = load_or_create_admin_password()
    Handler.session_token = load_or_create_session_token()
    if args.apply:
        apply_router_stack(args.wan, args.lan, lan_cidr)
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    WEB_PID.write_text(str(os.getpid()))
    print(f"Router manager: http://127.0.0.1:{args.port}")
    print(f"WAN={args.wan} LAN={args.lan} LAN_IP={lan_cidr}")
    print(f"Admin login: {Handler.admin_user} / {Handler.admin_password}")
    try:
        server.serve_forever()
    finally:
        if WEB_PID.exists() and WEB_PID.read_text().strip() == str(os.getpid()):
            WEB_PID.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
