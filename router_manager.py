#!/usr/bin/env python3
import argparse
import base64
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse


BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = BASE_DIR / "state"
STATE_FILE = STATE_DIR / "router_state.json"
DNSMASQ_CONF = STATE_DIR / "dnsmasq.conf"
DNSMASQ_LEASES = STATE_DIR / "dnsmasq.leases"
DNSMASQ_PID = STATE_DIR / "dnsmasq.pid"
REDSOCKS_CONF = STATE_DIR / "redsocks.conf"
REDSOCKS_PID = STATE_DIR / "redsocks.pid"
DOMAIN_PROXY_PREFIX = "domain_proxy"
WEB_PID = STATE_DIR / "router_manager.pid"
ADMIN_PASSWORD_FILE = STATE_DIR / "admin_password.txt"
SESSION_FILE = STATE_DIR / "session_token.txt"

DEFAULT_LAN_CIDR = "10.42.0.1/24"
DEFAULT_ADMIN_USER = "admin"
PROXY_CHAIN = "ROUTER_PROXY"
PROXY_LOCAL_BASE = 23450
PROXY_TYPES = ("http", "https", "socks5", "socks4")
PROXY_TEST_URLS = {
    "4": "https://api.ipify.org",
    "6": "https://api6.ipify.org",
}


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


def delete_existing_rule(cmd):
    for _ in range(50):
        if not sudo_success(cmd):
            return


def require_commands(names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        install = "sudo apt-get update && sudo apt-get install -y dnsmasq-base redsocks iptables conntrack"
        raise RuntimeError(f"Thieu lenh: {', '.join(missing)}. Cai bang: {install}")


def load_state():
    STATE_DIR.mkdir(exist_ok=True)
    if not STATE_FILE.exists():
        return {"proxies": [], "assignments": {}, "lan_cidr": DEFAULT_LAN_CIDR}
    return json.loads(STATE_FILE.read_text())


def public_state(state):
    data = json.loads(json.dumps(state))
    for proxy in data.get("proxies", []):
        if proxy.get("password"):
            proxy["password"] = "********"
    return data


def save_state(state):
    STATE_DIR.mkdir(exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.replace(STATE_FILE)


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
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                break
            for _ in range(20):
                time.sleep(0.1)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
    WEB_PID.unlink(missing_ok=True)


def write_dnsmasq_conf(lan_if, lan_cidr):
    lan_ip, _, _ = cidr_parts(lan_cidr)
    dhcp_start, dhcp_end, netmask = dhcp_range_for(lan_cidr)
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
                f"dhcp-leasefile={DNSMASQ_LEASES}",
                f"pid-file={DNSMASQ_PID}",
                "log-dhcp",
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


def stop_router(wan_if, lan_if):
    iptables_proxy_reset(lan_if)
    stop_pid(REDSOCKS_PID)
    stop_redsocks_processes()
    stop_domain_proxy_workers()
    stop_pid(DNSMASQ_PID)
    delete_existing_rule(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", wan_if, "-j", "MASQUERADE"])
    for rule in (
        ["FORWARD", "-i", lan_if, "-o", wan_if, "-j", "ACCEPT"],
        ["FORWARD", "-i", wan_if, "-o", lan_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ):
        delete_existing_rule(["iptables", "-D", *rule])


def list_leases(lan_if, lan_cidr):
    lan_net = ipaddress.ip_interface(lan_cidr).network
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
        if ip not in leases:
            leases[ip] = {"ip": ip, "mac": lladdr, "hostname": "", "expires": "", "source": "arp"}
        elif lladdr and not leases[ip].get("mac"):
            leases[ip]["mac"] = lladdr
    return sorted(leases.values(), key=lambda x: tuple(int(p) for p in x["ip"].split(".")))


def proxy_key(proxy):
    auth = f"{proxy.get('login', '')}@" if proxy.get("login") else ""
    return f"{proxy['type']}://{auth}{format_host_port(proxy['host'], proxy['port'])} [{proxy_ip_label(proxy)}]"


def proxy_ip_version(proxy):
    version = str(proxy.get("ip_version", "4")).lower().removeprefix("ipv")
    return version if version in ("4", "6") else "4"


def proxy_ip_label(proxy):
    return "IPv6" if proxy_ip_version(proxy) == "6" else "IPv4"


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


def iptables_proxy_reset(lan_if):
    delete_existing_rule(["iptables", "-t", "nat", "-D", "PREROUTING", "-i", lan_if, "-p", "tcp", "-j", PROXY_CHAIN])
    sudo(["iptables", "-t", "nat", "-F", PROXY_CHAIN], check=False)
    sudo(["iptables", "-t", "nat", "-X", PROXY_CHAIN], check=False)
    delete_existing_rule(["ip6tables", "-D", "FORWARD", "-i", lan_if, "-j", "REJECT"])
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


def apply_proxy_rules(lan_if):
    state = load_state()
    proxies = state.get("proxies", [])
    assignments = state.get("assignments", {})
    lan_cidr = state.get("lan_cidr", DEFAULT_LAN_CIDR)
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
    if not proxies or not assignments:
        stop_pid(REDSOCKS_PID)
        stop_redsocks_processes()
        stop_domain_proxy_workers()
        return
    start_redsocks(proxies, lan_ip)
    start_domain_proxy_workers(proxies, lan_ip)
    sudo(["ip6tables", "-I", "FORWARD", "1", "-i", lan_if, "-j", "REJECT"], check=False)
    sudo(["iptables", "-t", "nat", "-N", PROXY_CHAIN], check=False)
    sudo(["iptables", "-t", "nat", "-F", PROXY_CHAIN])
    for net in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ):
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
    flush_client_conntrack(assignments.keys())


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
    lan_ip, _, lan_network = cidr_parts(lan_cidr)
    return {
        "wan_if": wan_if,
        "lan_if": lan_if,
        "lan_ip": lan_ip,
        "lan_network": lan_network,
        "dhcp_range": dhcp_range_for(lan_cidr),
        "interfaces": sh(["ip", "-br", "addr"], check=False),
        "routes": sh(["ip", "route"], check=False),
        "ip_forward": Path("/proc/sys/net/ipv4/ip_forward").read_text().strip(),
        "dnsmasq": pid_alive(DNSMASQ_PID),
        "redsocks": pid_alive(REDSOCKS_PID),
        "leases": list_leases(lan_if, lan_cidr),
        "state": public_state(state),
    }


def render_page(data, message="", proxy_check=None):
    state = data["state"]
    proxies = state.get("proxies", [])
    assignments = state.get("assignments", {})
    leases = {lease["ip"]: lease for lease in data["leases"]}
    for assigned_ip in assignments:
        leases.setdefault(
            assigned_ip,
            {"ip": assigned_ip, "mac": "", "hostname": "", "expires": "", "source": "manual"},
        )
    leases = [leases[ip] for ip in sorted(leases, key=lambda value: tuple(int(p) for p in value.split(".")))]
    proxy_options = ["<option value=''>Direct/NAT</option>"]
    for idx, proxy in enumerate(proxies):
        proxy_options.append(
            f"<option value='{idx}'>{html.escape(proxy_key(proxy))} -> localhost:{proxy_port(idx)}</option>"
        )
    device_rows = []
    for lease in leases:
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
        device_rows.append(
            f"""
            <tr>
              <td><strong>{html.escape(ip)}</strong><span>{html.escape(lease.get('source',''))}</span></td>
              <td>{html.escape(lease.get('mac',''))}</td>
              <td>{html.escape(lease.get('hostname',''))}</td>
              <td>
                <form method="post" action="/assign">
                  <input type="hidden" name="ip" value="{html.escape(ip)}">
                  <select name="proxy">{''.join(options)}</select>
                  <button>Save</button>
                </form>
              </td>
            </tr>
            """
        )
    proxy_rows = []
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
    form {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 0; }}
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
      form {{ align-items: stretch; }}
      select, button, input {{ width: 100%; }}
      .proxy-form {{ grid-template-columns: 1fr; }}
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
      <form method="get" action="/"><button class="neutral">Refresh</button></form>
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
        <div class="metric"><b>IP Forward</b><span class="{ 'ok' if data['ip_forward'] == '1' else 'bad' }">{html.escape(data['ip_forward'])}</span></div>
        <div class="metric"><b>Proxy Engine</b><span class="{ 'ok' if data['redsocks'] else 'bad' }">{'Running' if data['redsocks'] else 'Stopped'}</span></div>
        <div class="metric"><b>DHCP Range</b><span>{html.escape(data['dhcp_range'][0])} - {html.escape(data['dhcp_range'][1])}</span></div>
      </div>
      <div class="actions" style="margin-top:14px">
        <form method="post" action="/setup"><button class="primary">Apply LAN Router Config</button></form>
        <form method="post" action="/stop"><button class="danger">Stop Test Router</button></form>
      </div>
    </section>
    <section>
      <h2>Devices</h2>
      <table>
        <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Proxy</th></tr></thead>
        <tbody>{''.join(device_rows) if device_rows else '<tr><td colspan="4">Chua thay thiet bi nao. Cam laptop vao cong LAN out roi cho 5-10 giay.</td></tr>'}</tbody>
      </table>
      <form method="post" action="/assign" style="margin-top:14px">
        <input type="text" name="ip" placeholder="Gan thu cong IP, vi du 10.42.0.50">
        <select name="proxy">{''.join(assign_options)}</select>
        <button>Assign IP</button>
      </form>
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
        <thead><tr><th>Upstream proxy</th><th>Proxy IP</th><th>Auth</th><th>Local port</th><th>Action</th></tr></thead>
        <tbody>{''.join(proxy_rows) if proxy_rows else '<tr><td colspan="5">Chua co proxy. Thiet bi hien dang di Direct/NAT.</td></tr>'}</tbody>
      </table>
    </section>
    <section>
      <h2>System</h2>
      <pre>{html.escape(data['interfaces'])}</pre>
      <pre>{html.escape(data['routes'])}</pre>
    </section>
  </main>
</body>
</html>"""


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
        if parsed.path == "/api/status":
            data = command_status(self.wan_if, self.lan_if)
            self.respond(json.dumps(data, indent=2), content_type="application/json")
            return
        message = parse_qs(parsed.query).get("msg", [""])[0]
        try:
            data = command_status(self.wan_if, self.lan_if)
            self.respond(render_page(data, message))
        except Exception as exc:
            self.respond(f"<pre>{html.escape(str(exc))}</pre>", status=500)

    def do_HEAD(self):
        if not self.is_authenticated():
            self.send_response(303)
            self.send_header("Location", "/login")
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
                ensure_router(self.wan_if, self.lan_if, self.lan_cidr)
                apply_proxy_rules(self.lan_if)
                self.redirect("Router config applied")
                return
            if self.path == "/stop":
                stop_router(self.wan_if, self.lan_if)
                self.redirect("Router stopped")
                return
            if self.path == "/proxy/add":
                data = self.form()
                proxy = parse_proxy_form(data)
                state = load_state()
                state.setdefault("proxies", [])
                if proxy_identity(proxy) not in [proxy_identity(item) for item in state["proxies"]]:
                    state["proxies"].append(proxy)
                save_state(state)
                apply_proxy_rules(self.lan_if)
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
                remove_proxy(idx, self.lan_if)
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
                apply_proxy_rules(self.lan_if)
                self.redirect("Assignment saved")
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
    parser.add_argument("--lan-cidr", default=DEFAULT_LAN_CIDR)
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
        stop_web_server()
        stop_router(args.wan, args.lan)
        print(f"Stopped router services/rules for WAN={args.wan} LAN={args.lan}")
        return
    if args.replace:
        stop_web_server()
    state = load_state()
    state["lan_cidr"] = args.lan_cidr
    save_state(state)
    Handler.wan_if = args.wan
    Handler.lan_if = args.lan
    Handler.lan_cidr = args.lan_cidr
    Handler.admin_user = args.admin_user
    Handler.admin_password = load_or_create_admin_password()
    Handler.session_token = load_or_create_session_token()
    if args.apply:
        ensure_router(args.wan, args.lan, args.lan_cidr)
        apply_proxy_rules(args.lan)
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    WEB_PID.write_text(str(os.getpid()))
    print(f"Router manager: http://127.0.0.1:{args.port}")
    print(f"WAN={args.wan} LAN={args.lan} LAN_IP={args.lan_cidr}")
    print(f"Admin login: {Handler.admin_user} / {Handler.admin_password}")
    try:
        server.serve_forever()
    finally:
        if WEB_PID.exists() and WEB_PID.read_text().strip() == str(os.getpid()):
            WEB_PID.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
