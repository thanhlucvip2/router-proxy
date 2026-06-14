# Ubuntu Router Manager

Quick test setup for this PC:

- WAN/internet input: `enp7s0`
- LAN output: `enp10s0`
- LAN gateway: `10.42.0.1/24`
- DHCP range: auto-derived from `10.42.0.1/24`
- Web dashboard: `http://127.0.0.1:8080`
- From a laptop plugged into LAN output: `http://10.42.0.1:8080`
- Admin username: `admin`
- Admin password: stored in `state/admin_password.txt`

Install runtime tools if they are missing:

```bash
sudo apt-get update
sudo apt-get install -y dnsmasq-base redsocks iptables conntrack hostapd iw
```

Run:

```bash
./run-router.sh
```

Set a custom admin password before running:

```bash
ROUTER_ADMIN_PASSWORD='your-strong-password' ./run-router.sh
```

Stop temporary router services and rules:

```bash
./stop-router.sh
```

WiFi hotspot:

- Open the dashboard, use the `WiFi Hotspot` section, choose the WiFi card such as `wlan0`, set SSID/password, then click `Start Hotspot`.
- When hotspot is enabled, the app creates `br-router` and bridges the wired LAN port with the WiFi AP. Wired and WiFi clients share the same DHCP/NAT/proxy gateway.
- Password must be 8-63 printable ASCII characters.
- The WiFi card/driver must support AP mode. Check with:

```bash
iw list | grep -A 20 "Supported interface modes"
```

Proxy formats supported by the dashboard:

```text
http
https
socks5
socks4
```

You can enter host/port/auth in the form, or paste a full URL:

```text
socks5://host:port
socks4://host:port
http://host:port
https://host:port
socks5://user:pass@host:port
```
