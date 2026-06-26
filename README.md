# Ubuntu Router Manager

Quick test setup for this PC:

- WAN/internet input: `enp8s0`
- LAN outputs: `enp3s0f0`, `enp3s0f1`
- WiFi hotspot: `wlp7s0`
- LAN gateway: `10.42.0.1/24`
- DHCP range: auto-derived from `10.42.0.1/24`
- Web dashboard: `http://127.0.0.1:4500`
- From a laptop plugged into LAN output: `http://10.42.0.1:4500`
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
- For better WiFi throughput, choose `5 GHz fast` with a non-DFS channel such as `36`, `40`, `44`, `48`, `149`, `153`, `157`, or `161`. The generated `hostapd` config enables 802.11ac/VHT80 for this mode.
- Use the correct two-letter regulatory country code for the device location. If the country is wrong, 5 GHz AP mode may be blocked or transmit power may stay very low.
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
