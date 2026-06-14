# Ubuntu Router Manager

Quick test setup for this PC:

- WAN/internet input: `enp7s0`
- LAN output: `enp9s0`
- LAN gateway: `10.42.0.1/24`
- DHCP range: auto-derived from `10.42.0.1/24`
- Web dashboard: `http://127.0.0.1:8080`
- From a laptop plugged into LAN output: `http://10.42.0.1:8080`
- Admin username: `admin`
- Admin password: stored in `state/admin_password.txt`

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
