import { Injectable } from '@nestjs/common';
import { PROXY_ASSIGN_FAMILIES } from './constants';
import { NetworkService } from './network.service';
import { StateService } from './state.service';
import { htmlEscape } from './util';

@Injectable()
export class DashboardService {
  constructor(
    private readonly state: StateService,
    private readonly network: NetworkService,
  ) {}

  login(message = '', adminUser = 'admin'): string {
    return `<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Router Login</title>
  <style>
    *{box-sizing:border-box} body{margin:0;min-height:100vh;display:grid;place-items:center;background:#eef3f8;font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#16202a;padding:20px}
    .panel{width:min(100%,420px);background:white;border:1px solid #d8e1ea;border-radius:8px;padding:24px;box-shadow:0 18px 40px rgba(15,23,42,.08)}
    h1{margin:0 0 8px;font-size:24px;letter-spacing:0} p{margin:0 0 18px;color:#64748b} form{display:grid;gap:12px}
    label{display:grid;gap:6px;font-size:13px;color:#64748b;font-weight:700} input{width:100%;border:1px solid #d8e1ea;border-radius:6px;padding:11px 12px;min-height:42px}
    button{border:0;border-radius:6px;min-height:42px;background:#0f766e;color:white;font-weight:700;cursor:pointer}.msg{margin-bottom:14px;padding:10px 12px;border-radius:8px;background:#fef2f2;color:#b91c1c;border:1px solid #fecaca}
  </style>
</head>
<body><section class="panel"><h1>Ubuntu Router Manager</h1><p>Dang nhap de quan ly router va proxy.</p>${message ? `<div class="msg">${htmlEscape(message)}</div>` : ''}
<form method="post" action="/login"><label>Username<input name="username" autocomplete="username" value="${htmlEscape(adminUser)}"></label><label>Password<input type="password" name="password" autocomplete="current-password"></label><button>Login</button></form></section></body></html>`;
  }

  renderPage(data: any, message = '', proxyCheck?: any): string {
    const main = this.renderMain(data, message, proxyCheck);
    return `<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ubuntu Router Manager</title>
  <style>
    :root{color-scheme:light;--bg:#f6f7f9;--panel:#fff;--ink:#1f2937;--muted:#687385;--line:#d8dde6;--accent:#0f766e;--blue:#2563eb;--danger:#b91c1c;--soft:#eef2f7}
    *{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--ink)}a{color:var(--blue);text-decoration:none;font-weight:700}
    header{padding:20px 28px 12px;border-bottom:1px solid var(--line);background:var(--panel);display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
    h1{margin:0 0 6px;font-size:24px;letter-spacing:0}main{max-width:1180px;margin:0 auto;padding:22px;display:grid;gap:18px}section{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px}h2{font-size:17px;margin:0 0 14px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.metric{border:1px solid var(--line);border-radius:8px;padding:12px;min-height:74px}.metric b{display:block;font-size:13px;color:var(--muted);margin-bottom:4px}.ok{color:var(--accent);font-weight:800}.bad{color:var(--danger);font-weight:800}
    .actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:middle}th{color:var(--muted);font-size:13px}td span{display:block;color:var(--muted);font-size:12px;margin-top:2px}
    form{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0}input,select,textarea{border:1px solid var(--line);border-radius:6px;padding:9px 10px;min-height:38px;background:white;color:var(--ink);font:inherit}input[type=text]{min-width:min(100%,300px)}input[type=number]{width:120px}textarea{width:min(100%,760px);min-height:132px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;line-height:1.45}.stack-form{align-items:flex-start}
    button{border:0;border-radius:6px;min-height:38px;padding:9px 13px;background:var(--blue);color:white;font-weight:700;cursor:pointer}button:disabled{opacity:.7;cursor:wait}.primary{background:var(--accent)}.danger{background:var(--danger)}.neutral{background:#4b5563}.checking,.saving{color:var(--blue);font-weight:800}
    pre{overflow:auto;padding:12px;border-radius:8px;border:1px solid var(--line);background:#101827;color:#dbeafe;max-height:240px}.msg{padding:10px 12px;border-radius:8px;background:#e0f2fe;border:1px solid #bae6fd}.socket-status{min-height:26px;padding:5px 9px;border-radius:999px;background:#fee2e2;color:#991b1b;font-size:12px;font-weight:800}.socket-status.live{background:#d1fae5;color:#047857}
    @media(max-width:720px){header{display:block;padding:18px}main{padding:14px}table,thead,tbody,th,td,tr{display:block}thead{display:none}tr{border-bottom:1px solid var(--line);padding:8px 0}td{border-bottom:0;padding:6px 0}form{align-items:stretch}select,button,input{width:100%}}
  </style>
</head>
<body>
  <header><div><h1>Ubuntu Router Manager</h1><div>WAN: <strong>${htmlEscape(data.wan_if)}</strong> | LAN out: <strong>${htmlEscape(data.lan_if)}</strong> | Gateway: <strong>${htmlEscape(data.lan_ip)}</strong></div></div><div class="actions"><button type="button" class="neutral" data-refresh-status>Refresh</button><span class="socket-status" data-socket-status>Offline</span><a href="/api/status">JSON</a><a href="/logout">Logout</a></div></header>
  ${main}
  <script>
    (() => {
      const states = new Map();
      const getIndex = form => form.querySelector('input[name="index"]')?.value || '';
      const setState = (index, state) => {
        states.set(String(index), state);
        renderState(index);
      };
      const renderState = index => {
        const state = states.get(String(index));
        const status = document.querySelector('[data-proxy-check-status="' + index + '"]');
        const button = document.querySelector('[data-proxy-check-button="' + index + '"]');
        if (status) {
          status.className = state?.className || '';
          status.textContent = state?.text || '';
        }
        if (button) {
          button.disabled = Boolean(state?.loading);
          button.textContent = state?.loading ? 'Checking' : 'Check';
        }
      };
      window.routerProxyChecks = { reapply: () => states.forEach((_state, index) => renderState(index)) };
      document.addEventListener('submit', async event => {
        const form = event.target.closest?.('[data-proxy-check-form]');
        if (!form) return;
        event.preventDefault();
        const index = getIndex(form);
        setState(index, { loading: true, className: 'checking', text: 'Checking...' });
        try {
          const response = await fetch('/proxy/check', {
            method: 'POST',
            headers: { Accept: 'application/json' },
            body: new URLSearchParams(new FormData(form)),
          });
          const data = await response.json().catch(() => ({}));
          const ok = response.ok && data.ok;
          const detail = String(data.ip || data.detail || 'Khong co ket qua');
          const ping = Number.isFinite(Number(data.ping_ms)) ? ' | Ping: ' + Number(data.ping_ms) + ' ms' : '';
          setState(index, { loading: false, className: ok ? 'ok' : 'bad', text: (ok ? 'IP: ' : 'Error: ') + detail + ping });
        } catch (error) {
          setState(index, { loading: false, className: 'bad', text: 'Error: ' + (error?.message || error) });
        }
      });
    })();
    (() => {
      const states = new Map();
      const keyFor = form => form.dataset.assignKey || form.querySelector('input[name="ip"]')?.value || 'manual';
      const renderState = key => {
        const state = states.get(String(key));
        const status = document.querySelector('[data-assign-status="' + key + '"]');
        const form = document.querySelector('[data-proxy-assign-form][data-assign-key="' + key + '"]');
        const button = form?.querySelector('[data-assign-button]');
        const select = form?.querySelector('select[name="proxy"]');
        if (select && state?.proxy !== undefined) select.value = state.proxy;
        if (status) {
          status.className = state?.className || '';
          status.textContent = state?.text || '';
        }
        if (button) {
          button.disabled = Boolean(state?.loading);
          button.textContent = state?.loading ? 'Saving' : (button.dataset.defaultText || 'Save');
        }
      };
      const setState = (key, state) => {
        states.set(String(key), state);
        renderState(key);
      };
      window.routerProxyAssignments = { reapply: () => states.forEach((_state, key) => renderState(key)) };
      document.addEventListener('submit', async event => {
        const form = event.target.closest?.('[data-proxy-assign-form]');
        if (!form) return;
        event.preventDefault();
        const key = keyFor(form);
        const data = new FormData(form);
        const proxy = String(data.get('proxy') || '');
        setState(key, { loading: true, proxy, className: 'saving', text: 'Saving...' });
        try {
          const response = await fetch('/assign', {
            method: 'POST',
            headers: { Accept: 'application/json' },
            body: new URLSearchParams(data),
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok || !payload.ok) throw new Error(payload.detail || 'Save failed');
          setState(key, { loading: false, proxy, className: 'ok', text: 'Saved: ' + (payload.proxyLabel || 'Direct/NAT') });
        } catch (error) {
          setState(key, { loading: false, proxy, className: 'bad', text: 'Error: ' + (error?.message || error) });
        }
      });
    })();
    (()=>{let socket=null,retry=null;const status=()=>document.querySelector('[data-socket-status]');const setLive=v=>{const el=status();if(el){el.textContent=v?'Live':'Offline';el.classList.toggle('live',v)}};const connect=()=>{if(retry)clearTimeout(retry);const proto=location.protocol==='https:'?'wss:':'ws:';socket=new WebSocket(proto+'//'+location.host+'/ws/status');socket.addEventListener('open',()=>setLive(true));socket.addEventListener('message',ev=>{try{const data=JSON.parse(ev.data);const main=document.querySelector('main');if(data.type==='dashboard'&&data.html&&main&&!document.querySelector('input:focus,select:focus')){main.outerHTML=data.html;window.routerProxyChecks?.reapply?.();window.routerProxyAssignments?.reapply?.()}}catch(_){}});socket.addEventListener('close',()=>{setLive(false);retry=setTimeout(connect,2000)});socket.addEventListener('error',()=>{setLive(false);socket.close()})};document.addEventListener('click',ev=>{if(ev.target.closest('[data-refresh-status]')){ev.preventDefault();if(socket&&socket.readyState===WebSocket.OPEN)socket.send(JSON.stringify({type:'refresh'}))}});connect()})();
  </script>
</body>
</html>`;
  }

  renderMain(data: any, message = '', proxyCheck?: any): string {
    const state = data.state || {};
    const proxies = state.proxies || [];
    const assignments = state.assignments || {};
    const hotspot = this.state.normalizedHotspot(state);
    const proxyOptions = [`<option value="">Direct/NAT</option>`, ...proxies.map((proxy: any, idx: number) => `<option value="${idx}">${htmlEscape(this.network.proxyKey(proxy))}</option>`)];
    const wifiNames = Array.from(new Set([hotspot.ifname, ...(data.wifi_interfaces || [])].filter(Boolean)));
    const selectedWifi = hotspot.ifname || String(wifiNames[0] || '');
    const wifiOptions = wifiNames.map((name) => `<option value="${htmlEscape(String(name))}">`).join('');
    const bandOptions = [['2.4', '2.4 GHz'], ['5', '5 GHz fast']].map(([value, label]) => `<option value="${value}"${hotspot.band === value ? ' selected' : ''}>${label}</option>`).join('');
    const familyOptions = PROXY_ASSIGN_FAMILIES.map((value) => `<option value="${value}">${this.network.proxyFamilyLabel(value)}</option>`).join('');
    const cards = (data.network_cards || []).map((card: any) => `<tr><td><strong>${htmlEscape(card.name)}</strong><span>${htmlEscape(card.kind)}</span></td><td>${htmlEscape(card.role)}</td><td>${htmlEscape(card.state)}</td><td>${htmlEscape(card.mac)}</td><td>${htmlEscape((card.addresses || []).join(', ') || '-')}<span>${htmlEscape(card.master ? `master: ${card.master}` : '')}</span></td></tr>`).join('');
    const deviceRows = (data.leases || []).map((lease: any) => {
      const current = assignments[lease.ip] ?? '';
      const options = proxyOptions.map((opt) => current !== '' && opt.includes(`value="${current}"`) ? opt.replace('<option', '<option selected') : current === '' && opt.includes('value=""') ? opt.replace('<option', '<option selected') : opt).join('');
      const mac = String(lease.mac || '').toLowerCase();
      const name = state.device_names?.[mac] || '';
      const dhcpIp = state.dhcp_reservations?.[mac] || '';
      const connectionDetail = [lease.interface, lease.detail].filter(Boolean);
      const connectionText = Array.from(new Set(connectionDetail)).join(' ');
      return `<tr><td><strong>${htmlEscape(lease.ip)}</strong><span>${htmlEscape(lease.source || '')}</span></td><td><strong>${htmlEscape(name || '-')}</strong>${dhcpIp ? `<span>DHCP ${htmlEscape(dhcpIp)}</span>` : ''}</td><td>${htmlEscape(lease.mac || '')}</td><td>${htmlEscape(lease.hostname || '')}</td><td><strong>${htmlEscape(lease.connection || 'Unknown')}</strong><span>${htmlEscape(connectionText)}</span></td><td><span class="${lease.online ? 'ok' : 'bad'}">${lease.online ? 'Online' : 'Offline'}</span><span>${htmlEscape(lease.online ? lease.last_seen_text : lease.disconnected_text)}</span></td><td><form method="post" action="/assign" data-proxy-assign-form data-assign-key="${htmlEscape(lease.ip)}"><input type="hidden" name="ip" value="${htmlEscape(lease.ip)}"><select name="proxy">${options}</select><button data-assign-button data-default-text="Save">Save</button></form><span data-assign-status="${htmlEscape(lease.ip)}"></span></td><td><form method="post" action="/device/edit"><input type="hidden" name="mac" value="${htmlEscape(mac)}"><input type="text" name="name" value="${htmlEscape(name)}" placeholder="Name"><input type="text" name="ip_address" value="${htmlEscape(dhcpIp || lease.ip)}" placeholder="DHCP IP"><button class="neutral" ${mac ? '' : 'disabled'}>Edit</button></form></td></tr>`;
    }).join('');
    const proxyRows = proxies.map((proxy: any, idx: number) => {
      const checkPing = proxyCheck && Number.isFinite(Number(proxyCheck.ping_ms)) ? ` | Ping: ${Number(proxyCheck.ping_ms)} ms` : '';
      const checked = proxyCheck && proxyCheck.index === idx ? `<span data-proxy-check-status="${idx}" class="${proxyCheck.ok ? 'ok' : 'bad'}">${proxyCheck.ok ? 'IP: ' : 'Error: '}${htmlEscape(proxyCheck.ip || proxyCheck.detail)}${htmlEscape(checkPing)}</span>` : `<span data-proxy-check-status="${idx}"></span>`;
      return `<tr><td><strong>${htmlEscape(String(proxy.type).toUpperCase())}</strong><span>${htmlEscape(this.network.formatHostPort(proxy.host, proxy.port))}</span></td><td>${this.network.proxyIpLabel(proxy)}${checked}</td><td>${htmlEscape(proxy.login ? 'user/pass' : 'none')}</td><td>${this.network.proxyPort(idx)}</td><td>${this.network.proxyLoadCounts(assignments, [idx])[idx] || 0}</td><td><form method="post" action="/proxy/check" data-proxy-check-form><input type="hidden" name="index" value="${idx}"><button type="submit" class="neutral" data-proxy-check-button="${idx}">Check</button></form><form method="post" action="/proxy/delete"><input type="hidden" name="index" value="${idx}"><button class="danger">Delete</button></form></td></tr>`;
    }).join('');
    const assignmentRows = proxies.map((proxy: any, idx: number) => `<tr><td>${idx}</td><td>${htmlEscape(this.network.proxyKey(proxy))}</td><td>${this.network.proxyIpLabel(proxy)}</td><td>${this.network.proxyLoadCounts(assignments, [idx])[idx] || 0}</td></tr>`).join('');

    return `<main>
      ${message ? `<div class="msg">${htmlEscape(message)}</div>` : ''}
      <section><h2>Router</h2><div class="grid">
        ${this.metric('DHCP/NAT', data.dnsmasq ? 'Running' : 'Stopped', data.dnsmasq)}
        ${this.metric('WiFi Hotspot', data.hostapd ? 'Running' : hotspot.enabled ? 'Configured' : 'Off', data.hostapd)}
        ${this.metric('IP Forward', data.ip_forward, data.ip_forward === '1')}
        ${this.metric('Proxy Engine', data.redsocks ? 'Running' : 'Stopped', data.redsocks)}
        ${this.metric('LAN CIDR', state.lan_cidr || '')}
        ${this.metric('DHCP Range', `${data.dhcp_range?.[0] || ''} - ${data.dhcp_range?.[1] || ''}`)}
        ${this.metric('WAN MAC', data.wan_mac || '')}
        ${this.metric('LAN MAC', data.lan_mac || '')}
      </div><div class="actions" style="margin-top:14px"><form method="post" action="/setup"><button class="primary">Apply LAN Router Config</button></form><form method="post" action="/lan/save"><input type="text" name="lan_cidr" value="${htmlEscape(state.lan_cidr || '')}"><button class="neutral">Save LAN CIDR</button></form><form method="post" action="/mac/rotate"><input type="hidden" name="target" value="wan"><button class="neutral">Rotate WAN MAC</button></form><form method="post" action="/mac/rotate"><input type="hidden" name="target" value="lan"><button class="neutral">Rotate LAN MAC</button></form><form method="post" action="/stop"><button class="danger">Stop Test Router</button></form></div></section>
      <section><h2>WiFi Hotspot</h2><div class="grid">${this.metric('Interface', hotspot.ifname || selectedWifi || 'none')}${this.metric('SSID', hotspot.ssid)}${this.metric('Band', this.state.wifiBandLabel(hotspot.band))}${this.metric('Channel', hotspot.channel)}${this.metric('Country', hotspot.country)}</div><form method="post" action="/hotspot/save" style="margin-top:14px"><input type="text" name="ifname" list="wifi-ifaces" value="${htmlEscape(selectedWifi)}" placeholder="wlan0"><datalist id="wifi-ifaces">${wifiOptions}</datalist><select name="band">${bandOptions}</select><input type="text" name="ssid" maxlength="32" value="${htmlEscape(hotspot.ssid)}"><input type="password" name="password" placeholder="${hotspot.password ? 'configured' : '8-63 chars'}"><input type="text" name="country" maxlength="2" value="${htmlEscape(hotspot.country)}"><input type="number" name="channel" min="1" max="161" value="${hotspot.channel}"><button class="primary">Start Hotspot</button></form><div class="actions" style="margin-top:12px"><form method="post" action="/hotspot/stop"><button class="danger">Stop Hotspot</button></form></div></section>
      <section><h2>Network Cards</h2><table><thead><tr><th>Interface</th><th>Role</th><th>State</th><th>MAC</th><th>Addresses</th></tr></thead><tbody>${cards || '<tr><td colspan="5">Khong doc duoc card mang.</td></tr>'}</tbody></table></section>
      <section><h2>Devices</h2><table><thead><tr><th>IP</th><th>Name</th><th>MAC</th><th>Hostname</th><th>Connection</th><th>Status</th><th>Proxy</th><th>DHCP Binding</th></tr></thead><tbody>${deviceRows || '<tr><td colspan="8">Chua co thiet bi.</td></tr>'}</tbody></table><form method="post" action="/assign" style="margin-top:14px" data-proxy-assign-form data-assign-key="manual"><input type="text" name="ip" placeholder="Gan thu cong IP"><select name="proxy">${proxyOptions.join('')}</select><button data-assign-button data-default-text="Assign IP">Assign IP</button><span data-assign-status="manual"></span></form><div class="actions" style="margin-top:12px"><form method="post" action="/assign/clear"><button class="neutral">Clear Assignments</button></form><form method="post" action="/devices/clear-offline"><button class="neutral">Clear Offline</button></form></div></section>
      <section><h2>Fast Proxy Assign</h2><div class="grid">${this.metric('Assigned Devices', Object.keys(assignments).length)}${this.metric('Visible Devices', (data.leases || []).length)}${this.metric('Proxies', proxies.length)}${this.metric('Mode', 'One device / one proxy')}</div><div class="actions" style="margin-top:14px"><form method="post" action="/assign/bulk"><input type="hidden" name="scope" value="online"><select name="family">${familyOptions}</select><button class="primary">Assign Online Devices</button></form><form method="post" action="/assign/bulk"><input type="hidden" name="scope" value="all"><select name="family">${familyOptions}</select><button>Assign All Known</button></form></div><table style="margin-top:12px"><thead><tr><th>#</th><th>Proxy</th><th>IP</th><th>Devices</th></tr></thead><tbody>${assignmentRows || '<tr><td colspan="4">Chua co proxy de gan.</td></tr>'}</tbody></table></section>
      <section><h2>Proxy</h2><form method="post" action="/proxy/add"><select name="type"><option value="http">HTTP</option><option value="https">HTTPS</option><option value="socks5" selected>SOCKS5</option><option value="socks4">SOCKS4</option></select><select name="ip_version"><option value="4">IPv4</option><option value="6">IPv6</option></select><input type="text" name="host" placeholder="proxy.example.com"><input type="number" name="port" min="1" max="65535" placeholder="1080"><input type="text" name="login" placeholder="username"><input type="password" name="password" placeholder="password"><button>Add Proxy</button></form><form method="post" action="/proxy/add" style="margin-top:10px"><input type="text" name="url" placeholder="Hoac dan URL: socks5://user:pass@host:port"><select name="ip_version"><option value="4">IPv4</option><option value="6">IPv6</option></select><button>Add Proxy</button></form><form class="stack-form" method="post" action="/proxy/add-bulk" style="margin-top:10px"><textarea name="bulk_proxies" spellcheck="false" placeholder="sock5:206.125.175.208:28367:DlnaEv:Qlfcub:ipv4&#10;sock5:206.125.175.117:20217:PYiGvc:YZunKT:ipv6&#10;http:200.229.24.170:25148:YufMaX:WJamao:ipv4"></textarea><button class="primary">Add Bulk</button></form><table style="margin-top:12px"><thead><tr><th>Upstream proxy</th><th>Proxy IP</th><th>Auth</th><th>Local port</th><th>Devices</th><th>Action</th></tr></thead><tbody>${proxyRows || '<tr><td colspan="6">Chua co proxy. Thiet bi hien dang di Direct/NAT.</td></tr>'}</tbody></table></section>
      <section><h2>System</h2><pre>${htmlEscape(data.interfaces || '')}</pre><pre>${htmlEscape(data.routes || '')}</pre></section>
    </main>`;
  }

  private metric(label: string, value: unknown, status?: boolean): string {
    const cls = status === undefined ? '' : status ? ' class="ok"' : ' class="bad"';
    return `<div class="metric"><b>${htmlEscape(label)}</b><span${cls}>${htmlEscape(value)}</span></div>`;
  }
}
