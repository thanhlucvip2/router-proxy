import { All, Body, Controller, Get, Head, Post, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { timingSafeEqual } from 'node:crypto';
import { AppContext } from './app.context';
import { DashboardService } from './dashboard.service';
import { NetworkService } from './network.service';
import { StateService } from './state.service';
import { StatusService } from './status.service';
import { formValue, normalizeMac } from './util';

@Controller()
export class AppController {
  constructor(
    private readonly ctx: AppContext,
    private readonly dashboard: DashboardService,
    private readonly network: NetworkService,
    private readonly state: StateService,
    private readonly status: StatusService,
  ) {}

  private safeEqual(left: string, right: string): boolean {
    const a = Buffer.from(left);
    const b = Buffer.from(right);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  private authenticated(req: Request): boolean {
    if (!this.ctx.adminPassword) return true;
    const token = (req as any).cookies?.router_session || '';
    return Boolean(token) && this.safeEqual(String(token), this.ctx.sessionToken);
  }

  private redirect(res: Response, message = ''): void {
    res.redirect(303, `/${message ? `?msg=${encodeURIComponent(message)}` : ''}`);
  }

  private wantsJson(req: Request): boolean {
    return String(req.headers.accept || '').includes('application/json');
  }

  private currentLanIf(): string {
    return this.network.activeLanIf(this.ctx.options.lan);
  }

  private currentLanCidr(): string {
    return this.state.loadState().lan_cidr || this.ctx.options.lanCidr;
  }

  @Get('/login')
  login(@Query('msg') msg: string, @Res() res: Response): void {
    res.type('html').send(this.dashboard.login(msg || '', this.ctx.options.adminUser));
  }

  @Get('/logout')
  logout(@Res() res: Response): void {
    res.clearCookie('router_session', { path: '/' });
    res.redirect(303, '/login?msg=Logged%20out');
  }

  @Post('/login')
  doLogin(@Body() body: any, @Res() res: Response): void {
    const username = formValue(body, 'username');
    const password = formValue(body, 'password');
    if (this.safeEqual(username, this.ctx.options.adminUser) && this.safeEqual(password, this.ctx.adminPassword)) {
      res.cookie('router_session', this.ctx.sessionToken, { path: '/', httpOnly: true, sameSite: 'lax' });
      res.redirect(303, '/');
      return;
    }
    res.status(401).type('html').send(this.dashboard.login('Sai username hoac password', this.ctx.options.adminUser));
  }

  @Get('/api/status')
  apiStatus(@Req() req: Request, @Res() res: Response): void {
    if (!this.authenticated(req)) {
      res.redirect(303, '/login');
      return;
    }
    res.json(this.status.commandStatus(this.ctx.options.wan, this.ctx.options.lan));
  }

  @Get('/')
  index(@Req() req: Request, @Res() res: Response, @Query('msg') msg = ''): void {
    if (!this.authenticated(req)) {
      res.redirect(303, '/login');
      return;
    }
    try {
      const data = this.status.commandStatus(this.ctx.options.wan, this.ctx.options.lan);
      res.type('html').send(this.dashboard.renderPage(data, msg));
    } catch (error: any) {
      res.status(500).type('html').send(`<pre>${String(error?.message || error)}</pre>`);
    }
  }

  @Head('*')
  head(@Req() req: Request, @Res() res: Response): void {
    if (!this.authenticated(req)) {
      res.redirect(303, '/login');
      return;
    }
    res.status(200).end();
  }

  @Post('*')
  async post(@Req() req: Request, @Res() res: Response, @Body() body: any): Promise<void> {
    if (req.path === '/login') {
      this.doLogin(body, res);
      return;
    }
    if (!this.authenticated(req)) {
      res.redirect(303, '/login');
      return;
    }
    try {
      const path = req.path;
      if (path === '/setup') {
        const lanIf = this.network.applyRouterStack(this.ctx.options.wan, this.ctx.options.lan, this.currentLanCidr());
        this.redirect(res, `Router config applied on ${lanIf}`);
        return;
      }
      if (path === '/lan/save') {
        const lanCidr = this.network.normalizeLanCidr(formValue(body, 'lan_cidr'));
        const state = this.state.loadState();
        state.lan_cidr = lanCidr;
        state.assignments = Object.fromEntries(Object.entries(state.assignments || {}).filter(([ip]) => this.network.listClientIps(this.currentLanIf(), lanCidr).includes(ip) || true));
        this.state.saveState(state);
        this.ctx.options.lanCidr = lanCidr;
        const lanIf = this.network.applyRouterStack(this.ctx.options.wan, this.ctx.options.lan, lanCidr);
        const [start, end] = this.network.dhcpRangeFor(lanCidr);
        this.redirect(res, `LAN CIDR saved on ${lanIf}: ${lanCidr}; DHCP ${start} - ${end}`);
        return;
      }
      if (path === '/stop') {
        const state = this.state.loadState();
        const lanIf = this.network.activeLanIf(this.ctx.options.lan, state);
        this.network.stopRouter(this.ctx.options.wan, lanIf, this.ctx.options.lan);
        if (lanIf !== this.ctx.options.lan) for (const staleIf of this.network.interfaceList(this.ctx.options.lan)) this.network.stopRouter(this.ctx.options.wan, staleIf, this.ctx.options.lan);
        this.redirect(res, 'Router stopped');
        return;
      }
      if (path === '/mac/rotate') {
        const target = formValue(body, 'target');
        const [, newMac] = this.network.rotateInterfaceMac(target === 'wan' ? this.ctx.options.wan : this.currentLanIf());
        this.network.applyRouterStack(this.ctx.options.wan, this.ctx.options.lan, this.currentLanCidr());
        this.redirect(res, `${target.toUpperCase()} MAC rotated: ${newMac}`);
        return;
      }
      if (path === '/hotspot/save') {
        const state = this.state.loadState();
        const oldHotspot = this.state.normalizedHotspot(state);
        const ifname = formValue(body, 'ifname').trim();
        if (!ifname) throw new Error('Chua chon card WiFi');
        this.network.requireInterface(ifname, 'WiFi');
        if (ifname === this.ctx.options.wan) throw new Error('Card WiFi hotspot khong duoc trung voi WAN');
        const wifiNames = this.network.wirelessInterfaces();
        if (wifiNames.length && !wifiNames.includes(ifname)) throw new Error(`${ifname} khong phai WiFi interface. WiFi hien co: ${wifiNames.join(', ')}`);
        const ssid = formValue(body, 'ssid').trim();
        if (!ssid) throw new Error('Ten WiFi dang trong');
        const password = formValue(body, 'password') || oldHotspot.password;
        if (password.length < 8 || password.length > 63) throw new Error('Password WiFi phai tu 8 den 63 ky tu');
        const band = this.state.wifiBand(formValue(body, 'band', oldHotspot.band));
        if (!band) throw new Error('Band WiFi chi ho tro 2.4 hoac 5 GHz');
        const country = this.state.normalizeWifiCountry(formValue(body, 'country', oldHotspot.country));
        let channel = Number(formValue(body, 'channel', String(oldHotspot.channel)));
        if (!Number.isInteger(channel) || !this.state.validChannelsForBand(band).includes(channel)) channel = this.state.defaultChannelForBand(band);
        state.hotspot = { enabled: true, ifname, ssid, password, band, country, channel };
        this.state.saveState(state);
        const lanIf = this.network.applyRouterStack(this.ctx.options.wan, this.ctx.options.lan, this.currentLanCidr());
        this.redirect(res, `WiFi hotspot started on ${lanIf}`);
        return;
      }
      if (path === '/hotspot/stop') {
        const state = this.state.loadState();
        const hotspot = this.state.normalizedHotspot(state);
        const oldLanIf = this.network.activeLanIf(this.ctx.options.lan, state);
        hotspot.enabled = false;
        state.hotspot = hotspot;
        this.state.saveState(state);
        this.network.stopRouter(this.ctx.options.wan, oldLanIf, this.ctx.options.lan);
        const lanIf = this.network.applyRouterStack(this.ctx.options.wan, this.ctx.options.lan, this.currentLanCidr());
        this.redirect(res, `WiFi hotspot stopped; LAN output ${lanIf}`);
        return;
      }
      if (path === '/proxy/add') {
        const proxy = this.network.parseProxyForm(body);
        const state = this.state.loadState();
        if (!state.proxies.some((item) => this.network.proxyIdentity(item) === this.network.proxyIdentity(proxy))) state.proxies.push(proxy);
        this.state.saveState(state);
        this.network.applyProxyRules(this.currentLanIf(), []);
        this.redirect(res, 'Proxy added');
        return;
      }
      if (path === '/proxy/add-bulk') {
        const proxies = this.network.parseProxyBulk(formValue(body, 'bulk_proxies'));
        if (!proxies.length) throw new Error('Chua co proxy nao de them');
        const state = this.state.loadState();
        const identities = new Set(state.proxies.map((item) => this.network.proxyIdentity(item)));
        let added = 0;
        let skipped = 0;
        for (const proxy of proxies) {
          const identity = this.network.proxyIdentity(proxy);
          if (identities.has(identity)) {
            skipped += 1;
            continue;
          }
          state.proxies.push(proxy);
          identities.add(identity);
          added += 1;
        }
        this.state.saveState(state);
        if (added) this.network.applyProxyRules(this.currentLanIf(), []);
        this.redirect(res, `Bulk proxy added: ${added}; duplicate skipped: ${skipped}`);
        return;
      }
      if (path === '/proxy/check') {
        const idx = Number(formValue(body, 'index', '-1'));
        const result = await this.network.checkProxy(idx);
        res.json({ index: idx, ...result });
        return;
      }
      if (path === '/proxy/delete') {
        this.network.removeProxy(Number(formValue(body, 'index', '-1')), this.currentLanIf());
        this.redirect(res, 'Proxy deleted');
        return;
      }
      if (path === '/assign') {
        const ip = formValue(body, 'ip').trim();
        ipaddrParse(ip);
        const proxyIdx = formValue(body, 'proxy');
        const state = this.state.loadState();
        let proxyLabel = 'Direct/NAT';
        if (proxyIdx === '') delete state.assignments[ip];
        else {
          const idx = Number(proxyIdx);
          if (!Number.isInteger(idx) || idx < 0 || idx >= state.proxies.length) throw new Error('Proxy index khong hop le');
          state.assignments[ip] = idx;
          proxyLabel = this.network.proxyKey(state.proxies[idx]);
        }
        this.state.saveState(state);
        this.network.applyProxyRulesSoon(this.currentLanIf(), [ip]);
        if (this.wantsJson(req)) {
          res.json({ ok: true, ip, proxy: proxyIdx, proxyLabel, detail: `Queued ${ip} -> ${proxyLabel}` });
          return;
        }
        this.redirect(res, 'Assignment saved');
        return;
      }
      if (path === '/assign/bulk') {
        const family = this.network.proxyFamily(formValue(body, 'family', 'all'));
        const scope = formValue(body, 'scope', 'online');
        const lanIf = this.currentLanIf();
        const lanCidr = this.currentLanCidr();
        const state = this.state.loadState();
        let clients: string[] = [];
        if (scope === 'online') {
          const data = this.status.commandStatus(this.ctx.options.wan, this.ctx.options.lan);
          clients = (data.leases || []).filter((row: any) => row.online).map((row: any) => String(row.ip || '')).filter(Boolean);
        } else {
          clients = this.network.assignmentClientIps(lanIf, lanCidr, state);
        }
        const cleanClients = this.network.normalizeAssignmentIps(lanCidr, clients);
        const result = this.network.assignClientsToProxies(state, cleanClients, family);
        this.state.saveState(state);
        this.network.applyProxyRules(lanIf, cleanClients);
        const detail = `Assigned ${result.count} devices to ${result.proxyCount} ${this.network.proxyFamilyLabel(family)} proxies`;
        if (this.wantsJson(req)) {
          res.json({ ok: true, ...result, detail });
          return;
        }
        this.redirect(res, detail);
        return;
      }
      if (path === '/device/edit') {
        const mac = normalizeMac(formValue(body, 'mac'));
        if (!mac) throw new Error('MAC khong hop le');
        const lanCidr = this.currentLanCidr();
        const name = formValue(body, 'name').trim().slice(0, 64);
        const dhcpIp = this.state.normalizeDhcpReservationIp(formValue(body, 'ip_address'), lanCidr);
        const state = this.state.loadState();
        const prev = state.dhcp_reservations[mac] || '';
        if (dhcpIp) {
          for (const [otherMac, otherIp] of Object.entries(state.dhcp_reservations)) {
            if (normalizeMac(otherMac) !== mac && otherIp === dhcpIp) throw new Error(`DHCP IP ${dhcpIp} da duoc gan cho ${otherMac}`);
          }
          state.dhcp_reservations[mac] = dhcpIp;
        } else delete state.dhcp_reservations[mac];
        if (name) state.device_names[mac] = name;
        else delete state.device_names[mac];
        const removed = prev !== dhcpIp ? this.network.removeDnsmasqLeasesForMac(mac) : [];
        this.state.saveDhcpBindingsConfig(state);
        this.state.saveState(state);
        const lanIf = this.currentLanIf();
        this.network.startDnsmasq(lanIf, lanCidr);
        this.redirect(res, prev !== dhcpIp ? this.network.refreshDhcpClient(mac, lanIf, [prev, dhcpIp, ...removed]) : 'Device updated');
        return;
      }
      if (path === '/assign/clear') {
        const state = this.state.loadState();
        const oldAssignedIps = Object.keys(state.assignments || {});
        state.assignments = {};
        if (state.load_balance) state.load_balance.enabled = false;
        this.state.saveState(state);
        this.network.applyProxyRules(this.currentLanIf(), oldAssignedIps);
        this.redirect(res, 'All devices set to Direct/NAT');
        return;
      }
      if (path === '/devices/clear-offline') {
        const data = this.status.commandStatus(this.ctx.options.wan, this.ctx.options.lan);
        const state = this.state.loadState();
        const now = this.status.timestampNow();
        let count = 0;
        for (const row of data.leases || []) {
          const key = this.status.devicePresenceKey(row);
          if (key && !row.online && !(key in state.hidden_offline_devices)) {
            state.hidden_offline_devices[key] = now;
            count += 1;
          }
        }
        this.state.saveState(state);
        this.redirect(res, `Cleared ${count} offline devices; new active devices will reappear automatically`);
        return;
      }
      res.status(404).send('not found');
    } catch (error: any) {
      if ((req.path === '/assign' || req.path === '/assign/bulk') && this.wantsJson(req)) {
        res.status(500).json({ ok: false, detail: String(error?.message || error) });
        return;
      }
      if (req.path === '/proxy/check') {
        res.status(500).json({ ok: false, detail: String(error?.message || error), ip: '', ping_ms: null });
        return;
      }
      res.status(500).type('html').send(`<pre>${String(error?.message || error)}</pre>`);
    }
  }

  @All('*')
  notFound(@Res() res: Response): void {
    res.status(404).send('not found');
  }
}

function ipaddrParse(ip: string): void {
  // Lazy import keeps the controller free of parser details in route code.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  require('ipaddr.js').parse(ip);
}
