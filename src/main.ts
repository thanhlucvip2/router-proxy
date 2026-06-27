import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { json, urlencoded } from 'express';
import cookieParser from 'cookie-parser';
import { WebSocketServer } from 'ws';
import { writeFileSync, rmSync } from 'node:fs';
import { AppContext } from './app.context';
import { AppModule } from './app.module';
import { DEFAULT_ADMIN_USER, DEFAULT_LAN_CIDR, WEB_PID } from './constants';
import { NetworkService } from './network.service';
import { StateService } from './state.service';
import { StatusService } from './status.service';
import { DashboardService } from './dashboard.service';
import { runDomainProxyWorker } from './domain-proxy.worker';

interface CliOptions {
  wan?: string;
  lan?: string;
  lanCidr?: string;
  host: string;
  port: number;
  apply: boolean;
  stop: boolean;
  replace: boolean;
  adminUser: string;
  domainProxyWorker?: string;
}

function parseArgs(argv: string[]): CliOptions {
  const args: CliOptions = { host: '0.0.0.0', port: 8080, apply: false, stop: false, replace: false, adminUser: DEFAULT_ADMIN_USER };
  for (let idx = 0; idx < argv.length; idx += 1) {
    const item = argv[idx];
    const next = () => argv[++idx] || '';
    if (item === '--wan') args.wan = next();
    else if (item === '--lan') args.lan = next();
    else if (item === '--lan-cidr') args.lanCidr = next();
    else if (item === '--host') args.host = next();
    else if (item === '--port') args.port = Number(next());
    else if (item === '--apply') args.apply = true;
    else if (item === '--stop') args.stop = true;
    else if (item === '--replace') args.replace = true;
    else if (item === '--admin-user') args.adminUser = next();
    else if (item === '--domain-proxy-worker') args.domainProxyWorker = next();
  }
  return args;
}

async function bootstrap(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.domainProxyWorker) {
    runDomainProxyWorker(args.domainProxyWorker);
    return;
  }
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { logger: ['error', 'warn', 'log'] });
  app.use(json());
  app.use(urlencoded({ extended: false }));
  app.use(cookieParser());

  const state = app.get(StateService);
  const network = app.get(NetworkService);
  const status = app.get(StatusService);
  const dashboard = app.get(DashboardService);
  const ctx = app.get(AppContext);

  const wan = args.wan || network.detectWan();
  const lan = args.lan || network.detectLan(wan);
  if (!wan || !lan) throw new Error('Khong detect duoc WAN/LAN interface');
  network.setRuntime(wan, lan);

  if (args.stop) {
    const currentState = state.loadState();
    const lanIf = network.activeLanIf(lan, currentState);
    network.stopWebServer();
    network.stopRouter(wan, lanIf, lan);
    if (lanIf !== lan) for (const staleIf of network.interfaceList(lan)) network.stopRouter(wan, staleIf, lan);
    console.log(`Stopped router services/rules for WAN=${wan} LAN=${lanIf}`);
    await app.close();
    return;
  }

  if (args.replace) network.stopWebServer();
  const currentState = state.loadState();
  const lanCidr = network.normalizeLanCidr(args.lanCidr || currentState.lan_cidr || DEFAULT_LAN_CIDR);
  if (currentState.lan_cidr !== lanCidr) {
    currentState.lan_cidr = lanCidr;
    state.saveState(currentState);
  }
  ctx.options = { wan, lan, lanCidr, host: args.host, port: args.port, adminUser: args.adminUser };
  ctx.adminPassword = state.loadOrCreateAdminPassword();
  ctx.sessionToken = state.loadOrCreateSessionToken();

  if (args.apply) network.applyRouterStack(wan, lan, lanCidr);

  const server = await app.listen(args.port, args.host);
  const wsServer = new WebSocketServer({ noServer: true });
  wsServer.on('connection', (socket) => {
    let nextSend = 0;
    let lastHtml = '';
    let force = true;
    socket.on('message', (raw) => {
      try {
        const payload = JSON.parse(raw.toString());
        if (payload.type === 'refresh') force = true;
      } catch {
        // ignore invalid websocket payloads
      }
    });
    const timer = setInterval(() => {
      if (socket.readyState !== socket.OPEN) return;
      const now = Date.now();
      if (!force && now < nextSend) return;
      try {
        const data = status.commandStatus(wan, lan);
        const html = dashboard.renderMain(data);
        if (force || html !== lastHtml) {
          socket.send(JSON.stringify({ type: 'dashboard', html, ts: Math.floor(now / 1000) }));
          lastHtml = html;
        }
        force = false;
        nextSend = now + 5000;
      } catch (error: any) {
        socket.send(JSON.stringify({ type: 'error', detail: String(error?.message || error) }));
      }
    }, 1000);
    socket.on('close', () => clearInterval(timer));
  });
  server.on('upgrade', (req, socket, head) => {
    if (!req.url?.startsWith('/ws/status')) {
      socket.destroy();
      return;
    }
    wsServer.handleUpgrade(req, socket, head, (ws) => wsServer.emit('connection', ws, req));
  });

  rmSync(WEB_PID, { force: true });
  writeFileSync(WEB_PID, String(process.pid));
  console.log(`Router manager: http://127.0.0.1:${args.port}`);
  console.log(`WAN=${wan} LAN=${lan} LAN_IP=${lanCidr}`);
  console.log(`Admin login: ${args.adminUser} / ${ctx.adminPassword}`);
  const cleanup = () => {
    rmSync(WEB_PID, { force: true });
  };
  process.on('exit', cleanup);
  process.on('SIGTERM', () => {
    cleanup();
    process.exit(0);
  });
}

bootstrap().catch((error) => {
  console.error(error?.message || error);
  process.exit(1);
});
