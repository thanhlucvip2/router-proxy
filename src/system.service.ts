import { Injectable } from '@nestjs/common';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { mkdirSync } from 'node:fs';

@Injectable()
export class SystemService {
  sh(cmd: string[], check = true, capture = true): string {
    const result = spawnSync(cmd[0], cmd.slice(1), {
      encoding: 'utf8',
      stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'ignore',
    });
    if (check && result.status !== 0) {
      const detail = String(result.stderr || result.stdout || '').trim();
      throw new Error(`${cmd.join(' ')} failed: ${detail}`);
    }
    return String(result.stdout || '').trim();
  }

  sudo(cmd: string[], check = true, capture = true): string {
    if (typeof process.geteuid === 'function' && process.geteuid() === 0) {
      return this.sh(cmd, check, capture);
    }
    return this.sh(['sudo', '-n', ...cmd], check, capture);
  }

  sudoInput(cmd: string[], input: string, check = true): string {
    const actual = typeof process.geteuid === 'function' && process.geteuid() === 0 ? cmd : ['sudo', '-n', ...cmd];
    const result = spawnSync(actual[0], actual.slice(1), {
      input,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    if (check && result.status !== 0) {
      const detail = String(result.stderr || result.stdout || '').trim();
      throw new Error(`${actual.join(' ')} failed: ${detail}`);
    }
    return String(result.stdout || '').trim();
  }

  sudoSuccess(cmd: string[]): boolean {
    const actual = typeof process.geteuid === 'function' && process.geteuid() === 0 ? cmd : ['sudo', '-n', ...cmd];
    return spawnSync(actual[0], actual.slice(1), { stdio: 'ignore' }).status === 0;
  }

  sudoWriteText(path: string, text: string): void {
    if (typeof process.geteuid === 'function' && process.geteuid() === 0) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, text);
      return;
    }
    const result = spawnSync('sudo', ['-n', 'tee', path], {
      input: text,
      encoding: 'utf8',
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    if (result.status !== 0) {
      throw new Error(`Khong ghi duoc ${path}: ${String(result.stderr || '').trim()}`);
    }
  }

  commandExists(name: string): boolean {
    return spawnSync('sh', ['-c', `command -v "$1" >/dev/null 2>&1`, 'sh', name], { stdio: 'ignore' }).status === 0;
  }

  requireCommands(names: string[]): void {
    const missing = names.filter((name) => !this.commandExists(name));
    if (missing.length) {
      const install = 'sudo apt-get update && sudo apt-get install -y dnsmasq-base redsocks iptables conntrack hostapd iw';
      throw new Error(`Thieu lenh: ${missing.join(', ')}. Cai bang: ${install}`);
    }
  }

  deleteExistingRule(cmd: string[]): void {
    for (let idx = 0; idx < 50; idx += 1) {
      if (!this.sudoSuccess(cmd)) return;
    }
  }

  pidAlive(pidFile: string): boolean {
    try {
      const pid = Number(readFileSync(pidFile, 'utf8').trim());
      if (!Number.isInteger(pid)) return false;
      return this.sudoSuccess(['kill', '-0', String(pid)]);
    } catch {
      return false;
    }
  }

  stopPid(pidFile: string): void {
    let pid = 0;
    try {
      pid = Number(readFileSync(pidFile, 'utf8').trim());
    } catch {
      return;
    }
    if (!Number.isInteger(pid) || pid <= 0) return;
    for (const sig of ['TERM', 'KILL']) {
      this.sudo(['kill', `-${sig}`, String(pid)], false);
      for (let idx = 0; idx < 10; idx += 1) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
        if (!this.pidAlive(pidFile)) break;
      }
      if (!this.pidAlive(pidFile)) break;
    }
    rmSync(pidFile, { force: true });
  }

  readJsonCommand(cmd: string[], fallback: any[] = []): any[] {
    try {
      return JSON.parse(this.sh(cmd, false) || '[]');
    } catch {
      return fallback;
    }
  }

  readFile(path: string, fallback = ''): string {
    try {
      return readFileSync(path, 'utf8');
    } catch {
      return fallback;
    }
  }

  fileExists(path: string): boolean {
    return existsSync(path);
  }
}
