// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// Starts the Wall Connector and Backup Gateway simulators and tcmon,
// completes first-run setup through the real forms, adds the simulated Wall
// Connector and Gateway via the GUI and saves the signed-in browser state
// for the tests.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { request } from '@playwright/test';
import { BASE_URL } from './playwright.config.mjs';

export const PASSWORD = 'purple otter kayak sunrise';
const ROOT = resolve(import.meta.dirname, '..');
const SIM = '127.0.0.1:18099';
const GWSIM = '127.0.0.1:18098';
const GW_PASSWORD = 'E2EPW'; // the simulator's test password

function start(cmd, args, env) {
  const p = spawn(join(ROOT, 'bin', cmd), args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  p.stdout.on('data', (d) => { log += d; });
  p.stderr.on('data', (d) => { log += d; });
  return { p, log: () => log };
}

async function until(fn, what, ms = 20000) {
  const end = Date.now() + ms;
  for (;;) {
    try { const v = await fn(); if (v) return v; } catch { /* not ready */ }
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

const tokenOf = (html) => html.match(/name="csrf_token" value="([^"]+)"/)?.[1];

export default async function globalSetup() {
  const data = mkdtempSync(join(tmpdir(), 'tcmon-e2e-'));
  const sim = start('wcsim', ['-listen', SIM, '-scenario', 'charging']);
  const gwsim = start('gwsim', ['-listen', GWSIM, '-scenario', 'day'], { GWSIM_PASSWORD: GW_PASSWORD });
  const app = start('tcmon', ['serve', '-data-dir', data], {
    TCMON_LISTEN: '127.0.0.1:18443',
    TCMON_PUBLIC_HOSTNAMES: 'localhost',
    TZ: 'UTC',
  });
  writeFileSync(join(import.meta.dirname, '.pids.json'), JSON.stringify([sim.p.pid, gwsim.p.pid, app.p.pid]));
  const setupToken = await until(() => app.log().match(/"setup_token":"([A-Z0-9]+)"/)?.[1], 'setup token');

  const ctx = await request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true });
  await until(async () => (await ctx.get('/healthz')).ok(), 'tcmon to listen');

  const setupPage = await (await ctx.get('/setup')).text();
  let res = await ctx.post('/setup', {
    form: { csrf_token: tokenOf(setupPage), token: setupToken, password: PASSWORD, confirm: PASSWORD },
    headers: { 'Sec-Fetch-Site': 'same-origin', Origin: BASE_URL },
    maxRedirects: 0,
  });
  if (res.status() !== 303) throw new Error(`setup failed: ${res.status()} ${await res.text()}\n${app.log()}`);

  const form = await (await ctx.get('/settings/devices/new')).text();
  res = await ctx.post('/settings/devices/new', {
    form: {
      csrf_token: tokenOf(form), action: 'save', name: 'Garage', address: SIM, breaker: '60', voltage: '240', hz: '60',
      interval: '60', plugged_interval: '1', fast_when_plugged: '1', enabled: '1',
    },
    headers: { 'Sec-Fetch-Site': 'same-origin', Origin: BASE_URL },
    maxRedirects: 0,
  });
  if (res.status() !== 303) throw new Error(`adding the device failed: ${res.status()} ${await res.text()}`);
  // The Backup Gateway, the way an owner adds it: find it, confirm the
  // certificate, enter the customer password.
  const post = (path, form) => ctx.post(path, {
    form, headers: { 'Sec-Fetch-Site': 'same-origin', Origin: BASE_URL }, maxRedirects: 0,
  });
  const gwPage = await (await ctx.get('/settings/gateway')).text();
  const gwForm = { csrf_token: tokenOf(gwPage), name: 'Powerwall', interval: '15', charging_interval: '5' };
  let gwRes;
  try {
    gwRes = await until(async () => {
      const r = await post('/settings/gateway/find', { ...gwForm, address: GWSIM });
      return r.status() === 200 ? r : null;
    }, 'the Gateway simulator');
  } catch (e) {
    throw new Error(`${e.message}\n--- gwsim log ---\n${gwsim.log()}`);
  }
  const pin = (await gwRes.text()).match(/name="pin" value="([0-9a-f]{64})"/)?.[1];
  res = await post('/settings/gateway', { ...gwForm, address: GWSIM, pin, trust: '1', enabled: '1', password: GW_PASSWORD });
  if (res.status() !== 200) throw new Error(`adding the Gateway failed: ${res.status()} ${await res.text()}`);

  // Wait for the first poll so the dashboard has data.
  try {
    await until(async () => (await (await ctx.get('/')).text()).includes('Charging'), 'first poll');
  } catch (e) {
    throw new Error(`${e.message}\n--- tcmon log ---\n${app.log()}\n--- simulator log ---\n${sim.log()}`);
  }

  mkdirSync(join(import.meta.dirname, '.auth'), { recursive: true });
  await ctx.storageState({ path: join(import.meta.dirname, '.auth', 'state.json') });
  await ctx.dispose();
  process.env.TCMON_E2E_SIM = `http://${SIM}`;
}
