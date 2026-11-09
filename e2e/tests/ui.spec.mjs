// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { BASE_URL } from '../playwright.config.mjs';

const PASSWORD = 'purple otter kayak sunrise';
const SIM = 'http://127.0.0.1:18099';
const PAGES = ['/', '/devices/1', '/alerts', '/alerts/rules/handle_temp_high', '/notifications', '/notifications/new',
  '/settings', '/settings/devices', '/settings/devices/new', '/settings/devices/1', '/settings/security',
  '/diagnostics', '/about', '/costs', '/costs?period=month', '/costs?period=year', '/settings/energy'];
const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

// Collects CSP / Trusted Types violations and script errors.
function watch(page) {
  const problems = [];
  page.on('console', (m) => {
    if (/content[- ]security[- ]policy|refused to|trusted ?(html|script|type)/i.test(m.text())) problems.push(m.text());
  });
  page.on('pageerror', (e) => problems.push(String(e)));
  return problems;
}

// pollNow asks tcmon to poll device 1 at once (as the "Poll now" button does).
async function pollNow(page) {
  const csrf = await page.locator('input[name="csrf_token"]').first().inputValue();
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await page.request.post('/devices/1/poll', {
      form: { csrf_token: csrf, back: 'home' }, headers: { 'Sec-Fetch-Site': 'same-origin', Origin: BASE_URL }, maxRedirects: 0,
    });
    if (!(res.headers().location ?? '').includes('poll-limited')) return;
    await page.waitForTimeout(11_000); // poll-now is rate limited to once per 10 s
  }
}

async function settle(page, path) {
  if (path.startsWith('/devices/')) {
    await expect(page.locator('tcmon-chart').first().locator('svg, p.hint')).toBeVisible();
    await expect(page.locator('tcmon-chart p.hint', { hasText: 'Loading' })).toHaveCount(0);
  }
}

for (const theme of ['dark', 'light']) {
  test(`every page is accessible (WCAG 2.2 AA) with no CSP violations — ${theme} theme`, async ({ page, context }) => {
    await context.addCookies([{ name: 'tcmon_theme', value: theme, url: BASE_URL }]);
    const problems = watch(page);
    for (const path of PAGES) {
      await page.goto(path);
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await settle(page, path);
      const { violations } = await new AxeBuilder({ page }).withTags(WCAG).analyze();
      expect(violations.map((v) => `${path}: ${v.id} — ${v.help}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    }
    expect(problems).toEqual([]);
  });
}

test('sign-in page is accessible and signing in works', async ({ browser }) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const problems = watch(page);
  await page.goto('/');
  await expect(page).toHaveURL(/\/login$/);
  const { violations } = await new AxeBuilder({ page }).withTags(WCAG).analyze();
  expect(violations.map((v) => v.id)).toEqual([]);
  await page.getByLabel('Password').fill('not the password at all');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert')).toContainText('Incorrect password');
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible();
  expect(problems).toEqual([]);
  await context.close();
});

test('theme toggle applies at once and is rendered by the server on the next load (no flash)', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Light' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.getByRole('button', { name: 'Light' })).toHaveAttribute('aria-pressed', 'true');
  const html = await (await page.request.get('/')).text();
  expect(html).toContain('data-theme="light"');
  await page.getByRole('button', { name: 'Dark' }).click();
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(bg).toBe('rgb(15, 17, 21)');
  await page.getByRole('button', { name: 'Auto' }).click();
});

test('dashboard updates live over SSE after a poll, without reloading', async ({ page }) => {
  const problems = watch(page);
  await page.goto('/');
  const state = page.locator('[data-device-id="1"] [data-role="state-text"]');
  await expect(state).toHaveText(/Charging|Idle/);
  const target = (await state.textContent()) === 'Idle' ? ['charging', 'Charging'] : ['idle', 'Idle'];
  await page.evaluate(() => { window.__marker = 'same page'; });
  await page.request.post(`${SIM}/_sim/scenario`, { form: { name: target[0] } });
  await pollNow(page);
  await expect(state).toHaveText(target[1], { timeout: 20_000 });
  expect(await page.evaluate(() => window.__marker)).toBe('same page');
  expect(problems).toEqual([]);
});

test('device charts redraw live after a poll, without reloading', async ({ page }) => {
  const problems = watch(page);
  await page.goto('/devices/1');
  const charts = page.locator('tcmon-chart');
  await expect(charts.locator('svg')).toHaveCount(await charts.count());
  await page.evaluate(() => {
    window.__marker = 'same page';
    for (const svg of document.querySelectorAll('tcmon-chart svg')) svg.dataset.old = '1';
  });
  let fetched = 0;
  page.on('response', (r) => { if (r.url().includes('/series?') && r.ok()) fetched++; });
  await pollNow(page);
  await expect(charts.locator('svg[data-old]')).toHaveCount(0, { timeout: 20_000 });
  await expect(charts.locator('svg')).toHaveCount(await charts.count());
  expect(fetched).toBeGreaterThanOrEqual(await charts.count());
  expect(await page.evaluate(() => window.__marker)).toBe('same page');
  expect(problems).toEqual([]);
});

test('works at 320 px wide without horizontal scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  for (const path of ['/', '/devices/1', '/alerts', '/notifications/new', '/settings', '/settings/devices/1', '/diagnostics',
    '/costs', '/settings/energy']) {
    await page.goto(path);
    await settle(page, path);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `${path} overflows horizontally by ${overflow}px`).toBeLessThanOrEqual(0);
  }
});

test('settings save with the defaults, including "Keep forever" retention', async ({ page }) => {
  await page.goto('/settings');
  await expect(page.locator('#rollups_days')).toHaveValue('0');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await expect(page).toHaveURL(/[?]ok=settings-saved/);
});

test('device page draws charts and the settings form tests the connection', async ({ page }) => {
  await page.goto('/devices/1');
  await expect(page.locator('tcmon-chart svg').first()).toBeVisible();
  await expect(page.locator('tcmon-chart svg').first()).toHaveAttribute('aria-label', /last 24h/);
  await page.goto('/settings/devices/1');
  await page.getByRole('button', { name: 'Test connection' }).click();
  await expect(page.getByRole('status')).toContainText('Found a Wall Connector');
});
