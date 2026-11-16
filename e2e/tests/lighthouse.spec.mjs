// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// Lighthouse budget (plan §8) on the main pages, signed in, over the app's
// self-signed HTTPS, as a desktop and as a throttled phone. Performance must
// be ≥ 95 (the plan's bar; it depends on timing). Accessibility and best
// practices must be 100: they are deterministic, and Lighthouse weights single
// audits so lightly that e.g. unreadable text still scores 96. Runs in
// Chromium only (Lighthouse drives Chrome through the DevTools protocol).
// Set TCMON_LH_REPORTS=<dir> to keep the JSON reports.
import { readFileSync, mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, expect, chromium } from '@playwright/test';
import lighthouse from 'lighthouse';
import desktopConfig from 'lighthouse/core/config/desktop-config.js';
import { BASE_URL } from '../playwright.config.mjs';

const MIN = { performance: 95, accessibility: 100, 'best-practices': 100 };
const CATEGORIES = Object.keys(MIN);
const PAGES = ['/login', '/', '/devices/1', '/alerts', '/notifications', '/settings', '/costs', '/diagnostics',
  '/settings/gateway', '/solar'];
const PORT = 19222;
// Lighthouse sometimes fails to measure a metric on a CI runner (a null
// category score, no failing audit to show); such a run is repeated, a real
// low score never is.
const MAX_ATTEMPTS = 3;
const STATE = join(import.meta.dirname, '..', '.auth', 'state.json');

const configs = {
  desktop: desktopConfig,
  mobile: undefined, // Lighthouse's default: a mid-range phone on a throttled connection
};

test.describe('Lighthouse', () => {
  test.skip(({ browserName }) => browserName !== 'chromium', 'Lighthouse needs Chromium');

  let context;
  let profile;

  test.beforeAll(async () => {
    profile = mkdtempSync(join(tmpdir(), 'tcmon-lh-'));
    // A persistent context is the browser's default context, which is where
    // Lighthouse opens its tab, so the session cookie applies to the audit.
    context = await chromium.launchPersistentContext(profile, {
      channel: 'chromium', // full Chromium (new headless), closer to real Chrome than the headless shell
      ignoreHTTPSErrors: true,
      args: [`--remote-debugging-port=${PORT}`, '--ignore-certificate-errors'],
    });
  });

  test.afterAll(async () => {
    await context?.close();
    if (profile) rmSync(profile, { recursive: true, force: true });
  });

  for (const [form, config] of Object.entries(configs)) {
    test(`main pages meet the Lighthouse budget (${form})`, async () => {
      test.setTimeout(PAGES.length * 60_000);
      const failures = [];
      const scores = {};
      for (const path of PAGES) {
        // Sign-in is audited signed out; every other page signed in.
        await context.clearCookies();
        if (path !== '/login') await context.addCookies(JSON.parse(readFileSync(STATE, 'utf8')).cookies);
        let result;
        for (let attempt = 1; ; attempt++) {
          result = await lighthouse(`${BASE_URL}${path}`, {
            port: PORT,
            output: 'json',
            logLevel: 'error',
            onlyCategories: CATEGORIES,
            disableStorageReset: true,
          }, config);
          const unmeasured = CATEGORIES.filter((id) => result.lhr.categories[id].score === null);
          if (unmeasured.length === 0) break;
          const why = result.lhr.runtimeError?.message ??
            Object.values(result.lhr.audits).find((a) => a.errorMessage)?.errorMessage ?? 'no reason given';
          console.log(`Lighthouse (${form}) ${path}: ${unmeasured.join(', ')} not measured (${why}), attempt ${attempt}`);
          if (attempt === MAX_ATTEMPTS) {
            failures.push(`${path}: ${unmeasured.join(', ')} not measured after ${MAX_ATTEMPTS} attempts: ${why}`);
            break;
          }
        }
        const lhr = result.lhr;
        expect(lhr.finalDisplayedUrl, `${path} was redirected (signed out?)`).toBe(`${BASE_URL}${path}`);
        scores[path] = {};
        for (const id of CATEGORIES) {
          if (lhr.categories[id].score === null) continue; // reported above
          const score = Math.round(lhr.categories[id].score * 100);
          scores[path][id] = score;
          if (score < MIN[id]) {
            const lost = lhr.categories[id].auditRefs
              .filter((r) => r.weight > 0 && lhr.audits[r.id].score !== null && lhr.audits[r.id].score < 1)
              .map((r) => `${r.id} (${lhr.audits[r.id].displayValue ?? lhr.audits[r.id].score})`);
            failures.push(`${path} ${id} ${score} < ${MIN[id]}: ${lost.join(', ')}`);
          }
        }
        if (process.env.TCMON_LH_REPORTS) {
          mkdirSync(process.env.TCMON_LH_REPORTS, { recursive: true });
          writeFileSync(join(process.env.TCMON_LH_REPORTS, `${form}${path.replaceAll('/', '_') || '_'}.json`), result.report);
        }
      }
      console.log(`Lighthouse (${form}):`, JSON.stringify(scores));
      expect(failures).toEqual([]);
    });
  }
});
