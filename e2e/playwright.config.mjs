// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
import { defineConfig, devices } from '@playwright/test';

export const BASE_URL = process.env.TCMON_E2E_URL ?? 'https://localhost:18443';

const engines = (process.env.TCMON_E2E_BROWSERS ?? 'chromium,firefox,webkit').split(',');
const all = {
  chromium: devices['Desktop Chrome'],
  firefox: devices['Desktop Firefox'],
  webkit: devices['Desktop Safari'],
};

export default defineConfig({
  testDir: './tests',
  // One shared server: run tests one at a time.
  workers: 1,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  globalSetup: './global-setup.mjs',
  globalTeardown: './global-teardown.mjs',
  use: {
    baseURL: BASE_URL,
    // The app serves a self-signed certificate by design (owner decision D12).
    ignoreHTTPSErrors: true,
    storageState: '.auth/state.json',
    trace: 'retain-on-failure',
  },
  projects: engines.map((name) => ({ name, use: { ...all[name] } })),
});
