// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export default async function globalTeardown() {
  try {
    for (const pid of JSON.parse(readFileSync(join(import.meta.dirname, '.pids.json'), 'utf8'))) {
      try { process.kill(pid, 'SIGTERM'); } catch { /* already gone */ }
    }
  } catch { /* nothing started */ }
}
