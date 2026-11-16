-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- The optional monthly summary email, opted into per email channel like the
-- weekly digest (0006). Off for existing channels.

ALTER TABLE notify_channels ADD COLUMN monthly_digest INTEGER NOT NULL DEFAULT 0 CHECK (monthly_digest IN (0, 1));
