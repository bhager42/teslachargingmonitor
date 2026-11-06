-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- Phase 8: the optional weekly digest email (owner decision D19), opted into
-- per email channel. Off for existing channels.

ALTER TABLE notify_channels ADD COLUMN digest INTEGER NOT NULL DEFAULT 0 CHECK (digest IN (0, 1));
