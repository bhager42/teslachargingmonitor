-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- When the current firmware version was first seen, for the firmware_stale
-- alert rule. Device events are pruned by retention, so the timestamp is kept
-- here. Existing rows start from the newest recorded firmware change, or from
-- when the device was first seen.

ALTER TABLE device_info ADD COLUMN firmware_since_at INTEGER NOT NULL DEFAULT 0;

UPDATE device_info SET firmware_since_at = COALESCE(
    (SELECT MAX(e.ts) FROM device_events e
     WHERE e.device_id = device_info.device_id AND e.kind = 'firmware_changed'),
    first_seen_at);
