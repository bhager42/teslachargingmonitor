-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Brad Hager and contributors
--
-- Phase 6b: electricity price history for charging costs (owner decision
-- D18). Costs are computed from lifetime energy counter deltas; nothing is
-- denormalized, so changing a price never leaves stale totals behind.

CREATE TABLE energy_rates (
    id                    INTEGER PRIMARY KEY,
    effective_from        INTEGER NOT NULL,
    price_per_kwh         REAL    NOT NULL CHECK (price_per_kwh >= 0 AND price_per_kwh < 100),
    offpeak_price_per_kwh REAL    CHECK (offpeak_price_per_kwh IS NULL OR (offpeak_price_per_kwh >= 0 AND offpeak_price_per_kwh < 100)),
    offpeak_start_min     INTEGER NOT NULL DEFAULT 0 CHECK (offpeak_start_min BETWEEN 0 AND 1439),
    offpeak_end_min       INTEGER NOT NULL DEFAULT 0 CHECK (offpeak_end_min BETWEEN 0 AND 1439),
    monthly_fee           REAL    NOT NULL DEFAULT 0 CHECK (monthly_fee >= 0 AND monthly_fee < 100000),
    created_at            INTEGER NOT NULL
);
CREATE INDEX energy_rates_effective ON energy_rates (effective_from);
