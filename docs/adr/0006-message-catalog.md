<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Brad Hager and contributors -->

# 0006 — Message catalog for user-facing text

- **Status:** Accepted (2026-11-06)

## Context

Phase 8 step 6 asks for i18n scaffolding: user-facing text moved to a
message catalog, English only, without changing any text. No translation
is planned, so the goal is that adding a language later is a data change
plus a small amount of wiring, not a hunt through templates and Go code.

## Decision

- **Own small package, no dependency.** `internal/i18n` (about 300 lines)
  instead of `golang.org/x/text/message` or go-i18n: we need keyed messages,
  named arguments and one/other plurals, nothing more, and every dependency
  is supply-chain surface (ADR 0004, plan §8).
- **Format:** one flat JSON object per language,
  `internal/i18n/locales/<lang>.json`, embedded in the binary. Keys are
  `section.name` (section = page or area, `common.*` for shared words).
  A message is a string, or `{"one": …, "other": …}` when it depends on a
  count. Arguments are named, `{name}`, so a translation can reorder them.
- **Markup:** only keys ending in `_html` may contain markup, and only `a`
  (`href`, `rel="noopener"`, `download`), `code`, `strong`, `em`, `kbd`. The
  catalog is embedded and validated at start-up, and arguments are
  HTML-escaped, so `th` cannot inject markup. Everything else is plain text
  that html/template escapes as usual. Whole sentences go in one message,
  links included, rather than being split around the markup.
- **Strict at render time:** the template functions `t`, `th` and `tn`
  return an error (failing the render) for an unknown key, a missing or
  unused argument, or the wrong kind of message. Go code uses `T`/`N`, which
  return the key itself on a mistake so it is visible.
- **Go code** uses the package-level catalog `tr` in `internal/web`
  (`tr.T("key", "name", value)`), so formatting a message is one call.
  Tests set `i18n.ReportErrors`, so an unknown key or a wrong argument in
  Go code fails the test run instead of quietly showing the key.
- **Browser script:** `app.mjs` holds no text. Each page carries the few
  messages it needs (`jsMessageKeys`) in a
  `<script type="application/json" id="tcmon-messages">` data block, which
  is not executable and so needs no CSP exception; the script fills in
  `{placeholders}` itself.
- **Tests keep it complete:** `TestCatalogCoverage` fails when a template
  or Go code uses a key that does not exist (or with the wrong function),
  or when a catalog key is not used anywhere; `TestJavaScriptMessages` does
  the same for `app.mjs`. Loading rejects duplicate keys, stray
  braces and disallowed markup.
- **Not in the catalog:** log lines, CLI output and error details meant
  for the operator; health and API endpoints; CSV column headers (a file
  format other tools read); device data (names, firmware, codes); units,
  number and date formats (they stay as they are until a language needs
  them).
- **Language selection:** English is the only catalog, and templates are
  parsed with its functions. Adding a language means adding
  `locales/<lang>.json`, parsing the templates once per catalog, and
  choosing one per request (a setting, or `Accept-Language`). The
  `<html lang>` attribute already comes from the catalog.

## Consequences

- Templates read `{{t "devices.title"}}` instead of the text itself, so
  changing wording means editing `en.json`.
- The conversion was checked two ways: every converted template, expanded
  back from the catalog, matches the original source, and 81 rendered
  pages (all routes, every alert rule, every flash message, error states)
  match byte for byte after HTML-entity normalisation.
