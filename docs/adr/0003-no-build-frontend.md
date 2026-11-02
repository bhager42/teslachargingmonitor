# 0003 — Framework-free, no-build frontend

- **Status:** Accepted (2026-11-02)

## Context
The UI is a handful of pages. npm build chains add a large supply-chain
surface and churn, and inline scripts conflict with a strict CSP.

## Decision
Server-render pages with `html/template`; enhance with native ES modules,
modern CSS (`light-dark()`, nesting, `@layer`, container queries) and
Web Components. No bundler, no framework. Third-party browser code (e.g.
uPlot) is vendored, pinned and checksum-verified under `web/static/vendor/`.
Node is used only for Playwright end-to-end tests, never at runtime.

## Consequences
- Strict CSP with no `unsafe-inline`; Trusted Types enforceable.
- No runtime JS dependencies to audit beyond vendored files.
- Developers write standards-based code without framework conveniences.
