# Standalone report viewer

`report.html` is compiled into the CLI; its single `{{PANTRY_BUNDLE}}` token is replaced with script-safe JSON by `src/html.rs`. Keep CSS, JavaScript and images embedded so generated reports work offline.

The PNG is the unmodified official Waffuru mark from `waffuruai/website`, `public/brand/waffuru-waffle.png` (retrieved 2026-10-29). Colors follow that repository’s `src/content/pages/brand.ts`; fonts use local system fallbacks. The viewer adapts the report example supplied for Pantry issue #36.

Run `mise run test html` (or `node tests/html/test-viewer.cjs`) from the repository root for synthetic viewer behavior checks. These do not replace opening a generated report to inspect layout, printing, and clipboard behavior in a real browser.
