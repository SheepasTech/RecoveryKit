# Browser smoke test for the control-server page

Drives the real `recoverykit/web/index.html` page in headless Microsoft Edge through the Chrome DevTools Protocol
(no npm packages). It is a manual check, not part of the unit-test suite (`python -m unittest`).

Run it from the RecoveryKit folder:

    node tests\browser\smoke.mjs

Needs: Microsoft Edge (`msedge.exe` under Program Files), Node.js 22+ (global `WebSocket` and `fetch`), and Python
with the repo's own modules. Nothing is installed and everything talks to 127.0.0.1 only.

What it does: `serve_fixture.py` starts a plain-HTTP control server and one connected dry-run agent against a fake
offline Windows, all in temp dirs (the repo's `config/` and `cases/` are not touched). `smoke.mjs` then walks the page
like a user (sign-in, pair, scan, report views, bundle, revoke, forget token), including a markup injection probe,
and prints PASS/FAIL per step plus console messages, exceptions, failed requests, non-127.0.0.1 requests and CSP
violations. The exit code is non-zero on any failure. A full run takes about a minute (the scan is the slow part).

Screenshots (1280x900, 420x900 and one dark-mode shot) go to `tests\browser\out\` (git-ignored).
