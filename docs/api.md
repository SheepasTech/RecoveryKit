# RecoveryKit API

Two APIs, both JSON over HTTP under `/api/v1`. The agent API runs on the machine being examined; the server API runs on the main machine and can relay calls to connected agents. Neither is needed for standalone use: `run.cmd` with the menu or `run.cmd --scan --auto` works with no server at all.

| Mode | Command | Who talks to whom |
|---|---|---|
| Serverless, interactive | `run.cmd` | operator at the console |
| Serverless, headless | `run.cmd --scan --auto [--bundle]` | nobody: scan, report, exit |
| Headless agent | `run.cmd --serve [--port 8766] [--allow-repairs]` | a local program calls the agent API on 127.0.0.1 |
| Remote session | `run.cmd --connect URL --token T` | the agent dials out; the server relays agent API calls |
| Control server | `run.cmd --server --bind <LAN IP> [--intake DIR]` | operator and agents call the server |

## Agent API

Listens on `127.0.0.1` only. Every request needs `Authorization: Bearer <token>`; the token is generated at start, shown on the console and written to `cases\_api-token.txt` (deleted on exit). Optional header `X-RK-Operator: <name>` is recorded in the logs.

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/status` | | version, environment, admin, busy, scanned, case_id, case_dir, target, dry_run, allow_repairs |
| POST | `/scan` | `{ticket?, target?, target_path?, chkdsk?, answers?}` | section summary `{name: {title, status, reason, items[]}}`. Synchronous; takes a minute or more |
| GET | `/sections` | | the same summary |
| GET | `/case` | | the whole `case.json` |
| GET | `/report` | | `report.md` as `text/markdown` |
| GET | `/suggestions?refresh=1` | | `{suggestions[], what_changed[], rule_errors[]}` |
| POST | `/answers` | `{symptom?, firmware_sees_disk?, boot_menu_wbm?, recent_change?, data_backed_up?, stop_code?, symptom_text?}` | the stored answers |
| POST | `/boot-result` | `{booted: true|false|null, note?}` | |
| GET | `/files` | | `[{path, size}]` of the run folder |
| GET | `/files/<path>` | | the file (`application/octet-stream`). Paths outside the run folder give 404 |
| GET | `/audit?since=<seq>` | | audit entries with a higher sequence number |
| GET | `/log?offset=<n>` | | `{text, next, size}`: debug.log from that byte offset, for streaming |
| POST | `/bundle` | | `{path, size, download}` |
| GET | `/bundle/download` | | the zip |
| POST | `/repair/source` | `{path, index?}` | source check verdict |
| GET | `/repair/steps` | | `{steps: [{id, title, command, effect, risk, evidence, token}], blockers[], dry_run}` |
| POST | `/repair/run` | `{id, token, confirm: "yes", operator?}` | `{result, output, next}` |

Answer values: `symptom` is one of `no_boot_device, repair_loop, stop_code, spinning, other, unknown`; `firmware_sees_disk`, `boot_menu_wbm`, `data_backed_up` are `yes, no, unknown`; `recent_change` is `update, driver, power, hardware, none, unknown`.

Errors are `{"error": "..."}` with status 400 (bad input), 401 (token), 403 (not enabled), 404, 405, 409 (not confirmed or refused by the command wrapper), 500.

### Repairs through the API

Off unless the agent was started with `--allow-repairs` (loopback) or `--allow-remote-repairs` (relayed). A step runs only when the request carries `confirm: "yes"` and the `token` that `/repair/steps` returned for that exact command line. The command wrapper still applies every rule: forbidden commands, target re-check, BCD export first, no repairs on the running Windows, `--dry-run`. One step at a time; test boot between steps and record it with `/boot-result`.

Step tokens are single use and valid for one listing only: each `GET /repair/steps` mixes a fresh random value into every token, `POST /scan` clears the list, and a successful or refused `/repair/run` removes the step. A second POST with the same id gives 404 ("list the steps again"); a step listed for one target is refused (409) if the target changed since. For a relayed call the operator name is the one the server passes on; `operator` in the body is only honoured on loopback.

`POST /scan` bodies are type-checked (400): `ticket` string or number of at most 20 characters, `target` one drive letter, `target_path` string, `chkdsk` boolean, `answers` an object of strings. A relayed `/scan` may not set `target_path` (403): an operator must not point the scan at arbitrary folders of the target machine.

## Server API

`run.cmd --server` binds to `127.0.0.1:8765` unless `--bind` names a LAN address. Tokens are generated on first start in `config\token-server.json`: `operator_token` for the routes below (`Authorization: Bearer`), `agent_token` for agents.

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/status` | | version, agents, store, intake |
| GET | `/agents` | | `[{id, name, version, paired, revoked, repairs_enabled_on_target, seconds_since_seen}]` |
| POST | `/agents/<id>/pair` | `{code}` | the 6-digit code shown on the target's screen. Five wrong codes lock the session |
| POST | `/agents/<id>/revoke` | | ends the session on the target |
| GET, POST | `/agents/<id>/api/<agent path>` | as the agent API | relays the call (for example `/agents/ab12cd34/api/status`) and returns the agent's answer |
| POST | `/agents/<id>/fetch-bundle` | | bundles on the agent, pulls the zip into the store as `<case_id>-<YYYYMMDD-HHMMSS>.zip` (a `-2`, `-3` suffix instead of overwriting), copies it under the same name to `<intake>\ITW <ticket>\` when both are known. The name is chosen by the server; case id and ticket are sanitised (`[A-Za-z0-9_-]`, 64 characters; ticket `[A-Za-z0-9]`, 20), and the blob must be a readable zip or the call fails with 502 and nothing is stored |
| GET | `/bundles` | | stored bundles |
| GET | `/cases` | | stored cases with their runs (target, ticket, section status), read from the stored bundles |

Relayed sessions are read-only: GET routes plus `POST /scan`, `/bundle`, `/answers`, `/boot-result`, `/repair/source`. `POST /repair/run` needs `--allow-remote-repairs` on the target.

A browser page for these routes is served at `/` (paste the operator token once).

Command-line client: `run.cmd --ctl [--url URL] [--token T] agents | pair ID CODE | get ID PATH | post ID PATH [JSON] | fetch-bundle ID | bundles | revoke ID`.

## Agent to server protocol

The agent only makes outbound requests: `POST /agent/v1/hello`, `/agent/v1/poll` (held up to 20 s), `/agent/v1/result`. Metadata travels as base64 JSON in `X-RK-Meta`, the body is raw, and `X-RK-Sig` is HMAC-SHA256 over the request path, the metadata and the body's SHA-256 with the agent token (a captured `poll` cannot be replayed as `hello`); a response is signed over the same request path. Each request has a fresh nonce and a rising counter `n` (an integer below 2^53 that may rise by at most 1,000,000 per message); each response is signed over the request's nonce. `hello` for an agent id that is already known is refused (409) unless that entry was never paired and has been silent for 10 minutes; the server keeps at most 64 agents (the longest-unseen unpaired one makes room; with all 64 paired, 429).

A relayed job carries `expires`; the server also sends `ttl` (seconds left at delivery) and the agent measures it with its own monotonic clock, never its wall clock. A job whose call timed out at the operator (504) is never delivered afterwards, and an agent answers a job with `ttl <= 0` with 410 without running it. The agent's result `status` is clamped to 200-599 (else 502) and `ctype` to `application/json`, `application/zip`, `application/octet-stream` or `text/markdown` (optionally `; charset=utf-8`), anything else becomes `application/octet-stream`. Request bodies are limited to 64 MiB, except the agent's `result` route (1 GiB); an agent whose result is refused with 413 sends a small JSON error result for that job. Missing, non-numeric or negative `Content-Length`, and chunked bodies, are refused with 400 and the connection is closed; sockets time out after 30 s. A session ends on a keypress on the target, after `--session-minutes`, or when revoked.

Without TLS the traffic is authenticated but not encrypted, so use it on a trusted LAN only. With `config\server-cert.pem` and `config\server-key.pem` present the server speaks HTTPS; the agent pins the certificate with `--pin <sha256>`.
