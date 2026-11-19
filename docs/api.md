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
| GET | `/agents` | | `[{id, name, version, paired, revoked, revoked_reason, repairs_enabled_on_target, seconds_since_seen}]`. `revoked_reason` is `"too many invalid signatures"` when the server revoked the agent itself (see "Bad MACs" below), else null |
| POST | `/agents/<id>/pair` | `{code}` | the pairing code shown on the target's screen: 10 characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no I, O, 0, 1), shown grouped as `XXXXX-XXXXX`. Upper or lower case, with or without the dash or spaces: the server upper-cases the code and removes `-` and spaces (nothing else is mapped, an `O` stays an `O`). Five wrong codes lock the session |
| POST | `/agents/<id>/revoke` | | ends the session on the target |
| GET, POST | `/agents/<id>/api/<agent path>` | as the agent API | relays the call (for example `/agents/ab12cd34/api/status`) and returns the agent's answer |
| POST | `/agents/<id>/fetch-bundle` | | bundles on the agent, pulls the zip into the store as `<case_id>-<YYYYMMDD-HHMMSS>.zip` (a `-2`, `-3` suffix instead of overwriting), copies it under the same name to `<intake>\ITW <ticket>\` when both are known. The name is chosen by the server; case id and ticket are sanitised (`[A-Za-z0-9_-]`, 64 characters; ticket `[A-Za-z0-9]`, 20), and the blob must be a readable zip or the call fails with 502 and nothing is stored: the zip directory is read first and a bundle with more than 20,000 members, more than 4 GiB declared in total, or a member declared above 100 MiB at more than 1000 times its compressed size is refused before any member is decompressed |
| GET | `/bundles` | | stored bundles |
| GET | `/cases` | | stored cases with their runs (target, ticket, section status), read from the stored bundles |

Relayed sessions are read-only: GET routes plus `POST /scan`, `/bundle`, `/answers`, `/boot-result`, `/repair/source`. `POST /repair/run` needs `--allow-remote-repairs` on the target.

A browser page for these routes is served at `/` (paste the operator token once). Its pairing box takes 11 characters (the dashed form), turns off autocomplete and spell checking and asks the keyboard for capitals.

Operator routes (`/api/v1/...`): the bearer token is checked from the headers BEFORE any body byte is read. A request without the right token is answered 401 at once and the connection is closed, whatever `Content-Length` it announces (a body of up to 64 KiB is drained for a moment so the answer is not lost to a connection reset; a larger one is not read at all). A `GET` or `HEAD` with a body (`Content-Length` above 0) is refused with 400 on every route.

Command-line client (control characters in what the server sends are removed before printing): `run.cmd --ctl [--url URL] [--token T] [--pin SHA256] [--ca FILE] agents | pair ID CODE | get ID PATH | post ID PATH [JSON] | fetch-bundle ID | bundles | revoke ID`.

## Agent to server protocol

The agent only makes outbound requests: `POST /agent/v1/hello`, `/agent/v1/poll` (held up to 20 s), `/agent/v1/result`. Metadata travels as base64 JSON in `X-RK-Meta` (it holds the agent id, the counter `n` and a nonce), the body is raw, and every request carries two MACs, both HMAC-SHA256:

- `X-RK-Head` over `"req\n" + path + "." + meta_b64 + "." + Content-Length`. The server checks it before it reads any body byte: a missing or wrong head MAC is answered 401, and a `Content-Length` above the route's limit 413, in both cases without reading the body and with the connection closed.
- `X-RK-Sig` over `label + "\n" + path + "\n"`, the metadata and the body's SHA-256 (a captured `poll` cannot be replayed as `hello`). The label is `req` on what the agent sends and `resp` on what the server answers, so a request can never be reflected back as an answer (on plain HTTP a man in the middle could otherwise do exactly that). A response is signed over the same request path with the same key, with the `resp` label, and carries the request's nonce.

Key: the agent token until the agent is paired, afterwards the session key `HMAC-SHA256(agent_token, "session|" + agent_id + "|" + pairing_code)` (hex), the pairing code being its 10 normalised characters. Over TLS a holder of the agent token alone (another stick) cannot speak for a paired agent, and a network observer sees nothing. This does NOT hold on plain HTTP (`--no-tls`): the hello carries `sha256(code + "|" + agent_id)`, and a LAN sniffer sees it. 10 characters of a 32-letter alphabet are 50 bits: a large offline search, but not an impossible one for someone with fast hardware, and once the code is known a sniffer who ALSO has the agent token (it is on every stick that connects to this server) derives the session key and can speak for the agent. `--no-tls` is therefore for a trusted LAN only. The agent cannot know when the operator paired it: the server answers the first token-signed poll after pairing with `{paired: true, switch: true}`, still signed with the token and changing no state (no job, no counter); the agent then signs everything with the session key. From the first message the server sees signed with the session key, a message for that agent id signed with the token is refused with 401. The signature is verified before any per-agent state is touched, so a forged message never changes the counter, `last_seen` or the job queue. Each request has a rising counter `n` (an integer below 2^53 that may rise by at most 1,000,000 per message). The agent id is 8 lower-case hex digits (`[0-9a-f]{8}`, anything else is 400 before any state exists); `name` and `version` are reduced to printable ASCII (60 and 20 characters). `hello` for an agent id that is already known is refused (409) unless that entry was never paired and has been silent for 10 minutes. The server keeps at most 64 agents: a new `hello` replaces only an unpaired entry silent for at least 10 minutes, otherwise the answer is a signed 429; paired or revoked entries silent for more than 2 hours are dropped (on every `hello` and every `GET /agents`). The agent treats any reply other than 200 to a poll as a failure with the same backoff as a network error (2 s, 4 s, ... up to 10 s) and ends the session after 5 in a row.

Bad MACs: the server counts messages whose agent id EXISTS in its table and whose `X-RK-Head` or `X-RK-Sig` is wrong. After 20 for one agent id the entry is revoked with the reason "too many invalid signatures": `GET /agents` shows `revoked: true` and that reason, the server prints a line, and the agent's next poll is answered `{revoked: true}`. A legitimate agent then has to start a new session (its end-of-session message says so: run `--connect` again, which makes a new agent id and a new pairing code). This guards the pairing code against online guessing of the session key (a wrong key can only show up as a bad MAC). Trade-off: ids that do not exist are never counted and create no state, and over TLS the agent id is visible to nobody but the two ends, so a party without the agent token cannot pick a victim. On plain HTTP the id is visible, so someone on the LAN who sees it can send 20 bad messages and end that session (nothing is exposed by it; the agent just reconnects). The same holds for anyone who has the agent token, with or without TLS.

A relayed job carries `expires`; the server also sends `ttl` (seconds left at delivery) and the agent measures it with its own monotonic clock, never its wall clock. A job whose call timed out at the operator (504) is never delivered afterwards, and an agent answers a job with `ttl <= 0` with 410 without running it. The agent's result `status` is clamped to 200-599 (else 502) and `ctype` to `application/json`, `application/zip`, `application/octet-stream` or `text/markdown` (optionally `; charset=utf-8`), anything else becomes `application/octet-stream`. Request bodies are limited to 64 MiB, except the agent's `result` route (1 GiB, and only when the job id in the metadata is a pending job of that same agent). A request must arrive complete (headers and body) within 120 s in total, besides the 30 s limit between two reads; for `/agent/v1/result` the total is 120 s plus 1 s per MiB of `Content-Length` (counted only after the head MAC was accepted). An agent whose result cannot be delivered, for ANY reason (refused with 413, connection error, timeout, or an answer other than 200), makes one more attempt to deliver a small JSON error result for that job (status 502, `{"error": "result upload failed: <reason>"}`; status 413 with its own text when the server refused the size), so the operator is answered at once instead of after the 1800 s job timeout.

Connections: each server accepts at most 64 at a time and at most 8 at a time from one remote address (127.0.0.1 and ::1 have no per-address limit, and may use 8 more slots once the 64 are taken, so the operator on the server PC can always get in). A connection refused for capacity is answered, not just dropped: on plain HTTP the server writes a minimal `HTTP/1.1 503` response, half-closes, reads what the client already sent for a moment (so the answer is not lost to a connection reset) and closes; on TLS the connection is closed WITHOUT a handshake, because a TLS client could not read a plain answer (the client sees a closed or reset connection, not a 503). The limits are parameters of `Server.start` (`max_conn`, `per_addr`, `exempt`, `reserve`). Missing, non-numeric or negative `Content-Length`, and chunked bodies, are refused with 400 and the connection is closed; a stalled socket times out after 30 s. A session ends on a keypress on the target, after `--session-minutes`, or when revoked.

TLS: the server speaks HTTPS by default. The control host PC is the certificate authority (ADR 0020): `run.cmd --server` issues `config\server-cert.pem` (leaf + CA certificate) and `config\server-key.pem` from the CA in `%LOCALAPPDATA%\ITwork\CA` (`--ca-dir` to change it), with the host name and addresses as subject alternative names. The agent and `--ctl` verify the chain against the CA certificate (`--ca FILE`, default `config\ca-cert.pem` on the stick, copied there by `Install-ToUsb.ps1`; `--ctl` on the server PC reads it from the CA folder) and check that the address they used is in the certificate; `--pin <sha256>` instead trusts exactly one certificate. An `https://` URL with neither a CA file nor a pin is refused, never connected unverified. The handshake is done per connection in its own thread: a client that fails it is logged in one line and does not affect others. `--no-tls` serves plain HTTP: authenticated but not encrypted, use on a trusted LAN only (`http://` agents print a warning; see the key paragraph above for what a LAN sniffer who has the agent token can do). The token and pairing code still authenticate the agent; client certificates are not issued. The server context sets `OP_NO_RENEGOTIATION`. A server that cannot start (port in use, certificate or key unusable) prints one line and exits with code 2; a server certificate whose key does not match is issued again by `tlsca.ensure_server_cert`. Server URLs (`--connect`, `--ctl --url`) must start with `http://` or `https://` (the scheme may be in any case); `--pin` must be 64 hex characters (colons allowed) and wins over `--ca`; an `https://` URL against a server run with `--no-tls` fails with a hint to use `http://`.
