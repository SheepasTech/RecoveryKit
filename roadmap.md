# Roadmap

Where each phase stands. The design is in [RecoveryKit-spec.md](RecoveryKit-spec.md); what changed is in [CHANGELOG.md](CHANGELOG.md).

"Built" means implemented and covered by the automated tests on the development PC. Nothing has been run in a real WinRE boot or against a real broken PC yet; that is the next milestone for every phase.

## Phases

| # | Phase | State |
|---|---|---|
| 1 | Discovery, log collection, report (read-only) | Built |
| 2 | Repair helpers: source check, DISM/SFC, BCD with export first, data copy-out, disk online, BitLocker unlock | Built, repairs exercised in dry-run only |
| 3 | Troubleshooting assistant driven by `config/assistant.toml` | Built |
| 4 | Client-server: engine API, agent API (`--serve`), control server (`--server`), outbound agent session (`--connect`) | Built, tested over loopback only |
| 5 | Plugins: `plugins/*.py` through the command wrapper | Built (loader, SHA-256 manifest, source check); no plugin shipped |
| 6 | Registry diffing: snapshot of the startup-relevant keys and a diff against the previous run of the same case | Built (no comparison with known-good values) |
| 7 | Driver rollback: list third-party drivers of the offline install, propose removal of one | Built; removal exercised in dry-run only |
| 8 | Malware triage: autoruns, services, scheduled tasks of the offline install, read-only, neutral flags | Built |
| 9 | Scheduled tasks: inventory of the target's tasks; unattended scheduled scans on the server side | Target side built (part of 8); server side planned |
| 10 | Fleet mode: the server tracks many agents and cases, history per machine | First cut: stored-cases view built from received bundles; no persistent agent list |
| 11 | GUI: browser front end served by the control server, on top of the same API | First cut: one page; not yet seen in a browser |
| 12 | Plugin marketplace: signed plugin index, install and update from the server | Planned |

Phases 6 to 12 were the spec's "deferred" list and are now in scope. Still not built: server-side scheduled scans (9), the plugin marketplace (12), mutual TLS (client certificates; server TLS is built), a custom WinPE image.

## Before any phase can be called done

- Boot a real PC into stock WinRE and run `run.cmd --scan` from the USB: does the bundled Python start, which tools are missing, is the right disk picked.
- Run as administrator on a normal Windows against an attached disk: BCD capture, BitLocker status, raw event logs.
- Walk one real repair through the menu on a disposable test install.
- Two machines on a LAN for the remote session (TLS is built; try it over the LAN).
- Open the browser page in a real browser.

## Notes on what is left

- **9 Scheduled tasks, server side.** Periodic jobs through the existing relay. Needs a decision on unattended sessions first: remote sessions are short and operator-attended by design.
- **10 Fleet mode.** The server keeps agents in memory; it needs a small persistent store and per-machine history (the stored-cases view reads the received bundles).
- **11 GUI.** The page calls `/api/v1`; check it in a browser and extend it.
- **12 Plugin marketplace.** Depends on a signature scheme for plugins; the standard library has no asymmetric signing, and an HMAC with the shared token would let anyone with the agent token publish code. The current checksum list is an integrity check, not a sandbox.
- **TLS.** Built (ADR 0020): the control host is the CA, the server speaks HTTPS by default, sticks carry the CA certificate. Tested on 127.0.0.1 only, not yet on a real LAN or in WinRE. Remaining: client certificates for agents (mutual TLS).
