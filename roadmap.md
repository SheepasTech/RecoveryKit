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
| 5 | Plugins: `plugins/*.py` through the command wrapper | Built (loader and source check); no plugin shipped |
| 6 | Registry diffing: compare the target's hives with the previous run and with known-good values | Planned |
| 7 | Driver rollback: list recently added drivers of the offline install, propose removal of one | Planned |
| 8 | Malware triage: autoruns, services, scheduled tasks and run keys of the offline install, read-only | Planned |
| 9 | Scheduled tasks: inventory of the target's tasks; unattended scheduled scans on the server side | Planned |
| 10 | Fleet mode: the server tracks many agents and cases, history per machine | Planned |
| 11 | GUI: browser front end served by the control server, on top of the same API | Planned |
| 12 | Plugin marketplace: signed plugin index, install and update from the server | Planned |

Phases 6 to 12 were the spec's "deferred" list and are now in scope.

## Before any phase can be called done

- Boot a real PC into stock WinRE and run `run.cmd --scan` from the USB: does the bundled Python start, which tools are missing, is the right disk picked.
- Run as administrator on a normal Windows against an attached disk: BCD capture, BitLocker status, raw event logs.
- Walk one real repair through the menu on a disposable test install.
- Two machines on a LAN for the remote session; decide on TLS certificates.

## Notes per planned phase

- **6 Registry diffing.** The hive parser already reads offline hives. Needs: a walker that dumps selected subtrees (services, control set, servicing state) into the case, and a diff against the previous run of the same case.
- **7 Driver rollback.** `dism /Image /Get-Drivers` (allow-listed as a repair-class read) and `DriverDatabase` in the SYSTEM hive give the third-party drivers and their dates. Removal is `dism /Remove-Driver`, to be added to the wrapper's allowlist with the usual confirmation.
- **8 Malware triage.** Read-only listing from the offline SOFTWARE/SYSTEM/NTUSER hives and `System32\Tasks`. It reports unusual entries; it does not judge or remove.
- **9 Scheduled tasks.** Target side is part of 8. Server side: periodic jobs through the existing relay.
- **10 Fleet mode.** The server keeps agents in memory today; it needs a small persistent store and a case index.
- **11 GUI.** Static pages served by the control server calling `/api/v1`; no change to the agent.
- **12 Plugin marketplace.** Depends on a signature scheme for plugins; the current source check is a guard, not a sandbox.
