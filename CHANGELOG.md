# Changelog

Newest first. "Verified" says how a change was checked; anything not listed there was not checked.

## 0.4.0 - 2026-11-19

Added
- Registry snapshot of the startup-relevant keys with a list of findings and a diff against the previous run of the same case (`modules/regdiff.py`).
- Third-party driver inventory from the target's `INF\oem*.inf`, newest first, and a proposed `dism /Remove-Driver` step (`modules/drivers.py`).
- Startup inventory: autoruns, auto-start services and scheduled tasks of the target, with neutral flags for entries worth a look (`modules/triage.py`).
- Client-server model: `engine.py` holds every operation; `--serve` exposes the agent API on 127.0.0.1; `--server` runs the control server; `--connect` makes the agent dial out; `--ctl` is the operator client (`net.py`, [docs/api.md](docs/api.md)).
- Control server: stored-cases view (`/api/v1/cases`) and a browser page at `/`.
- Repairs through the API, bound to a token for the exact command and to an enable switch given on the target.
- Repair menu: bring an offline disk online, unlock a BitLocker volume (key never logged).
- `--target-path` for a target that is a folder (mounted image).
- Device ID of eight 4-letter component codes (`CPU-RAM-RSPD-MOBO-GPU-USER-DISK-UNIT`), a `devices/` registry on the stick that maps every code to its component, and device-specific settings (`modules/device.py`, `core/hwinfo.py`). `--decode-id` prints an ID's components.
- Assistant rules for recent drivers, registry findings and flagged startup entries.

- Built-in reader for `.evtx` files, used when `wevtutil` is missing (as it may be in WinRE), so the level-filtered event export still works (`core/evtx.py`).
- Findings from the collected logs: Startup Repair root cause, CBS and DISM errors with their HRESULTs, corrupt component files, device install failures, notable events (unexpected shutdowns, storage and hardware errors), problems in the BCD listing (`modules/loganalysis.py`), with assistant rules that cite them.

Security (after an independent review; details in the ADR on hardening)
- Fixed: a BitLocker recovery key typed for the unlock step was stored in `case.json`. The audit log already redacted it; the repair record now does too.
- The command wrapper's read-only class is a positive allowlist per tool; tools are resolved only from `System32` or verified `tools/`; diskpart lines with control characters are refused; repairs that address the running Windows are refused by the wrapper itself.
- API repair tokens are single-use and die with the next scan. The BCD backup must exist at the time of the repair.
- Server protocol: signature covers the path, no session takeover by re-sending `hello`, job time-to-live, server-chosen bundle names, size and type checks on everything an agent sends.
- Discovery never offers the recovery environment's own Windows as a target, stops when the case output would land on the target volume, and does not follow links on the target.
- Plugins load only when listed with a matching SHA-256 in `plugins/manifest.sha256`. The spec no longer claims plugins are sandboxed.
- Tokens and the pairing code are shown on the console and kept out of the logs.

Changed
- The spec's deferred items are now roadmap phases 6 to 12.

Verified
- 207 unit tests on Python 3.15 and on the bundled 3.14, not elevated.
- Device ID and hardware reading on the development PC only (one Intel NUC); SMBIOS parsing also against a synthetic table.
- Server, pairing, relayed scan, bundle retrieval and revocation over 127.0.0.1 only.
- Repair steps in dry-run only.

## 0.3.0 - 2026-11-19

Added
- Core: read-only registry hive parser, disk and volume inventory through Windows IOCTLs, command wrapper with allowlist, forbidden list and audit log, case folders, always-on debug log, plain-text UI.
- Discovery, log collection, report, troubleshooting assistant (`config/assistant.toml`), repair helpers, plugin loader.
- `run.cmd`, `Install-ToUsb.ps1`, embeddable Python 3.14.10 with a pinned SHA-256.

Verified
- Scan of the development PC's running Windows from the project folder and from the USB stick with the bundled Python.
- Scan of a fake offline Windows built from real hive files.
- Not verified: WinRE, administrator-only paths, real repairs.

## 0.1.0 - 2026-11-19

- Project skeleton and specification v0.2.
