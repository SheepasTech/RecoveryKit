# Changelog

Newest first. "Verified" says how a change was checked; anything not listed there was not checked.

## 0.5.2 - 2026-11-19

Fixed (from a short verification of the 0.5.1 fixes)
- The remote path now also survives a name on the target that is not valid Unicode: API answers, the bundle and relayed jobs no longer fail on it, and a job that cannot produce its result is answered with an error while the session goes on.
- One byte budget for a whole enumeration of registry keys (a crafted 1 MB hive could still use hundreds of MB); multi-string values are bounded by their decoded size.
- The control server and the loopback API refuse unknown paths and unauthenticated requests before reading a body.
- Only 20 invalid signatures in a row revoke an agent; a valid message resets the count.
- Device-namespace spellings of network and system paths are recognised by the command wrapper.
- The check that keeps the case output off the target stops the scan when the check itself fails.
- The certificate script puts the CA key back to owner-only access at every run. The installer's secret check reads files up to 4 MB.

Known and not fixed
- The installer's secret check is a guard against mistakes: it does not look into `python`, into large or nested archives, or for tokens in forms other than JSON.
- On `--no-tls`, someone on the LAN who knows an agent's id can end its session with invalid messages; they cannot take it over.
- A scan can still be slowed by a very large damaged event log: the built-in reader stops after 60 seconds per file.

Verified
- 544 unit tests on Python 3.15, not elevated.

## 0.5.1 - 2026-11-19

Security and robustness (third independent review)
- A file or folder name on the target that is not valid Unicode no longer ends a scan: every file that receives target strings is written with escapes, and a failing save cannot leave a section.
- Hive reading is linear in the size of the hive: children of a key are walked once instead of being re-opened by name (a crafted hive took over a minute, now 0.02 s); a key name may contain `/`; values have a byte budget per call.
- The event-log reader has a budget per file (steps and 60 s) and per value, and says when it stopped early.
- Pairing code is 10 characters from an unambiguous alphabet, shown as `XXXXX-XXXXX`; 20 invalid signatures for an agent revoke its session; signatures carry a direction label.
- Control server: the operator token is checked before a request body is read; at most 8 connections per client address with reserved slots for the local machine; the upload deadline grows with the size of the result; a failed upload is reported to the operator at once.
- Certificate script: creating the CA is atomic (six parallel first runs give one CA); files are written to a temporary name and renamed; key files get an access list of the current user only, also when an existing key file is replaced; certificates are valid from a day before issue; a server key that does not match its certificate is re-issued.
- Installer: `config` is copied by allowlist; the final check looks into files for key material and token values.
- Report: `%` is escaped, invisible format characters are dropped, a pipe in a command stays a pipe, a code value cannot be read as a Dataview or Templater expression. The unit identifier (system UUID or serial) is no longer printed in the report, the device table or on the console; it stays in `device.json`.
- Wrapper: one rule for network paths in every spelling; exact switch tokens for `bcdedit` and `smartctl`; copy-out cannot target the running system's folders or a network share.
- A scan that stops because the output folder is on the target writes nothing further there, also when the folder is given as a `\\?\` or `\\localhost\C$` path.

Fixed
- Found in a live run, not by the tests: the server could not start with TLS from the project folder, because replacing an existing key file kept that file's extra access entries. A regression test covers it.
- Two assistant rules told the operator to run commands the kit itself refuses as unsafe (`bcdedit` on the EFI partition's store, `chkdsk /scan` described as read-only).

Verified
- The page of the control server in headless Edge, driven through the DevTools protocol: pairing, relayed scan, every panel, an injection probe through real data, light and dark, wide and narrow.
- Real two-process sessions over TLS with a temporary CA.
- The reviewer's own fuzzing: 25,600 mutated hives and 6,040 mutated event logs produced only the intended error types; 535 million command lines enumerated, nothing in the read-only class writes or executes.
- Not verified: two machines on a LAN, anything in WinRE, an administrator session, a real repair.

## 0.5.0 - 2026-11-19

Added
- The control host PC is the certificate authority. `New-ItworkCertificates.ps1` creates one private CA per user (outside the repository, no certificate store, no administrator) and issues the server certificate. `--server` uses TLS by default and refuses to start without it unless `--no-tls` is given. `Install-ToUsb.ps1` puts only the CA certificate on the stick. Agents verify the server against it; an `https://` connection with neither CA nor `--pin` is refused.
- After pairing, agent and server sign with a session key derived from the pairing code, so the shared agent token alone cannot take over a paired session.

Security (second independent review)
- A corrupted or hostile target disk can no longer hang or blind a scan: the hive parser bounds every count and size and raises one error type only (3000-mutation fuzz test); the log analyser clips long lines and uses linear patterns; the event-log reader has a work budget per record; folder walks do not follow links and are capped; one unreadable install no longer hides the others.
- Files are collected only if they resolve inside the target and land inside the case folder; odd file names are replaced by safe ones.
- Every value written into `report.md` and `devices/index.md` is escaped, so a registry string or file name cannot inject headings, links, images or code blocks into the report. Control characters are stripped from console output.
- `bcdedit` may only open a store that is a copy inside the case folder. More read-only forms tightened (`reg query`, `wevtutil qe`, `reagentc`, robocopy paths); arguments with control characters, quotes or look-alike switch characters are refused; checksum manifests in UTF-16 are read.
- A scan now stops immediately when the case output is on the target volume, including through a junction.
- Server: requests are authenticated from their headers before the body is read; connection cap and request deadline; stale agents expire; bundles are checked for size before being unpacked.

Verified
- Real TLS handshakes against a temporary CA, including a CA created under Windows PowerShell 5.1 and used under PowerShell 7 and the reverse.
- Not verified: two machines on a LAN, anything in WinRE, the browser page in a browser.

## 0.4.1 - 2026-11-19

Security (after an independent review; details in the ADR on hardening)
- Fixed: a BitLocker recovery key typed for the unlock step was stored in `case.json`. The audit log already redacted it; the repair record now does too.
- The command wrapper's read-only class is a positive allowlist per tool; tools are resolved only from `System32` or verified `tools/`; diskpart lines with control characters are refused; repairs that address the running Windows are refused by the wrapper itself.
- API repair tokens are single-use and die with the next scan. The BCD backup must exist at the time of the repair.
- Server protocol: signature covers the path, no session takeover by re-sending `hello`, job time-to-live, server-chosen bundle names, size and type checks on everything an agent sends.
- Discovery never offers the recovery environment's own Windows as a target, stops when the case output would land on the target volume, and does not follow links on the target.
- Plugins load only when listed with a matching SHA-256 in `plugins/manifest.sha256`. The spec no longer claims plugins are sandboxed.
- Tokens and the pairing code are shown on the console and kept out of the logs.

Changed
- Specification updated to v0.3: it now states what was decided and built (built-in hive parser, disk inventory through Windows IOCTLs, plain-text UI, engine with agent and server APIs, device ID, the inventories, plugins as trusted code).
- Operator manual lists every switch and has a first-run checklist for a real machine.
- Browser page: pairing input survives the refresh, device ID shown, log findings view, labels and live status region.

Verified
- 339 unit tests, twice on Python 3.15 and once on the bundled 3.14, not elevated. They include every input from the review that used to be accepted.
- Missing tools are simulated by replacing the tool resolver; a scan with no external tools at all still completes with a reason for every gap.
- Not verified at that point: the TLS path, anything in WinRE, the browser page in a browser.

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

Changed
- The spec's deferred items are now roadmap phases 6 to 12.

Verified
- 262 unit tests on Python 3.15 and on the bundled 3.14, not elevated.
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
