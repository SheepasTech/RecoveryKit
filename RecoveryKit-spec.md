# RecoveryKit: merged spec (v0.3)

Portable USB toolkit that diagnoses, collects evidence from, and (only with confirmation) repairs unbootable Windows installations. It runs from any Windows-related environment: normal Windows, WinRE, WinPE, or the Windows Setup Shift+F10 prompt.

Merges `project idea1.txt` (a hand-worked case and its guardrails) and `project idea2.txt` (the RecoveryKit vision). Replaces `debug/log-extractor.ps1`.

Status (RecoveryKit 0.5.1): built and tested by an automated suite of over 500 tests on the development PC (Windows 11, not elevated). Not verified: a real WinRE boot, an administrator session, a real offline disk, any real repair command, two machines on a LAN, and the browser page used by hand (it was only driven by a script in headless Edge). Statements below describe what the code does; where the environment decides (which tools WinRE has), the kit reports what is missing instead of assuming.

## 1. Principles

1. **Read-only by default.** Scanning and collecting never write to the target disk. Repairs are a separate, explicit step. Repairs against the running Windows are refused.
2. **Never assume.** Identify the target by disk number, partition size and contents (`\Windows\System32\Config\SYSTEM`), never by a fixed letter. Re-verify before every repair step.
3. **Show, then ask.** Every repair prints the exact command and its effect and waits for a typed yes. No silent retries. Through the API the typed yes is an explicit confirm bound to the shown command (6.6); without the enable switch on the target the API cannot repair.
4. **Forbidden commands** (not implemented in the kit; plugins are trusted code that must be listed with its checksum, see section 5): `diskpart clean`, `format`, `delete partition`, `bootrec /fixmbr`, blind `bcdboot` and `bcdedit /set` without a prior BCD export.
5. **Back up before changing.** Before any BCD change, export the original to the case folder; the wrapper refuses the change unless that export exists as a file. The kit never writes to the target's registry.
6. **Record everything.** Every command, its arguments, exit code and output goes to the audit log, including refused, declined and dry-run commands. A repair writes a "started" line before it runs, so an interrupted repair leaves a trace.
7. **SFC clean does not mean bootable.** The report never says "fixed" until the target has booted; that is a user-confirmed field.
8. **Everything degrades.** If a section cannot run, the report says why. A failed section never aborts the others, and nothing fails silently. The one stop: a scan ends when the case output would be written onto the target volume (use `--out`); it writes no report then, because the report would land on the target.

## 2. Environments and capability matrix

| Environment | Python from USB | PowerShell | Network | Notes |
|---|---|---|---|---|
| Normal Windows | yes | yes | yes | Target usually an attached disk or second install |
| WinRE (stock) | bundled Python expected, not yet verified | **no** | manual (`wpeutil InitializeNetwork`, typed by the operator) | Which tools exist (`wevtutil`, `manage-bde`, `robocopy`, `dism`, `bcdedit`, `chkdsk`) is not yet verified; missing ones are reported |
| WinPE (own build, optional) | as WinRE | optional | automatic via `startnet.cmd` | Not built; same drive-letter behaviour as WinRE |
| Setup Shift+F10 | as WinRE | no | usually none | Same as WinRE |

Rules:
- Core uses only Python stdlib plus the Windows tools above. Disks, partitions and volumes come from Windows IOCTLs through `ctypes` (only `core/` imports it), so they do not depend on the language of the environment or on administrator rights. `diskpart` and `wmic` output is never parsed. `wmic` is a last fallback for disk health only, after `smartctl` and PowerShell. PowerShell runs only built-in fixed snippets, and only when present.
- 64-bit only (WinRE has no WOW64).
- BitLocker: detect with `manage-bde -status` and report. If a volume is locked, the repair menu can unlock it with a recovery key the operator types; the key is never stored or logged.

## 3. USB layout

```
RecoveryKit/
  run.cmd                  launcher: finds its own drive, picks Python, starts the menu
  Install-ToUsb.ps1        fetches the embeddable Python, copies the kit to a stick (config by allowlist), adds the CA certificate, checks the result for keys and tokens
  python/                  embeddable 64-bit Python + ._pth pointing at lib/
  lib/                     empty: no third-party dependencies
  recoverykit/             core/ (hive parser, IOCTLs, wrapper, case, log, ui), modules/,
                           engine.py, net.py, web/ (browser page)
  config/                  kit.toml, assistant.toml (decision rules), ca-cert.pem (CA certificate, public part, put there by the installer)
  cases/                   output, one folder per case (see section 4)
  devices/                 device registry and per-device settings (see section 4)
  plugins/                 optional, with manifest.sha256 (see section 5)
  tools/                   optional third-party binaries (smartctl, etc.), checksummed
  docs/
  tests/                   unit tests (stdlib unittest)
```

- All paths are relative to the launcher; the USB letter is never assumed.
- Output goes to `cases/` on the USB, or to `--out`. If the USB is read-only or full, ask for another writable location. Never write to the target disk except in a confirmed repair step.
- `tools/` entries have a SHA-256 manifest, verified at start; only verified binaries are used.

## 4. Case model and output

One **case** per target disk and run set.

- **Case ID** = `ITW-<ticket>-<target id>` if the operator enters a ticket number, else `T-<target id>`. The target ID is derived from the **target** (disk serial / UniqueId plus a hash of the offline registry `MachineGuid`), not the machine running the kit. This fixes the old script, which hashed the bench PC.
- **Device ID** = eight codes of four capital letters, joined by dashes: `CPU-RAM-RSPD-MOBO-GPU-USER-DISK-UNIT`. Each code is a hash of one component (CPU name; RAM size and module part numbers; rated and running memory speed; board manufacturer and product; PCI IDs of the display adapters; last logged-on user; target disk model; system UUID or board serial), so a changed component changes only its code. `XXXX` means not readable. The UUID or serial behind the last code is not shown on the console, in the report, in `case.json` or through the API (it reads "kept in device.json"); the raw value stays in `inventory/device.json` and the device registry. It comes from SMBIOS and the hardware registry key, which need no WMI or PowerShell. It describes the machine the kit runs on: in WinRE that is the customer's PC; with the disk attached to a bench PC it is the bench PC, and the scan says so. The case ID does not depend on it.
- `devices/` next to `cases/`: `index.md` (all devices in plain words), `components.json` (every code and the component it stands for), `devices/<ID>/device.json` (components, hardware, runs) and `devices/<ID>/settings.json` (notes, ticket, answers; applied at each scan, command-line values win). `--decode-id <ID>` prints the components. `devices/` holds user names and serial numbers: customer data, like `cases/`.
- Folder: `cases/<case-id>/<YYYYMMDD-HHMM>/` (`cases/_pending/...` until the target is known).

```
case.json           machine-readable summary (schema versioned)
report.md           human-readable case file (see 6.3)
inventory/          disks, partitions, volumes, installs, hardware, registry snapshot,
                    drivers, autoruns, services, tasks, log findings (json)
logs/               collected logs, raw and untouched
exports/            BCD backup and working copy
debug.log           everything shown, asked, answered and run
audit.log           every command attempted, with exit code; full output in audit/
```

- `logs/` files keep original names, prefixed by source (`target-`, `host-`).
- `--bundle` produces a single `.zip` of the run for transfer to the main machine.
- Ticket integration: a bundle is copied into the vault as `Inbox/Tickets/ITW <nr>/` by hand, or by the control server's `--intake` folder.

## 5. Architecture

- **Core engine** (`engine.py`): one engine holds every operation (scan, case, files, suggestions, repair proposals, run step, bundle). It has no UI. It runs modules in a fixed order, records status per section (`ok`, `missing`, `error`, `skipped`), owns the audit log and case folder, and runs one operation at a time.
- **Front ends are thin**: the plain-text menu, the headless CLI (`--scan --auto`), the agent API and the control server. All call the engine.
- **Module** = a Python file with `collect()` (read-only, returns data and files) and optionally `repair_steps()` (returns proposed steps, never runs them itself).
- **Command wrapper** (`core/runner.py`): the only place that starts external programs (never through a shell). It is a positive allowlist: each tool has spelled-out read-only forms, repair forms and host forms; anything not matched is refused. Tools are named by bare name and resolved only from `%SystemRoot%\System32` or verified `tools/`: no PATH, no current directory. It runs with a timeout, captures output and exit code, and writes the audit entry. Built-in modules do not import `subprocess` or `ctypes` (a test enforces it). One other place starts a process: on the control host only, `tlsca.py` runs the certificate script with a fixed argument list.
- **UI**: a plain-text numbered menu on `print`/`input`, ASCII only. No third-party UI library; `lib/` holds no dependencies. GUI is out of scope for the agent; the control server serves one browser page (6.6).
- **Plugins**: modules from `plugins/` follow the same interface and are expected to run commands only through the command wrapper. A plugin is trusted code: nothing technically stops listed plugin code from doing otherwise. Plugins load only when listed with a matching SHA-256 in `plugins/manifest.sha256`; the source check is a guard against mistakes, not a sandbox.
- **APIs**: the agent API (JSON over HTTP, `/api/v1`) runs on 127.0.0.1 of the target and nowhere else. The server API runs on the main machine, serves the operator and relays agent calls. Both work without the other: the kit is fully usable with no server (serverless) and with nobody at the keyboard (headless). Routes: `docs/api.md`.

## 6. Modules

### 6.1 Discovery (phase 1)
- Disks, partitions, volumes, drive-letter mapping from Windows IOCTLs (`\\.\PhysicalDriveN`, volume extents). No `diskpart` or `wmic` parsing. RAM-disk volumes and the recovery environment's own Windows are never offered as targets.
- Offline Windows installs: all volumes with `\Windows\System32\Config\SYSTEM`; present a choice list. `--target-path` names a folder that contains `Windows` (mounted image); it is verified by contents and repairs against it are refused (disk unknown).
- Per install: edition, build and revision, language, architecture, read from the offline registry by a built-in read-only hive parser. `reg load` is never used (it replays hive logs and writes to the target); `dism /Image` queries are not used (DISM mounts the hives). Hive transaction logs are not replayed: a dirty hive is flagged as possibly stale.
- Boot structure: which EFI/System partition and Recovery partition exist, on which disk; boot mode (UEFI/BIOS) of the running environment.
- Environment: running OS, PowerShell and Python versions, network adapters.
- **Free-space check** on the target volume (warn below 10 GB or 10%).
- **Transient-error handling**: a read-only command may be retried once on a named transient exit code (for example DISM error 32). Repair steps are never retried.

### 6.2 Log collection (phase 1)
Per source, record found/missing/error:
- Target: `SrtTrail.txt`, `CBS.log`, `DISM\dism.log`, `Panther\` setup logs, `setupapi.dev.log`, `ntbtlog.txt`, minidumps (copied up to a size limit) and `MEMORY.DMP` (metadata only). Event logs `System`, `Application`, `Kernel-Boot`, `Kernel-PnP`, `Diagnostics-Performance`: the raw `.evtx` is copied, plus an export filtered by level (critical, error, warning) first and limited after (fixing the old 200-then-filter bug), made by `wevtutil` or, when it is missing, by the built-in `.evtx` reader. Links and reparse points on the target are not followed.
- BCD: `EFI\Microsoft\Boot\BCD` is copied out through the volume GUID path (no drive letter is assigned, the EFI partition is not written) to `exports/`: one untouched `.bak` (the backup required before any BCD change) and a working copy, on which `bcdedit /store <copy> /enum all /v` runs. Reading the EFI partition needs administrator or WinRE.
- Host (the environment running the kit): its own DISM/CBS logs, labelled `host-` so they are never confused with the target's.
- Disk health: `smartctl` from `tools/` if present, else PowerShell storage cmdlets if present, else `wmic diskdrive` status as a last fallback; `chkdsk <x>:` (read-only mode, no switches) only with `--chkdsk`.
- Pending operations: `pending.xml`, `reboot.xml`, servicing state flags in the offline registry.

### 6.3 Reporting (phase 1)
- `case.json` plus `report.md` generated from it.
- Report structure (taken from idea 1):
  1. **Confirmed facts** (target disk, size, free space, build, edition, language, partitions)
  2. **Not yet established** (exact boot failure, whether firmware sees the disk; prompted from the operator)
  3. **Actions taken and results** (from audit log)
  4. **Current state**
  5. **Suggested next step**, with the evidence for it
- The header shows the device ID; a "things to look at" list carries the findings of 6.7 to 6.10.
- Human report and JSON are produced from the same data, never separately.

### 6.4 Repair helpers (phase 2)
Staged and confirmed one at a time, each followed by "test boot, then record the result":
1. **Repair-source check**: before any `dism /RestoreHealth /Source:`, read the WIM/ESD/SWM header and its XML (not localized `dism` output) and compare the source's build, edition, architecture and **language** with the target. Build must be equal; an unknown target value counts as a mismatch. Refuse mismatches with the reason (idea 1: lt-LT source against an en-US target gave 0x800f0915); `/RestoreHealth` is then proposed without `/Source`. Split `.swm` sources are handled by an explicit export step.
2. DISM `/ScanHealth` then `/RestoreHealth` with `/Image` only; SFC offline (`/offbootdir`, `/offwindir`) only. `dism /Online`, `sfc /scannow` on the running system, `chkdsk /r` are not offered. Never two operations on the same image at once. Use `/ScratchDir` on a volume with free space.
3. Recovery-style options: uninstall a quality update (`dism /Remove-Package`, exact package name), remove a third-party driver (6.9); System Restore and Startup Repair as guidance only.
4. BCD: inspect first; any rewrite requires a prior export, shows the exact command, and is offered only for a GPT target disk with exactly one EFI partition and a lettered Windows volume.
5. Files: copy-out of user data to a chosen drive (back-up-first helper, with free-space check).
6. Storage: bring an offline disk online; unlock a BitLocker volume (key typed, never stored or logged).

### 6.5 Troubleshooting assistant (phase 3)
- Symptom-based flow driven by `config/assistant.toml`: no boot device, automatic-repair loop, stop code, spinning dots, missing `SrtTrail.txt`, and so on.
- Branches follow idea 1 section A to E: establish the failure, source-mismatch, recovery options, boot configuration, storage/hardware.
- Suggestions cite the scan result that triggered them. The assistant proposes; it never executes without section 1 rule 3.
- "What changed?": diff against the previous run of the same case (inventory, pending updates, event counts).

### 6.6 Control server (phase 4, optional)
- Off by default; on only when the operator runs `run.cmd --connect` on the target. The session ends on a keypress on the target, after `--session-minutes` (default 60), or when the server revokes it.
- **The agent connects out** to the server on the main machine (HTTPS by default, long-poll; no WebSocket). No inbound ports on the target. The agent API itself listens on 127.0.0.1 only.
- The server binds to the interface named with `--bind` (default 127.0.0.1; give the LAN address), never `0.0.0.0` by default.
- Authentication: a pre-shared agent token (generated on the server in `config/token-server.json`) plus a per-session pairing code shown on the target that the operator enters on the server before any job is relayed. The code is 10 characters from an alphabet without I, O, 0 and 1, shown as `XXXXX-XXXXX`; it may be typed in any case, with or without the dash. Five wrong codes lock the session.
- Every message carries two HMAC-SHA256 values: a head MAC (`X-RK-Head`, over path, metadata and `Content-Length`) that the server checks before it reads any body byte, and a signature (`X-RK-Sig`) over a direction label, path, metadata and the body's hash. The label is `req` on what the agent sends and `resp` on what the server answers, so a request cannot be reflected back as an answer. Before pairing the key is the agent token; after pairing it is a session key derived from the agent token, the agent id and the pairing code, so the agent token alone cannot speak for a paired session. 20 invalid signatures for one agent id revoke that session; the agent then has to start a new one (new id, new code).
- TLS is the default. The control host PC is the certificate authority: `--server` issues its certificate from the CA in `%LOCALAPPDATA%\ITwork\CA` via `New-ItworkCertificates.ps1` (the CA is created on first need), and agents verify it against the CA certificate that `Install-ToUsb.ps1` put on the stick (`--pin` is the alternative). An `https://` connection is never made unverified. The server refuses to start without TLS unless `--no-tls` is given; then traffic is authenticated but not encrypted, and on a LAN where someone also has the agent token the session can be taken over: trusted LAN only. Certificates are valid from a day before they are issued; a target clock that is further off makes verification fail (WinRE clocks are often wrong).
- Limits: 64 connections at a time, 8 per remote address (the local machine is exempt and has reserved slots); request bodies up to 64 MiB, an agent's result up to 1 GiB; a request must arrive within 120 s, plus 1 s per MiB for a result.
- Modes: **read-only** (GET routes, scan, bundle, answers, source check) by default; **repairs** only when the target session was started with `--allow-remote-repairs` (`--allow-repairs` for the loopback API). A repair request carries `confirm: "yes"` and the single-use token returned for that exact command line; the token dies with the next scan or listing. The command wrapper still applies every rule. No arbitrary-shell route exists.
- Every remote action goes into `audit.log` with the operator name. The API token and the pairing code are shown on the console only and never written to a log. Server log: `<store>\_server-logs\`.
- Server stores received bundles under `--store` (named by the server, verified as zip, never overwritten), can copy them to a vault intake folder, and lists stored cases. It serves one browser page at `/` (the operator pastes the operator token once). Fleet history beyond that is not built.
- Network bring-up in WinRE: the operator types `wpeutil InitializeNetwork` (the wrapper allows it, no module runs it); for missing NIC drivers, `drvload` of an `.inf` (allowed without switches).

### 6.7 Log findings (phase 1)
- From the collected logs, a list of findings with the file and line that caused each: Startup Repair root cause (`SrtTrail.txt`), CBS and DISM errors with their HRESULTs, corrupt component files, setup and device-install failures (`setupapi`), notable events (unexpected shutdowns, storage and hardware errors), problems in the BCD listing. Written to `inventory/log-findings.json` and fed to the assistant.

### 6.8 Registry snapshot and diff (phase 6)
- Snapshot of the startup-relevant keys of the offline registry (safe-boot flag, setup in progress, control-set mismatch, pending servicing, non-default shell) with a findings list. From the second run of a case, `registry-changes.txt` lists what changed since the previous run. Read-only.

### 6.9 Driver inventory (phase 7)
- Third-party drivers of the target (`INF\oem*.inf`), newest first; drivers added shortly before the install's last activity are listed in the report. Removal (`dism /Image /Remove-Driver /Driver:oemNN.inf`) is a proposed, confirmed repair step.

### 6.10 Startup inventory (phase 8, 9)
- Autoruns, auto-start services and scheduled tasks of the target, with neutral flags for entries worth a look. Findings, not verdicts: the kit never labels anything as malware and never removes an entry.

## 7. Security

- Customer data (names, PINs, disk contents) stays on the USB and the main machine; nothing is sent elsewhere.
- The USB may contain case and device data: offer `--wipe-case` and warn on leaving it with a customer. `--wipe-case` does not remove `devices\<ID>` or the `%TEMP%` copy of the log.
- No secrets in `config/` committed to git; the server token is generated per install and git-ignored. BitLocker keys, API tokens and pairing codes are never logged or stored in the case.
- Vendored dependencies (none) and `tools/` binaries are pinned and checksummed. The bundled Python is pinned by SHA-256 in `Install-ToUsb.ps1`.
- The control host is the certificate authority: the CA key stays on that PC (never on a stick); sticks carry only the CA certificate; no unverified TLS connection is ever made.
- Forbidden-command list (section 1.4) is enforced in the command wrapper, not just by convention.
- Plugins are trusted code with the kit's rights. A plugin loads only with a matching SHA-256 in `plugins/manifest.sha256`; list only code you have read.
- Everything read from a target (registry hives, event logs, text logs, file names) is treated as hostile input: parsers are bounded and fail with one error type, links are not followed, collected files must resolve inside the target and land inside the case folder, and every value written to `report.md`, `devices/index.md` or the console is escaped or stripped of control characters.
- The installer copies `config/` by allowlist and ends with a check of file contents for private keys and token values (`-CheckOnly <folder>` runs only that check).

## 8. Phases and acceptance

Every phase below is built and covered by the automated tests on the development PC. None has been run in WinRE or against a real broken PC; that run is the acceptance step for each "done when".

| Phase | Scope | Done when | State |
|---|---|---|---|
| 1 | Discovery + log collection + report | On a stock WinRE boot, `run.cmd` finds the offline install, picks the correct disk without any hard-coded letter, produces a case folder where every section is `ok`/`missing`/`error` with reasons, and nothing on the target changed (verified by timestamps/hashes) | Built. Tested on a fake offline Windows and on the running Windows of the dev PC. Not run in WinRE |
| 2 | Repair helpers | Source-mismatch check blocks the lt-LT/en-US case; each repair shows its command, asks, logs, and exports before changing BCD | Built. Source check proven on the lt-LT/en-US case; repairs run in dry-run only |
| 3 | Assistant | Given the idea 1 case inputs, suggests the same next steps in the same order | Built. Idea 1 case fixture yields branches A to E in order |
| 4 | Control server | Pair, read-only stream, bundle retrieval and revocation work over LAN; no inbound port on target | Built. Proven over 127.0.0.1, with and without TLS, between real processes (real handshakes against a test CA); not between two machines on a LAN |
| 5 | Plugins and extras | Third-party module loads through the command wrapper only, with a matching checksum | Built (loader, manifest, source check). No plugin shipped |
| 6 | Registry diffing | A second scan lists what changed in the startup-relevant keys | Built |
| 7 | Driver rollback | Recent third-party drivers listed; removal of one is a confirmed step | Built; removal in dry-run only |
| 8 | Malware triage | Autoruns, services, tasks listed with neutral flags; nothing removed | Built |
| 9 | Scheduled tasks | Target task inventory (part of 8); unattended scheduled scans from the server | Target side built; server side planned |
| 10 | Fleet mode | Server tracks many agents and cases, history per machine | First cut: stored-cases view built from bundles; no persistent agent list |
| 11 | GUI | Browser front end on the same API | First cut: one page served by the server. Driven in headless Edge by `tests/browser/smoke.mjs` (sign-in, pairing, scan, panels, bundle, revoke); nobody has used it by hand |
| 12 | Plugin marketplace | Signed plugin index, install and update from the server | Planned |

Deferred (not built): server-side scheduled scans (needs a decision on unattended sessions), plugin marketplace (needs a signature scheme; the standard library has no asymmetric signing), client certificates for agents (mutual TLS), custom WinPE image.

## 9. Known issues carried over from `log-extractor.ps1`

- ID hashed from the bench PC instead of the target. The case ID comes from the target's disk serial and `MachineGuid`; the device ID is separate and says when it describes another machine.
- `system.md` described the bench PC, not the target. Target facts come from the target's own registry; host data is labelled `host-`.
- Errors silenced by `SilentlyContinue`; empty sections gave no reason. Every section and source has a status and a reason; an exception marks only its own section.
- Event logs read newest 200 then filtered by level. The level filter runs first, the limit after.
- Target's own CBS log not collected; `Get-Item` output printed as raw format objects. CBS and DISM logs are copied as files from the target and labelled by source; nothing is printed as objects.
- Hard-coded `C:` and `W:`; output written to Desktop; no disk health data. The target is found by contents; output goes to `cases/` next to the launcher or `--out`; a disk health section exists.

## 10. Open questions

Answered:
1. UI: a plain-text menu; `textual` is not used.
2. Boot method: stock WinRE and Setup Shift+F10; no custom WinPE image.
3. Bundle destination: copied into `Inbox/Tickets/` by hand, or by the server's `--intake` folder.
4. `wmic`: not used for discovery; last fallback for disk health only.
5. Repository: `Tools/RecoveryKit` in the vault, its own git repo; USB install at `<USB>:\ITWORK\RecoveryKit`.

Open:
1. What does a real WinRE boot show: does the bundled Python start, which tools exist (`wevtutil`, `manage-bde`, `robocopy`), does the console show the menu correctly?
2. Client certificates (mutual TLS) for agents: wanted or not? Server certificates are settled: the control host is the CA and sticks carry its certificate.
3. Should the old test case and device entry on the USB (`cases\ITW-99999-...`, `devices\`) be kept?
