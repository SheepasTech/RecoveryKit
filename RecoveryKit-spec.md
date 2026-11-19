# RecoveryKit: merged spec (v0.2)

Portable USB toolkit that diagnoses, collects evidence from, and (only with confirmation) repairs unbootable Windows installations. It runs from any Windows-related environment: normal Windows, WinRE, WinPE, or the Windows Setup Shift+F10 prompt.

Merges `project idea1.txt` (a hand-worked case and its guardrails) and `project idea2.txt` (the RecoveryKit vision). Replaces `debug/log-extractor.ps1`.

## 1. Principles

1. **Read-only by default.** Scanning and collecting never write to the target disk. Repairs are a separate, explicit step.
2. **Never assume.** Identify the target by disk number, partition size and contents (`\Windows\System32\Config\SYSTEM`), never by a fixed letter. Re-verify before every repair step.
3. **Show, then ask.** Every repair prints the exact command and its effect and waits for a typed yes. No silent retries.
4. **Forbidden commands** (not implemented in the kit; plugins are trusted code that must be listed with its checksum, see section 5): `diskpart clean`, `format`, `delete partition`, `bootrec /fixmbr`, blind `bcdboot` and `bcdedit /set` without a prior BCD export.
5. **Back up before changing.** Before any BCD or registry change, export the original to the case folder.
6. **Record everything.** Every command, its arguments, exit code and output goes to the audit log.
7. **SFC clean does not mean bootable.** The report never says "fixed" until the target has booted; that is a user-confirmed field.
8. **Everything degrades.** If a section cannot run, the report says why. A failed section never aborts the others, and nothing fails silently.

## 2. Environments and capability matrix

| Environment | Python from USB | PowerShell | Network | Notes |
|---|---|---|---|---|
| Normal Windows | yes | yes | yes | Target usually an attached disk or second install |
| WinRE (stock) | yes | **no** | manual (`wpeutil InitializeNetwork`) | Only `cmd`, `dism`, `bcdedit`, `reg`, `diskpart`, `chkdsk`, `wmic` |
| WinPE (own build, optional) | yes | optional | automatic via `startnet.cmd` | Same drive-letter behaviour as WinRE |
| Setup Shift+F10 | yes | no | usually none | Same as WinRE |

Rules:
- Core uses only Python stdlib plus the Windows tools above. `wmic` is a fallback only where it still exists (newer builds removed it); PowerShell/CIM is used when present.
- 64-bit only (WinRE has no WOW64).
- BitLocker: detect with `manage-bde -status` and report. If locked, collection stops at the metadata that is readable and asks for the recovery key; the tool never stores keys.

## 3. USB layout

```
RecoveryKit/
  run.cmd                  launcher: finds its own drive, picks Python, starts the TUI
  python/                  embeddable 64-bit Python + ._pth pointing at lib/
  lib/                     vendored pure-Python deps (no compiler needed)
  recoverykit/             core + modules (see section 5)
  config/                  kit.toml, allowlists, repair playbooks
  cases/                   output, one folder per case (see section 4)
  tools/                   optional third-party binaries (smartctl, etc.), checksummed
  docs/
```

- All paths are relative to the launcher; the USB letter is never assumed.
- Output goes to `cases/` on the USB. If the USB is read-only or full, ask for another writable location. Never write to the target disk except in a confirmed repair step.
- `tools/` entries have a SHA-256 manifest, verified at start.

## 4. Case model and output

One **case** per target disk and run set.

- **Case ID** = `ITW-<ticket>` if the operator enters a ticket number, plus a short target ID. The target ID is derived from the **target** (disk serial / UniqueId plus the offline registry `MachineGuid`), not the machine running the kit. This fixes the old script, which hashed the bench PC.
- Folder: `cases/<case-id>/<YYYYMMDD-HHMM>/`

```
case.json           machine-readable summary (schema versioned)
report.md           human-readable case file (section 7)
inventory/          disks.json, partitions.json, hardware.json, installs.json
logs/               collected logs, raw and untouched
exports/            bcd.bak, registry hives (only when requested)
audit.log           every command run, with exit code
```

- `logs/` files keep original names, prefixed by source (`target-`, `host-`).
- `--bundle` produces a single `.zip` of the run for transfer to the main machine.
- Ticket integration: a bundle can be dropped into the vault as `Inbox/Tickets/ITW <nr>/` (manual copy at first).

## 5. Architecture

- **Core engine**: runs modules in a fixed order, records status per section (`ok`, `missing`, `error`, `skipped`), owns the audit log and case folder.
- **Module** = a Python file with `collect()` (read-only, returns data and files) and optionally `repair_steps()` (returns proposed steps, never runs them itself).
- **Command wrapper**: single place that runs external tools with a timeout, captures output and exit code, and writes the audit entry. Modules cannot call subprocess directly.
- **UI**: TUI first (`textual` if it works in WinRE, plain-text menu fallback). GUI is out of scope for v1.
- **Plugins**: modules from `config/` or `plugins/` follow the same interface; none can bypass the command wrapper or the forbidden list. Plugins load only when listed with a matching SHA-256 in `plugins/manifest.sha256`; the source check is a guard against mistakes, not a sandbox.

## 6. Modules

### 6.1 Discovery (phase 1)
- Disks, partitions, volumes, drive-letter mapping (via `diskpart`/`wmic`/CIM depending on environment).
- Offline Windows installs: all volumes with `\Windows\System32\Config\SYSTEM`; present a choice list.
- Per install: edition, build and revision, language, architecture (from the offline registry via `reg load` to a temporary key, always unloaded afterwards, or `dism /Image:<x>:\ /Get-CurrentEdition` and `/Get-Intl`).
- Boot structure: which EFI/System partition and Recovery partition exist, on which disk; boot mode (UEFI/BIOS) of the running environment.
- Environment: running OS, PowerShell and Python versions, network adapters.
- **Free-space check** on the target volume (warn below 10 GB or 10%).
- **Transient-error handling**: DISM error 32 and similar are retried once before being reported.

### 6.2 Log collection (phase 1)
Per source, record found/missing/error:
- Target: `SrtTrail.txt`, `CBS.log`, `DISM\dism.log`, `Panther\` setup logs, minidumps and `MEMORY.DMP` (metadata only unless requested), event logs `System`, `Application` (filter by level first, then limit, fixing the old 200-then-filter bug), `Microsoft-Windows-Kernel-*` boot logs where present.
- BCD: `bcdedit /store <EFI>\EFI\Microsoft\Boot\BCD /enum all` (read-only), exported raw copy.
- Host (the environment running the kit): its own DISM/CBS logs, labelled `host-` so they are never confused with the target's.
- Disk health: `smartctl` from `tools/` if present, else `wmic diskdrive` status; `chkdsk <x>: /scan` (read-only).
- Pending operations: `pending.xml`, `Windows\WinSxS\pending.xml`, `reboot.xml`, servicing state flags in the offline registry.

### 6.3 Reporting (phase 1)
- `case.json` plus `report.md` generated from it.
- Report structure (taken from idea 1):
  1. **Confirmed facts** (target disk, size, free space, build, edition, language, partitions)
  2. **Not yet established** (exact boot failure, whether firmware sees the disk; prompted from the operator)
  3. **Actions taken and results** (from audit log)
  4. **Current state**
  5. **Suggested next step**, with the evidence for it
- Human report and JSON are produced from the same data, never separately.

### 6.4 Repair helpers (phase 2)
Staged and confirmed one at a time, each followed by "test boot, then record the result":
1. **Repair-source check**: before any `dism /RestoreHealth /Source:`, compare the source's build family, edition, architecture and **language** with the target. Refuse mismatches with the reason (idea 1: lt-LT source against an en-US target gave 0x800f0915). Split `.swm` sources are handled by an explicit export step.
2. DISM `/ScanHealth` then `/RestoreHealth`; SFC offline (`/offbootdir`, `/offwindir`). Never two operations on the same image at once. Use `/ScratchDir` on a volume with free space.
3. Recovery-style options as guidance only: uninstall latest quality update (`dism /Remove-Package`), System Restore points listing, Startup Repair.
4. BCD: inspect first; any rewrite requires a prior export, shows the exact diff, and lists which EFI partition the firmware will use.
5. Files: copy-out of user data to a chosen drive (back-up-first helper, with free-space check).

### 6.5 Troubleshooting assistant (phase 3)
- Symptom-based flow driven by `config/` decision files: no boot device, automatic-repair loop, stop code, spinning dots, missing `SrtTrail.txt`, and so on.
- Branches follow idea 1 section A to E: establish the failure, source-mismatch, recovery options, boot configuration, storage/hardware.
- Suggestions cite the scan result that triggered them. The assistant proposes; it never executes without section 1 rule 3.
- "What changed?": diff against the previous run of the same case (inventory, pending updates, event counts).

### 6.6 Control server (phase 4, optional)
- Off by default; on only when the operator runs `run.cmd --connect` and approves each session on screen.
- **The agent connects out** to the server on the main machine (HTTP/WebSocket). No inbound ports on the target.
- LAN only; server binds to the LAN interface, not `0.0.0.0` by default.
- Authentication: per-session pairing code shown on the target, plus a pre-shared token. TLS with a self-signed cert pinned on the USB if feasible.
- Modes: **read-only** (stream logs, fetch case files) by default; **allowlisted commands** only after the operator enables it for the session; no arbitrary shell.
- Every remote action goes into `audit.log` with the operator identity. Session ends on a keypress on the target or timeout.
- Server stores received bundles under a case folder and can drop them into the vault intake.
- Network bring-up in WinRE: `wpeutil InitializeNetwork`; for missing NIC drivers, `drvload` from `tools/drivers/`.

## 7. Security

- Customer data (names, PINs, disk contents) stays on the USB and the main machine; nothing is sent elsewhere.
- The USB may contain case data: offer `--wipe-case` and warn on leaving it with a customer.
- No secrets in `config/` committed to git; the pairing token is generated per install.
- Vendored dependencies and `tools/` binaries are pinned and checksummed.
- Forbidden-command list (section 1.4) is enforced in the command wrapper, not just by convention.

## 8. Phases and acceptance

| Phase | Scope | Done when |
|---|---|---|
| 1 | Discovery + log collection + report | On a stock WinRE boot, `run.cmd` finds the offline install, picks the correct disk without any hard-coded letter, produces a case folder where every section is `ok`/`missing`/`error` with reasons, and nothing on the target changed (verified by timestamps/hashes) |
| 2 | Repair helpers | Source-mismatch check blocks the lt-LT/en-US case; each repair shows its command, asks, logs, and exports before changing BCD |
| 3 | Assistant | Given the idea 1 case inputs, suggests the same next steps in the same order |
| 4 | Control server | Pair, read-only stream, bundle retrieval and revocation work over LAN; no inbound port on target |
| 5 | Plugins and extras | Third-party module loads through the command wrapper only |

Deferred: GUI, fleet mode, malware triage, scheduled tasks, plugin marketplace, driver rollback, registry diffing.

## 9. Known issues carried over from `log-extractor.ps1`

- ID hashed from the bench PC instead of the target
- `system.md` described the bench PC, not the target
- Errors silenced by `SilentlyContinue`; empty sections gave no reason
- Event logs read newest 200 then filtered by level
- Target's own CBS log not collected; `Get-Item` output printed as raw format objects
- Hard-coded `C:` and `W:`; output written to Desktop; no disk health data

## 10. Open questions

1. Does `textual` work acceptably in your WinRE console, or is a plain-text menu the target UI? (Test on a real WinRE boot.)
2. Build a custom WinPE image as the recommended boot method, or rely on the stock WinRE only?
3. Which bundle destination: manual copy into `Inbox/Tickets/`, or the server delivers it?
4. Keep `wmic` as a fallback, or require PowerShell/CIM or `diskpart` only?
5. Where does the repository live (`Tools/recoverykit` in the vault, its own git repo)?
