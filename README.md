---
tags: [tools, recovery]
---
# RecoveryKit

Portable USB toolkit that diagnoses, collects evidence from and (only with confirmation) repairs unbootable Windows installations. It is meant to run from normal Windows, WinRE, WinPE or the Windows Setup Shift+F10 prompt, with its own Python on the stick.

> **Status.** Implemented and covered by automated tests on one development PC (Windows 11, not elevated). **Not yet exercised: a real WinRE boot, an administrator session, a real offline disk, any real repair command, and two machines on a LAN.** Scanning is read-only, so a first try on a real machine is safe; treat the repair helpers as untested until one has been walked through on a disposable install.

The design is in [RecoveryKit-spec.md](RecoveryKit-spec.md), progress in [roadmap.md](roadmap.md), changes in [CHANGELOG.md](CHANGELOG.md). No customer data or keys are stored in this repository.

## Quick start

Prepare the USB stick once, on a normal Windows PC (downloads the embeddable Python, checks its SHA-256, copies the kit):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Install-ToUsb.ps1 -Destination D:\ITWORK\RecoveryKit
```

On the broken PC, boot WinRE (Troubleshoot > Advanced options > Command Prompt) or press Shift+F10 in Windows Setup, find the stick's letter and run:

```
E:\ITWORK\RecoveryKit\run.cmd
```

The menu starts with **Scan**: it finds the Windows installations by disk and contents (never by letter), asks which one is the target, collects logs and writes `report.md`. Nothing on the target is changed by a scan. The operator manual is [docs/manual.md](docs/manual.md).

## What it does

| Area | What you get |
|---|---|
| Discovery | Disks, partitions, volumes, offline Windows installs with edition, build, language and architecture, EFI and Recovery partitions, free space, BitLocker status |
| Logs | SrtTrail, CBS, DISM, Panther, setupapi, minidumps, event logs (raw `.evtx` plus an export filtered by level first), a copy of the BCD store and its listing, pending operations, disk health |
| Inventories | Registry snapshot with the startup-relevant findings and a diff against the previous run; third-party drivers newest first; autoruns, services and scheduled tasks with entries worth a look |
| Device ID | Eight 4-letter codes, one per component (`CPU-RAM-RSPD-MOBO-GPU-USER-DISK-UNIT`), with a registry on the stick that maps each code to its component and holds device-specific settings |
| Report | `case.json` and `report.md` from the same data: confirmed facts, not yet established, actions taken, current state, suggested next steps |
| Assistant | Ordered suggestions from `config/assistant.toml`, each citing the finding that triggered it |
| Repair helpers | Repair-source check (build, edition, architecture, language), DISM ScanHealth/RestoreHealth, offline SFC, package and driver removal, BCD rebuild with export first, copy user data out, bring a disk online, unlock BitLocker |
| Remote | The same engine behind an HTTP API: headless on the target, or relayed through a control server with a browser page |

## Safety rules

- Scanning and collecting never write to the target disk. The offline registry is read with a built-in parser instead of `reg load`; the BCD is copied out and inspected on the copy.
- Every external command goes through one wrapper with an allowlist. `diskpart clean`, `format`, `delete partition`, `bootrec /fixmbr`, blind `bcdboot` and BCD changes without a prior export cannot run through any path.
- A repair step shows the exact command and its effect, re-checks the target, and waits for a typed `yes`. Nothing is retried automatically. Repairs against the running Windows are refused.
- The report never says "fixed". Only a boot confirmed by the operator is recorded as booted.
- A section that cannot run says why; it never stops the others.

## Command line

| Switch | Meaning |
|---|---|
| (none) | Text menu |
| `--scan` | Discovery, logs, inventories and report, then exit |
| `--auto` | Never wait for input. Defaults are used; no repair is ever confirmed |
| `--target W` / `--target-path DIR` | Target by drive letter, or a folder that contains `Windows` (mounted image). Still verified by contents |
| `--ticket NR` | Ticket number for the case ID (`ITW-<ticket>-<target id>`) |
| `--out DIR` | Case output location when the USB is read-only or full |
| `--chkdsk` | Add a read-only `chkdsk` (slow) |
| `--answer KEY=VALUE` | Pre-answer a boot-failure question, e.g. `symptom=repair_loop` |
| `--dry-run` | Repair steps are shown and logged, never executed |
| `--bundle` | Zip the run folder |
| `--wipe-case ID` | Delete a case from the output location |
| `--decode-id ID` | Show which components a device ID stands for |
| `--serve` | Headless: agent API on 127.0.0.1 ([docs/api.md](docs/api.md)) |
| `--connect URL --token T` | Remote session: the agent dials out to the control server |
| `--server --bind IP` | Run the control server (API and browser page) on the main machine |
| `--ctl ...` | Command-line client for the control server |

## Output

One case per target. The case ID comes from the target's disk and install, not from the PC running the kit.

```
cases/<case-id>/<YYYYMMDD-HHMM>/
  case.json      machine-readable summary
  report.md      the case file for a person
  inventory/     disks, partitions, volumes, installs, registry snapshot, drivers, autoruns, services, tasks
  logs/          collected logs, prefixed target- or host-
  exports/       BCD backup
  audit.log      every command attempted, with exit code; full output in audit/
  debug.log      everything shown, asked, answered and run
```

Next to `cases/` the stick keeps `devices/`: `index.md` (every device seen, in plain words), `components.json` (code to component) and one folder per device with `device.json` and `settings.json`.

Case and device folders hold customer-identifying data. `cases/` and `devices/` are git-ignored; wipe a case before leaving the stick with a customer.

## Logs

Logging is always on. Details are in [docs/logging.txt](docs/logging.txt). On a normal Windows a mirror of `debug.log` also goes to `%TEMP%\Debug\RecoveryKit\<run>\`, like the other ITwork tools.

## Layout

| Path | Purpose |
|---|---|
| `run.cmd` | Launcher. Pure `cmd`, relative to its own location |
| `Install-ToUsb.ps1` | Fetches the embeddable Python and copies the kit to a stick. Never touches `cases\` there |
| `python/` | Embeddable 64-bit Python 3.14, git-ignored |
| `recoverykit/core/` | Hive parser, disk inventory, command wrapper, case model, logging, console UI |
| `recoverykit/modules/` | discovery, logs, regdiff, drivers, triage, assistant, repair, report |
| `recoverykit/engine.py`, `net.py`, `web/` | The engine and its API, the server, the browser page |
| `config/` | `kit.toml`, `assistant.toml` |
| `plugins/` | Optional `*.py` with `collect(ctx)`; they can only run commands through the wrapper |
| `tools/` | Optional third-party binaries (smartctl), used only when listed in `tools/manifest.sha256` |
| `tests/` | `python -m unittest discover -s tests -t .` |
| `docs/` | Manual, API, logging, module interface |

## Development

Python standard library only. Tests run on any Windows with Python 3.11+ and need no administrator rights; they build a fake offline Windows with real registry hive files and never execute a repair.
