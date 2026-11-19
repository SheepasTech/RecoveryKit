# RecoveryKit operator manual

## What it is

A USB toolkit that diagnoses an unbootable Windows installation, collects its logs and writes a report. Repairs exist but only run after a typed confirmation. It carries its own 64-bit Python, so it needs no Python and no PowerShell on the machine it runs on. 64-bit only.

## Preparing the USB

On a normal Windows PC, from the project folder:

```
powershell -ExecutionPolicy Bypass -File .\Install-ToUsb.ps1
```

- Default destination is `D:\ITWORK\RecoveryKit`. Use `-Destination <path>` for another one. The drive must exist; the root of the system drive is refused.
- First run downloads the embedded Python into `python\` (checksum verified). `-RefreshPython` downloads it again.
- `-WhatIf` shows what would be copied and changes nothing.
- `cases\` on the USB is never deleted or overwritten, so collected case data survives a re-install.
- It writes `kit-version.txt` and finishes by running `run.cmd --version`.

## Booting the broken PC into WinRE

1. Boot into WinRE: Troubleshoot > Advanced options > Command Prompt. Or, from Windows Setup, press Shift+F10.
2. Find the USB letter. It differs on every PC. Try `dir D:\ITWORK`, `dir E:\ITWORK`, and so on, or run `diskpart`, then `list volume`, then `exit`.
3. Run `<letter>:\ITWORK\RecoveryKit\run.cmd`.

## Running on a normal Windows

Attach the disk of the broken PC and run `run.cmd` from the kit. Run it as administrator for full results.

## Switches

| Switch | Effect |
|---|---|
| `--scan` | Discovery, log collection and report, no menu |
| `--auto` | Never waits for input; uses defaults; never confirms a repair |
| `--target <letter>` | Use this drive letter as the target Windows |
| `--ticket <nr>` | Ticket number, used in the case id |
| `--out <dir>` | Write case output here (USB read-only or full) |
| `--chkdsk` | Add a read-only chkdsk (slow) |
| `--dry-run` | Repairs are shown and logged, never executed |
| `--bundle` | Zip the run folder |
| `--wipe-case <case-id>` | Delete that case from the USB |
| `--version` | Print the version |

## Where the output goes

`cases\<case-id>\<YYYYMMDD-HHMM>\` on the USB (`cases\_pending\...` until the target is known):

```
case.json     machine-readable summary
report.md     human-readable case file
inventory/    disks.json, partitions.json, hardware.json, installs.json
logs/         collected logs, raw and untouched (prefixed target- or host-)
exports/      bcd.bak, registry hives (only when requested)
debug.log     everything shown and run
audit.log     every command attempted, with exit code
audit/        full output of each command
```

Details of the logs: `docs\logging.txt`.

## Safety rules

- Scanning and collecting never write to the target disk. Repairs are a separate step.
- The target is identified by disk, partition size and contents, never by a fixed drive letter, and is checked again before every repair step.
- Every repair shows the exact command and its effect and waits for a typed yes.
- Some commands are not built in at all: `diskpart clean`, `format`, `delete partition`, `bootrec /fixmbr`, and blind `bcdboot` or `bcdedit /set` without a BCD export first.
- Before any BCD or registry change the original is exported to the case folder.
- A clean SFC does not mean the PC boots. The report says "fixed" only after you confirm it booted.
- If a section cannot run, the report says why and the others continue.

## Customer data

The USB can hold customer data (names, PINs, disk contents) in `cases\`. Before leaving the USB with a customer, delete the cases with `run.cmd --wipe-case <case-id>` (or remove the `cases\` contents). Nothing is sent over the network.
