# RecoveryKit operator manual

## What it is

A USB toolkit that diagnoses an unbootable Windows installation, collects its logs and writes a report. Repairs exist but only run after a typed confirmation. It carries its own 64-bit Python, so it needs no Python and no PowerShell on the machine it runs on. 64-bit only.

**Status.** Built and unit-tested on one development PC. It has not been run in WinRE or against a real broken PC yet, so whether the bundled Python starts there and which tools WinRE has are not confirmed. Use the first-run checklist below ("First run on a real machine") on the first real machine.

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

Run `run.cmd --help` for the same list. Abbreviations of switch names are not accepted.

Scan:

| Switch | Effect |
|---|---|
| (none) | Text menu |
| `--scan` | Discovery, log collection, inventories and report, no menu |
| `--auto` | Never waits for input; uses defaults; never confirms a repair |
| `--target <letter>` | Use this drive letter as the target Windows (still verified by contents) |
| `--target-path <dir>` | Folder that contains `Windows` (mounted image or mapped folder). Verified by contents; disk and partition are shown as unknown, so repairs against it are refused |
| `--ticket <nr>` | Ticket number, used in the case id (`ITW-<nr>-<target id>`; without it `T-<target id>`) |
| `--out <dir>` | Write case output here instead of `cases\` next to `run.cmd` (USB read-only or full, or the case would land on the target disk) |
| `--chkdsk` | Add a read-only chkdsk of the target (slow) |
| `--answer KEY=VALUE` | Pre-answer a boot-failure question; repeatable. Keys: `symptom` (`no_boot_device`, `repair_loop`, `stop_code`, `spinning`, `other`, `unknown`), `firmware_sees_disk`, `boot_menu_wbm`, `data_backed_up` (`yes`, `no`, `unknown`), `recent_change` (`update`, `driver`, `power`, `hardware`, `none`, `unknown`). Example: `--answer symptom=repair_loop` |
| `--bundle` | Zip the run folder when done |
| `--dry-run` | Repairs are shown and logged, never executed |

Headless agent API (this machine only):

| Switch | Effect |
|---|---|
| `--serve` | Serve the agent API on 127.0.0.1 and wait. Prints a token; every request needs it |
| `--port <n>` | Port for `--serve` (default 8766) or `--server` (default 8765) |
| `--allow-repairs` | Let loopback API clients run confirmed repair steps. Without it the API cannot repair |

Remote session (the agent dials out; no port is opened on the target):

| Switch | Effect |
|---|---|
| `--connect <url>` | Control server URL, for example `https://192.168.1.10:8765`. It must start with `http://` or `https://` (any case); `http://` only for a server run with `--no-tls`. A server that cannot be reached gives one line and exit code 2 |
| `--token <T>` | Agent token of the server (`agent_token` in the server's `config\token-server.json`). Needed with `--connect` |
| `--ca <file>` | CA certificate that signed the server (default `config\ca-cert.pem` on the stick). Used for `https://` URLs |
| `--pin <sha256>` | Expected SHA-256 fingerprint of the server's TLS certificate (64 hex characters, colons allowed), for a server whose CA is not on the stick. Replaces the CA check: given together with `--ca`, the pin is used and `--ca` ignored (the program says so) |
| `--session-minutes <n>` | Session length (default 60) |
| `--allow-remote-repairs` | Let the remote operator run confirmed repair steps in this session. Default: read-only |

Control server (on the main machine):

| Switch | Effect |
|---|---|
| `--server` | Run the control server. HTTPS by default: the certificate is issued from this PC's CA (see "TLS" below); it refuses to start if that fails, unless `--no-tls` is given |
| `--no-tls` | Run the server over plain HTTP (authenticated but not encrypted: trusted LAN only; on a LAN where someone also has the agent token, the pairing code can be found out and the session taken over). Only applies to `--server`: with `--connect` or `--ctl` it is ignored and the program says so |
| `--ca-dir <dir>` | Folder of the certificate authority (default `%LOCALAPPDATA%\ITwork\CA`) |
| `--bind <ip>` | Interface to bind (default 127.0.0.1; give the LAN address to be reachable) |
| `--store <dir>` | Where received bundles are stored (default `cases\_server`) |
| `--intake <dir>` | Also copy bundles to `<dir>\ITW <ticket>\` (vault intake) |
| `--ctl ...` | Operator client: `agents`, `pair ID CODE`, `get ID PATH`, `post ID PATH [JSON]`, `fetch-bundle ID`, `bundles`, `revoke ID`. The code may be typed in any case, with or without the dash |

Other:

| Switch | Effect |
|---|---|
| `--decode-id <id>` | Show which components a device ID stands for, then exit |
| `--wipe-case <case-id>` | Delete that case folder from the output location (asks for a typed yes), then exit |
| `--version` | Print the version |

## Where the output goes

`cases\<case-id>\<YYYYMMDD-HHMM>\` on the USB (`cases\_pending\...` until the target is known):

```
case.json     machine-readable summary
report.md     human-readable case file
inventory/    disks, partitions, hardware, installs, registry snapshot, drivers,
              autoruns, services, tasks, log-findings.json (mostly .json)
logs/         collected logs, raw and untouched (prefixed target- or host-)
exports/      BCD: bcd-<label>.bak (untouched backup) and .work (the copy bcdedit reads)
debug.log     everything shown and run
audit.log     every command attempted, with exit code
audit/        full output of each command
```

Details of the logs: `docs\logging.txt`.

## Safety rules

- Scanning and collecting never write to the target disk. Repairs are a separate step.
- The target is identified by disk, partition size and contents, never by a fixed drive letter, and is checked again before every repair step.
- Every repair shows the exact command and its effect and waits for a typed yes.
- Repairs against the running Windows are refused. Only offline installs can be repaired.
- Every external program goes through one allowlist; anything not on it is refused and logged.
- Some commands are not built in at all: `diskpart clean`, `format`, `delete partition`, `bootrec /fixmbr`, and blind `bcdboot` or `bcdedit /set` without a BCD export first.
- Before any BCD change the original is exported to the case folder; the change is refused if that export does not exist. The kit never writes to the target's registry.
- A clean SFC does not mean the PC boots. The report says "fixed" only after you confirm it booted.
- If a section cannot run, the report says why and the others continue.

## Customer data

The USB can hold customer data (names, PINs, disk contents) in `cases\`. Before leaving the USB with a customer, delete the cases with `run.cmd --wipe-case <case-id>` (or remove the `cases\` contents). `--wipe-case` does not remove `devices\<ID>` (user names, serial numbers) or the copy of the log in `%TEMP%`; delete those by hand. Deleted files on a USB stick can still be recoverable. Nothing is sent over the network unless you start a remote session.

## Device ID

Every scan prints a device ID made of eight 4-letter codes, one per component:

```
CPU -RAM -RSPD-MOBO-GPU -USER-DISK-UNIT
YWUC-EHQX-DZBG-LWAM-TTAD-UFOB-XPJB-SDVR
```

Each code is a hash of that component, so the same CPU always gives the same CPU code and a RAM swap changes only the RAM codes. `RSPD` is "rated / running" memory speed: when the running speed is below the rated one, the XMP/EXPO profile is not active. `XXXX` means the component could not be read.

The stick keeps a `devices` folder next to `cases`:

| File | Content |
|---|---|
| `devices\index.md` | Table of every device seen, with its components in plain words |
| `devices\components.json` | Every code and the component it stands for |
| `devices\<ID>\device.json` | That device: components, full hardware details, list of runs |
| `devices\<ID>\settings.json` | Settings for that device: `notes` (shown at every scan), `ticket` (names the case), `answers` (pre-fills the boot-failure questions) |

`run.cmd --decode-id <ID>` prints the components of an ID. Edit the settings from the menu ("Device settings") or in a text editor.

The hardware codes describe the PC the kit is running on. In WinRE that is the customer's PC. If the customer's disk is attached to another PC, they describe that other PC, and the scan says so.

The folder holds user names and serial numbers. Treat it like `cases`.

## Inventories in every scan

Besides the logs, a scan writes read-only findings and inventories into `inventory\`:

- `log-findings.json`: what the collected logs say (Startup Repair root cause, CBS and DISM errors with HRESULTs, corrupt component files, device install failures, notable events, problems in the BCD listing). Each finding names its file.

- `registry-snapshot.json` with a list of startup-relevant findings (safe-boot flag, setup in progress, control-set mismatch, pending servicing, non-default shell). From the second run of a case on, `registry-changes.txt` lists what changed.
- `drivers.json`: third-party drivers, newest first. Drivers added in the 30 days before the install's last activity are listed in the report. The menu item "Third-party drivers" proposes removing one (a confirmed repair step).
- `autoruns.json`, `services.json`, `tasks.json`: what starts automatically, with entries worth a look marked. These are findings, not verdicts; nothing is removed.

## When a scan stops

A scan stops, before collecting anything, if the case output (or the `devices\` folder) would be written onto the target Windows volume. Nothing is written to the target. The screen says `Scan stopped: ... Choose another output location with --out.` Run it again with a folder on another drive, for example:

```
run.cmd --scan --out E:\cases
```

`cases\` next to `run.cmd` is the default, so this normally happens only when the kit itself sits on the target disk, or when `--out` points there. If the USB is read-only or has under 50 MB free, the kit asks for another folder (with `--auto` it uses a folder under `%TEMP%`, which is lost on reboot in WinRE).

## Plugins

Optional Python files in `plugins\` (`collect(ctx)`, see `docs\module-interface.md`). A plugin runs only if `plugins\manifest.sha256` lists it with the SHA-256 of the file. No manifest, not listed, or a changed file: the plugin is not loaded and its section shows an error with the reason. A listed plugin is trusted code and runs with the kit's rights; list only code you have read.

To add an entry, compute the hash and append a line `<64 hex>  <file name>`:

```
certutil -hashfile plugins\name.py SHA256
```

```
# plugins\manifest.sha256
<the 64 hex digits from certutil, no spaces>  name.py
```

Edit the plugin again and its hash changes: update the line. No plugin ships with the kit.

## The repair menu

Menu "Repair and backup helpers" first asks `Enter repair mode?` and needs a typed yes. It also works before a scan (disk online, BitLocker unlock, source check). The items, in the order they appear:

1. Check a repair source (WIM/ESD/SWM): compares build, edition, architecture and language with the target and refuses a mismatch.
2. List / run a proposed repair step (offline target only): DISM, SFC, BCD steps; a BCD step is offered only when a BCD export was made in this run, the target disk is GPT, the Windows volume has a letter and the disk has exactly one EFI System partition; otherwise the menu says why.
3. Remove an update package (offline target only): you type the exact package name.
4. Copy user data out to another drive (whenever there is a target): shows needed and free space first, refuses if it does not fit.
5. Bring an offline disk online (only when an offline disk exists).
6. Unlock a BitLocker volume: asks for the drive letter and the recovery key (hidden, never logged).
7. Show guidance (no commands run).
8. Record boot test result: booted / did not boot / not tested, plus a note. Only this sets "booted" in the report.
9. Back.

The main menu items are: Scan; Troubleshooting assistant; Repair and backup helpers; Third-party drivers (propose removing one); Answer / update the boot-failure questions; Device settings (notes, ticket); Bundle this run into a zip; Quit. Everything except Scan, Repair and Quit needs a scan first.

Each step is run one at a time. After a step, test-boot the target and record the result before the next step.

## Dry run

With `--dry-run` a repair step shows everything and runs nothing. Per step the screen prints: why (the finding that triggered it), the exact command, the effect, the risk, for BCD steps the backup file, and the line `DRY RUN: the command will be recorded but not executed.` It still asks `Run this command?`. Answer yes and `audit.log` gets an entry of kind `dry-run` ("not executed"); answer no and it gets `declined`. The target is not touched either way. Use it to read what a repair would do before doing it.

## First run on a real machine (not yet tested in WinRE)

Nothing here has been run in WinRE. Treat the first real boot as a test and write down what you see.

1. Boot WinRE (or Shift+F10), find the stick, start `run.cmd`. Note whether the bundled Python starts (the first line says `Using bundled Python`).
2. Scan first, read-only: choose Scan, or `run.cmd --scan`. Note any section marked `missing` or `error` (for example no `wevtutil`, no `manage-bde`) and the reason.
3. Compare the chosen disk with what you know: model, size, partition, edition and language. If it is not the customer's disk, stop.
4. Open `report.md` in the case folder (`type`, or on the main machine after bundling). Check facts, the "not yet established" list and the findings.
5. Only then consider repairs: try `--dry-run` first, one step at a time, test-boot after each, record the result.
6. Bundle the case (`--bundle` or the menu) and copy it to the main machine. Write down what differed from this manual.

## Headless and remote use

- No server, nobody at the keyboard: `run.cmd --scan --auto --bundle`.
- A program on the same machine: `run.cmd --serve` and call the agent API on 127.0.0.1 with the token it prints.
- From the main machine: start `run.cmd --server --bind <LAN address>` there, then on the target run `run.cmd --connect https://<address>:8765 --token <agent_token>` and tell the operator the pairing code shown on the target's screen: 10 letters and digits in two groups, like `K7QF4-M2XWP` (no I, O, 0 or 1 in it; the operator can type it in any case, with or without the dash, in the browser page or with `--ctl pair <id> <code>`). If the server sees 20 messages with a wrong signature for the agent's id it revokes the agent ("too many invalid signatures" in the agent list); the target says so when its session ends, and `--connect` has to be run again for a new session and a new code. Open `https://<address>:8765/` in a browser (it will warn about the certificate unless this PC's CA is installed in the browser; the page is only a front end, every call still needs the operator token), or use `run.cmd --ctl`.

The target never opens a LAN port: it dials out. A remote session is read-only unless it was started with `--allow-remote-repairs`, and ends on a keypress on the target, after `--session-minutes` (default 60), or when revoked. Traffic is encrypted with TLS unless the server was started with `--no-tls` (then it is authenticated but not encrypted: trusted LAN only). All routes are in `docs\api.md`.

## TLS

The technician's main PC (the control host) is the certificate authority (CA) for all ITwork tools (ADR 0020).

- **Where it lives.** `%LOCALAPPDATA%\ITwork\CA\` on the server PC: `ca-cert.pem` (public), `ca-key.pem` (the private key), `issued.log` and a `README.txt`. It is created the first time it is needed, by `New-ItworkCertificates.ps1` (Windows PowerShell 5.1 or PowerShell 7, no administrator rights, nothing is added to the Windows certificate store). Use `--ca-dir <dir>` for another folder.
- **The key stays on the server PC.** Never copy `ca-key.pem` to a USB stick, a share or a ticket: whoever has it can impersonate the server. `Install-ToUsb.ps1` copies from `config\` only `kit.toml` and `assistant.toml` (an allowlist) plus the CA's `ca-cert.pem` (refused if it contains a key block), and refuses to finish if, under the destination (outside `cases\`, `devices\` and `python\`), a file called `ca-key.pem`, `server-key.pem` or `token-server.json` exists, or any file smaller than 64 KB (also inside a small zip) contains a private key block or a token key as it is written in `token-server.json` (the operator and the agent token, in quotes); it names the files. `Install-ToUsb.ps1 -CheckOnly <folder>` runs only that check on a folder (exit 0 clean, 1 not). If the CA folder is lost, a new CA is made and every stick needs `Install-ToUsb.ps1` again.
- **Server certificate.** `run.cmd --server` issues `config\server-cert.pem` and `config\server-key.pem` (git-ignored) from the CA when they are missing, expire within 30 days, or do not cover this PC's name and addresses (computer name, `localhost`, `127.0.0.1`, the LAN addresses and `--bind`). It prints the server URL and the CA fingerprint. If PowerShell or the script is missing the server does not start; fix that or use `--no-tls`.
- **Sticks.** Run `Install-ToUsb.ps1` on the server PC: it puts `config\ca-cert.pem` on the stick (and prints its fingerprint; use `-CaDir` for a CA elsewhere). The agent (`--connect https://...`) trusts a server only if its certificate chains to that file and the address you typed is in the certificate. A stick without the file refuses an `https://` connection; it never falls back to an unverified one. `--ca <file>` uses another CA file; `--pin <sha256>` trusts exactly one server certificate instead (for a server whose CA is not on the stick).
- **The server's address changed** (new DHCP lease, another network): restart `run.cmd --server`. It sees the address is not in the certificate and issues a new one from the same CA; sticks need no change.
- **Clocks in WinRE.** WinRE often starts with a wrong date. A certificate is only valid between its dates (certificates start 24 hours before they were issued), so a clock that is far off makes the connection fail with a message that shows the local date. Set it first, in the WinRE command prompt: `date 2026-11-19` and `time 14:30` (use today's date and the time in your format), then connect again.
- **The operator client** `run.cmd --ctl` on the server PC finds the CA certificate in the CA folder by itself and uses `https://127.0.0.1:8765` when there is one (pass `--url http://...` for a `--no-tls` server, or `--ca <file>`).
- Not built: client certificates for agents (mutual TLS). The agent token and the pairing code still authenticate the agent.
