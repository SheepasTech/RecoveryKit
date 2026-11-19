# Module interface (for contributors)

Python 3.11+ **stdlib only**. The kit must run from an embeddable Python in WinRE: no pip packages, no PowerShell assumed, ASCII-only console output, 64-bit only. Tests: `python -m unittest discover -s tests -v` from the project root (stdlib `unittest`).

## Hard rules for modules (`recoverykit/modules/*.py`, plugins)

- **Never** import `subprocess`, `ctypes`, `os.system`, `os.popen`, `os.startfile`. External programs run only through `ctx.runner`. `tests/test_core.py` enforces this for the shipped modules.
- **Never write to the target.** Files are only created under `ctx.case.dir` (use `ctx.case.collect_file`, `write_text`, `write_json`).
- Never assume a drive letter. Use `ctx.target.root` / `ctx.target.windir`; a volume without a letter has a `\\?\Volume{guid}\` root, which `open()` and `os.path` accept.
- Every section is wrapped in `with ctx.case.section(name, title) as sec:`. An exception inside marks only that section `error`. Record each source with `sec.item(name, status, reason, **extra)` where status is `ok | missing | error | skipped` and **reason says why** whenever it is not ok. Nothing fails silently; no bare `except: pass`.
- Repairs against the running Windows are refused by the wrapper itself, whatever the module says. `Target.online` tells you; do not propose target-touching steps for it.
- `collect(ctx)` is read-only. `repair_steps(ctx)` returns `RepairStep` objects and never runs them; the menu passes them to `ctx.runner.repair(step)`.

## Plugins: trusted code, not a sandbox

To list a plugin, append `<sha256>  <file name>` to `plugins/manifest.sha256` (`certutil -hashfile plugins\name.py SHA256` prints the hash). Any edit of the plugin changes its hash. A plugin (`plugins/*.py`, `collect(ctx)` returning a dict) loads only when `plugins/manifest.sha256` lists it with a matching SHA-256 (same line format as `tools/manifest.sha256`: `<64 hex>  <file name>`, `#` comments). Not listed, no manifest or a changed file: its section is `error` with the reason and it is never imported. `plugins.check_source` additionally refuses obvious dangerous constructs (banned imports and `from os import system`, aliases of `os`/`shutil`, `getattr`, `_private` attribute access, assignments to `ctx` attributes, `open` in a write mode, `eval`/`exec`/`globals`...). That check is a guard against mistakes plus an integrity check, NOT a sandbox: a listed plugin is trusted code and runs with the kit's rights. Write files through `ctx.case.write_text/write_json`.

## The command wrapper (what `classify(argv)` allows)

Deny by default. A command is named by its bare tool name (`dism`, not a path); it is resolved only from `%SystemRoot%\System32` or from `tools/` when listed in `tools/manifest.sha256` (no PATH, no current directory). Classes:

- **read**: runs through `ctx.runner.run()`. Per tool only spelled-out forms: `reg query`; `wevtutil` queries; `wmic <alias> get <props> [/value]`; `bcdedit /enum` and `/store <file> /enum`, and `bcdedit /export` only into the case folder; `manage-bde -status`; `chkdsk X:` with no switches; `dism /Get-WimInfo` and `/Online /Get-...`; `smartctl` read options; `robocopy` with the kit's own switches for copying; `ipconfig`, `ver`, `systeminfo`, `hostname`, `whoami`, `reagentc /info`.
- **repair**: changes the target. Only through `ctx.runner.repair(step)`, which shows the command and effect, needs a typed yes, re-checks the target and runs once with no retry. Examples: `dism /Image: ...` (ScanHealth, RestoreHealth, Remove-Package, Remove-Driver), offline `sfc`, `bcdedit /store`, `bcdboot /s`, `chkdsk X: /f` and `/scan`, `bootrec /rebuildbcd`. Commands that change the BCD need a BCD export file made in this run.
- **host**: acts on the recovery environment, not the target: `wpeutil InitializeNetwork`, `drvload <inf>` (no switches), `manage-bde -unlock -RecoveryPassword`.
- **forbidden / unknown**: refused and audited. Includes `diskpart` (only through `run_diskpart` with checked lines: list, select, detail, online disk, assign/remove letter, clear readonly), `powershell` (only built-in snippets through `run_ps(name)`), `format`, `bootrec /fixmbr` and `/fixboot`, `dism /Online` changes, `sfc /scannow`, `chkdsk /r`, `reg` anything but `query`, and every tool not listed.

To add a tool or form: add a pattern in `core/runner.py` and a test in `tests/`.

## Objects (read the source, it is short)

- `recoverykit/core/context.py`: `Ctx` (`kit_root, cfg, env, case, ui, runner, options, inventory, target`), `Target` (`root, windir, online, letter, volume, disk, partition, info, reg`), `RegView` (`get(hive, path, name, default)`, `subkeys(hive, path)`, `values(hive, path)` (dict), `exists(hive, path)`, `control_set()`; hive is `"SOFTWARE"` or `"SYSTEM"`; works for offline and running installs).
- `recoverykit/core/case.py`: `Case.section()`, `Section.item()/set()/data`, `Case.collect_file(src, rel_dest, source="target"|"host", max_bytes=None)` (returns an entry dict with `status`, `reason`, `size`, `sha256`), `write_text(rel, text)`, `write_json(rel, obj)`, `path(*parts)`. Relative paths use `/`.
- `recoverykit/core/runner.py`: `Runner.run(argv, purpose, timeout=120, retry_rc=())` for **read-only** commands (raises `Refused` otherwise; a missing tool returns a `Result` with `rc=None` and `.error` set, it does not raise), `run_ps(name)` for the built-in PowerShell snippets, `run_diskpart(lines, purpose)` (list/select/detail only), `note_bcd_backup(path)`, `repair(step)`, `verified_tools`, `resolve(name)`. `Result`: `rc, out, error, timed_out, ok, seconds`. `classify(argv)` shows what is allowed. `RepairStep(id, title, effect, argv=None, diskpart=None, risk="", timeout=3600, touches_target=True, target_check=None, secrets=(), evidence="")`.
- `ctx.inventory`: `disks` (from `core/winapi.disks()`: `number, model, serial, bus, size, style, offline, partitions[{number, offset, size, type, volume, letter, fs}]`), `volumes` (`guid_path, letter, fs, label, size, free, disk, partition, drive_type`), `installs` (list of `Target`).
- `ctx.env`: `kind` (`windows|winre|winpe|setup`), `admin`, `firmware`, `windir`, `tools{name: path|None}`, `powershell`.
- `ctx.cfg`: parsed `config/kit.toml`.
- `ctx.ui`: `say(text)`, `ask(prompt, default)`, `choose(title, [(key, label)], default)`, `confirm_yes(question)`. Never `print()` or `input()` directly: the UI logs everything.
- Logging: `from ..core.log import LOG`; `LOG.info(...)`.

## Case data

`case.json` (`ctx.case.data`): `schema, case_id, ticket, environment, target{root, online, letter, disk, partition, volume, info{product, edition, build, ubr, build_full, architecture, language, ui_languages}}, operator_answers{symptom, firmware_sees_disk, boot_menu_wbm, recent_change, data_backed_up}, sections{name: {title, status, reason, items[], data{}}}, files[], source_check, booted_after_repair`.

Section names so far, in scan order: `environment, disks, installs, output_location, target, free_space, boot_structure, bitlocker, hardware, operator` (discovery); `device`; `logs_target, event_logs, bcd, logs_host, disk_health, pending` (logs); `log_findings` (loganalysis); `registry` (regdiff); `drivers`; `autoruns, services, tasks` (triage); `plugin_<name>` (one per plugin); `assistant`. Created later: `repairs`, `source_check`. If `output_location` is an error the scan stops after discovery (the case would be written on the target volume).

Other hive files (a user's `NTUSER.DAT`) can be read with `from ..core import regf` and `regf.Hive(path)` (`open(path)`, `Key.values()`, `Key.subkey_names()`, `Key.subkeys()`, `hive.dirty`; raises `regf.HiveError`/`OSError`). On a running Windows the loaded user hives are locked: report that as the reason.

Test fixture: `tests/fakewin.py` has `make_hive(path, tree)` (tree = `{"values": {name: sz("..")|dword(n)|multi([..])}, "keys": {name: tree}}`) and `make_target(root)` which builds a fake offline `<root>/Windows` with SOFTWARE and SYSTEM hives. Extend the tree you need by writing your own hives with `make_hive` in your test; do not change `make_target`'s existing output.

## Testing on the development PC

The dev PC's `C:` is the **running Windows**. Never execute a real repair or anything that writes outside a temp directory. Test repairs with a fake runner / `dry_run=True`, and file logic with temp folders that mimic a target (`<tmp>/Windows/...`).
