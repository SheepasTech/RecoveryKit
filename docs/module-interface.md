# Module interface (for contributors)

Python 3.11+ **stdlib only**. The kit must run from an embeddable Python in WinRE: no pip packages, no PowerShell assumed, ASCII-only console output, 64-bit only. Tests: `python -m unittest discover -s tests -v` from the project root (stdlib `unittest`).

## Hard rules for modules (`recoverykit/modules/*.py`, plugins)

- **Never** import `subprocess`, `ctypes`, `os.system`, `os.popen`, `os.startfile`. External programs run only through `ctx.runner`. `tests/test_rules.py` enforces this.
- **Never write to the target.** Files are only created under `ctx.case.dir` (use `ctx.case.collect_file`, `write_text`, `write_json`).
- Never assume a drive letter. Use `ctx.target.root` / `ctx.target.windir`; a volume without a letter has a `\\?\Volume{guid}\` root, which `open()` and `os.path` accept.
- Every section is wrapped in `with ctx.case.section(name, title) as sec:`. An exception inside marks only that section `error`. Record each source with `sec.item(name, status, reason, **extra)` where status is `ok | missing | error | skipped` and **reason says why** whenever it is not ok. Nothing fails silently; no bare `except: pass`.
- `collect(ctx)` is read-only. `repair_steps(ctx)` returns `RepairStep` objects and never runs them; the menu passes them to `ctx.runner.repair(step)`.

## Plugins: trusted code, not a sandbox

A plugin (`plugins/*.py`, `collect(ctx)` returning a dict) loads only when `plugins/manifest.sha256` lists it with a matching SHA-256 (same line format as `tools/manifest.sha256`: `<64 hex>  <file name>`, `#` comments). Not listed, no manifest or a changed file: its section is `error` with the reason and it is never imported. `plugins.check_source` additionally refuses obvious dangerous constructs (banned imports and `from os import system`, aliases of `os`/`shutil`, `getattr`, `_private` attribute access, assignments to `ctx` attributes, `open` in a write mode, `eval`/`exec`/`globals`...). That check is a guard against mistakes plus an integrity check, NOT a sandbox: a listed plugin is trusted code and runs with the kit's rights. Write files through `ctx.case.write_text/write_json`.

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

Section names so far: `environment, disks, installs, target, free_space, boot_structure, bitlocker, hardware, operator` (discovery); `logs_target, event_logs, bcd, logs_host, disk_health, pending` (logs); `assistant`; `repairs`; `registry` (regdiff); `drivers`; `autoruns`, `services`, `tasks` (triage).

Other hive files (a user's `NTUSER.DAT`) can be read with `from ..core import regf` and `regf.Hive(path)` (`open(path)`, `Key.values()`, `Key.subkey_names()`, `Key.subkeys()`, `hive.dirty`; raises `regf.HiveError`/`OSError`). On a running Windows the loaded user hives are locked: report that as the reason.

Test fixture: `tests/fakewin.py` has `make_hive(path, tree)` (tree = `{"values": {name: sz("..")|dword(n)|multi([..])}, "keys": {name: tree}}`) and `make_target(root)` which builds a fake offline `<root>/Windows` with SOFTWARE and SYSTEM hives. Extend the tree you need by writing your own hives with `make_hive` in your test; do not change `make_target`'s existing output.

## Testing on the development PC

The dev PC's `C:` is the **running Windows**. Never execute a real repair or anything that writes outside a temp directory. Test repairs with a fake runner / `dry_run=True`, and file logic with temp folders that mimic a target (`<tmp>/Windows/...`).
