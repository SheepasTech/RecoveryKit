---
tags: [tools, recovery]
---
# RecoveryKit

Portable USB toolkit that diagnoses, collects evidence from and (only with confirmation) repairs unbootable Windows installations. Runs from normal Windows, WinRE, WinPE or the Setup Shift+F10 prompt.

> **Status.** Specification only. No code yet. The full design is in [RecoveryKit-spec.md](RecoveryKit-spec.md); plans are in [roadmap.md](roadmap.md).

Replaces the old `debug/log-extractor.ps1`. No customer data or keys are stored in this project.

## Layout

Planned layout, from spec section 3. The USB letter is never assumed; every path is relative to the launcher.

| Path | Purpose |
|---|---|
| `run.cmd` | Launcher: finds its own drive, picks Python, starts the TUI (not written yet) |
| `python/` | Embeddable 64-bit Python, fetched at build time, git-ignored |
| `lib/` | Vendored pure-Python dependencies |
| `recoverykit/` | Core engine and modules |
| `config/` | `kit.toml`, allowlists, repair playbooks |
| `cases/` | Output, one folder per case. Git-ignored: holds customer data |
| `tools/` | Optional third-party binaries (smartctl etc.), SHA-256 manifest |
| `docs/` | Manual, logging notes, caveats |
| `debug/` | Local debug output, git-ignored |

## Logs

Follows the convention of the other tools: debug logs go to `%TEMP%\Debug\RecoveryKit\<run timestamp>\`. In WinRE, where `%TEMP%` is a RAM disk, the case folder on the USB is the log. Details will go in `docs/logging.txt`.
