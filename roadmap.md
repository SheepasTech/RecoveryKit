# Roadmap

Rough goals, not a task list. Nothing here is built yet. The detail is in [RecoveryKit-spec.md](RecoveryKit-spec.md) section 8.

## Phases
1. Discovery, log collection and report (read-only).
2. Repair helpers: source-mismatch check, DISM/SFC, BCD with export first.
3. Troubleshooting assistant driven by decision files.
4. Optional control server (agent connects out, LAN only, read-only by default).
5. Plugins and extras.

## Before phase 1
- Answer the open questions in spec section 10 (textual vs plain menu in WinRE, custom WinPE, bundle destination, `wmic` fallback, repo location).
- Test stock WinRE: which tools exist, whether embeddable Python runs, drive-letter behaviour.

## Later
GUI, fleet mode, malware triage, scheduled tasks, plugin marketplace, driver rollback, registry diffing.
