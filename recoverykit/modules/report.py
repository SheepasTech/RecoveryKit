"""report.md, generated from the same data as case.json (never separately).

Structure from the hand-worked case: confirmed facts, not yet established,
actions and results, current state, suggested next step. The report never says
the machine is fixed: only an operator-confirmed boot is reported as booted.
"""
import json
import os

GB = 2 ** 30

ANSWER_TEXT = {
    "symptom": "What happens at boot",
    "firmware_sees_disk": "Firmware lists the target disk",
    "boot_menu_wbm": "Boot menu shows Windows Boot Manager",
    "recent_change": "Recent change before the failure",
    "data_backed_up": "Customer data backed up",
    "stop_code": "Stop code / message",
    "symptom_text": "Description",
}


def _gb(n):
    return "%.1f GB" % (n / GB) if isinstance(n, (int, float)) else "unknown"


def _audit(case_dir):
    out = []
    try:
        with open(os.path.join(case_dir, "audit.log"), encoding="utf-8") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append({"seq": "?", "kind": "unreadable", "command": line.strip()[:200]})
    except OSError:
        pass
    return out


def render(data, audit):
    """Return the report text for case data `data` and audit entries `audit`."""
    L = []
    add = L.append
    sections = data.get("sections", {})
    tgt = data.get("target") or {}
    info = tgt.get("info") or {}
    env = data.get("environment") or {}

    add("# RecoveryKit case %s" % (data.get("case_id") or "(no target)"))
    add("")
    dev = data.get("device") or {}
    if dev.get("id"):
        add("- Device ID: `%s`" % dev["id"])
    add("- Ticket: %s" % (data.get("ticket") or "not given"))
    add("- Run started: %s" % data.get("started"))
    add("- Kit version: %s, case schema %s" % (data.get("kit_version"), data.get("schema")))
    add("- Run from: %s (%s firmware, %s), administrator: %s" % (
        env.get("kind", "?"), env.get("firmware", "?"),
        (env.get("os") or {}).get("product") or "?", "yes" if env.get("admin") else "NO"))
    add("")

    add("## 1. Confirmed facts")
    add("")
    if not tgt:
        add("No target Windows installation was identified. See section 4 for the reason.")
    else:
        d, p, v = tgt.get("disk") or {}, tgt.get("partition") or {}, tgt.get("volume") or {}
        add("| Item | Value |")
        add("|---|---|")
        add("| Target | `%s`%s |" % (tgt.get("root"), " (the RUNNING Windows, not an offline install)" if tgt.get("online") else " (offline install)"))
        add("| Disk | Disk %s, %s, %s, %s, %s |" % (d.get("number", "?"), d.get("model") or "model unknown", _gb(d.get("size")), d.get("bus") or "?", d.get("style") or "?"))
        add("| Partition | %s, %s (%s) |" % (p.get("number", "?"), _gb(p.get("size")), p.get("type") or "?"))
        add("| File system | %s, %s free of %s |" % (v.get("fs") or "?", _gb(v.get("free")), _gb(v.get("size"))))
        add("| Windows | %s, edition %s, version %s |" % (info.get("product") or "unknown", info.get("edition") or "unknown", info.get("display_version") or "?"))
        add("| Build | %s |" % (info.get("build_full") or "unknown"))
        add("| Architecture | %s |" % (info.get("architecture") or "unknown"))
        add("| Language | %s (UI languages: %s) |" % (info.get("language") or "unknown", ", ".join(info.get("ui_languages") or []) or "unknown"))
        boot = (sections.get("boot_structure") or {}).get("data") or {}
        efi = boot.get("efi_partitions") or []
        rec = boot.get("recovery_partitions") or []
        add("| EFI System partitions | %s |" % (", ".join("disk %s part %s (%d MB)%s" % (e["disk"], e["partition"], e["size"] // 2**20, ", target disk" if e.get("on_target_disk") else "") for e in efi) or "none found"))
        add("| Recovery partitions | %s |" % (", ".join("disk %s part %s (%d MB)" % (e["disk"], e["partition"], e["size"] // 2**20) for e in rec) or "none found"))
        if boot.get("note"):
            add("")
            add("Note: %s." % boot["note"])
        for e in info.get("errors") or []:
            add("")
            add("Not readable: %s." % e)
    add("")

    if dev.get("segments"):
        add("Device `%s` (one code per component; the hardware is that of the PC the kit ran on):" % dev["id"])
        add("")
        add("| Code | Component | Value |")
        add("|---|---|---|")
        for sg in dev["segments"]:
            add("| %s | %s | %s |" % (sg.get("code"), sg.get("label"), str(sg.get("detail") or "not readable").replace("|", "/")))
        add("")

    add("## 2. Not yet established")
    add("")
    ans = data.get("operator_answers") or {}
    if not ans:
        add("- The operator was not asked.")
    for k, v in ans.items():
        if not v:
            continue
        add("- %s: %s" % (ANSWER_TEXT.get(k, k), "**not established**" if v == "unknown" else v))
    b = data.get("booted_after_repair")
    add("- Target boots: %s" % ("operator confirmed it booted" if b is True else "operator reports it did NOT boot" if b is False else "**not tested / not confirmed**"))
    add("")

    add("## 3. Actions taken and results")
    add("")
    changing = [a for a in audit if a.get("kind") in ("repair", "host")]
    add("Commands that changed something: %s. Read-only commands: %d. Refused, declined or dry-run: %d." % (
        len(changing) or "none", sum(1 for a in audit if a.get("kind") == "read"),
        sum(1 for a in audit if a.get("kind") in ("refused", "declined", "dry-run"))))
    add("")
    if audit:
        add("| # | Kind | Command | Exit code | Note |")
        add("|---|---|---|---|---|")
        for a in audit:
            cmd = str(a.get("command", ""))
            if len(cmd) > 110:
                cmd = cmd[:107] + "..."
            note = a.get("error") or a.get("note") or ""
            if a.get("timed_out"):
                note = "TIMED OUT. " + note
            add("| %s | %s | `%s` | %s | %s |" % (a.get("seq"), a.get("kind"), cmd.replace("|", "\\|"),
                                              a.get("exit_code") if a.get("exit_code") is not None else "-", note.replace("|", "/")))
        add("")
    for r in data.get("repair_log") or []:
        add("- Repair step `%s` (%s): exit code %s%s%s%s" % (
            r.get("id"), r.get("kind"), r.get("rc"),
            ", finding: %s" % r["finding"] if r.get("finding") else "",
            ", error %s" % r["error_code"] if r.get("error_code") else "",
            ". Note: %s" % r["note"] if r.get("note") else ""))
    sc = data.get("source_check")
    if sc:
        add("- Repair source `%s` index %s: %s" % (sc.get("path"), sc.get("index"), "matches the target" if sc.get("ok") else "REFUSED: " + "; ".join(
            "%s target=%s source=%s" % (m.get("field"), m.get("target"), m.get("source")) for m in sc.get("mismatches") or [])))
    add("")

    add("## 4. Current state")
    add("")
    add("| Section | Status | Detail |")
    add("|---|---|---|")
    for name, s in sections.items():
        if name == "assistant":
            continue
        add("| %s | %s | %s |" % (s.get("title") or name, s.get("status"), (s.get("reason") or "").replace("|", "/")))
    add("")
    problems = [(s.get("title") or n, i) for n, s in sections.items() for i in s.get("items") or [] if i.get("status") != "ok"]
    if problems:
        add("Items that were not collected, and why:")
        add("")
        for title, i in problems:
            add("- %s / %s: %s%s" % (title, i.get("name"), i.get("status"), " - " + i["reason"] if i.get("reason") else " - (no reason recorded)"))
        add("")
    look = []
    for n in ((sections.get("registry") or {}).get("data") or {}).get("notable") or []:
        look.append("Registry: %s" % n)
    drv = (sections.get("drivers") or {}).get("data") or {}
    if drv.get("recent"):
        look.append("Drivers added in the %s days before the install's last activity: %s" % (
            drv.get("recent_days", 30), ", ".join(str(x) for x in drv["recent"][:12])))
    for name, label in (("autoruns", "autorun"), ("services", "service"), ("tasks", "scheduled task")):
        fl = ((sections.get(name) or {}).get("data") or {}).get("flagged") or []
        if fl:
            look.append("%d flagged %s entr%s (see inventory/%s.json)" % (len(fl), label, "y" if len(fl) == 1 else "ies", name))
    chg = ((sections.get("registry") or {}).get("data") or {}).get("changes") or []
    if chg:
        look.append("%d registry change(s) since the previous run (inventory/registry-changes.txt)" % len(chg))
    if look:
        add("Things to look at (findings, not verdicts):")
        add("")
        for x in look:
            add("- %s" % str(x).replace("|", "/"))
        add("")
    files = data.get("files") or []
    add("Files collected: %d ok, %d missing, %d error, %d metadata only." % tuple(
        sum(1 for f in files if f.get("status") == s) for s in ("ok", "missing", "error", "skipped")))
    ro = data.get("read_only_check")
    if ro:
        add("")
        add("Read-only check: %s" % ro.get("summary"))
    add("")
    add("A clean SFC or DISM result does not mean the machine boots. This report does not claim the target is fixed.")
    add("")

    add("## 5. Suggested next steps")
    add("")
    assist = (sections.get("assistant") or {}).get("data") or {}
    sugg = assist.get("suggestions") or []
    if not sugg:
        add("No suggestions were generated (the assistant did not run, or no rule matched).")
    last = None
    n = 0
    for s in sugg:
        if s.get("branch") != last:
            last = s.get("branch")
            add("")
            add("**Branch %s**" % last)
            add("")
        n += 1
        add("%d. **%s** %s" % (n, s.get("title"), s.get("text")))
        ev = s.get("evidence") or {}
        if ev:
            add("   - Because: %s" % "; ".join("%s = %s" % (k, v) for k, v in ev.items()))
    wc = assist.get("what_changed") or []
    if wc:
        add("")
        add("### Changed since the previous run of this case")
        add("")
        for c in wc:
            add("- %s" % c)
    add("")
    return "\n".join(L)


def generate(case):
    """Write report.md in the case folder from case.data and audit.log. Returns its path."""
    case.save()
    return case.write_text("report.md", render(case.data, _audit(case.dir)))
