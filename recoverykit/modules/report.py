"""report.md, generated from the same data as case.json (never separately).

Structure from the hand-worked case: confirmed facts, not yet established,
actions and results, current state, suggested next step. The report never says
the machine is fixed: only an operator-confirmed boot is reported as booted.

The report is read in Obsidian and most strings in it come from the inspected
disk, the operator, a remote client or a log: every interpolated value goes
through core.mdsafe (text for prose and cells, code for paths and commands).
"""
import json
import os

from ..core.mdsafe import code as C, text as T

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
    return "%.1f GB" % (n / GB) if isinstance(n, (int, float)) and not isinstance(n, bool) else "unknown"


def _mb(n):
    return str(n // 2 ** 20) if isinstance(n, int) else "?"


def _audit(case_dir):
    out = []
    try:
        with open(os.path.join(case_dir, "audit.log"), encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    out.append(e if isinstance(e, dict) else {"seq": "?", "kind": "unreadable", "command": line.strip()[:200]})
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

    add("# RecoveryKit case %s" % (T(data.get("case_id"), 80) or "(no target)"))
    add("")
    dev = data.get("device") or {}
    if dev.get("id"):
        add("- Device ID: %s" % C(dev["id"]))
    add("- Ticket: %s" % (T(data.get("ticket"), 40) or "not given"))
    add("- Run started: %s" % (T(data.get("started"), 40) or "?"))
    add("- Kit version: %s, case schema %s" % (T(data.get("kit_version"), 40), T(data.get("schema"), 40)))
    add("- Run from: %s (%s firmware, %s), administrator: %s" % (
        T(env.get("kind", "?"), 40), T(env.get("firmware", "?"), 40),
        T((env.get("os") or {}).get("product")) or "?", "yes" if env.get("admin") else "NO"))
    add("")

    add("## 1. Confirmed facts")
    add("")
    if not tgt:
        add("No target Windows installation was identified. See section 4 for the reason.")
    else:
        d, p, v = tgt.get("disk") or {}, tgt.get("partition") or {}, tgt.get("volume") or {}
        add("| Item | Value |")
        add("|---|---|")
        add("| Target | %s%s |" % (C(tgt.get("root"), table=True) or "?", " (the RUNNING Windows, not an offline install)" if tgt.get("online") else " (offline install)"))
        add("| Disk | Disk %s, %s, %s, %s, %s |" % (T(d.get("number", "?"), 20), T(d.get("model")) or "model unknown", _gb(d.get("size")), T(d.get("bus"), 40) or "?", T(d.get("style"), 40) or "?"))
        add("| Partition | %s, %s (%s) |" % (T(p.get("number", "?"), 20), _gb(p.get("size")), T(p.get("type"), 60) or "?"))
        add("| File system | %s, %s free of %s |" % (T(v.get("fs"), 40) or "?", _gb(v.get("free")), _gb(v.get("size"))))
        add("| Windows | %s, edition %s, version %s |" % (T(info.get("product")) or "unknown", T(info.get("edition")) or "unknown", T(info.get("display_version"), 60) or "?"))
        add("| Build | %s |" % (T(info.get("build_full"), 60) or "unknown"))
        add("| Architecture | %s |" % (T(info.get("architecture"), 40) or "unknown"))
        add("| Language | %s (UI languages: %s) |" % (T(info.get("language"), 60) or "unknown", ", ".join(T(x, 60) for x in info.get("ui_languages") or [] if isinstance(x, str)) or "unknown"))
        boot = (sections.get("boot_structure") or {}).get("data") or {}
        efi = boot.get("efi_partitions") or []
        rec = boot.get("recovery_partitions") or []
        add("| EFI System partitions | %s |" % (", ".join("disk %s part %s (%s MB)%s" % (T(e.get("disk"), 20), T(e.get("partition"), 20), _mb(e.get("size")), ", target disk" if e.get("on_target_disk") else "") for e in efi) or "none found"))
        add("| Recovery partitions | %s |" % (", ".join("disk %s part %s (%s MB)" % (T(e.get("disk"), 20), T(e.get("partition"), 20), _mb(e.get("size"))) for e in rec) or "none found"))
        if boot.get("note"):
            add("")
            add("Note: %s." % T(boot["note"]))
        for e in info.get("errors") or []:
            add("")
            add("Not readable: %s." % T(e))
    add("")

    if dev.get("segments"):
        add("Device %s (one code per component; the hardware is that of the PC the kit ran on):" % C(dev.get("id")))
        add("")
        add("| Code | Component | Value |")
        add("|---|---|---|")
        for sg in dev["segments"]:
            if not isinstance(sg, dict):
                continue
            add("| %s | %s | %s |" % (T(sg.get("code"), 40), T(sg.get("label"), 80), T(sg.get("detail")) or "not readable"))
        add("")

    add("## 2. Not yet established")
    add("")
    ans = data.get("operator_answers") or {}
    if not ans:
        add("- The operator was not asked.")
    for k, v in ans.items():
        if not v:
            continue
        add("- %s: %s" % (ANSWER_TEXT.get(k) or T(k, 60), "**not established**" if v == "unknown" else T(v)))
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
            note = T(a.get("error") or a.get("note"))
            if a.get("timed_out"):
                note = "TIMED OUT. " + note
            add("| %s | %s | %s | %s | %s |" % (
                T(a.get("seq"), 20), T(a.get("kind"), 40), C(a.get("command", ""), 110, table=True) or "-",
                T(a.get("exit_code"), 20) if a.get("exit_code") is not None else "-", note))
        add("")
    for r in data.get("repair_log") or []:
        add("- Repair step %s (%s): exit code %s%s%s%s" % (
            C(r.get("id")) or "?", T(r.get("kind"), 60), T(r.get("rc"), 20),
            ", finding: %s" % T(r["finding"]) if r.get("finding") else "",
            ", error %s" % T(r["error_code"], 60) if r.get("error_code") else "",
            ". Note: %s" % T(r["note"]) if r.get("note") else ""))
    sc = data.get("source_check")
    if sc:
        add("- Repair source %s index %s: %s" % (C(sc.get("path")) or "?", T(sc.get("index"), 20), "matches the target" if sc.get("ok") else "REFUSED: " + "; ".join(
            "%s target=%s source=%s" % (T(m.get("field"), 60), T(m.get("target"), 100), T(m.get("source"), 100)) for m in sc.get("mismatches") or [])))
    add("")

    add("## 4. Current state")
    add("")
    add("| Section | Status | Detail |")
    add("|---|---|---|")
    for name, s in sections.items():
        if name == "assistant":
            continue
        add("| %s | %s | %s |" % (T(s.get("title") or name, 100), T(s.get("status"), 40), T(s.get("reason"), 700)))
    add("")
    problems = [(s.get("title") or n, i) for n, s in sections.items() for i in s.get("items") or [] if i.get("status") != "ok"]
    if problems:
        add("Items that were not collected, and why:")
        add("")
        for title, i in problems:
            add("- %s / %s: %s%s" % (T(title, 100), T(i.get("name"), 120), T(i.get("status"), 40), " - " + T(i["reason"]) if i.get("reason") else " - (no reason recorded)"))
        add("")
    look = []
    for h in ((sections.get("log_findings") or {}).get("data") or {}).get("headline") or []:
        look.append("Logs: %s" % T(h))
    for n in ((sections.get("registry") or {}).get("data") or {}).get("notable") or []:
        look.append("Registry: %s" % T(n))
    drv = (sections.get("drivers") or {}).get("data") or {}
    if drv.get("recent"):
        look.append("Drivers added in the %s days before the install's last activity: %s" % (
            T(drv.get("recent_days", 30), 20), ", ".join(T(x, 80) for x in drv["recent"][:12])))
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
            add("- %s" % x)
        add("")
    files = data.get("files") or []
    add("Files collected: %d ok, %d missing, %d error, %d metadata only." % tuple(
        sum(1 for f in files if f.get("status") == s) for s in ("ok", "missing", "error", "skipped")))
    ro = data.get("read_only_check")
    if ro:
        add("")
        add("Read-only check: %s" % T(ro.get("summary"), 600))
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
            add("**Branch %s**" % T(last, 60))
            add("")
        n += 1
        add("%d. **%s** %s" % (n, T(s.get("title"), 150), T(s.get("text"), 1200)))
        ev = s.get("evidence") or {}
        if ev:
            add("   - Because: %s" % "; ".join("%s = %s" % (T(k, 60), "absent" if v is None else T(v, 200)) for k, v in ev.items()))
    wc = assist.get("what_changed") or []
    if wc:
        add("")
        add("### Changed since the previous run of this case")
        add("")
        for c in wc:
            add("- %s" % T(c))
    add("")
    return "\n".join(L)


def generate(case):
    """Write report.md in the case folder from case.data and audit.log. Returns its path."""
    case.save()
    return case.write_text("report.md", render(case.data, _audit(case.dir)))
