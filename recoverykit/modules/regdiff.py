"""Registry snapshot of the target and diff against the previous run of the same case.

Read-only: everything is read through ctx.target.reg (RegView); files are only written into the case.
"""
import json
import os

from ..core.log import LOG

SVC = "Services"
CBS = r"Microsoft\Windows\CurrentVersion\Component Based Servicing"
RUN_KEYS = (r"Microsoft\Windows\CurrentVersion\Run",
            r"Microsoft\Windows\CurrentVersion\RunOnce",
            r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
SNAP_REL = "inventory/registry-snapshot.json"
CHANGES_REL = "inventory/registry-changes.txt"
MAX_DIFF = 200
MAX_UNUSUAL = 20


def _norm(v):
    """JSON-serialisable form of a registry value."""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()[:64]
    if isinstance(v, (list, tuple)):
        return [_norm(x) for x in v]
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


def snapshot(reg):
    cs = reg.control_set()
    services = {}
    base = cs + "\\" + SVC
    for name in reg.subkeys("SYSTEM", base):
        vals = reg.values("SYSTEM", base + "\\" + name)
        services[name] = {"start": _norm(vals.get("Start")), "type": _norm(vals.get("Type")),
                          "image_path": _norm(vals.get("ImagePath")),
                          "error_control": _norm(vals.get("ErrorControl"))}

    control = {}
    sm = cs + r"\Control\Session Manager"
    control["BootExecute"] = _norm(reg.get("SYSTEM", sm, "BootExecute"))
    ops = reg.get("SYSTEM", sm, "PendingFileRenameOperations")
    if isinstance(ops, (list, tuple)):
        control["PendingFileRenameOperations_count"] = len([x for x in ops if x])
    else:
        control["PendingFileRenameOperations_count"] = 1 if ops else 0
    control["SafeBoot_OptionValue"] = _norm(reg.get("SYSTEM", cs + r"\Control\SafeBoot\Option", "OptionValue"))
    for n in ("CrashDumpEnabled", "AutoReboot"):
        control[n] = _norm(reg.get("SYSTEM", cs + r"\Control\CrashControl", n))
    for n in ("Current", "Default", "LastKnownGood", "Failed"):
        control["Select_" + n] = _norm(reg.get("SYSTEM", "Select", n))
    for n in ("SystemSetupInProgress", "SetupType", "CmdLine", "OOBEInProgress"):
        control["Setup_" + n] = _norm(reg.get("SYSTEM", "Setup", n))

    servicing = {
        "RebootPending": bool(reg.exists("SOFTWARE", CBS + r"\RebootPending")),
        "PackagesPending": bool(reg.exists("SOFTWARE", CBS + r"\PackagesPending")),
        "SessionsPending": bool(reg.exists("SOFTWARE", CBS + r"\SessionsPending")),
        "WindowsUpdate_RebootRequired": bool(reg.exists(
            "SOFTWARE", r"Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")),
    }

    cv = r"Microsoft\Windows NT\CurrentVersion"
    version = {n: _norm(reg.get("SOFTWARE", cv, n)) for n in ("CurrentBuild", "UBR", "EditionID", "DisplayVersion")}

    run = {}
    for key in RUN_KEYS:
        for vname, val in reg.values("SOFTWARE", key).items():
            run[key + "\\" + vname] = _norm(val)

    winlogon = {n: _norm(reg.get("SOFTWARE", cv + r"\Winlogon", n)) for n in ("Shell", "Userinit")}
    return {"services": services, "control": control, "servicing": servicing, "version": version,
            "run": run, "winlogon": winlogon}


def _strip_root(p):
    p = p.strip().strip('"')
    low = p.lower()
    for pre in ("\\systemroot\\", "\\??\\"):
        if low.startswith(pre):
            return p[len(pre):]
    return p


def _usual_image(path):
    if not isinstance(path, str) or not path.strip():
        return False
    low = _strip_root(path).lower()
    return low.startswith("system32\\") or low.startswith("system32\\drivers\\")


def notable(snap):
    out = []
    c, svc = snap.get("control", {}), snap.get("services", {})
    sb = c.get("SafeBoot_OptionValue")
    if sb not in (None, ""):
        out.append("SafeBoot OptionValue is set, so the machine boots into safe mode (value: %s)." % sb)
    cmd = c.get("Setup_CmdLine")
    if c.get("Setup_SystemSetupInProgress") == 1 or (isinstance(cmd, str) and cmd.strip()):
        out.append("Windows thinks setup is in progress (SystemSetupInProgress=%s, Setup CmdLine=%r)."
                   % (c.get("Setup_SystemSetupInProgress"), cmd))
    cur, dflt, failed = c.get("Select_Current"), c.get("Select_Default"), c.get("Select_Failed")
    if (cur is not None and dflt is not None and cur != dflt) or (failed is not None and failed != 0):
        out.append("The control sets do not match (Select Current=%s, Default=%s, Failed=%s)." % (cur, dflt, failed))
    for k, v in snap.get("servicing", {}).items():
        if v:
            out.append("The servicing flag %s is set, so updates are waiting for a reboot or completion." % k)
    be = c.get("BootExecute")
    if be is not None and be != ["autocheck autochk *"]:
        out.append("BootExecute is not the default 'autocheck autochk *' (value: %s)." % (be,))
    wl = snap.get("winlogon", {})
    shell, ui = wl.get("Shell"), wl.get("Userinit")
    if isinstance(shell, str) and shell.strip().lower() != "explorer.exe":
        out.append("Winlogon Shell is not explorer.exe (value: %s)." % shell)
    if isinstance(ui, str) and not ui.strip().lower().rstrip(",").endswith("userinit.exe"):
        out.append("Winlogon Userinit is not the default userinit.exe (value: %s)." % ui)
    odd = [n for n in sorted(svc, key=str.lower)
           if svc[n].get("start") in (0, 1) and svc[n].get("image_path") is not None  # in-box kernel drivers have none
           and not _usual_image(svc[n].get("image_path"))]
    for n in odd[:MAX_UNUSUAL]:
        out.append("boot/system-start service %s has an unusual image path: %s" % (n, svc[n].get("image_path")))
    if len(odd) > MAX_UNUSUAL:
        out.append("%d more boot/system-start services have unusual image paths." % (len(odd) - MAX_UNUSUAL))
    return out


def diff(old, new):
    lines = []
    os_, ns = old.get("services", {}), new.get("services", {})
    for n in sorted(set(ns) - set(os_), key=str.lower):
        lines.append("service %s added (image path %s)" % (n, ns[n].get("image_path")))
    for n in sorted(set(os_) - set(ns), key=str.lower):
        lines.append("service %s removed (image path %s)" % (n, os_[n].get("image_path")))
    for n in sorted(set(os_) & set(ns), key=str.lower):
        for f in ("start", "type", "image_path", "error_control"):
            if os_[n].get(f) != ns[n].get(f):
                lines.append("service %s %s %s -> %s" % (n, f, os_[n].get(f), ns[n].get(f)))
    for sect in ("control", "servicing", "version", "winlogon"):
        o, n = old.get(sect, {}), new.get(sect, {})
        for k in sorted(set(o) | set(n)):
            if o.get(k) != n.get(k):
                lines.append("%s %s: %s -> %s" % (sect, k, o.get(k), n.get(k)))
    o, n = old.get("run", {}), new.get("run", {})
    for k in sorted(set(n) - set(o)):
        lines.append("run entry added: %s = %s" % (k, n[k]))
    for k in sorted(set(o) - set(n)):
        lines.append("run entry removed: %s = %s" % (k, o[k]))
    for k in sorted(set(o) & set(n)):
        if o[k] != n[k]:
            lines.append("run entry changed: %s: %s -> %s" % (k, o[k], n[k]))
    if len(lines) > MAX_DIFF:
        more = len(lines) - MAX_DIFF
        lines = lines[:MAX_DIFF] + ["... and %d more change(s) not listed" % more]
    return lines


def _previous_run(case_dir):
    """Name of the latest earlier sibling run folder that holds a snapshot, or None."""
    parent, cur = os.path.split(os.path.abspath(case_dir))
    if os.path.basename(parent) == "_pending":
        return None
    try:
        names = sorted(os.listdir(parent))
    except OSError:
        return None
    for name in reversed(names):
        if name < cur and os.path.isfile(os.path.join(parent, name, *SNAP_REL.split("/"))):
            return name
    return None


def collect(ctx):
    with ctx.case.section("registry", "Registry snapshot and changes") as sec:
        if ctx.target is None:
            sec.set("skipped", "no target")
            return None
        ctx.ui.say("Collecting: Registry snapshot and changes")
        reg = ctx.target.reg
        snap = snapshot(reg)
        for name, why in sorted(reg.errors.items()):
            sec.item("hive " + name, "error", why)
        for name, d in sorted(reg.dirty.items()):
            if d:
                sec.item("hive " + name, "ok", "hive not cleanly flushed: values may be stale")
        ctx.case.write_json(SNAP_REL, snap)
        sec.data["counts"] = {k: len(v) for k, v in snap.items()}
        notes = notable(snap)
        sec.data["notable"] = notes
        for line in notes:
            ctx.ui.say("  ! " + line)

        sec.data["previous_run"], sec.data["changes"] = None, []
        prev = _previous_run(ctx.case.dir)
        if prev:
            ppath = os.path.join(os.path.dirname(os.path.abspath(ctx.case.dir)), prev, *SNAP_REL.split("/"))
            try:
                with open(ppath, "r", encoding="utf-8") as f:
                    old = json.load(f)
                if not isinstance(old, dict):
                    raise ValueError("snapshot is not a JSON object")
                changes = diff(old, snap)
            except (OSError, ValueError) as e:
                sec.item("previous snapshot " + prev, "error", "%s: %s" % (type(e).__name__, e))
            else:
                sec.data["previous_run"], sec.data["changes"] = prev, changes
                ctx.case.write_text(CHANGES_REL, "Changes since run %s\n\n%s\n" % (
                    prev, "\n".join(changes) if changes else "(no changes)"))
                ctx.ui.say("  %d registry change(s) since run %s" % (len(changes), prev))
        LOG.info("REGDIFF| counts %s previous %s", sec.data["counts"], sec.data["previous_run"])
    return None
