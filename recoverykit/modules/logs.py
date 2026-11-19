"""Phase 2 log collection: target logs, event logs, BCD, host logs, disk health, pending operations.

Read-only. Files are only copied into the case folder; external programs run through ctx.runner.
"""
import os
import shutil

from ..core.log import LOG

MB = 2 ** 20
ADMIN_HINT = " (needs administrator / WinRE)"
LEVEL_QUERY = "*[System[(Level=1 or Level=2 or Level=3)]]"


def _win(rel):
    return rel.replace("/", "\\")


def _flat(rel):
    return rel.replace("/", "_").replace("\\", "_").replace("$", "").replace("~", "")


def _why(e):
    """Reason of a collect_file entry, with the administrator hint for permission errors."""
    r = e.get("reason") or ""
    if e["status"] == "error" and ("PermissionError" in r or "denied" in r.lower()):
        r += ADMIN_HINT
    return r


def _file_item(sec, name, e, **extra):
    return sec.item(name, e["status"], _why(e), size=e.get("size"), dest=e.get("dest"), **extra)


def _lim(ctx):
    return ctx.cfg.get("limits", {})


def collect(ctx):
    sections = (("logs_target", "Logs on the target", _logs_target),
                ("event_logs", "Event logs of the target", _event_logs),
                ("bcd", "Boot configuration data (BCD)", _bcd),
                ("logs_host", "Logs of the environment running the kit", _logs_host),
                ("disk_health", "Disk health", _disk_health),
                ("pending", "Pending operations on the target", _pending))
    for name, title, fn in sections:
        with ctx.case.section(name, title) as sec:
            if ctx.target is None:
                sec.set("skipped", "no target")
            else:
                ctx.ui.say("Collecting: %s" % title)
                fn(ctx, sec)
    return None


# ------------------------------------------------------------------ 1. target logs
def _logs_target(ctx, sec):
    t, case, lim = ctx.target, ctx.case, _lim(ctx)
    max_log = lim.get("max_log_mb", 200) * MB
    max_dump = lim.get("max_dump_mb", 8) * MB
    lcfg = ctx.cfg.get("logs", {})
    todo = [(rel, os.path.join(t.windir, _win(rel))) for rel in lcfg.get("target", [])]
    todo += [(rel, os.path.join(t.root, _win(rel))) for rel in lcfg.get("target_root", [])]
    for rel, src in todo:
        e = case.collect_file(src, "logs/target-" + _flat(rel), source="target", max_bytes=max_log)
        _file_item(sec, rel, e)

    # minidumps
    mdir = os.path.join(t.windir, "Minidump")
    try:
        found = []
        with os.scandir(mdir) as it:
            for d in it:
                if d.name.lower().endswith(".dmp") and d.is_file():
                    found.append((d.stat().st_mtime, d.name, d.path))
        found.sort(reverse=True)
        keep = found[:lim.get("max_minidumps", 10)]
        if not keep:
            sec.item("minidumps", "missing", "Minidump folder exists but holds no .dmp files")
        for _, name, path in keep:
            e = case.collect_file(path, "logs/target-minidump-" + name, source="target", max_bytes=max_dump)
            _file_item(sec, "minidump " + name, e)
        if len(found) > len(keep):
            sec.item("minidumps older", "skipped", "%d older dump(s) not copied (max_minidumps)" % (len(found) - len(keep)))
    except (FileNotFoundError, NotADirectoryError):
        sec.item("minidumps", "missing", "no Minidump folder: no small memory dump was written")
    except OSError as ex:
        sec.item("minidumps", "error", "%s: %s" % (type(ex).__name__, ex.strerror or ex) + ADMIN_HINT)

    # MEMORY.DMP: metadata only
    mem = os.path.join(t.windir, "MEMORY.DMP")
    try:
        st = os.stat(mem)
        sec.item("MEMORY.DMP", "skipped", "metadata only", size=st.st_size, mtime=st.st_mtime)
    except FileNotFoundError:
        sec.item("MEMORY.DMP", "missing", "not found: no full/kernel memory dump")
    except OSError as ex:
        sec.item("MEMORY.DMP", "error", "%s: %s" % (type(ex).__name__, ex.strerror or ex))


# ------------------------------------------------------------------ 2. event logs
def _count_events(text):
    return sum(1 for ln in text.splitlines() if ln.startswith("Event["))


def _event_logs(ctx, sec):
    t, case, lim = ctx.target, ctx.case, _lim(ctx)
    evmax = lim.get("event_max", 200)
    for name in ctx.cfg.get("logs", {}).get("event_logs", []):
        src = os.path.join(t.windir, "System32", "winevt", "Logs", name + ".evtx")
        fname = name.replace("%4", "-")
        dest = "logs/target-evtx-%s.evtx" % fname
        e = case.collect_file(src, dest, source="target", max_bytes=lim.get("max_log_mb", 200) * MB)
        copy_txt = "copy %s%s" % (e["status"], ": " + _why(e) if _why(e) else "")
        argv = None
        if e["status"] == "ok":
            argv = ["wevtutil", "qe", case.path(*dest.split("/")), "/lf:true", "/q:" + LEVEL_QUERY,
                    "/c:%d" % evmax, "/rd:true", "/f:text"]
        elif t.online:
            argv = ["wevtutil", "qe", name.replace("%4", "/"), "/q:" + LEVEL_QUERY,
                    "/c:%d" % evmax, "/rd:true", "/f:text"]
        exp_ok, events = False, None
        if argv is None:
            exp_txt = "export not done: no readable copy and the target is offline"
        else:
            res = ctx.runner.run(argv, "errors/warnings of event log %s" % name, timeout=180)
            if res.error:
                exp_txt = "export not done: %s (the raw .evtx is still in the case)" % res.error
            elif res.rc != 0:
                exp_txt = "wevtutil exit code %s%s" % (res.rc, (": " + res.out.strip()[:150]) if res.out else "")
            else:
                case.write_text("logs/target-events-%s.txt" % fname, res.out)
                events = _count_events(res.out)
                exp_ok, exp_txt = True, "export ok"
        if e["status"] == "ok" or exp_ok:
            status = "ok"
        else:
            status = e["status"] if e["status"] in ("missing", "error") else "error"
        extra = {"size": e.get("size")}
        if events is not None:
            extra["events"] = events
        sec.item(name, status, "%s; %s" % (copy_txt, exp_txt), **extra)


# ------------------------------------------------------------------ 3. BCD
def _bcd_store(ctx, sec, label, src, on_target):
    """Copy one BCD store into the case, enumerate the working copy. Returns True if copied."""
    case = ctx.case
    bak_rel, work_rel = "exports/bcd-%s.bak" % label, "exports/bcd-%s.work" % label
    e = case.collect_file(src, bak_rel, source="target")
    if e["status"] != "ok":
        sec.item("bcd-" + label, e["status"], _why(e) or "not copied", src=src)
        return False
    bak, work = case.path(*bak_rel.split("/")), case.path(*work_rel.split("/"))
    noted = ""
    if on_target:
        noted = "; backup recorded" if ctx.runner.note_bcd_backup(bak) else "; backup could not be recorded"
    try:
        shutil.copyfile(bak, work)
    except OSError as ex:
        sec.item("bcd-" + label, "error", "copied%s but working copy failed: %s" % (noted, ex), src=src)
        return True
    res = ctx.runner.run(["bcdedit", "/store", work, "/enum", "all", "/v"], "list BCD entries of %s" % label, timeout=60)
    if res.error:
        sec.item("bcd-" + label, "error", "copied%s; bcdedit not run: %s" % (noted, res.error), src=src)
    elif res.rc != 0:
        sec.item("bcd-" + label, "error", "copied%s; bcdedit exit code %s: %s" % (noted, res.rc, res.out.strip()[:150]), src=src)
    else:
        case.write_text("logs/target-bcd-%s.txt" % label, res.out)
        sec.item("bcd-" + label, "ok", "copied%s and listed" % noted, src=src, dest=bak_rel)
    return True


def _bcd(ctx, sec):
    t, case = ctx.target, ctx.case
    bs = case.data.get("sections", {}).get("boot_structure", {}).get("data", {})
    efis = bs.get("efi_partitions", [])
    copied = 0
    if not efis:
        sec.item("efi", "missing", "no EFI System partition recorded by discovery")
    for p in efis:
        label = "disk%s-part%s" % (p["disk"], p["partition"])
        if not p.get("volume"):
            sec.item("bcd-" + label, "error", "EFI System partition has no volume path (not mounted/readable)" + ADMIN_HINT)
            continue
        src = os.path.join(p["volume"], "EFI", "Microsoft", "Boot", "BCD")
        copied += _bcd_store(ctx, sec, label, src, bool(p.get("on_target_disk")))
    if t.disk and t.disk.get("style") == "MBR":
        for v in ctx.inventory.get("volumes", []):
            if v.get("disk") != t.disk.get("number") or not v.get("fs"):
                continue
            root = v["letter"] + ":\\" if v.get("letter") else v["guid_path"]
            label = "bios-disk%s-part%s" % (v.get("disk"), v.get("partition"))
            copied += _bcd_store(ctx, sec, label, os.path.join(root, "Boot", "BCD"), True)
    if not copied and t.online and ctx.env.get("admin"):
        res = ctx.runner.run(["bcdedit", "/enum", "all", "/v"], "list BCD entries of the running system", timeout=60)
        if res.ok:
            case.write_text("logs/target-bcd-live.txt", res.out)
            sec.item("bcd-live", "ok", "listed from the running system", dest="logs/target-bcd-live.txt")
        else:
            sec.item("bcd-live", "error", res.error or "bcdedit exit code %s" % res.rc)
        out = case.path("exports", "bcd-live.bak")
        res = ctx.runner.run(["bcdedit", "/export", out], "export BCD of the running system", timeout=60)
        if res.ok and ctx.runner.note_bcd_backup(out):
            sec.item("bcd-live-export", "ok", "exported; backup recorded", dest="exports/bcd-live.bak")
            copied += 1
        else:
            sec.item("bcd-live-export", "error", res.error or "bcdedit /export exit code %s" % res.rc)
    if not copied:
        why = "no BCD store could be copied"
        if not ctx.env.get("admin"):
            why += ": not administrator, the EFI partition usually cannot be read" + ADMIN_HINT
        sec.set("error" if any(i["status"] == "error" for i in sec.items) else "missing", why)


# ------------------------------------------------------------------ 4. host logs
def _logs_host(ctx, sec):
    if ctx.target.online:
        sec.set("skipped", "the target is the running Windows: host logs are the target logs")
        return
    host = ctx.env.get("windir") or ""
    for rel in ctx.cfg.get("logs", {}).get("host", []):
        e = ctx.case.collect_file(os.path.join(host, _win(rel)), "logs/host-" + _flat(rel), source="host",
                                  max_bytes=_lim(ctx).get("max_log_mb", 200) * MB)
        _file_item(sec, rel, e)


# ------------------------------------------------------------------ 5. disk health
def _disk_health(ctx, sec):
    t, case, run = ctx.target, ctx.case, ctx.runner
    disk = t.disk.get("number") if t.disk else None
    if "smartctl" in run.verified_tools:
        sec.data["method"] = "smartctl"
        res = run.run(["smartctl", "--scan"], "list disks for SMART", timeout=60)
        if res.out:
            case.write_text("inventory/smart-scan.txt", res.out)
        if disk is None:
            sec.item("smart", "error", "target disk number unknown")
        else:
            res = run.run(["smartctl", "-a", "-j", "/dev/pd%d" % disk], "SMART data of target disk %d" % disk, timeout=120)
            if res.error:
                sec.item("smart-disk%d" % disk, "error", res.error)
            elif res.out:
                case.write_text("inventory/smart-disk%d.json" % disk, res.out)
                note = "" if res.rc == 0 else "smartctl exit code %s (bit mask: non-zero flags a SMART warning or an access problem)" % res.rc
                sec.item("smart-disk%d" % disk, "ok", note, dest="inventory/smart-disk%d.json" % disk)
            else:
                sec.item("smart-disk%d" % disk, "error", "no output, exit code %s%s" % (res.rc, "" if ctx.env.get("admin") else ADMIN_HINT))
    elif ctx.env.get("powershell") or ctx.env.get("tools", {}).get("powershell") or _ps_available(run):
        sec.data["method"] = "powershell"
        for name, rel, hint in (("physical-disks", "inventory/physical-disks.json", ""),
                                ("reliability", "inventory/reliability.json",
                                 "; reliability counters need administrator")):
            res = run.run_ps(name)
            if res.ok:
                case.write_text(rel, res.out)
                sec.item(name, "ok", dest=rel)
            else:
                sec.item(name, "error", (res.error or "exit code %s" % res.rc) + hint)
    elif ctx.env.get("tools", {}).get("wmic"):
        sec.data["method"] = "wmic"
        res = run.run(["wmic", "diskdrive", "get", "Model,SerialNumber,Status,Size"], "disk status via wmic", timeout=60)
        if res.ok:
            case.write_text("inventory/wmic-diskdrive.txt", res.out)
            sec.item("wmic", "ok", dest="inventory/wmic-diskdrive.txt")
        else:
            sec.item("wmic", "error", res.error or "exit code %s" % res.rc)
    else:
        sec.data["method"] = None
        sec.set("missing", "no smartctl in tools/, no PowerShell, no wmic in this environment")

    if not ctx.options.get("chkdsk"):
        sec.item("chkdsk", "skipped", "not requested: run with --chkdsk")
    elif not t.letter:
        sec.item("chkdsk", "skipped", "target volume has no drive letter")
    else:
        res = run.run(["chkdsk", "%s:" % t.letter], "read-only file system check of the target",
                      timeout=_lim(ctx).get("chkdsk_timeout_s", 3600))
        if res.out:
            case.write_text("logs/target-chkdsk.txt", res.out)
        if res.error:
            sec.item("chkdsk", "error", res.error)
        else:
            sec.item("chkdsk", "ok", "read-only mode, exit code %s" % res.rc, rc=res.rc, dest="logs/target-chkdsk.txt")


def _ps_available(run):
    """PowerShell known to the runner (set by run_ps) or found on PATH."""
    return bool(run.verified_tools.get("powershell") or shutil.which("powershell") or shutil.which("pwsh"))


# ------------------------------------------------------------------ 6. pending
def _pending(ctx, sec):
    t, case = ctx.target, ctx.case
    for fname in ("pending.xml", "reboot.xml"):
        e = case.collect_file(os.path.join(t.windir, "WinSxS", fname), "logs/target-%s" % fname, source="target",
                              max_bytes=_lim(ctx).get("max_log_mb", 200) * MB)
        if e["status"] == "missing":
            sec.item(fname, "missing", "not present (normal)")
        else:
            _file_item(sec, fname, e)
    r = t.reg
    cbs = r"Microsoft\Windows\CurrentVersion\Component Based Servicing"
    d = sec.data
    d["reboot_pending"] = bool(r.exists("SOFTWARE", cbs + r"\RebootPending"))
    d["packages_pending"] = bool(r.exists("SOFTWARE", cbs + r"\PackagesPending"))
    cs = r.control_set()
    ops = r.get("SYSTEM", cs + r"\Control\Session Manager", "PendingFileRenameOperations")
    if isinstance(ops, (list, tuple)):
        d["pending_file_rename_count"] = len([x for x in ops if x])
    else:
        d["pending_file_rename_count"] = 1 if ops else 0
    d["any_pending"] = bool(d["reboot_pending"] or d["packages_pending"] or d["pending_file_rename_count"]
                            or any(i["status"] in ("ok", "skipped") for i in sec.items))
    LOG.info("PENDING| %s", d)
