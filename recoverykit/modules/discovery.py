"""Phase 1 discovery: environment, disks, Windows installs, target choice, boot structure.

Read-only. Disks and volumes come from core.winapi (no diskpart, no drive-letter
assumptions); offline registry data comes from core.context.RegView.
"""
import hashlib
import os
import shutil

from ..core import winapi
from ..core.context import LCID, RegView, Target
from ..core.log import LOG

GB = 2 ** 30


def _gb(n):
    return "%.1f GB" % (n / GB) if isinstance(n, int) else "?"


def collect(ctx):
    """Run all discovery sections. Sets ctx.inventory and ctx.target (None if no install found)."""
    case, ui = ctx.case, ctx.ui

    with case.section("environment", "Environment running the kit") as sec:
        sec.data = ctx.env
        case.data["environment"] = ctx.env
        missing = sorted(t for t, p in ctx.env["tools"].items() if not p)
        if missing:
            sec.reason = "not present here: " + ", ".join(missing)
        if not ctx.env["admin"]:
            sec.reason = ("not running as administrator: BCD, BitLocker, event-log files and some logs "
                          "cannot be read. " + sec.reason).strip()

    with case.section("disks", "Disks, partitions and volumes") as sec:
        disks, vols = winapi.disks(), winapi.volumes()
        for v in vols:
            v["disk"] = v["extents"][0]["disk"] if v["extents"] else None
            v["partition"] = None
            for d in disks:
                if d["number"] != v["disk"]:
                    continue
                for p in d["partitions"]:
                    if v["extents"] and p["offset"] == v["extents"][0]["offset"]:
                        v["partition"] = p["number"]
                        p["volume"] = v["guid_path"]
                        p["letter"], p["fs"], p["label"] = v["letter"], v.get("fs"), v.get("label")
                        p["free"] = v.get("free")
        ctx.inventory.update(disks=disks, volumes=vols)
        case.write_json("inventory/disks.json", disks)
        case.write_json("inventory/partitions.json",
                        [dict(p, disk=d["number"]) for d in disks for p in d["partitions"]])
        case.write_json("inventory/volumes.json", vols)
        if not disks:
            sec.set("error", "no physical disk could be opened")
        for d in disks:
            note = "; ".join(d["errors"])
            if d.get("offline"):
                note = ("disk is OFFLINE: its volumes cannot be read until it is brought online. " + note).strip()
            sec.item("disk %d" % d["number"], "error" if d["errors"] else "ok", note,
                     model=d.get("model"), size=d.get("size"), bus=d.get("bus"), style=d.get("style"),
                     offline=d.get("offline"), partitions=len(d["partitions"]))
        sec.data = {"disk_count": len(disks), "volume_count": len(vols)}

    with case.section("installs", "Windows installations found") as sec:
        installs = find_installs(ctx)
        ctx.inventory["installs"] = installs
        case.write_json("inventory/installs.json", [_public(i) for i in installs])
        if not installs:
            sec.set("missing", "no volume contains \\Windows\\System32\\Config\\SYSTEM. If the target disk is "
                               "offline or BitLocker-locked it has to be brought online or unlocked first.")
        for t in installs:
            i = t.info
            sec.item(t.root, "ok" if not i.get("errors") else "error", "; ".join(i.get("errors", [])),
                     online=t.online, product=i.get("product"), build=i.get("build_full"),
                     edition=i.get("edition"), language=i.get("language"),
                     disk=t.disk["number"] if t.disk else None)

    target = choose_target(ctx)
    ctx.target = target
    if target:
        ctx.runner.target_online = target.online
        _assign_case(ctx)

    with case.section("target", "Chosen target") as sec:
        if not target:
            sec.set("missing", "no target chosen")
        else:
            sec.data = _public(target)
            case.data["target"] = sec.data
            if target.online:
                sec.reason = "the target is the running Windows (not an offline install); repair helpers are disabled"
            for name, why in target.reg.errors.items():
                sec.item("registry hive " + name, "error", why)
            for name, dirty in target.reg.dirty.items():
                if dirty:
                    sec.item("registry hive " + name, "ok",
                             "hive was not cleanly flushed (unsaved changes in its .LOG files); values may be stale")

    with case.section("free_space", "Free space on the target volume") as sec:
        if not target:
            sec.set("skipped", "no target")
        else:
            size, free = target.volume.get("size"), target.volume.get("free")
            lim = ctx.cfg.get("limits", {})
            sec.data = {"size": size, "free": free}
            if not size:
                sec.set("error", "size not readable: " + "; ".join(target.volume.get("errors", [])))
            else:
                pct = 100.0 * free / size
                sec.data["free_percent"] = round(pct, 1)
                low = free < lim.get("free_space_warn_gb", 10) * GB or pct < lim.get("free_space_warn_percent", 10)
                sec.data["low"] = low
                sec.reason = "%s free of %s (%.0f%%)%s" % (_gb(free), _gb(size), pct,
                                                          " - LOW: repairs and updates may fail" if low else "")

    with case.section("boot_structure", "Boot structure") as sec:
        sec.data = boot_structure(ctx)
        if not sec.data["efi_partitions"] and ctx.env["firmware"] == "UEFI":
            sec.reason = "no EFI System partition found on any disk"

    with case.section("bitlocker", "BitLocker status") as sec:
        res = ctx.runner.run(["manage-bde", "-status"], "BitLocker status of all volumes", timeout=60)
        if res.error:
            sec.set("missing", res.error)
        elif res.rc != 0:
            sec.set("error", "manage-bde -status exit code %s%s" % (
                res.rc, "" if ctx.env["admin"] else " (needs administrator)"))
        else:
            case.write_text("inventory/bitlocker.txt", res.out)
            sec.data = {"file": "inventory/bitlocker.txt"}
        unreadable = [v["guid_path"] for v in ctx.inventory.get("volumes", [])
                      if not v.get("fs") and v["drive_type"] == "fixed"]
        if unreadable:
            sec.data["unreadable_volumes"] = unreadable
            sec.reason = ("%d fixed volume(s) have no readable file system: possibly BitLocker-locked. "
                          "The kit never stores recovery keys." % len(unreadable))

    with case.section("hardware", "Hardware and network of the machine") as sec:
        res = ctx.runner.run_ps("hardware")
        if res.ok:
            case.write_text("inventory/hardware.json", res.out)
            sec.item("hardware", "ok", file="inventory/hardware.json")
        else:
            sec.item("hardware", "missing", res.error or "PowerShell query failed with exit code %s" % res.rc)
        res = ctx.runner.run(["ipconfig", "/all"], "network adapters", timeout=30)
        if res.ok:
            case.write_text("inventory/network.txt", res.out)
            sec.item("network", "ok", file="inventory/network.txt")
        else:
            sec.item("network", "missing", res.error or "ipconfig exit code %s" % res.rc)

    with case.section("operator", "Not yet established (asked from the operator)") as sec:
        sec.data = ask_operator(ctx)
        case.data["operator_answers"] = sec.data
    return target


def find_installs(ctx):
    """Every volume that holds \\Windows\\System32\\Config\\SYSTEM, as Target objects."""
    out = []
    host_windir = ctx.env.get("windir") or ""
    by_num = {d["number"]: d for d in ctx.inventory.get("disks", [])}
    for v in ctx.inventory.get("volumes", []):
        if not v.get("fs"):
            continue
        root = v["letter"] + ":\\" if v["letter"] else v["guid_path"]
        windir = root + "Windows"
        if not _is_windows_dir(windir):
            continue
        online = False
        if ctx.env["kind"] == "windows" and host_windir:
            try:
                online = os.path.samefile(windir, host_windir)
            except OSError:
                online = False
        disk = by_num.get(v.get("disk"))
        part = next((p for p in disk["partitions"] if p["number"] == v.get("partition")), None) if disk else None
        t = Target(root=root, windir=windir, online=online, letter=v["letter"], volume=v, disk=disk, partition=part)
        t.reg = RegView(windir, online)
        t.info = install_info(t)
        out.append(t)
    explicit = ctx.options.get("target_path")
    if explicit:
        t = explicit_target(ctx, explicit, by_num)
        if t:
            out = [x for x in out if os.path.normcase(x.windir) != os.path.normcase(t.windir)] + [t]
    return out


def explicit_target(ctx, path, by_num):
    """--target-path: a folder that holds a Windows directory (a mounted image, a mapped folder, an attached
    volume the scan did not list). Still verified by contents."""
    root = os.path.abspath(path).rstrip("\\/") + "\\"
    windir = root + "Windows"
    if not _is_windows_dir(windir):
        ctx.ui.say("--target-path %s: no Windows installation there (Windows/System32/config missing)." % path)
        return None
    letter = root[0].upper() if len(root) == 3 and root[1] == ":" else None
    vol = next((v for v in ctx.inventory.get("volumes", []) if v["letter"] and v["letter"] == root[0].upper()), None)
    on_volume_root = bool(vol and letter)
    if on_volume_root:
        volume = vol
    else:
        volume = {"guid_path": None, "letter": letter, "fs": None, "label": "", "errors": [], "extents": [],
                  "drive_type": "unknown", "disk": None, "partition": None}
        try:
            du = shutil.disk_usage(root)
            volume.update(size=du.total, free=du.free)
        except OSError as e:
            volume["errors"].append(str(e))
    disk = by_num.get(volume.get("disk"))
    part = next((p for p in disk["partitions"] if p["number"] == volume.get("partition")), None) if disk else None
    online = False
    try:
        online = bool(ctx.env.get("windir")) and os.path.samefile(windir, ctx.env["windir"])
    except OSError:
        pass
    t = Target(root=root, windir=windir, online=online, letter=letter, volume=volume, disk=disk, partition=part)
    t.reg = RegView(windir, online)
    t.info = install_info(t)
    t.info["explicit_path"] = True
    if not on_volume_root:
        t.info["errors"].append("target given by path, not found as a volume root: disk and partition are unknown")
    return t


def _is_windows_dir(windir):
    """True if windir holds a Windows install: the SYSTEM hive, or (when the config folder is not
    readable without administrator rights) the config folder plus the kernel."""
    cfg = os.path.join(windir, "System32", "config")
    try:
        return os.path.exists(os.path.join(cfg, "SYSTEM")) or (
            os.path.isdir(cfg) and os.path.exists(os.path.join(windir, "System32", "ntoskrnl.exe")))
    except OSError:
        return False


def install_info(t):
    """Edition, build, language, architecture of an install, from its registry (read-only)."""
    r, errors = t.reg, []
    cv = r"Microsoft\Windows NT\CurrentVersion"
    build, ubr = r.get("SOFTWARE", cv, "CurrentBuild"), r.get("SOFTWARE", cv, "UBR")
    product = r.get("SOFTWARE", cv, "ProductName")
    if product and str(build or "").isdigit() and int(build) >= 22000:
        product = product.replace("Windows 10", "Windows 11")  # the registry still says 10 on Windows 11
    cs = r.control_set()
    lcid = r.get("SYSTEM", cs + r"\Control\Nls\Language", "InstallLanguage")
    ui_langs = r.subkeys("SYSTEM", cs + r"\Control\MUI\UILanguages")
    guid = r.get("SOFTWARE", r"Microsoft\Cryptography", "MachineGuid")
    for name, why in r.errors.items():
        errors.append("%s hive unreadable (%s)" % (name, why))
    info = {
        "product": product,
        "edition": r.get("SOFTWARE", cv, "EditionID"),
        "display_version": r.get("SOFTWARE", cv, "DisplayVersion"),
        "build": build, "ubr": ubr,
        "build_full": "10.0.%s.%s" % (build, ubr) if build and ubr is not None else (build and "10.0.%s" % build),
        "architecture": {"AMD64": "x64", "x86": "x86", "ARM64": "arm64"}.get(
            r.get("SYSTEM", cs + r"\Control\Session Manager\Environment", "PROCESSOR_ARCHITECTURE"), None),
        "language": (ui_langs[0] if ui_langs else LCID.get(str(lcid or "").lower())),
        "ui_languages": ui_langs,
        "install_language_lcid": lcid,
        "computer_name": r.get("SYSTEM", cs + r"\Control\ComputerName\ComputerName", "ComputerName"),
        "control_set": cs,
        "machine_guid_sha": hashlib.sha256(guid.encode()).hexdigest()[:16] if isinstance(guid, str) else None,
        "errors": errors,
    }
    return info


def target_id(t):
    """Short ID derived from the TARGET (disk serial + its MachineGuid), never from the host."""
    serial = (t.disk or {}).get("serial") or (t.disk or {}).get("disk_id") or t.volume.get("serial") or ""
    basis = "%s|%s" % (serial, t.info.get("machine_guid_sha") or "")
    return hashlib.sha256(basis.encode()).hexdigest()[:8]


def describe(t):
    i = t.info
    where = "disk %s part %s" % (t.disk["number"] if t.disk else "?", t.partition["number"] if t.partition else "?")
    return "%s  %s %s %s %s  [%s, %s, %s]%s" % (
        t.root, i.get("product") or "Windows", i.get("edition") or "", i.get("build_full") or "",
        i.get("language") or "", where, _gb(t.volume.get("size")), (t.disk or {}).get("model") or "?",
        "  << RUNNING Windows" if t.online else "")


def choose_target(ctx):
    installs = ctx.inventory.get("installs", [])
    if not installs:
        return None
    for t in installs:
        if t.info.get("explicit_path"):
            return t
    want = (ctx.options.get("target") or "").rstrip(":\\").upper()
    if want:
        for t in installs:
            if (t.letter or "").upper() == want:
                return t
        ctx.ui.say("No Windows installation on %s:. Choose from the list." % want)
    offline = [t for t in installs if not t.online]
    default = offline[0] if len(offline) == 1 else (installs[0] if len(installs) == 1 else None)
    if len(installs) == 1 and ctx.ui.auto:
        return installs[0]
    opts = [(t, describe(t)) for t in installs] + [(None, "None of these / stop here")]
    return ctx.ui.choose("Which Windows installation is the target? (identified by disk and contents, "
                         "not by letter)", opts, default)


def _assign_case(ctx):
    ticket = ctx.options.get("ticket")
    if ticket is None:
        ticket = ctx.ui.ask("Ticket number (Enter to skip)", "")
    ticket = "".join(ch for ch in str(ticket) if ch.isalnum())
    tid = target_id(ctx.target)
    ctx.case.assign("ITW-%s-%s" % (ticket, tid) if ticket else "T-%s" % tid, ticket or None)


def boot_structure(ctx):
    efi, rec = [], []
    tdisk = ctx.target.disk["number"] if ctx.target and ctx.target.disk else None
    for d in ctx.inventory.get("disks", []):
        for p in d["partitions"]:
            e = {"disk": d["number"], "partition": p["number"], "size": p["size"], "volume": p.get("volume"),
                 "on_target_disk": d["number"] == tdisk}
            if p["type"] == "EFI System":
                efi.append(e)
            elif p["type"] == "Windows Recovery":
                rec.append(e)
    return {"firmware_of_running_environment": ctx.env["firmware"], "efi_partitions": efi,
            "recovery_partitions": rec, "target_disk": tdisk,
            "target_disk_style": ctx.target.disk.get("style") if ctx.target and ctx.target.disk else None,
            "note": ("more than one EFI System partition exists: confirm which one the firmware uses before any "
                     "boot repair" if len(efi) > 1 else "")}


QUESTIONS = [
    ("symptom", "What happens when the target tries to boot?", [
        ("no_boot_device", "No boot device / disk not found"),
        ("repair_loop", "Automatic Repair loop"),
        ("stop_code", "Blue screen with a stop code"),
        ("spinning", "Spinning dots / black screen, never finishes"),
        ("other", "Something else"),
        ("unknown", "Not established yet"),
    ]),
    ("firmware_sees_disk", "Does the firmware (BIOS/UEFI setup) list the target disk?",
     [("yes", "Yes"), ("no", "No"), ("unknown", "Not checked")]),
    ("boot_menu_wbm", "Does the firmware boot menu show Windows Boot Manager for it?",
     [("yes", "Yes"), ("no", "No"), ("unknown", "Not checked")]),
    ("recent_change", "Was there a recent change before it stopped booting?", [
        ("update", "Windows update"), ("driver", "Driver or software install"), ("power", "Power loss / forced shutdown"),
        ("hardware", "Disk or hardware change"), ("none", "None known"), ("unknown", "Not established yet"),
    ]),
    ("data_backed_up", "Is the customer's data backed up?",
     [("yes", "Yes"), ("no", "No"), ("unknown", "Not established yet")]),
]


def ask_operator(ctx):
    """Answers for the 'Not yet established' part of the report. 'unknown' when not asked."""
    ans = {}
    pre = ctx.options.get("answers") or {}
    for key, question, opts in QUESTIONS:
        if key in pre:
            ans[key] = pre[key]
        elif ctx.ui.auto or not ctx.target:
            ans[key] = "unknown"
        else:
            ans[key] = ctx.ui.choose(question, opts, "unknown")
    if ans.get("symptom") == "stop_code" and not ctx.ui.auto:
        ans["stop_code"] = ctx.ui.ask("Stop code or exact message (Enter to skip)", "")
    elif ans.get("symptom") == "other" and not ctx.ui.auto:
        ans["symptom_text"] = ctx.ui.ask("Describe what happens (Enter to skip)", "")
    return ans


def _public(t):
    return {"root": t.root, "windir": t.windir, "online": t.online, "letter": t.letter,
            "disk": {k: t.disk.get(k) for k in ("number", "model", "serial", "bus", "size", "style", "offline")} if t.disk else None,
            "partition": {k: t.partition.get(k) for k in ("number", "size", "type")} if t.partition else None,
            "volume": {k: t.volume.get(k) for k in ("guid_path", "fs", "label", "size", "free")},
            "info": t.info}
