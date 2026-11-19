"""Repair helpers (phase 2, spec 6.4).

This module only PROPOSES repairs: repair_steps() and friends return RepairStep
objects and never run anything. The menu hands them, one at a time, to
ctx.runner.repair(), which shows the exact command, asks for a typed yes and
runs it. Nothing here starts a program.
"""
import os
import re
import shutil
import time

from .. import wim
from ..core import winapi
from ..core.log import LOG
from ..core.runner import RepairStep, Refused

PACKAGE_RE = re.compile(r"[A-Za-z0-9_.~\-]+")
ASSIGN_LETTERS = ("W", "V", "U", "T", "R", "Q")
EFI_LETTERS = ("S", "Y", "Z")
MIN_SCRATCH_FREE = 2 * 1024 ** 3
BOOT_NOT_CONFIRMED = ("boot not confirmed: no step result, including a clean scan, means the machine boots; "
                      "only a test boot does")

GUIDANCE = [
    "Uninstall the latest quality update from WinRE: boot the recovery environment, then Troubleshoot > "
    "Advanced options > Uninstall Updates > Uninstall latest quality update. No command is run by this kit. "
    "Test boot after it, and record the exact result.",
    "System Restore: from WinRE choose Troubleshoot > Advanced options > System Restore and pick a restore "
    "point dated before the problem started. Restore points exist only if System Protection was on. "
    "Test boot after it, and record the exact result.",
    "Startup Repair: from WinRE choose Troubleshoot > Advanced options > Startup Repair. It can fail or loop "
    "without changing anything useful; if it writes C:\\Windows\\System32\\Logfiles\\Srt\\SrtTrail.txt, "
    "collect that file. Test boot after it, and record the exact result.",
]


# ---------------------------------------------------------------- helpers
def _cmdline(argv):
    out = []
    for a in argv:
        a = str(a)
        out.append('"%s"' % a if (not a or " " in a or "\t" in a) else a)
    return " ".join(out)


def _used_letters(ctx):
    return {str(v.get("letter")).upper() for v in (ctx.inventory or {}).get("volumes", []) if v.get("letter")}


def _free_letter(ctx, candidates):
    used = _used_letters(ctx)
    for c in candidates:
        if c not in used:
            return c
    return None


def _image_arg(ctx):
    return "%s:\\" % ctx.target.letter


def _check(ctx):
    return lambda: target_check(ctx)


def _log_findings(ctx, step_id):
    return [e for e in ctx.case.data.get("repair_log", []) if e.get("id") == step_id and e.get("finding")]


# ---------------------------------------------------------------- source check
def check_source(ctx, wim_path, index=None):
    """Compare a repair source with the target before it is ever used. Stores the verdict in the case."""
    with ctx.case.section("source_check", "Repair source check") as sec:
        info = wim.read_info(wim_path)
        total = info.get("total_parts") or 1
        result = {"path": wim_path, "index": None, "ok": False, "mismatches": [], "image": None,
                  "is_split": total > 1, "errors": list(info["errors"])}
        images = info["images"]
        chosen = None
        if not images:
            result["mismatches"] = [{"field": "file", "target": None, "source": None,
                                     "why": "; ".join(info["errors"]) or "no images found"}]
        elif index is not None:
            chosen = next((i for i in images if i["index"] == index), None)
            if chosen is None:
                result["mismatches"] = [{"field": "index", "target": None, "source": index,
                                         "why": "image index %s is not in this file (has %s)"
                                                % (index, ", ".join(str(i["index"]) for i in images))}]
        else:
            tedition = ((ctx.target.info or {}).get("edition") or "").lower() if ctx.target else ""
            same = [i for i in images if tedition and (i["edition"] or "").lower() == tedition]
            if same:
                chosen = same[0]
            elif len(images) == 1:
                chosen = images[0]
            else:
                key = ctx.ui.choose("Which image in this source matches the target?",
                                    [(i["index"], "%s: %s (%s, %s, build %s, %s)" % (
                                        i["index"], i["name"], i["edition"], i["architecture"], i["version"],
                                        ",".join(i["languages"]))) for i in images],
                                    default=images[0]["index"])
                chosen = next((i for i in images if i["index"] == key), images[0])
        if chosen is not None:
            cmp_ = wim.compare_source((ctx.target.info if ctx.target else {}) or {}, chosen)
            result.update(index=chosen["index"], ok=cmp_["ok"], mismatches=cmp_["mismatches"], image=chosen)
        ctx.case.data["source_check"] = result
        sec.data.update(result)
        if result["ok"]:
            ctx.ui.say("Source ACCEPTED: %s image %s (%s, %s, build %s, %s) matches the target."
                       % (wim_path, result["index"], chosen["edition"], chosen["architecture"], chosen["version"],
                          ",".join(chosen["languages"])))
            if result["is_split"]:
                ctx.ui.say("This source is split (%d parts): it must be exported to a single file first; "
                           "that step is offered separately." % total)
        else:
            ctx.ui.say("Source REFUSED: %s will not be used for /RestoreHealth." % wim_path)
            for m in result["mismatches"]:
                ctx.ui.say("  - %s: %s" % (m["field"], m["why"]))
            ctx.ui.say("A source with a different language or build can fail with DISM error 0x800f0915 "
                       "(seen with an lt-LT source against an en-US target).")
        sec.set("ok", "source %s" % ("accepted" if result["ok"] else "refused"))
    return result


# ---------------------------------------------------------------- target re-check
def target_check(ctx):
    """Re-verify the target right before a repair. Returns (ok, message)."""
    t = ctx.target
    if t is None:
        return False, "no target selected"
    try:
        vols = winapi.volumes()
    except Exception as e:  # noqa: BLE001 - any failure to look must block the repair
        return False, "could not re-read volumes: %s: %s" % (type(e).__name__, e)
    guid = (t.volume or {}).get("guid_path")
    vol = next((v for v in vols if v.get("guid_path") == guid), None)
    if vol is None:
        return False, "the target volume %s is no longer present" % guid
    ext = vol.get("extents") or []
    want_disk = (t.disk or {}).get("number")
    if want_disk is None:
        return False, "the target disk number is unknown"
    if not ext or ext[0].get("disk") != want_disk:
        return False, "the target volume moved: it was on disk %s and is now on disk %s" % (
            want_disk, ext[0].get("disk") if ext else "unknown")
    now = vol.get("letter")
    if (now or None) != (t.letter or None):
        return False, "the drive letter changed: it was %s: and is now %s" % (
            t.letter or "(none)", ("%s:" % now) if now else "(none)")
    if not os.path.isdir(os.path.join(t.windir, "System32", "config")):
        return False, "%s no longer contains System32\\config" % t.windir
    return True, "target unchanged"


# ---------------------------------------------------------------- scratch
def scratch_dir(ctx):
    """<case>\\scratch if the case volume is NTFS with at least 2 GiB free, else None."""
    d = ctx.case.dir
    letter = os.path.splitdrive(os.path.abspath(d))[0][:1].upper()
    vol = next((v for v in (ctx.inventory or {}).get("volumes", [])
                if str(v.get("letter") or "").upper() == letter and letter), None)
    if not vol or str(vol.get("fs") or "").upper() != "NTFS":
        return None
    try:
        if shutil.disk_usage(d).free < MIN_SCRATCH_FREE:
            return None
        p = ctx.case.path("scratch")
        os.makedirs(p, exist_ok=True)
        return p
    except OSError as e:
        LOG.info("REPAIR| scratch dir not usable: %s", e)
        return None


# ---------------------------------------------------------------- steps
def _diskpart_assign(ctx, disk, part, letter):
    return ["select disk %d" % disk, "select partition %d" % part, "assign letter=%s" % letter]


def repair_steps(ctx):
    t = ctx.target
    if t is None:
        return []
    chk = _check(ctx)
    if t.letter is None:
        disk, part = (t.disk or {}).get("number"), (t.partition or {}).get("number")
        letter = _free_letter(ctx, ASSIGN_LETTERS)
        if disk is None or part is None or letter is None:
            return []
        return [RepairStep(
            id="assign_letter", title="Assign drive letter %s: to the Windows volume" % letter,
            effect="Assigns a temporary drive letter; no data is changed. DISM and SFC need a drive letter "
                   "to address the offline Windows install.",
            diskpart=_diskpart_assign(ctx, disk, part, letter),
            risk="Low. Only the letter mapping changes.", timeout=120, target_check=chk,
            evidence="The Windows volume has no drive letter.")]

    img = _image_arg(ctx)
    scratch = scratch_dir(ctx)
    extra = ["/ScratchDir:%s" % scratch] if scratch else []
    dism = ["dism", "/English", "/Image:%s" % img, "/Cleanup-Image"]
    sc = ctx.case.data.get("source_check")
    steps = [RepairStep(
        id="scanhealth", title="DISM /ScanHealth (check the component store)",
        effect="Scans the offline component store for corruption. It reports; it does not repair.",
        argv=dism + ["/ScanHealth"] + extra,
        risk="Low. DISM mounts the offline registry hives of the target and writes servicing logs there.",
        target_check=chk)]

    restore = dism + ["/RestoreHealth"]
    evidence = ""
    scans = _log_findings(ctx, "scanhealth")
    if scans:
        evidence = "ScanHealth result recorded in this session: %s." % scans[-1]["finding"]
    if sc:
        if sc.get("ok"):
            src_path, src_index = sc["path"], sc["index"]
            if sc.get("is_split"):
                first = sc["path"]
                stem = re.sub(r"\d+$", "", os.path.splitext(os.path.basename(first))[0])
                pattern = os.path.join(os.path.dirname(first), stem + "*.swm")
                exported = ctx.case.path("exports", "repair-source.wim")
                steps.append(RepairStep(
                    id="export_source", title="Export the split source to a single WIM",
                    effect="Joins the .swm parts into one WIM file inside the case folder so DISM can use it as a "
                           "repair source. The target is not touched.",
                    argv=["dism", "/English", "/Export-Image", "/SourceImageFile:%s" % first,
                          "/SWMFile:%s" % pattern, "/SourceIndex:%d" % sc["index"],
                          "/DestinationImageFile:%s" % exported, "/Compress:max", "/CheckIntegrity"],
                    risk="Low. Needs free space on the case drive about the size of the image.",
                    touches_target=False, target_check=chk, evidence="The checked repair source is a split WIM."))
                src_path, src_index = exported, 1
            prefix = "esd" if src_path.lower().endswith(".esd") else "wim"
            restore += ["/Source:%s:%s:%s" % (prefix, src_path, src_index), "/LimitAccess"]
            evidence = (evidence + " " if evidence else "") + "Source %s image %s passed the source check." % (
                sc["path"], sc["index"])
        else:
            why = "; ".join("%s: %s" % (m["field"], m["why"]) for m in sc.get("mismatches", [])) or "see source check"
            evidence = (evidence + " " if evidence else "") + (
                "The checked source %s was refused (%s), so no /Source is used." % (sc["path"], why))
    steps.append(RepairStep(
        id="restorehealth", title="DISM /RestoreHealth (repair the component store)",
        effect="Replaces corrupt component store files, from the verified source when one is given, otherwise "
               "from what DISM can reach on its own.",
        argv=restore + extra,
        risk="Medium. Changes servicing files in the target Windows; an interrupted run can leave servicing "
             "worse than before. No automatic rollback.",
        target_check=chk, evidence=evidence))

    steps.append(RepairStep(
        id="sfc", title="SFC offline scan and repair",
        effect="Checks protected system files of the offline install and restores damaged ones. "
               "A clean SFC result does not prove the machine boots.",
        argv=["sfc", "/scannow", "/offbootdir=%s" % img, "/offwindir=%s" % os.path.join(img, "Windows")],
        risk="Medium. Replaces system files in the target Windows.", target_check=chk))
    steps.append(RepairStep(
        id="list_packages", title="DISM /Get-Packages (list installed packages)",
        effect="Lists the installed update packages. Read-only in effect.",
        argv=["dism", "/English", "/Image:%s" % img, "/Get-Packages", "/Format:Table"],
        risk="Low. Classed as a repair because DISM mounts the offline registry of the target.",
        target_check=chk))
    return steps


def remove_package_step(ctx, package_name):
    if not isinstance(package_name, str) or not PACKAGE_RE.fullmatch(package_name):
        raise ValueError("invalid package name %r: only letters, digits, _ . ~ - are allowed" % (package_name,))
    if ctx.target is None or ctx.target.letter is None:
        raise ValueError("the target has no drive letter; assign one first")
    return RepairStep(
        id="remove_package", title="DISM /Remove-Package %s" % package_name,
        effect="Removes one update package from the offline install. Use the exact name from the package list.",
        argv=["dism", "/English", "/Image:%s" % _image_arg(ctx), "/Remove-Package", "/PackageName:%s" % package_name],
        risk="Medium. Removing the wrong package can break updates or features; pending operations may "
             "finish only at the next boot.",
        target_check=_check(ctx))


# ---------------------------------------------------------------- offline disks, BitLocker
def online_disk_steps(ctx):
    """One step per disk that Windows reports as offline (its volumes cannot be read until it is online)."""
    steps = []
    for d in (ctx.inventory or {}).get("disks", []):
        if not d.get("offline"):
            continue
        steps.append(RepairStep(
            id="online_disk", title="Bring disk %d online (%s, %.0f GB)" % (
                d["number"], d.get("model") or "model unknown", (d.get("size") or 0) / 2 ** 30),
            effect="Marks the disk online so its volumes can be read. No partition or file is changed. "
                   "Run the scan again afterwards.",
            diskpart=["select disk %d" % d["number"], "online disk"],
            risk="Low. Changes the disk's online/offline state only. If the disk is offline because of a "
                 "signature collision with another disk, Windows may assign it a new disk signature.",
            timeout=120, touches_target=False,
            evidence="Disk %d is reported offline." % d["number"]))
    return steps


def unlock_step(ctx, letter, recovery_key):
    """manage-bde -unlock for a BitLocker-locked volume. The key is never logged or stored."""
    letter = str(letter).strip().rstrip(":\\").upper()
    if len(letter) != 1 or not letter.isalpha():
        raise ValueError("type the single drive letter of the locked volume")
    key = recovery_key.strip()
    if not re.fullmatch(r"(\d{6}-){7}\d{6}", key):
        raise ValueError("a BitLocker recovery key is 8 groups of 6 digits separated by dashes")
    return RepairStep(
        id="unlock", title="Unlock BitLocker volume %s:" % letter,
        effect="Unlocks the volume for this session so it can be read. Nothing on the disk is changed and "
               "the volume locks again at reboot. The key is not written to any log or file.",
        argv=["manage-bde", "-unlock", "%s:" % letter, "-RecoveryPassword", key],
        risk="Low.", timeout=120, touches_target=False, secrets=(key,),
        evidence="The volume is BitLocker-locked.")


# ---------------------------------------------------------------- copy out
def _on_target_volume(ctx, dest):
    root = ctx.target.root
    d = os.path.abspath(dest)
    if ctx.target.letter and os.path.splitdrive(d)[0][:1].upper() == ctx.target.letter.upper():
        return True
    try:
        if os.path.commonpath([os.path.normcase(d), os.path.normcase(os.path.abspath(root))]) == \
                os.path.normcase(os.path.abspath(root)):
            return True
    except ValueError:
        pass
    drive = os.path.splitdrive(d)[0]
    try:
        if drive and os.path.samefile(drive + "\\", root):
            return True
    except OSError:
        pass
    return False


def copy_out_step(ctx, dest_dir, folders=("Users",)):
    if ctx.target is None:
        raise ValueError("no target selected")
    if len(folders) != 1:
        raise ValueError("one folder per copy step; got %d" % len(folders))
    if not os.path.isdir(dest_dir):
        raise ValueError("destination %s does not exist or is not a folder" % dest_dir)
    if _on_target_volume(ctx, dest_dir):
        raise ValueError("destination %s is on the target volume; choose another drive" % dest_dir)
    folder = folders[0]
    log = ctx.case.path("logs", "robocopy-%s.log" % time.strftime("%Y%m%d-%H%M%S"))
    return RepairStep(
        id="copy_out", title="Copy %s to %s" % (folder, dest_dir),
        effect="Copies the folder to the destination with timestamps and attributes. The target is only read; "
               "nothing is moved or deleted. Junctions are skipped.",
        argv=["robocopy", os.path.join(ctx.target.root, folder), os.path.join(dest_dir, folder), "/E", "/COPY:DAT",
              "/DCOPY:DAT", "/R:1", "/W:1", "/XJ", "/NP", "/TEE", "/LOG:%s" % log],
        risk="Low. Files that cannot be read are skipped and listed in the log.",
        touches_target=False, target_check=_check(ctx))


def _is_link(entry):
    try:
        if entry.is_symlink():
            return True
        isj = getattr(entry, "is_junction", None)
        if isj is not None and isj():
            return True
        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attrs & 0x400)
    except OSError:
        return False


def copy_out_precheck(ctx, dest_dir, folders=("Users",)):
    needed, errors = 0, 0
    stack = [os.path.join(ctx.target.root, f) for f in folders]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if _is_link(e):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            needed += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        errors += 1
        except OSError:
            errors += 1
    free = shutil.disk_usage(dest_dir).free
    return {"needed": needed, "free": free, "fits": needed <= free, "errors": errors}


# ---------------------------------------------------------------- BCD
def _efi_parts(ctx):
    parts = (ctx.target.disk or {}).get("partitions", []) if ctx.target else []
    return [p for p in parts if p.get("type") == "EFI System"]


def bcd_blockers(ctx):
    out = []
    if ctx.runner.bcd_backup is None or not ctx.runner.bcd_backup:
        out.append("no BCD export was made in this run; export the BCD store first")
    t = ctx.target
    if t is None:
        return out + ["no target selected"]
    if t.online:
        out.append("the target is the running Windows")
    if not t.disk or t.disk.get("style") != "GPT":
        out.append("the target disk is not GPT (style: %s); only UEFI/GPT boot repair is offered"
                   % ((t.disk or {}).get("style") or "unknown"))
    if t.letter is None:
        out.append("the Windows volume has no drive letter; assign one first")
    n = len(_efi_parts(ctx))
    if n != 1:
        out.append("the target disk has %d EFI System partitions; exactly one is required so the right one is "
                   "written" % n)
    return out


def bcd_steps(ctx):
    if bcd_blockers(ctx):
        return []
    t = ctx.target
    efi = _efi_parts(ctx)[0]
    chk = _check(ctx)
    steps = []
    letter = efi.get("letter")
    if not letter:
        letter = _free_letter(ctx, EFI_LETTERS)
        if letter is None:
            return []
        steps.append(RepairStep(
            id="assign_efi_letter", title="Assign drive letter %s: to the EFI System partition" % letter,
            effect="Assigns a temporary drive letter; no data is changed.",
            diskpart=_diskpart_assign(ctx, t.disk["number"], efi["number"], letter),
            risk="Low. Only the letter mapping changes.", timeout=120, target_check=chk))
    steps.append(RepairStep(
        id="bcdboot", title="bcdboot: rewrite boot files on EFI partition %s:" % letter,
        effect="Copies boot files from the target Windows to the EFI System partition and rebuilds its boot entry.",
        argv=["bcdboot", "%s:\\Windows" % t.letter, "/s", "%s:" % letter, "/f", "UEFI"],
        risk="HIGH. Rewrites boot files on that EFI partition. Entries of other installs on a shared EFI "
             "partition can be affected. The BCD export at %s is the way back." % ctx.runner.bcd_backup,
        target_check=chk))
    return steps


# ---------------------------------------------------------------- record
_FINDINGS = (
    ("not_repairable", ("cannot be repaired", "not repairable")),
    ("repairable", ("component store is repairable",)),
    ("healthy", ("no component store corruption detected",)),
    ("restored", ("the restore operation completed successfully",)),
    ("sfc_clean", ("did not find any integrity violations",)),
    ("sfc_unrepaired", ("unable to fix",)),
    ("sfc_repaired", ("successfully repaired",)),
)


def parse_finding(out):
    low = (out or "").lower()
    for name, needles in _FINDINGS:
        if any(n in low for n in needles):
            return name
    return None


def _emit(ctx):
    with ctx.case.section("repairs", "Repair helpers") as sec:
        sec.data["log"] = list(ctx.case.data.get("repair_log", []))
        sec.data["booted_after_repair"] = ctx.case.data.get("booted_after_repair")
        sec.data["boot_note"] = ctx.case.data.get("boot_note", "")
        sec.set("ok", BOOT_NOT_CONFIRMED)


def record(ctx, step, res, note=""):
    argv = step.argv if step.diskpart is None else None
    command = _cmdline(argv) if argv is not None else "diskpart: " + " / ".join(step.diskpart)
    if res is None:
        entry = {"kind": "declined", "rc": None, "error": "declined by operator", "finding": None, "error_code": None}
    else:
        m = re.search(r"0x[0-9A-Fa-f]{8}", res.out or "")
        entry = {"kind": res.kind, "rc": res.rc, "error": res.error or "", "finding": parse_finding(res.out),
                 "error_code": m.group(0) if m else None}
    entry.update({"id": step.id, "title": step.title, "command": command,
                  "time": time.strftime("%Y-%m-%dT%H:%M:%S"), "note": note})
    ctx.case.data.setdefault("repair_log", []).append(entry)
    _emit(ctx)
    return entry


# ---------------------------------------------------------------- menu
def refresh_letter(ctx):
    """After assign_letter: look the volume up again and adopt its new letter."""
    t = ctx.target
    for v in winapi.volumes():
        if v.get("guid_path") == (t.volume or {}).get("guid_path") and v.get("letter"):
            t.letter = str(v["letter"]).rstrip(":\\").upper()
            t.volume["letter"] = t.letter
            t.root = t.letter + ":\\"
            t.windir = t.root + "Windows"
            ctx.ui.say("The Windows volume is now %s:" % t.letter)
            return True
    ctx.ui.say("The drive letter could not be confirmed; steps stay blocked until it is.")
    return False


def _execute(ctx, step):
    try:
        res = ctx.runner.repair(step)
    except Refused as e:
        ctx.ui.say("Refused: %s" % e)
        return None
    record(ctx, step, res)
    if res is not None:
        if step.id == "assign_letter" and res.ok:
            refresh_letter(ctx)
        ctx.ui.say("Test boot before the next step, then record the result.")
    return res


def _fmt(n):
    return "%.1f GiB" % (n / 1024 ** 3)


def run_menu(ctx):
    ui, t = ctx.ui, ctx.target
    avail = t is not None and not t.online
    if t is None:
        ui.say("Repairs are unavailable: no target Windows install was selected. "
               "The repair source check can still be used.")
    elif t.online:
        ui.say("Repairs are unavailable: the target is the running Windows. Copying user data out and the "
               "repair source check can still be used.")
    if not ui.confirm_yes("Enter repair mode? Repairs change the target and are run one at a time."):
        ui.say("Repair mode not entered.")
        return
    ctx.runner.repairs_enabled = True
    try:
        while True:
            opts = [("source", "Check a repair source (WIM/ESD/SWM)")]
            if avail:
                opts.append(("step", "List / run a proposed repair step"))
                opts.append(("package", "Remove an update package"))
            if t is not None:
                opts.append(("copy", "Copy user data out to another drive"))
            if online_disk_steps(ctx):
                opts.append(("online", "Bring an offline disk online"))
            opts.append(("unlock", "Unlock a BitLocker volume (needs the recovery key)"))
            opts += [("guidance", "Show guidance (no commands run)"), ("boot", "Record boot test result"),
                     ("back", "Back")]
            key = ui.choose("Repair helpers", opts, default="back")
            if key == "back" or key is None:
                return
            try:
                if key == "source":
                    p = ui.ask("Path of the .wim / .esd / first .swm").strip().strip('"')
                    if p:
                        check_source(ctx, p)
                elif key == "step":
                    _menu_step(ctx)
                elif key == "package":
                    name = ui.ask("Exact package name (from the package list)").strip()
                    if name:
                        _execute(ctx, remove_package_step(ctx, name))
                elif key == "copy":
                    _menu_copy(ctx)
                elif key == "online":
                    steps = online_disk_steps(ctx)
                    k = ui.choose("Offline disks", [(i, s.title) for i, s in enumerate(steps)] + [("back", "Back")],
                                  default="back")
                    if k != "back" and k is not None:
                        res = _execute(ctx, steps[k])
                        if res is not None and res.ok:
                            ui.say("Disk is online. Go back and run the scan again to find its Windows install.")
                elif key == "unlock":
                    letter = ui.ask("Drive letter of the locked volume")
                    if letter:
                        rk = ui.ask("Recovery key (48 digits with dashes; not logged)", "", secret=True)
                        res = _execute(ctx, unlock_step(ctx, letter, rk))
                        if res is not None and res.ok:
                            ui.say("Unlocked. Go back and run the scan again.")
                elif key == "guidance":
                    for g in GUIDANCE:
                        ui.say("- " + g)
                elif key == "boot":
                    _menu_boot(ctx)
            except ValueError as e:
                ui.say("Not possible: %s" % e)
    finally:
        ctx.runner.repairs_enabled = False


def _menu_step(ctx):
    steps = repair_steps(ctx) + bcd_steps(ctx)
    if not steps:
        ctx.ui.say("No repair steps can be proposed (missing disk, partition or free drive letter information).")
    for b in bcd_blockers(ctx):
        ctx.ui.say("BCD repair not offered: %s" % b)
    if not steps:
        return
    key = ctx.ui.choose("Proposed steps", [(s.id, "%s - %s" % (s.id, s.title)) for s in steps] + [("back", "Back")],
                        default="back")
    step = next((s for s in steps if s.id == key), None)
    if step is not None:
        _execute(ctx, step)


def _menu_copy(ctx):
    dest = ctx.ui.ask("Destination folder on another drive").strip().strip('"')
    if not dest:
        return
    step = copy_out_step(ctx, dest)
    pre = copy_out_precheck(ctx, dest)
    ctx.ui.say("Needed: %s, free at destination: %s, unreadable folders/files: %d"
               % (_fmt(pre["needed"]), _fmt(pre["free"]), pre["errors"]))
    if not pre["fits"]:
        ctx.ui.say("Refused: the data does not fit on the destination.")
        return
    _execute(ctx, step)


def _menu_boot(ctx):
    r = ctx.ui.choose("Result of the test boot", [("yes", "Booted"), ("no", "Did not boot"), ("na", "Not tested")],
                      default="na")
    ctx.case.data["booted_after_repair"] = {"yes": True, "no": False}.get(r)
    ctx.case.data["boot_note"] = ctx.ui.ask("Note (exact result, error text)", "")
    _emit(ctx)
