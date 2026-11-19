"""Device ID: one 4-letter code per component, so the ID shows which PC it is and how it is configured.

    CPU -RAM -RSPD-MOBO-GPU -USER-DISK-UNIT
    KQZT-BMHA-WQPD-TRNE-AHCS-XXXX-JJQO-ZMPL

Each code is derived from a hash of that component's description, so two PCs with
the same CPU share the CPU code, and a PC whose RAM was swapped changes only its
RAM codes. XXXX means the component could not be read.

Kept on the flash drive, next to cases/:
    devices/components.json        every code ever seen -> the component it stands for
    devices/index.md               table of all devices, readable at a glance
    devices/<ID>/device.json       this device: components, full hardware, runs
    devices/<ID>/settings.json     device-specific settings (ticket, notes, target, answers)

The hardware is that of the machine the kit runs on. When the target disk is
attached to another PC, the hardware codes describe that other PC.
"""
import hashlib
import json
import os
import time

from ..core import hwinfo
from ..core.mdsafe import code as _code, text as _text
from ..core.log import LOG
from . import discovery

SEGMENTS = [
    ("CPU", "Processor"),
    ("RAM", "Memory modules"),
    ("RSPD", "Memory speed (rated / running)"),
    ("MOBO", "Mainboard"),
    ("GPU", "Graphics"),
    ("USER", "Windows user of the target"),
    ("DISK", "Target disk"),
    ("UNIT", "This unit (system UUID or board serial)"),
]
UNKNOWN = "XXXX"
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SKIP_PROFILES = {"public", "default", "default user", "all users", "defaultuser0", "defaultapppool"}
DEFAULT_SETTINGS = {"notes": "", "ticket": "", "target": "", "answers": {}}


def code(segment, value):
    """4 letters from the hash of a component description; XXXX when the value is unknown."""
    value = " ".join(str(value or "").split())
    if not value:
        return UNKNOWN
    n = int.from_bytes(hashlib.sha256(("%s|%s" % (segment, value.lower())).encode("utf-8")).digest()[:8], "big")
    out = ""
    for _ in range(4):
        n, r = divmod(n, 26)
        out += LETTERS[r]
    return "XXXY" if out == UNKNOWN else out


def target_user(target):
    """The Windows user the target belongs to: last logged-on user, else the newest profile folder."""
    if target is None:
        return ""
    key = r"Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    for name in ("LastLoggedOnSAMUser", "LastLoggedOnUser"):
        v = target.reg.get("SOFTWARE", key, name)
        if isinstance(v, str) and v.strip():
            return v.replace("/", "\\").split("\\")[-1].strip()
    users = os.path.join(target.root, "Users")
    best, best_t = "", 0.0
    try:
        with os.scandir(users) as it:
            for e in it:
                if e.name.lower() in SKIP_PROFILES or not e.is_dir(follow_symlinks=False):
                    continue
                t = e.stat(follow_symlinks=False).st_mtime
                if t > best_t:
                    best, best_t = e.name, t
    except OSError:
        return ""
    return best


def describe(hw, target):
    """{segment: (value used for the hash, human detail)} from hardware info and the chosen target."""
    cpu = hw.get("cpu") or {}
    cpu_v = cpu.get("name") or ""
    if cpu_v and (cpu.get("sockets") or 1) > 1:
        cpu_v += " x%d" % cpu["sockets"]
    mods = hw.get("memory") or []
    ram_v = rspd_v = ""
    if mods:
        total = sum(m.get("size_mb") or 0 for m in mods)
        kinds = sorted({m.get("type") or "" for m in mods} - {""})
        parts = sorted((m.get("part") or m.get("manufacturer") or "unknown module") for m in mods)
        ram_v = "%d GB = %s %s" % (round(total / 1024), " + ".join(
            "%d GB %s" % (round((m.get("size_mb") or 0) / 1024), p) for m, p in zip(
                sorted(mods, key=lambda m: (m.get("part") or m.get("manufacturer") or "unknown module")), parts)),
            "/".join(kinds))
        ram_v = ram_v.strip()
        rated = max((m.get("speed") or 0) for m in mods)
        running = max((m.get("configured_speed") or 0) for m in mods)
        if rated or running:
            rspd_v = "rated %s MT/s, running %s MT/s" % (rated or "?", running or "?")
    elif hw.get("memory_total_mb"):
        ram_v = "%d GB (modules not readable)" % round(hw["memory_total_mb"] / 1024)
    board, system = hw.get("board") or {}, hw.get("system") or {}
    mobo_v = " ".join(x for x in (board.get("manufacturer"), board.get("product")) if x) or \
        " ".join(x for x in (system.get("manufacturer"), system.get("product")) if x)
    gpus = sorted(hw.get("gpus") or [], key=lambda g: g.get("id", ""))
    gpu_v = " + ".join(g["id"] for g in gpus)
    gpu_d = " + ".join((g.get("name") or g["id"]) for g in gpus)
    disk = (target.disk or {}) if target is not None else {}
    disk_v = " ".join(x for x in (disk.get("model"),) if x)
    disk_d = "%s, %.0f GB" % (disk_v, (disk.get("size") or 0) / 2 ** 30) if disk_v else ""
    unit_v = system.get("uuid") or board.get("serial") or system.get("serial") or ""
    user_v = target_user(target)
    return {"CPU": (cpu_v, cpu_v), "RAM": (ram_v, ram_v), "RSPD": (rspd_v, rspd_v),
            "MOBO": (mobo_v, " ".join(x for x in (mobo_v, "BIOS " + hw["bios"]["version"] if (hw.get("bios") or {}).get("version") else "") if x)),
            "GPU": (gpu_v, gpu_d), "USER": (user_v, user_v), "DISK": (disk_v, disk_d), "UNIT": (unit_v, unit_v)}


def build(hw, target):
    """Return (device_id, segments) where segments is a list of {segment, label, code, value, detail}."""
    desc = describe(hw, target)
    segs = []
    for seg, label in SEGMENTS:
        value, detail = desc[seg]
        segs.append({"segment": seg, "label": label, "code": code(seg, value), "value": value, "detail": detail or value})
    return "-".join(s["code"] for s in segs), segs


def decode(devices_dir, device_id):
    """Look every code of an ID up in components.json. Unknown codes come back with value None."""
    reg = _load(os.path.join(devices_dir, "components.json"), {})
    codes = device_id.upper().split("-")
    out = []
    for (seg, label), c in zip(SEGMENTS, codes):
        slot = reg.get(seg)
        e = slot.get(c) if isinstance(slot, dict) else None
        e = e if isinstance(e, dict) else {}
        out.append({"segment": seg, "label": label, "code": c, "value": e.get("value"),
                    "detail": e.get("detail")})
    return out


def _load(path, default, expect=dict, problems=None):
    """Read a JSON file that must hold an `expect` (dict). Unreadable or of another type: the file is moved
    aside to .bad, `default` is returned and a sentence is appended to `problems` (if given)."""
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
        if expect is not None and not isinstance(obj, expect):
            raise ValueError("expected a JSON %s, found %s" % ("object" if expect is dict else expect.__name__,
                                                                 type(obj).__name__))
        return obj
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as e:
        LOG.error("DEVICE| %s not readable (%s): starting from an empty one, the old file is kept as .bad", path, e)
        if problems is not None:
            problems.append("%s is corrupt (%s): moved aside to %s.bad, defaults used" % (
                os.path.basename(path), e, os.path.basename(path)))
        try:
            os.replace(path, path + ".bad")
        except OSError:
            pass
        return default


def _save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, path)


def devices_dir(ctx):
    return ctx.options.get("devices_dir") or os.path.join(os.path.dirname(ctx.case.out_root), "devices")


def remember(ddir, device_id, segs, hw, run):
    """Update components.json, devices/<ID>/device.json, settings.json and index.md. Returns (settings, notes)."""
    today = time.strftime("%Y-%m-%d %H:%M")
    notes = []
    reg_path = os.path.join(ddir, "components.json")
    reg = _load(reg_path, {}, problems=notes)
    for s in segs:
        if s["code"] == UNKNOWN:
            continue
        slot = reg.get(s["segment"])
        if not isinstance(slot, dict):
            slot = reg[s["segment"]] = {}
        e = slot.get(s["code"])
        if not isinstance(e, dict) or not isinstance(e.get("devices"), list):
            e = slot[s["code"]] = {"value": s["value"], "detail": s["detail"], "first_seen": today, "devices": []}
        elif str(e.get("value", "")).lower() != s["value"].lower():
            notes.append("code %s for %s already stands for %r; this device has %r (hash collision): see "
                         "device.json for the real value" % (s["code"], s["segment"], e.get("value"), s["value"]))
            e.setdefault("also", [])
            if s["value"] not in e["also"]:
                e["also"].append(s["value"])
        e["last_seen"] = today
        if device_id not in e["devices"]:
            e["devices"].append(device_id)
    _save(reg_path, reg)

    dpath = os.path.join(ddir, device_id, "device.json")
    dev = _load(dpath, {}, problems=notes)
    dev.setdefault("first_seen", today)
    dev.update(id=device_id, last_seen=today, segments=segs, hardware=hw)
    runs = dev.get("runs")
    if not isinstance(runs, list):
        runs = dev["runs"] = []
    runs.append(run)
    del runs[:-50]
    _save(dpath, dev)

    spath = os.path.join(ddir, device_id, "settings.json")
    settings = _load(spath, None, problems=notes)
    if settings is None:
        settings = dict(DEFAULT_SETTINGS)
        _save(spath, settings)
    for k, v in DEFAULT_SETTINGS.items():
        settings.setdefault(k, v)

    _write_index(ddir)
    return settings, notes


def _write_index(ddir):
    rows = []
    try:
        names = sorted(os.listdir(ddir))
    except OSError:
        names = []
    for name in names:
        dev = _load(os.path.join(ddir, name, "device.json"), None) if os.path.isdir(os.path.join(ddir, name)) else None
        if not dev:
            continue
        segs = dev.get("segments") if isinstance(dev.get("segments"), list) else []
        d = {s["segment"]: _text(s.get("detail"), 120) or "-" for s in segs if isinstance(s, dict) and "segment" in s}
        runs = dev.get("runs")
        rows.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %d |" % (
            _code(dev.get("id") or name, 80) or "-", d.get("CPU", "-"), d.get("RAM", "-"), d.get("RSPD", "-"),
            d.get("MOBO", "-"), d.get("GPU", "-"), d.get("USER", "-"), d.get("DISK", "-"),
            _text(dev.get("last_seen"), 40) or "-", len(runs) if isinstance(runs, list) else 0))
    text = ["# Devices seen by this kit", "",
            "ID = " + "-".join(s for s, _ in SEGMENTS) + ". One 4-letter code per component; XXXX = not readable. "
            "`components.json` maps every code back to its component. Device-specific settings are in "
            "`<ID>/settings.json`.", "",
            "| Device ID | CPU | RAM | RAM speed | Mainboard | Graphics | User | Target disk | Last seen | Runs |",
            "|---|---|---|---|---|---|---|---|---|---|"] + [r.replace("\n", " ") for r in rows]
    try:
        with open(os.path.join(ddir, "index.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(text) + "\n")
    except OSError as e:
        LOG.error("DEVICE| index.md not written: %s", e)


def collect(ctx):
    """Section 'device': build the ID, show it, remember it on the flash drive, apply device settings."""
    with ctx.case.section("device", "Device identity") as sec:
        hw = hwinfo.collect()
        device_id, segs = build(hw, ctx.target)
        ctx.case.write_json("inventory/device.json", {"id": device_id, "segments": segs, "hardware": hw})
        sec.data = {"id": device_id, "segments": segs}
        ctx.case.data["device"] = {"id": device_id, "segments": segs}
        for e in hw.get("errors") or []:
            sec.item("hardware", "error", e)
        for s in segs:
            if s["code"] == UNKNOWN:
                sec.item(s["segment"], "missing", "%s could not be read%s" % (
                    s["label"], " (no target chosen)" if s["segment"] in ("USER", "DISK") and ctx.target is None else ""))
        ui = ctx.ui
        ui.say("Device ID: %s" % device_id)
        for s in segs:
            ui.say("  %-4s %s  %s" % (s["segment"], s["code"], s["detail"] or "(not readable)"))
        if ctx.target is not None and ctx.env.get("kind") == "windows" and not ctx.target.online:
            sec.reason = ("the hardware codes describe the PC the kit is running on; the target is a disk attached "
                          "to it, so they may not be the customer's PC")
            ui.say("  Note: %s." % sec.reason)
        ddir = devices_dir(ctx)
        try:
            settings, notes = remember(ddir, device_id, segs, hw, {
                "time": time.strftime("%Y-%m-%d %H:%M"), "case_id": ctx.case.data.get("case_id"),
                "environment": ctx.env.get("kind"), "run": os.path.basename(ctx.case.dir)})
        except OSError as e:
            sec.item("device store", "error", "could not write %s: %s" % (ddir, e))
            return device_id
        for n in notes:
            sec.item("device store", "error", n)
        sec.data["store"] = os.path.join(ddir, device_id)
        sec.data["settings"] = settings
        apply_settings(ctx, settings)
        ui.say("  Device folder: %s" % sec.data["store"])
    return device_id


def edit_settings(ctx):
    """Menu action: change the notes and ticket saved for this device on the flash drive."""
    dev = ctx.case.data.get("device") or {}
    if not dev.get("id"):
        ctx.ui.say("No device ID yet: run the scan first.")
        return
    spath = os.path.join(devices_dir(ctx), dev["id"], "settings.json")
    settings = _load(spath, None, dict) or dict(DEFAULT_SETTINGS)
    ctx.ui.say("Settings for device %s (%s)" % (dev["id"], spath))
    settings["notes"] = ctx.ui.ask("Notes for this device (shown at every scan)", settings.get("notes", ""))
    settings["ticket"] = ctx.ui.ask("Ticket number to use for this device", settings.get("ticket", ""))
    try:
        _save(spath, settings)
        ctx.ui.say("Saved.")
    except OSError as e:
        ctx.ui.say("Could not save: %s" % e)


def apply_settings(ctx, settings):
    """Device-specific settings saved on the flash drive: notes are shown, a saved ticket names the case,
    saved answers pre-fill the boot-failure questions (explicit command-line values win)."""
    ui = ctx.ui
    if not isinstance(settings, dict):
        settings = {}
    notes = "".join(ch for ch in str(settings.get("notes") or "") if ch.isprintable())[:500]
    if notes:
        ui.say("  Notes for this device: %s" % notes)
    ticket = "".join(ch for ch in str(settings.get("ticket") or "") if ch.isascii() and ch.isalnum())[:20]
    if ticket and not ctx.case.data.get("ticket"):
        cid = ctx.case.data.get("case_id") or ""
        tid = cid.rsplit("-", 1)[-1] if cid else ""
        if tid:
            if ctx.case.assign("ITW-%s-%s" % (ticket, tid), ticket):
                ui.say("  Ticket %s taken from this device's settings." % ticket)
            else:
                ui.say("  " + (ctx.case.data.get("folder_note") or "The run folder could not be moved."))
    saved = settings.get("answers") if isinstance(settings.get("answers"), dict) else {}
    valid_answers = {k: {o for o, _ in opts} for k, _q, opts in discovery.QUESTIONS}
    ignored = sorted(str(k) for k, v in saved.items() if not (isinstance(k, str) and isinstance(v, str)
                                                            and v in valid_answers.get(k, ())))
    if ignored:
        ui.say("  Ignored invalid saved answers: %s" % ", ".join(ignored)[:200])
    saved = {k: v for k, v in saved.items() if isinstance(k, str) and isinstance(v, str) and v in valid_answers.get(k, ())}
    current = ctx.case.data.get("operator_answers") or {}
    filled = {k: v for k, v in saved.items() if current.get(k, "unknown") == "unknown" and v}
    if filled:
        current.update(filled)
        ctx.case.data["operator_answers"] = current
        if "operator" in ctx.case.data["sections"]:
            ctx.case.data["sections"]["operator"]["data"] = current
        ui.say("  Answers taken from this device's settings: %s" % ", ".join(sorted(filled)))
