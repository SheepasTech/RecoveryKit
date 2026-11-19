"""Driver rollback (read-only inventory plus PROPOSED removal).

inventory() lists the third-party driver packages (<windir>\\INF\\oem*.inf) of the
target, newest first: a driver installed right before the machine stopped booting
is a prime suspect. collect() records that. remove_driver_step() only PROPOSES
a DISM /Remove-Driver step; the menu hands it to ctx.runner.repair(), which shows
the exact command, asks for a typed yes and runs it. Nothing here starts a program.
"""
import os
import re
import time

from ..core.runner import RepairStep, Refused
from . import repair

MAX_INF_BYTES = 2 * 1024 * 1024
MAX_INF_FILES = 2000
MAX_STR = 300
RECENT_DAYS = 30
BOOT_CRITICAL = {"scsiadapter", "hdc", "diskdrive", "volume", "system"}
OEM_RE = re.compile(r"oem\d+\.inf", re.IGNORECASE)
INF_NAME_RE = re.compile(r"^oem\d+\.inf$", re.IGNORECASE)
MENU_COUNT = 15


# ---------------------------------------------------------------- parsing
class _TooLarge(ValueError):
    pass


def _read_text(path):
    """Decode an INF: UTF-16 when it has a BOM, else UTF-8, else Latin-1. Raises OSError/ValueError."""
    with open(path, "rb") as f:
        raw = f.read(MAX_INF_BYTES + 1)
    if len(raw) > MAX_INF_BYTES:
        raise _TooLarge("file is larger than %d MB" % (MAX_INF_BYTES // 2 ** 20))
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _strip_comment(line):
    out, quoted = [], False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        elif ch == ";" and not quoted:
            break
        out.append(ch)
    return "".join(out).strip()


def _unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v


def _sections(text):
    """{lower section name: [(key lower, value)]}; lines without '=' are skipped."""
    secs, cur = {}, None
    for raw in text.splitlines():
        line = _strip_comment(raw.lstrip(chr(0xfeff)))
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = secs.setdefault(line[1:-1].strip().lower(), [])
            continue
        if cur is None or "=" not in line:
            continue
        k, v = line.split("=", 1)
        cur.append((k.strip().lower(), v.strip()))
    return secs


def _parse_inf(text):
    secs = _sections(text)
    strings = {}
    for name in sorted(secs, key=lambda n: (n != "strings", n)):
        if name == "strings" or name.startswith("strings."):
            for k, v in secs[name]:
                strings.setdefault(k, _unquote(v)[:MAX_STR])

    def resolve(v):
        v = _unquote(v)[:4 * MAX_STR]
        return re.sub(r"%([^%]+)%", lambda m: strings.get(m.group(1).lower(), m.group(0)), v)[:MAX_STR]

    ver = {}
    for k, v in secs.get("version", []):
        ver.setdefault(k, resolve(v))
    date, version = None, None
    dv = ver.get("driverver")
    if dv:
        d, _, version = dv.partition(",")
        m = re.fullmatch(r"\s*(\d{1,2})/(\d{1,2})/(\d{4})\s*", d)
        if m:
            date = "%s-%02d-%02d" % (m.group(3), int(m.group(1)), int(m.group(2)))
        version = version.strip()[:MAX_STR] or None
    return {"provider": ver.get("provider") or None, "class": ver.get("class") or None,
            "class_guid": ver.get("classguid") or None, "driver_date": date, "driver_version": version,
            "catalog": ver.get("catalogfile") or None}


def _iso(ts):
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
    except (OSError, OverflowError, ValueError):
        return None


def _inf_dir(windir):
    return os.path.join(windir, "INF")


def _plain_infs(inf_dir, pattern=None):
    """Names of regular, non-link files in inf_dir (at most MAX_INF_FILES). Raises OSError if unreadable."""
    names = []
    with os.scandir(inf_dir) as it:
        for d in it:
            if pattern is not None and not pattern.fullmatch(d.name):
                continue
            if not d.name.lower().endswith(".inf"):
                continue
            try:
                if d.is_symlink() or getattr(d, "is_junction", lambda: False)() or not d.is_file(follow_symlinks=False):
                    continue
                if getattr(d.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400:
                    continue
            except OSError:
                continue
            names.append(d.name)
            if len(names) >= MAX_INF_FILES:
                break
    return names


def inventory(windir):
    """Third-party drivers of the install at windir, newest installed_ts first. Raises OSError if INF is unreadable."""
    inf_dir = _inf_dir(windir)
    out = []
    for name in _plain_infs(inf_dir, OEM_RE):
        path = os.path.join(inf_dir, name)
        e = {"inf": name, "provider": None, "class": None, "driver_date": None, "driver_version": None,
             "installed": None, "installed_ts": 0.0, "size": None, "boot_critical": False}
        try:
            st = os.stat(path)
            e["installed_ts"], e["installed"], e["size"] = st.st_mtime, _iso(st.st_mtime), st.st_size
        except OSError as ex:
            e["error"] = "cannot stat: %s" % (ex.strerror or ex)
            out.append(e)
            continue
        try:
            info = _parse_inf(_read_text(path))
            e.update(info)
            e["boot_critical"] = (info["class"] or "").lower() in BOOT_CRITICAL
        except _TooLarge:
            e["skipped"] = "larger than %d MB" % (MAX_INF_BYTES // 2 ** 20)
        except (OSError, ValueError, OverflowError, MemoryError, RecursionError) as ex:
            e["error"] = ("%s: %s" % (type(ex).__name__, getattr(ex, "strerror", None) or ex))[:MAX_STR]
        out.append(e)
    out.sort(key=lambda d: d["installed_ts"], reverse=True)
    return out


def _newest_inf_mtime(windir):
    newest = None
    inf_dir = _inf_dir(windir)
    for name in _plain_infs(inf_dir):
        try:
            ts = os.stat(os.path.join(inf_dir, name)).st_mtime
        except OSError:
            continue
        newest = ts if newest is None else max(newest, ts)
    return newest


# ---------------------------------------------------------------- collect
def _line(d):
    return "  %s  %s  %s  %s  %s%s" % (d["inf"], (d["installed"] or "?")[:10], d["provider"] or "?",
                                      d["class"] or "?", d["driver_version"] or "?",
                                      " [boot-critical class]" if d["boot_critical"] else "")


def collect(ctx):
    with ctx.case.section("drivers", "Third-party drivers of the target") as sec:
        if ctx.target is None:
            sec.set("skipped", "no target Windows install selected")
            return
        windir = ctx.target.windir
        inf_dir = _inf_dir(windir)
        if not os.path.isdir(inf_dir):
            sec.set("missing", "%s not found" % inf_dir)
            return
        try:
            drivers = inventory(windir)
            newest_any = _newest_inf_mtime(windir)
        except OSError as e:
            sec.set("error", "cannot read %s: %s: %s" % (inf_dir, type(e).__name__, e.strerror or e))
            return
        ctx.case.write_json("inventory/drivers.json", drivers)
        cutoff = (newest_any - RECENT_DAYS * 86400) if newest_any is not None else None
        recent = [d for d in drivers if cutoff is not None and d["installed_ts"] >= cutoff]
        sec.data = {"count": len(drivers),
                    "newest": [{k: v for k, v in d.items() if k != "installed_ts"} for d in drivers[:10]],
                    "recent_days": RECENT_DAYS,
                    "recent": [d["inf"] for d in recent]}
        for d in drivers:
            if d.get("error"):
                sec.item(d["inf"], "error", d["error"])
            elif d.get("skipped"):
                sec.item(d["inf"], "skipped", d["skipped"])
        if recent:
            ctx.ui.say("Drivers installed in the %d days before the install's last activity:" % RECENT_DAYS)
            for d in recent:
                ctx.ui.say(_line(d))
        else:
            ctx.ui.say("No third-party drivers found in the last %d days of the install's activity."
                       % RECENT_DAYS)


# ---------------------------------------------------------------- steps
def _need_letter(ctx):
    if ctx.target is None or ctx.target.letter is None:
        raise ValueError("the target has no drive letter; assign one first")


def remove_driver_step(ctx, inf_name):
    if not isinstance(inf_name, str) or not INF_NAME_RE.fullmatch(inf_name):
        raise ValueError("invalid driver name %r: expected oemNN.inf" % (inf_name,))
    _need_letter(ctx)
    try:
        drivers = inventory(ctx.target.windir)
    except OSError as e:
        raise ValueError("cannot read the driver inventory: %s" % (e.strerror or e))
    d = next((x for x in drivers if x["inf"].lower() == inf_name.lower()), None)
    if d is None:
        raise ValueError("%s is not an installed third-party driver of this target" % inf_name)
    risk = "Medium. Windows may fall back to an inbox driver, or the device may have none."
    if d["boot_critical"]:
        risk = ("Medium to HIGH. WARNING: this is a %s (storage or system) driver; removing it can itself make "
                "the install unbootable. Export it or note the INF name %s first." % (d["class"], d["inf"]))
    return RepairStep(
        id="remove_driver", title="DISM /Remove-Driver %s (%s, %s)" % (d["inf"], d["provider"] or "unknown provider",
                                                                   d["class"] or "unknown class"),
        effect="Removes the driver package %s from the driver store of the offline install. Windows will use an "
               "inbox driver for the device if one exists; otherwise the device has no driver." % d["inf"],
        argv=["dism", "/English", "/Image:%s" % repair._image_arg(ctx), "/Remove-Driver", "/Driver:%s" % d["inf"]],
        risk=risk,
        evidence="Installed %s, provider %s, class %s, version %s." % (
            d["installed"] or "unknown", d["provider"] or "unknown", d["class"] or "unknown",
            d["driver_version"] or "unknown"),
        target_check=lambda: repair.target_check(ctx))


def list_drivers_step(ctx):
    _need_letter(ctx)
    return RepairStep(
        id="list_drivers", title="DISM /Get-Drivers (list drivers)",
        effect="Lists the drivers of the offline install as DISM sees them. Read-only in effect.",
        argv=["dism", "/English", "/Image:%s" % repair._image_arg(ctx), "/Get-Drivers", "/Format:Table"],
        risk="Low. Classed as a repair because DISM mounts the offline registry of the target.",
        target_check=lambda: repair.target_check(ctx))


# ---------------------------------------------------------------- menu
def _execute(ctx, step):
    ui = ctx.ui
    if not ui.confirm_yes("Enable repair mode for this one step (%s)?" % step.id):
        ui.say("Not enabled.")
        return None
    ctx.runner.repairs_enabled = True
    try:
        res = ctx.runner.repair(step)
    except Refused as e:
        ui.say("Refused: %s" % e)
        return None
    finally:
        ctx.runner.repairs_enabled = False
    repair.record(ctx, step, res)
    if res is not None:
        ui.say("Test boot before the next step, then record the result.")
    return res


def run_menu(ctx):
    ui, t = ctx.ui, ctx.target
    if t is None:
        ui.say("Driver rollback is unavailable: no target Windows install was selected.")
        return
    if t.online:
        ui.say("Driver rollback is unavailable: the target is the running Windows; only offline installs are changed.")
        return
    while True:
        try:
            drivers = inventory(t.windir)
        except OSError as e:
            ui.say("Cannot read the driver folder: %s" % (e.strerror or e))
            return
        shown = drivers[:MENU_COUNT]
        ui.say("Newest third-party drivers (installed date, provider, class, version):")
        for i, d in enumerate(shown, 1):
            ui.say("%3d." % i + _line(d))
        key = ui.choose("Driver rollback", [("remove", "Remove one of these drivers"),
                                            ("dism", "Run DISM's own driver list"), ("back", "Back")],
                        default="back")
        if key == "back" or key is None:
            return
        try:
            if key == "remove":
                n = ui.ask("Number of the driver to remove (blank to cancel)").strip()
                if not n:
                    continue
                if not n.isdigit() or not 1 <= int(n) <= len(shown):
                    ui.say("Not a number from the list.")
                    continue
                _execute(ctx, remove_driver_step(ctx, shown[int(n) - 1]["inf"]))
            elif key == "dism":
                _execute(ctx, list_drivers_step(ctx))
        except ValueError as e:
            ui.say("Not possible: %s" % e)
