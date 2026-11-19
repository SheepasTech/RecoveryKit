"""Startup / malware triage inventory: what the target starts automatically.

Read-only. Lists autoruns, services/drivers set to start and scheduled tasks, and marks entries a
technician should look at. It only reports: it never decides that something is malware and never
removes or changes anything. Files are only written under the case folder.
"""
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime

from ..core import regf
from ..core.log import LOG

ADMIN_HINT = " (needs administrator / WinRE)"
TASK_MAX = 1024 * 1024
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
MAX_SAY = 40

F_WRITABLE = "runs from a user-writable location"
F_LOLBIN = "script host or LOLBin launcher"
F_ENCODED = "encoded or downloaded command"
F_MISSING = "file is missing on the target"
F_WINLOGON = "non-default Winlogon value"
F_IFEO = "Image File Execution Options debugger"
F_APPINIT = "AppInit_DLLs is set"
F_BOOTEXEC = "non-default BootExecute"
F_BOOTDRV = "boot or system start driver outside System32"
F_HIDDEN = "hidden task"
F_UNPARSEABLE = "unparseable task file"
F_STARTUP = "program or script file in a Startup folder"

WRITABLE = ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\downloads\\", "\\$recycle.bin\\")
DEFENDER = "\\programdata\\microsoft\\windows defender\\"
LOLBINS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "bitsadmin.exe", "certutil.exe", "msiexec.exe")
ENCODED = ("-enc", "-encodedcommand", "frombase64string", "downloadstring", "iex ", "invoke-expression",
           "http://", "https://")
EXE_RE = re.compile(r"(.*?\.(?:exe|dll|sys|bat|cmd|ps1|vbs))(?=$|[\s\",;])", re.I)

RUN_KEYS = (("Run", r"Microsoft\Windows\CurrentVersion\Run"),
            ("RunOnce", r"Microsoft\Windows\CurrentVersion\RunOnce"),
            ("Run (WOW6432Node)", r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            ("RunOnce (WOW6432Node)", r"WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("Policies Explorer Run", r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"))
USER_RUN_KEYS = (("Run", r"Software\Microsoft\Windows\CurrentVersion\Run"),
                 ("RunOnce", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"))
STARTUP_REL = "Microsoft\\Windows\\Start Menu\\Programs\\Startup"


# ------------------------------------------------------------------ pure helpers
def _txt(v):
    if isinstance(v, (list, tuple)):
        return "; ".join(str(x) for x in v if x)
    if isinstance(v, bytes):
        return v.decode("utf-16-le", "replace").rstrip("\x00") if len(v) % 2 == 0 else v.hex()
    return "" if v is None else str(v)


def _ascii(s):
    return str(s).encode("ascii", "replace").decode("ascii")


def _exe_of(command):
    """Executable part of a command line (quoted, or up to the first .exe/.dll/... token)."""
    c = (command or "").strip()
    if c.startswith('"'):
        end = c.find('"', 1)
        return c[1:end] if end > 0 else c[1:]
    m = EXE_RE.match(c)
    if m:
        return m.group(1)
    return c.split(None, 1)[0] if c else ""


def _base(exe):
    b = exe.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    if b == "%comspec%":
        return "cmd.exe"
    return b if "." in b else b + ".exe"


def flags_for(command):
    """Pattern-match the raw command string (nothing is expanded). Returns a list of flag texts."""
    out = []
    low = (command or "").lower()
    if not low.strip():
        return out
    chk = low.replace(DEFENDER, "\\")
    if any(p in chk for p in WRITABLE):
        out.append(F_WRITABLE)
    if _base(_exe_of(command)) in LOLBINS:
        out.append(F_LOLBIN)
    if any(p in low for p in ENCODED):
        out.append(F_ENCODED)
    return out


def exists_on_target(root, windir, command):
    """True/False if the executable of `command` resolves to a path on the target; None if it cannot be resolved."""
    p = _exe_of(command).strip()
    if not p:
        return None
    if p.startswith("\\??\\"):
        p = p[4:]
    low = p.lower()
    rootp = root.rstrip("\\")
    win = windir.rstrip("\\")
    for pre, base in (("%systemroot%\\", win), ("%windir%\\", win), ("\\systemroot\\", win),
                      ("%programfiles%\\", rootp + "\\Program Files"),
                      ("%programdata%\\", rootp + "\\ProgramData")):
        if low.startswith(pre):
            p = base + "\\" + p[len(pre):]
            break
    else:
        if re.match(r"^[A-Za-z]:\\", p):
            p = rootp + "\\" + p[3:]
        elif low.startswith(("system32\\", "syswow64\\")):
            p = win + "\\" + p
        else:
            return None
    if "%" in p:
        return None
    try:
        return os.path.exists(p)
    except (OSError, ValueError):
        return None


def _flags(root, windir, command, extra=()):
    fl = list(extra) + flags_for(command)
    if exists_on_target(root, windir, command) is False:
        fl.append(F_MISSING)
    seen = []
    for f in fl:
        if f not in seen:
            seen.append(f)
    return seen


# ------------------------------------------------------------------ collect
def collect(ctx):
    res = {}
    sections = (("autoruns", "Programs started automatically", _autoruns),
                ("services", "Services and drivers set to start", _services),
                ("tasks", "Scheduled tasks", _tasks))
    for name, title, fn in sections:
        with ctx.case.section(name, title) as sec:
            if ctx.target is None:
                sec.set("skipped", "no target")
            else:
                ctx.ui.say("Collecting: %s" % title)
                res[name] = fn(ctx, sec)
    _summary(ctx, res)
    return None


# ------------------------------------------------------------------ 1. autoruns
def _entry(source, name, command, root, windir, extra=()):
    command = _txt(command)
    return {"source": source, "name": name, "command": command, "flags": _flags(root, windir, command, extra)}


def _list_users(root):
    """(names of folders under Users, error text or None)."""
    try:
        with os.scandir(os.path.join(root, "Users")) as it:
            names = [d.name for d in it if d.is_dir() and d.name.lower() not in ("all users", "default user")]
        return sorted(names), None
    except FileNotFoundError:
        return [], "no Users folder"
    except OSError as e:
        return [], "%s: %s%s" % (type(e).__name__, e.strerror or e, ADMIN_HINT)


def _autoruns(ctx, sec):
    t = ctx.target
    reg, root, windir = t.reg, t.root, t.windir
    cs = reg.control_set()
    ents = []

    def add(*a, **k):
        ents.append(_entry(*a, root=root, windir=windir, **k))

    for label, path in RUN_KEYS:
        vals = reg.values("SOFTWARE", path)
        for n, v in vals.items():
            add("HKLM " + label, n, v)
        sec.item("HKLM " + label, "ok", "%d value(s)" % len(vals))

    wl = r"Microsoft\Windows NT\CurrentVersion\Winlogon"
    shell = _txt(reg.get("SOFTWARE", wl, "Shell"))
    if shell:
        bad = shell.strip().lower() != "explorer.exe"
        add("Winlogon", "Shell", shell, extra=(F_WINLOGON,) if bad else ())
    ui_ = _txt(reg.get("SOFTWARE", wl, "Userinit"))
    if ui_:
        v = ui_.strip().lower().rstrip(",")
        bad = "," in v or not v.endswith("\\userinit.exe")
        add("Winlogon", "Userinit", ui_, extra=(F_WINLOGON,) if bad else ())
    appinit = _txt(reg.get("SOFTWARE", r"Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"))
    if appinit.strip():
        add("Windows", "AppInit_DLLs", appinit, extra=(F_APPINIT,))

    ifeo = r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for exe in reg.subkeys("SOFTWARE", ifeo):
        dbg = _txt(reg.get("SOFTWARE", ifeo + "\\" + exe, "Debugger"))
        if dbg:
            add("IFEO", exe, dbg, extra=(F_IFEO,))

    boot = reg.get("SYSTEM", cs + r"\Control\Session Manager", "BootExecute")
    for s in (boot if isinstance(boot, (list, tuple)) else [boot]):
        s = _txt(s)
        if s.strip():
            bad = s.strip().lower() != "autocheck autochk *"
            add("Session Manager", "BootExecute", s, extra=(F_BOOTEXEC,) if bad else ())
    for hname in ("SOFTWARE", "SYSTEM"):
        why = getattr(reg, "errors", {}).get(hname)
        if why:
            sec.item("hive " + hname, "error", why + ADMIN_HINT)

    users, uerr = _list_users(root)
    if uerr:
        sec.item("users", "missing" if uerr.startswith("no ") else "error", uerr)
    for u in users:
        _user_hive(sec, root, windir, u, ents)
        _startup(sec, root, windir, "user %s Startup" % u,
                 os.path.join(root, "Users", u, "AppData", "Roaming", STARTUP_REL), ents)
    _startup(sec, root, windir, "common Startup", os.path.join(root, "ProgramData", STARTUP_REL), ents)

    ctx.case.write_json("inventory/autoruns.json", ents)
    flagged = [e for e in ents if e["flags"]]
    sec.data = {"count": len(ents), "flagged": flagged}
    return ents


def _user_hive(sec, root, windir, user, ents):
    path = os.path.join(root, "Users", user, "NTUSER.DAT")
    if not os.path.exists(path):
        return
    try:
        h = regf.Hive(path)
    except (OSError, regf.HiveError) as e:
        why = "%s: %s" % (type(e).__name__, e.strerror if isinstance(e, OSError) and e.strerror else e)
        if isinstance(e, PermissionError):
            why += "; expected on a running Windows (the hive of a logged-in user is locked) or run as administrator / WinRE"
        sec.item("user " + user, "error", why)
        return
    n = 0
    try:
        for label, kpath in USER_RUN_KEYS:
            key = h.open(kpath)
            for name, val in (key.values() if key else {}).items():
                ents.append(_entry("user %s %s" % (user, label), name, val, root, windir))
                n += 1
        sec.item("user " + user, "ok", "%d value(s)" % n)
    except (OSError, regf.HiveError) as e:
        sec.item("user " + user, "error", "%s: %s" % (type(e).__name__, e))
    finally:
        h.close()


def _startup(sec, root, windir, label, folder, ents):
    try:
        with os.scandir(folder) as it:
            files = sorted(d.name for d in it if d.is_file() and d.name.lower() != "desktop.ini")
    except (FileNotFoundError, NotADirectoryError):
        return
    except OSError as e:
        sec.item(label, "error", "%s: %s%s" % (type(e).__name__, e.strerror or e, ADMIN_HINT))
        return
    for f in files:
        ext = os.path.splitext(f)[1].lower()
        fl = [F_STARTUP] if ext in (".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".ps1", ".hta", ".scr", ".com") else []
        ents.append({"source": label, "name": f, "command": os.path.join(folder, f), "flags": fl})
    sec.item(label, "ok", "%d file(s)" % len(files))


# ------------------------------------------------------------------ 2. services
def _boot_outside_system32(image):
    p = image.strip().replace("/", "\\")
    low = p.lower()
    for pre in ("\\??\\", "\\systemroot\\", "%systemroot%\\"):
        if low.startswith(pre):
            p, low = p[len(pre):], low[len(pre):]
    m = re.match(r"^[a-z]:\\windows\\", low)
    if m:
        low = low[m.end():]
    return not low.startswith("system32\\")


def _services(ctx, sec):
    t = ctx.target
    reg, root, windir = t.reg, t.root, t.windir
    base = reg.control_set() + r"\Services"
    out = []
    for name in sorted(reg.subkeys("SYSTEM", base)):
        v = reg.values("SYSTEM", base + "\\" + name)
        start = v.get("Start")
        if not isinstance(start, int) or start not in (0, 1, 2):
            continue
        image = _txt(v.get("ImagePath"))
        extra = (F_BOOTDRV,) if start in (0, 1) and image and _boot_outside_system32(image) else ()
        out.append({"name": name, "start": start, "type": v.get("Type"), "image_path": image,
                    "display_name": _txt(v.get("DisplayName")), "object_name": _txt(v.get("ObjectName")),
                    "flags": _flags(root, windir, image, extra)})
    why = getattr(reg, "errors", {}).get("SYSTEM")
    if why:
        sec.item("hive SYSTEM", "error", why + ADMIN_HINT)
    ctx.case.write_json("inventory/services.json", out)
    sec.data = {"count": len(out), "flagged": [e for e in out if e["flags"]]}
    return out


# ------------------------------------------------------------------ 3. tasks
def _read_task(full, rel, windir_root):
    root, windir = windir_root
    st = os.stat(full)
    ent = {"path": rel, "author": "", "enabled": True, "hidden": False, "actions": [], "run_as": "",
           "triggers": [], "modified": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"), "flags": []}
    try:
        if st.st_size > TASK_MAX:
            raise ValueError("file is larger than 1 MB")
        with open(full, "rb") as f:
            raw = f.read(TASK_MAX)
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = raw.decode("utf-16")
        else:
            text = raw.decode("utf-8-sig", "replace")
        text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
        tree = ET.fromstring(text)
    except OSError:
        raise
    except (ValueError, ET.ParseError, UnicodeError) as e:
        ent["error"] = "%s: %s" % (type(e).__name__, e)
        ent["flags"] = [F_UNPARSEABLE]
        return ent
    for el in tree.iter():
        if isinstance(el.tag, str) and el.tag.startswith("{" + TASK_NS + "}"):
            el.tag = el.tag.split("}", 1)[1]

    def tx(path):
        e = tree.find(path)
        return (e.text or "").strip() if e is not None else ""

    ent["author"] = tx("RegistrationInfo/Author")
    ent["enabled"] = tx("Settings/Enabled").lower() != "false"
    ent["hidden"] = tx("Settings/Hidden").lower() == "true"
    ent["run_as"] = tx("Principals/Principal/UserId") or tx("Principals/Principal/GroupId")
    trg = tree.find("Triggers")
    ent["triggers"] = [c.tag for c in trg] if trg is not None else []
    fl = []
    for ex in tree.findall("Actions/Exec"):
        cmd = ((ex.findtext("Command") or "").strip() + " " + (ex.findtext("Arguments") or "").strip()).strip()
        ent["actions"].append(cmd)
        fl += _flags(root, windir, cmd)
    if ent["hidden"] and not rel.startswith("Microsoft/"):
        fl.append(F_HIDDEN)
    ent["flags"] = [f for i, f in enumerate(fl) if f not in fl[:i]]
    return ent


def _tasks(ctx, sec):
    t = ctx.target
    top = os.path.join(t.windir, "System32", "Tasks")
    out = []

    def walk(folder, rel):
        try:
            with os.scandir(folder) as it:
                items = sorted(it, key=lambda d: d.name.lower())
        except OSError:
            if not rel:
                raise
            return sec.item("tasks/" + rel, "error", "folder could not be read" + ADMIN_HINT)
        for d in items:
            r = rel + "/" + d.name if rel else d.name
            try:
                if d.is_dir():
                    walk(d.path, r)
                else:
                    out.append(_read_task(d.path, r, (t.root, t.windir)))
            except OSError as e:
                sec.item("tasks/" + r, "error", "%s: %s" % (type(e).__name__, e.strerror or e))

    try:
        walk(top, "")
    except FileNotFoundError:
        sec.set("missing", "no Windows\\System32\\Tasks folder on the target: %s" % top)
        return out
    except PermissionError as e:
        sec.set("error", "%s: %s%s" % (type(e).__name__, e.strerror or e, ADMIN_HINT))
        return out
    except OSError as e:
        sec.set("error", "%s: %s" % (type(e).__name__, e.strerror or e))
        return out
    for e in out:
        # Windows' own tasks legitimately use rundll32, cmd and msiexec: that alone is not a finding there.
        if e["path"].startswith("Microsoft/"):
            e["flags"] = [f for f in e["flags"] if f != F_LOLBIN]
    ctx.case.write_json("inventory/tasks.json", out)
    sec.data = {"count": len(out), "non_microsoft": sum(1 for e in out if not e["path"].startswith("Microsoft/")),
                "flagged": [e for e in out if e["flags"]]}
    return out


# ------------------------------------------------------------------ summary
def _summary(ctx, res):
    say = ctx.ui.say
    lines = []
    say("Startup triage (entries below are items to look at, not verdicts):")
    for name, label, key in (("autoruns", "Autoruns", "source"), ("services", "Services/drivers", None),
                             ("tasks", "Scheduled tasks", "path")):
        ents = res.get(name)
        if ents is None:
            say("  %s: not collected" % label)
            continue
        flagged = [e for e in ents if e["flags"]]
        say("  %s: %d listed, %d to look at" % (label, len(ents), len(flagged)))
        for e in flagged:
            if name == "autoruns":
                who, cmd = "%s/%s" % (e["source"], e["name"]), e["command"]
            elif name == "services":
                who, cmd = "service/" + e["name"], e["image_path"]
            else:
                who, cmd = "task/" + e["path"], "; ".join(e["actions"]) or e.get("error", "")
            lines.append("  ! %s: %s  [%s]" % (who, cmd, ", ".join(e["flags"])))
    for ln in lines[:MAX_SAY]:
        say(_ascii(ln))
    if len(lines) > MAX_SAY:
        say("  ... %d more in inventory/*.json" % (len(lines) - MAX_SAY))
    LOG.info("TRIAGE| %d flagged line(s)", len(lines))
