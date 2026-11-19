"""The command wrapper: the only place that starts external programs.

- classify() sorts every command line into read / repair / host / forbidden /
  unknown. Only allow-listed patterns run; everything else is refused.
- Runner.run() executes read-only commands. Runner.repair() executes a
  RepairStep after showing the exact command and getting a typed yes.
- Forbidden commands (spec 1.4) cannot run through any path.
- Every attempt, including refusals, goes to audit.log with exit code; full
  output goes to audit/NNNN-<tool>.txt.

No shell is ever used (shell=False), so arguments cannot smuggle a second command.
"""
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field

from .log import LOG

READ, REPAIR, HOST, FORBIDDEN, UNKNOWN = "read", "repair", "host", "forbidden", "unknown"


class Refused(Exception):
    """The wrapper would not run the command."""


@dataclass
class Result:
    argv: list
    rc: object = None          # int, or None if the program never ran / timed out
    out: str = ""
    seconds: float = 0.0
    timed_out: bool = False
    error: str = ""            # why it did not run, if it did not
    seq: int = 0
    kind: str = READ

    @property
    def ok(self):
        return self.rc == 0 and not self.error


@dataclass
class RepairStep:
    id: str
    title: str
    effect: str                      # plain words: what this changes
    argv: list = None                # the exact command, or
    diskpart: list = None            # diskpart script lines
    risk: str = ""
    timeout: int = 3600
    touches_target: bool = True
    target_check: object = None      # callable -> (ok, message); re-verifies the target right before running
    secrets: tuple = ()
    evidence: str = ""               # which finding led to this proposal


def _base(exe):
    name = os.path.basename(str(exe)).lower()
    for ext in (".exe", ".com"):
        if name.endswith(ext):
            name = name[:-len(ext)]
    return name


def _flags(args):
    """Lower-cased switch names: '/Image:W:\\' -> '/image', '-status' -> '-status'."""
    out = []
    for a in args:
        a = a.lower()
        if a.startswith("/") or a.startswith("-"):
            out.append(a.split(":", 1)[0].split("=", 1)[0])
    return out


_DISM_REPAIR = {"/cleanup-image", "/scanhealth", "/checkhealth", "/restorehealth", "/source", "/limitaccess",
                "/scratchdir", "/image", "/remove-package", "/packagename", "/get-packages", "/get-currentedition",
                "/get-intl", "/get-drivers", "/remove-driver", "/driver", "/english", "/logpath", "/format", "/revertpendingactions"}
_DISM_EXPORT = {"/export-image", "/sourceimagefile", "/sourceindex", "/destinationimagefile", "/compress", "/swmfile",
                "/checkintegrity", "/english", "/logpath", "/scratchdir"}
_ROBOCOPY_BAD = {"/mov", "/move", "/purge", "/mir", "/zb", "/sec", "/secfix", "/nocopy", "/create", "/a-", "/a+", "/im", "/is", "/it"}
_SMART_OK = {"-a", "-i", "-h", "-x", "-c", "-l", "-j", "--json", "--scan", "--scan-open", "-d", "--all", "--info",
             "--health", "--xall"}


def _switch_values(args, name):
    """Values of every '<name>:<value>' / '<name>=<value>' argument (name lower-case, with its slash)."""
    out = []
    for a in args:
        a = str(a)
        if a.lower().startswith(name) and len(a) > len(name) and a[len(name)] in ":=":
            out.append(a[len(name) + 1:])
    return out


_DISM_PKG_RE = re.compile(r"^[A-Za-z0-9_.~\-]+$")
_DISM_INF_RE = re.compile(r"^oem\d+\.inf$", re.IGNORECASE)
_WMIC_PROPS_RE = re.compile(r"^[A-Za-z0-9_,]+$")
_WMIC_ALIAS_RE = re.compile(r"^[A-Za-z0-9_]+$")
_CHKDSK_VOL_RE = re.compile(r"^[A-Za-z]:$")
_CHKDSK_SW_RE = re.compile(r"^/[A-Za-z]+$")
_SMART_L_OK = {"error", "selftest", "xerror", "xselftest", "devstat", "sataphy", "ssd", "directory", "background"}
_SMART_D_RE = re.compile(r"^[A-Za-z0-9,+]+$")
_WEVT_READ = ("qe", "query-events", "el", "enum-logs", "gl", "get-log", "gli", "get-loginfo")
_ROBO_SWITCHES = {"/e", "/copy", "/dcopy", "/r", "/w", "/xj", "/np", "/tee", "/log", "/fft", "/xd", "/xf"}
_ROBO_VALUE = {"/copy": {"DAT", "DT", "D"}, "/dcopy": {"DAT", "DA", "T", "D"}}
_ROBO_NUM = {"/r", "/w"}


def _inside(path, folder):
    """True if absolute, normalised `path` is inside `folder` (never raises)."""
    try:
        p = os.path.normcase(os.path.abspath(path))
        f = os.path.normcase(os.path.abspath(folder))
        return p != f and os.path.commonpath([p, f]) == f
    except (ValueError, TypeError):
        return False


def _robocopy(args):
    if len(args) < 2 or args[0].startswith("/") or args[1].startswith("/"):
        return FORBIDDEN, "robocopy needs a source and a destination first"
    prev = None
    for a in args[2:]:
        if not a.startswith("/"):
            if prev in ("/xd", "/xf"):
                continue
            return FORBIDDEN, "unexpected robocopy argument %r" % a
        name, _, val = a.partition(":")
        name = name.lower()
        prev = name
        if name not in _ROBO_SWITCHES:
            return FORBIDDEN, "robocopy switch %s is not on the allowlist" % name
        if name in _ROBO_VALUE and val.upper() not in _ROBO_VALUE[name]:
            return FORBIDDEN, "robocopy %s value %r is not allowed" % (name, val)
        if name in _ROBO_NUM and not val.isdigit():
            return FORBIDDEN, "robocopy %s needs a number" % name
        if name == "/log" and not val:
            return FORBIDDEN, "robocopy /LOG needs a path"
        if name in ("/e", "/xj", "/np", "/tee", "/fft") and ":" in a:
            return FORBIDDEN, "robocopy %s takes no value" % name
    return HOST, ""


def classify(argv, case_dir=None):
    """Return (class, reason) for a command line. Deny by default.

    case_dir: the case folder; `bcdedit /export <path>` is only read-only when <path> is inside it.
    """
    if not argv:
        return UNKNOWN, "empty command"
    if any(c in str(argv[0]) for c in "\\/:"):
        return FORBIDDEN, "give the tool name only, not a path: %s" % argv[0]
    exe = _base(argv[0])
    args = [str(a) for a in argv[1:]]
    if exe in ("bcdedit", "bootrec", "bcdboot"):      # '-switch' is '/switch' for these
        args = ["/" + a[1:] if a.startswith("-") and len(a) > 1 else a for a in args]
    low = [a.lower() for a in args]
    fl = _flags(args)

    # --- forbidden outright (spec 1.4)
    if exe in ("format", "fdisk", "bootsect", "cipher", "clean", "diskpart", "cmd", "powershell", "pwsh", "wscript",
               "cscript", "mshta", "rundll32", "del", "rd", "rmdir", "takeown", "icacls", "vssadmin", "wbadmin",
               "mountvol", "label", "convert", "compact", "fsutil"):
        why = {"diskpart": "diskpart only runs through run_diskpart() with checked script lines",
               "powershell": "PowerShell only runs through run_ps() with built-in read-only scripts",
               "pwsh": "PowerShell only runs through run_ps() with built-in read-only scripts",
               "format": "format is a forbidden command"}.get(exe, "%s is not allowed" % exe)
        return FORBIDDEN, why
    if exe == "bootrec":
        if "/fixmbr" in fl or "/fixboot" in fl:
            return FORBIDDEN, "bootrec /fixmbr and /fixboot are forbidden commands"
        if fl == ["/scanos"]:
            return READ, ""
        if fl == ["/rebuildbcd"]:
            return REPAIR, "needs-bcd-backup"
        return UNKNOWN, "unrecognised bootrec arguments"

    if exe == "dism":
        if "/get-wiminfo" in fl or "/get-imageinfo" in fl:
            return (READ, "") if set(fl) <= {"/get-wiminfo", "/get-imageinfo", "/wimfile", "/imagefile", "/index", "/english"} \
                else (UNKNOWN, "unexpected dism arguments")
        if "/online" in fl:
            return (READ, "") if all(f.startswith("/get-") or f in ("/online", "/english", "/format") for f in fl) \
                else (FORBIDDEN, "dism /Online changes are not offered: the kit repairs offline targets only")
        if "/export-image" in fl:
            return (REPAIR, "") if set(fl) <= _DISM_EXPORT else (UNKNOWN, "unexpected dism export arguments")
        if "/image" in fl and set(fl) <= _DISM_REPAIR:
            if "/remove-package" in fl:
                pk = _switch_values(args, "/packagename")
                if not pk or not all(_DISM_PKG_RE.fullmatch(v) for v in pk):
                    return FORBIDDEN, "dism /Remove-Package needs a plain /PackageName: value"
            if "/remove-driver" in fl:
                dv = _switch_values(args, "/driver")
                if not dv or not all(_DISM_INF_RE.fullmatch(v) for v in dv):
                    return FORBIDDEN, "dism /Remove-Driver needs a /Driver:oemNN.inf value"
            return REPAIR, ""
        return UNKNOWN, "dism arguments not on the allowlist"

    if exe == "sfc":
        if "/offbootdir" in fl and "/offwindir" in fl and set(fl) <= {"/scannow", "/verifyonly", "/offbootdir", "/offwindir", "/offlogfile"}:
            return REPAIR, ""
        return FORBIDDEN, "sfc is only run against an offline target (/offbootdir and /offwindir)"

    if exe == "bcdedit":
        if "/import" in fl or "/createstore" in fl or "/sysstore" in fl:
            return FORBIDDEN, "bcdedit store replacement is not offered"
        if "/export" in fl:
            if not set(fl) <= {"/export", "/store"}:
                return FORBIDDEN, "bcdedit /export takes no other switches"
            i = low.index("/export")
            dest = args[i + 1] if i + 1 < len(args) else ""
            if case_dir and dest and not dest.startswith("/") and _inside(dest, case_dir):
                return READ, ""
            return FORBIDDEN, "bcdedit /export is only allowed to a file inside the case folder"
        if set(fl) <= {"/enum", "/v", "/store"}:
            return READ, ""
        if "/store" not in fl:
            return FORBIDDEN, "bcdedit without /store would edit the BCD of the running environment"
        return REPAIR, "needs-bcd-backup"

    if exe == "bcdboot":
        if not set(fl) <= {"/s", "/f", "/l", "/v"}:
            return FORBIDDEN, "bcdboot switches are limited to /s /f /l /v"
        if "/s" not in fl:
            return FORBIDDEN, "blind bcdboot (without /s <EFI partition>) is forbidden"
        return REPAIR, "needs-bcd-backup"

    if exe == "reg":
        if low and low[0] == "query":
            return READ, ""
        return FORBIDDEN, "reg %s is not offered; hives are read with the built-in parser" % (low[0] if low else "")

    if exe == "manage-bde":
        if set(fl) == {"-status"}:
            return READ, ""
        if fl == ["-unlock", "-recoverypassword"]:
            return HOST, ""
        return FORBIDDEN, "manage-bde is limited to -status and -unlock -RecoveryPassword"

    if exe == "chkdsk":
        if not args or not _CHKDSK_VOL_RE.fullmatch(args[0]):
            return FORBIDDEN, "chkdsk takes a drive letter such as W: as its first argument"
        if len(args) == 1:
            return READ, ""  # no switches = read-only mode
        allowed = {"/f", "/scan", "/x", "/perf", "/forceofflinefix", "/spotfix", "/offlinescanandfix"}
        if all(_CHKDSK_SW_RE.fullmatch(a) and a.lower() in allowed for a in args[1:]):
            return REPAIR, ""
        return FORBIDDEN, "chkdsk /r and other switches are not offered"

    if exe == "wevtutil":
        if low and low[0] in _WEVT_READ:
            return READ, ""
        return FORBIDDEN, "wevtutil is limited to queries (no export, clear or set)"

    if exe == "wmic":
        if any(w in ("call", "set", "delete", "create", "terminate") for w in low):
            return FORBIDDEN, "wmic is limited to queries"
        if "get" not in low:
            return FORBIDDEN, "wmic is limited to '<alias> get <properties>'"
        i = low.index("get")
        alias, rest = args[:i], args[i + 1:]
        if not all(_WMIC_ALIAS_RE.fullmatch(a) for a in alias):
            return FORBIDDEN, "wmic alias words may only be letters, digits and _"
        if not rest or len(rest) > 2 or not _WMIC_PROPS_RE.fullmatch(rest[0]) or                 (len(rest) == 2 and rest[1].lower() != "/value"):
            return FORBIDDEN, "wmic get takes one property list and optionally /value"
        return READ, ""

    if exe == "smartctl":
        sfl = _flags([a for a in args if not a.lower().startswith("/dev/")])  # /dev/pdN is a device, not a switch
        if not set(sfl) <= _SMART_OK or any(a.startswith("-") and a not in _SMART_OK and a.lower() in _SMART_OK
                                            for a in args):
            return FORBIDDEN, "smartctl is limited to reading"
        for i, a in enumerate(args):
            nxt = args[i + 1] if i + 1 < len(args) else ""
            if a.lower() == "-l" and nxt.lower() not in _SMART_L_OK:
                return FORBIDDEN, "smartctl -l value %r is not allowed" % nxt
            if a.lower() == "-d" and not _SMART_D_RE.fullmatch(nxt):
                return FORBIDDEN, "smartctl -d value %r is not allowed" % nxt
        return READ, ""

    if exe == "robocopy":
        return _robocopy(args)

    if exe in ("ipconfig", "ver", "systeminfo", "hostname", "whoami"):
        return (READ, "") if not (set(fl) - {"/all", "/fo", "/nh"}) else (UNKNOWN, "unexpected arguments")
    if exe == "reagentc":
        return (READ, "") if fl == ["/info"] or set(fl) == {"/info", "/target"} else (FORBIDDEN, "reagentc is limited to /info")
    if exe == "wpeutil":
        return (HOST, "") if low == ["initializenetwork"] else (FORBIDDEN, "wpeutil is limited to InitializeNetwork")
    if exe == "drvload":
        if any(a.startswith("/") for a in args):
            return FORBIDDEN, "drvload switches (such as /offline) are not offered"
        return HOST, ""
    return UNKNOWN, "%s is not on the allowlist" % exe


_DP_READ = ("list ", "select ", "detail ", "exit", "rem ")
_DP_REPAIR = ("online disk", "assign letter=", "remove letter=", "attributes disk clear readonly")


def classify_diskpart(lines):
    """Class of a diskpart script: forbidden unless every line is on the allowlist."""
    worst = READ
    for raw in lines:
        if not isinstance(raw, str):
            return FORBIDDEN, "diskpart line is not text: %r" % (raw,)
        stripped = raw.strip(" \t")
        if any(ord(c) < 0x20 or ord(c) == 0x7f for c in stripped):
            return FORBIDDEN, "diskpart line contains a control character (line break or similar): %r" % raw
        line = " ".join(stripped.lower().split())
        if not line:
            continue
        if line.startswith(_DP_READ) or line == "rem":
            continue
        if line.startswith(_DP_REPAIR):
            worst = REPAIR
            continue
        return FORBIDDEN, "diskpart line not allowed: %r (clean, format, delete and anything not listed are forbidden)" % raw
    return worst, ""


def normalise_diskpart(lines):
    """The lines exactly as they are sent to diskpart: stripped, single spaces, no empty lines.
    Only call after classify_diskpart() accepted them."""
    return [n for n in (" ".join(str(ln).strip(" \t").split()) for ln in lines) if n]


def _dp_argv(lines):
    return ["diskpart"] + ["<%s>" % (" ".join(ln.split()) if isinstance(ln, str) else repr(ln)) for ln in lines]


# Built-in read-only PowerShell snippets. Parameters arrive as environment variables RK_P_<NAME>,
# never by string interpolation. Modules cannot supply their own script text.
PS_SCRIPTS = {
    "physical-disks": "Get-PhysicalDisk | Select-Object DeviceId,FriendlyName,SerialNumber,MediaType,BusType,HealthStatus,OperationalStatus,Size | ConvertTo-Json -Depth 3",
    "reliability": "Get-PhysicalDisk | ForEach-Object { $r = $_ | Get-StorageReliabilityCounter; [pscustomobject]@{DeviceId=$_.DeviceId; Temperature=$r.Temperature; Wear=$r.Wear; ReadErrorsTotal=$r.ReadErrorsTotal; WriteErrorsTotal=$r.WriteErrorsTotal; PowerOnHours=$r.PowerOnHours} } | ConvertTo-Json -Depth 3",
    "net-adapters": "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress | ConvertTo-Json -Depth 3",
    "hardware": "[pscustomobject]@{System=(Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory); Bios=(Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate); Board=(Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product); Cpu=(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores)} | ConvertTo-Json -Depth 4",
    "version": "$PSVersionTable.PSVersion.ToString()",
}


def _addresses_running_windows(argv):
    """True if a dism/sfc/bcdboot/chkdsk command line points at the running Windows install."""
    exe = _base(argv[0])
    args = [str(a) for a in argv[1:]]
    paths = []
    if exe == "dism":
        paths = _switch_values(args, "/image")
    elif exe == "sfc":
        paths = _switch_values(args, "/offbootdir") + _switch_values(args, "/offwindir")
    elif exe in ("bcdboot", "chkdsk") and args:
        paths = [args[0]]
    sysdrive = os.environ.get("SystemDrive", "").upper()
    sysroot = os.environ.get("SystemRoot", "")
    for p in paths:
        if not p:
            continue
        if sysdrive and os.path.splitdrive(os.path.abspath(p))[0].upper() == sysdrive:
            return True
        for cand in (p, os.path.join(p, "Windows")):
            try:
                if sysroot and os.path.samefile(cand, sysroot):
                    return True
            except (OSError, ValueError):
                pass
    return False


class Runner:
    def __init__(self, case, ui, kit_root, dry_run=False):
        self.case, self.ui, self.kit_root = case, ui, kit_root
        self.dry_run = dry_run
        self.repairs_enabled = False   # set by the repair menu only
        self.target_online = False     # True when the target is the running Windows: no repairs
        self.bcd_backup = None         # path of a verified BCD export made in this run
        self.bcd_backup_target = None  # id (volume GUID) of the target that export belongs to
        self.verified_tools = {}       # name -> path, filled by verify_tools()
        self._seq = 0
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- audit
    def _audit(self, res, purpose, note="", secrets=()):
        argv = [("<redacted>" if any(s and s in str(a) for s in secrets) else str(a)) for a in res.argv]
        out = res.out
        for s in secrets:
            if s:
                out = out.replace(s, "<redacted>")
        outfile = ""
        if out:
            outfile = "audit/%04d-%s.txt" % (res.seq, _base(argv[0]) if argv else "none")
            try:
                with open(self.case.path(*outfile.split("/")), "w", encoding="utf-8", errors="replace") as f:
                    f.write(out)
            except OSError as e:
                outfile = "(could not write output: %s)" % e
        entry = {"seq": res.seq, "time": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": res.kind, "purpose": purpose,
                 "command": subprocess.list2cmdline(argv), "argv": argv, "exit_code": res.rc,
                 "seconds": round(res.seconds, 2), "timed_out": res.timed_out, "error": res.error,
                 "note": note, "output_file": outfile}
        try:
            with open(self.case.path("audit.log"), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as e:
            LOG.error("AUDIT | cannot write audit.log: %s", e)
        LOG.info("CMD   | #%d %s [%s] rc=%s %.1fs %s%s", res.seq, entry["command"], res.kind, res.rc, res.seconds,
                 "TIMEOUT " if res.timed_out else "", res.error)
        if out:
            LOG.debug("OUTPUT| #%d\n%s", res.seq, out if len(out) < 20000 else out[:20000] + "\n...(truncated, full text in %s)" % outfile)

    def _next(self):
        with self._lock:
            self._seq += 1
            return self._seq

    def _refuse(self, argv, kind, reason, purpose, secrets=()):
        res = Result(list(argv), error="refused: " + reason, seq=self._next(), kind="refused")
        self._audit(res, purpose, note=kind, secrets=secrets)
        raise Refused(reason)

    # ---------------------------------------------------------------- execution
    def resolve(self, name):
        """Full path of a tool: verified tools/ binaries first, then the System32 folder of %SystemRoot% only
        (no PATH, no current directory, no PATHEXT). None if absent."""
        if any(c in str(name) for c in "\\/:"):
            return None
        base = _base(name)
        if base in self.verified_tools:
            return self.verified_tools[base]
        if not base:
            return None
        root = os.environ.get("SystemRoot") or os.environ.get("windir")
        if not root:
            return None
        s32 = os.path.join(root, "System32")
        dirs = [s32]
        if base == "powershell":
            dirs.append(os.path.join(s32, "WindowsPowerShell", "v1.0"))
        elif base == "wmic":
            dirs.append(os.path.join(s32, "wbem"))
        for d in dirs:
            for ext in (".exe", ".com"):
                p = os.path.join(d, base + ext)
                if os.path.isfile(p):
                    return p
        return None

    def _exec(self, argv, timeout, stdin_text=None, live=False, env=None):
        res = Result(list(argv))
        exe = self.resolve(argv[0])
        if not exe:
            res.error = "not available in this environment: %s" % argv[0]
            return res
        t0 = time.monotonic()
        try:
            p = subprocess.Popen([exe] + [str(a) for a in argv[1:]], stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False, env=env)
        except OSError as e:
            res.error = "could not start: %s" % e
            return res
        chunks = []

        def pump():
            for raw in iter(p.stdout.readline, b""):
                line = _decode(raw).rstrip("\r\n")
                chunks.append(line)
                if live:
                    self.ui.raw(line)
        t = threading.Thread(target=pump, daemon=True)
        t.start()
        try:
            if stdin_text is not None:
                try:
                    p.stdin.write(stdin_text.encode("mbcs", "replace"))
                    p.stdin.close()
                except OSError:
                    pass
            p.wait(timeout=timeout)
            res.rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            res.timed_out = True
            res.error = "timed out after %ds" % timeout
        t.join(5)
        p.stdout.close()
        res.out = "\n".join(chunks)
        res.seconds = time.monotonic() - t0
        return res

    def run(self, argv, purpose, timeout=120, retry_rc=(), secrets=()):
        """Run a read-only command. Raises Refused for anything not classified read.

        retry_rc: exit codes treated as transient and retried once (e.g. DISM error 32).
        A missing tool is not an exception: the Result has rc None and .error set.
        """
        kind, reason = classify(argv, case_dir=self.case.dir)
        if kind != READ:
            self._refuse(argv, kind, reason or "not a read-only command; use a repair step", purpose, secrets=secrets)
        res = self._exec(argv, timeout)
        res.seq, res.kind = self._next(), READ
        self._audit(res, purpose, secrets=secrets)
        if res.rc in retry_rc:
            LOG.info("CMD   | exit code %s treated as transient, retrying once", res.rc)
            res = self._exec(argv, timeout)
            res.seq, res.kind = self._next(), READ
            self._audit(res, purpose, note="retry after transient error", secrets=secrets)
        return res

    def run_ps(self, name, params=None, timeout=90):
        """Run one of the built-in read-only PowerShell snippets, if PowerShell exists."""
        script = PS_SCRIPTS[name]
        exe = self.resolve("powershell")
        if not exe:
            pw7 = os.path.join(os.environ.get("ProgramFiles", ""), "PowerShell", "7", "pwsh.exe")
            exe = pw7 if os.environ.get("ProgramFiles") and os.path.isfile(pw7) else None
        argv = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
        if not exe:
            res = Result(argv, error="not available in this environment: PowerShell", seq=self._next())
            self._audit(res, "built-in script %s" % name)
            return res
        env = dict(os.environ)
        for k, v in (params or {}).items():
            env["RK_P_" + k.upper()] = str(v)
        self.verified_tools.setdefault("powershell", exe)
        res = self._exec(argv, timeout, env=env)
        res.seq, res.kind = self._next(), READ
        self._audit(res, "built-in script %s" % name)
        return res

    def run_diskpart(self, lines, purpose, timeout=120):
        """Run a read-only diskpart script (list/select/detail only)."""
        kind, reason = classify_diskpart(lines)
        argv = _dp_argv(lines)
        if kind != READ:
            self._refuse(argv, kind, reason or "diskpart script changes state; use a repair step", purpose)
        res = self._exec(["diskpart"], timeout, stdin_text="\r\n".join(normalise_diskpart(lines)) + "\r\nexit\r\n")
        res.argv, res.seq, res.kind = argv, self._next(), READ
        self._audit(res, purpose)
        return res

    # ---------------------------------------------------------------- repairs
    def reset_for_scan(self):
        """Forget per-target state (the BCD export of a previous scan must not enable repairs for a new one)."""
        self.bcd_backup = None
        self.bcd_backup_target = None

    def note_bcd_backup(self, path, target_id=None):
        """Record that the BCD store was exported to `path` in this run (enables BCD repair steps)."""
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            self.bcd_backup = path
            self.bcd_backup_target = target_id
            LOG.info("BCD   | backup recorded: %s", path)
            return True
        return False

    def repair(self, step):
        """Show a repair step, ask for a typed yes, run it once. Returns Result, or None if declined.

        Refuses (raises Refused, audited) when: repairs are not enabled, the command is
        forbidden or unknown, the target is the running Windows, a BCD change has no prior
        export, or the target re-check fails.
        """
        lines = None
        if step.diskpart is not None:
            argv = _dp_argv(step.diskpart)
            kind, reason = classify_diskpart(step.diskpart)
            if kind in (READ, REPAIR):
                lines = normalise_diskpart(step.diskpart)
                argv = ["diskpart"] + ["<%s>" % ln for ln in lines]
        else:
            argv = list(step.argv)
            kind, reason = classify(argv, case_dir=self.case.dir)
        sec = step.secrets
        purpose = "repair step %s: %s" % (step.id, step.title)
        if kind in (FORBIDDEN, UNKNOWN):
            self._refuse(argv, kind, reason, purpose, sec)
        if kind == READ:
            self._refuse(argv, kind, "this is a read-only command; run it with run()", purpose, sec)
        if not self.repairs_enabled:
            self._refuse(argv, kind, "repairs are not enabled in this session", purpose, sec)
        if self.target_online and step.touches_target:
            self._refuse(argv, kind, "the target is the running Windows; repair helpers only work on offline targets", purpose, sec)
        if step.diskpart is None and _addresses_running_windows(argv):
            self._refuse(argv, kind, "this command addresses the running Windows", purpose, sec)
        if reason == "needs-bcd-backup" and not (self.bcd_backup and os.path.isfile(self.bcd_backup)):
            self._refuse(argv, kind, "no BCD export was made in this run; export the BCD first", purpose, sec)
        if step.target_check is not None:
            ok, msg = step.target_check()
            LOG.info("REPAIR| target re-check: %s %s", ok, msg)
            if not ok:
                self._refuse(argv, kind, "target re-check failed: %s" % msg, purpose, sec)

        shown = [("<hidden>" if any(s and s in str(a) for s in step.secrets) else str(a)) for a in argv]
        ui = self.ui
        ui.header("Repair step: %s" % step.title)
        if step.evidence:
            ui.say("Why:      %s" % step.evidence)
        ui.say("Command:  %s" % (subprocess.list2cmdline(shown) if step.diskpart is None else "diskpart script:"))
        if step.diskpart is not None:
            for ln in lines:
                ui.say("            %s" % ln)
        ui.say("Effect:   %s" % step.effect)
        if step.risk:
            ui.say("Risk:     %s" % step.risk)
        if reason == "needs-bcd-backup":
            ui.say("Backup:   %s" % self.bcd_backup)
        if self.dry_run:
            ui.say("DRY RUN: the command will be recorded but not executed.")
        if not ui.confirm_yes("Run this command?"):
            res = Result(argv, error="declined by operator", seq=self._next(), kind="declined")
            self._audit(res, purpose, secrets=step.secrets)
            ui.say("Not run.")
            return None
        if self.dry_run:
            res = Result(argv, error="dry run: not executed", seq=self._next(), kind="dry-run")
            self._audit(res, purpose, secrets=step.secrets)
            return res
        seq = self._next()
        self._audit(Result(argv, seq=seq, kind="started"), purpose, note="started", secrets=step.secrets)
        if step.diskpart is not None:
            res = self._exec(["diskpart"], step.timeout, stdin_text="\r\n".join(lines) + "\r\nexit\r\n", live=True)
            res.argv = argv
        else:
            res = self._exec(argv, step.timeout, live=True)
        res.seq, res.kind = seq, kind
        self._audit(res, purpose, secrets=step.secrets)
        ui.say("Exit code: %s%s" % (res.rc, "  (%s)" % res.error if res.error else ""))
        return res

    # ---------------------------------------------------------------- tools/ manifest
    def verify_tools(self):
        """Check tools/ against tools/manifest.sha256. Returns {name: 'ok'|reason}. Only verified
        binaries become runnable."""
        import hashlib
        tools_dir = os.path.join(self.kit_root, "tools")
        manifest = os.path.join(tools_dir, "manifest.sha256")
        status = {}
        if not os.path.isfile(manifest):
            return status
        with open(manifest, encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2 or line.lstrip().startswith("#"):
                    continue
                want, rel = parts[0].lower(), " ".join(parts[1:]).lstrip("*")
                p = os.path.join(tools_dir, rel.replace("/", os.sep))
                try:
                    escapes = os.path.commonpath([os.path.abspath(p), tools_dir]) != tools_dir
                except ValueError:
                    escapes = True
                if escapes:
                    status[rel] = "path escapes tools/"
                    continue
                try:
                    h = hashlib.sha256()
                    with open(p, "rb") as bf:
                        for chunk in iter(lambda: bf.read(1 << 20), b""):
                            h.update(chunk)
                except OSError as e:
                    status[rel] = "cannot read: %s" % e
                    continue
                if h.hexdigest() == want:
                    status[rel] = "ok"
                    self.verified_tools[_base(rel)] = p
                else:
                    status[rel] = "checksum mismatch, will not be used"
        LOG.info("TOOLS | %s", status)
        return status


def _decode(raw):
    if raw.count(b"\x00") > len(raw) // 4:   # UTF-16 output (sfc): keep the ASCII part
        raw = raw.replace(b"\x00", b"")
    for enc in ("utf-8", "oem"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1")
