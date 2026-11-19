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
import shutil
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
                "/get-intl", "/get-drivers", "/english", "/logpath", "/format", "/revertpendingactions"}
_DISM_EXPORT = {"/export-image", "/sourceimagefile", "/sourceindex", "/destinationimagefile", "/compress",
                "/checkintegrity", "/english", "/logpath", "/scratchdir"}
_ROBOCOPY_BAD = {"/mov", "/move", "/purge", "/mir", "/zb", "/sec", "/secfix", "/nocopy", "/create", "/a-", "/a+", "/im", "/is", "/it"}
_SMART_OK = {"-a", "-i", "-h", "-x", "-c", "-l", "-j", "--json", "--scan", "--scan-open", "-d", "--all", "--info",
             "--health", "--xall"}


def classify(argv):
    """Return (class, reason) for a command line. Deny by default."""
    if not argv:
        return UNKNOWN, "empty command"
    exe = _base(argv[0])
    args = [str(a) for a in argv[1:]]
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
            return (READ, "") if "/image" not in fl and "/online" not in fl else (UNKNOWN, "unexpected dism arguments")
        if "/online" in fl:
            return (READ, "") if all(f.startswith("/get-") or f in ("/online", "/english", "/format") for f in fl) \
                else (FORBIDDEN, "dism /Online changes are not offered: the kit repairs offline targets only")
        if "/export-image" in fl:
            return (REPAIR, "") if set(fl) <= _DISM_EXPORT else (UNKNOWN, "unexpected dism export arguments")
        if "/image" in fl and set(fl) <= _DISM_REPAIR:
            return REPAIR, ""
        return UNKNOWN, "dism arguments not on the allowlist"

    if exe == "sfc":
        if "/offbootdir" in fl and "/offwindir" in fl and set(fl) <= {"/scannow", "/verifyonly", "/offbootdir", "/offwindir", "/offlogfile"}:
            return REPAIR, ""
        return FORBIDDEN, "sfc is only run against an offline target (/offbootdir and /offwindir)"

    if exe == "bcdedit":
        if set(fl) <= {"/enum", "/v", "/store"}:
            return READ, ""
        if set(fl) <= {"/export", "/store"}:
            return READ, ""
        if "/import" in fl or "/createstore" in fl or "/sysstore" in fl:
            return FORBIDDEN, "bcdedit store replacement is not offered"
        return REPAIR, "needs-bcd-backup"

    if exe == "bcdboot":
        if "/s" not in fl:
            return FORBIDDEN, "blind bcdboot (without /s <EFI partition>) is forbidden"
        return REPAIR, "needs-bcd-backup"

    if exe == "reg":
        if low and low[0] in ("query", "export", "save"):
            return READ, ""
        return FORBIDDEN, "reg %s is not offered; hives are read with the built-in parser" % (low[0] if low else "")

    if exe == "manage-bde":
        if fl[:1] == ["-status"]:
            return READ, ""
        if fl[:1] == ["-unlock"]:
            return HOST, ""
        return FORBIDDEN, "manage-bde is limited to -status and -unlock"

    if exe == "chkdsk":
        if not fl:
            return READ, ""  # no switches = read-only mode
        if set(fl) <= {"/f", "/scan", "/x", "/perf", "/forceofflinefix", "/spotfix", "/offlinescanandfix"}:
            return REPAIR, ""
        return FORBIDDEN, "chkdsk /r and other switches are not offered"

    if exe == "wevtutil":
        if low and low[0] in ("qe", "query-events", "el", "enum-logs", "gl", "get-log", "gli", "get-loginfo", "epl", "export-log"):
            return READ, ""
        return FORBIDDEN, "wevtutil is limited to queries and exports"

    if exe == "wmic":
        if any(w in ("call", "set", "delete", "create") for w in low):
            return FORBIDDEN, "wmic is limited to queries"
        return READ, ""

    if exe == "smartctl":
        return (READ, "") if set(fl) <= _SMART_OK else (FORBIDDEN, "smartctl is limited to reading")

    if exe == "robocopy":
        if set(fl) & _ROBOCOPY_BAD:
            return FORBIDDEN, "robocopy switches that move or delete are forbidden"
        return HOST, ""

    if exe in ("ipconfig", "ver", "systeminfo", "hostname", "whoami"):
        return (READ, "") if not (set(fl) - {"/all", "/fo", "/nh"}) else (UNKNOWN, "unexpected arguments")
    if exe == "reagentc":
        return (READ, "") if fl == ["/info"] or set(fl) == {"/info", "/target"} else (FORBIDDEN, "reagentc is limited to /info")
    if exe == "wpeutil":
        return (HOST, "") if low == ["initializenetwork"] else (FORBIDDEN, "wpeutil is limited to InitializeNetwork")
    if exe == "drvload":
        return HOST, ""
    return UNKNOWN, "%s is not on the allowlist" % exe


_DP_READ = ("list ", "select ", "detail ", "exit", "rem ")
_DP_REPAIR = ("online disk", "assign letter=", "remove letter=", "attributes disk clear readonly")


def classify_diskpart(lines):
    """Class of a diskpart script: forbidden unless every line is on the allowlist."""
    worst = READ
    for raw in lines:
        line = " ".join(raw.strip().lower().split())
        if not line:
            continue
        if line.startswith(_DP_READ) or line == "rem":
            continue
        if line.startswith(_DP_REPAIR):
            worst = REPAIR
            continue
        return FORBIDDEN, "diskpart line not allowed: %r (clean, format, delete and anything not listed are forbidden)" % raw
    return worst, ""


# Built-in read-only PowerShell snippets. Parameters arrive as environment variables RK_P_<NAME>,
# never by string interpolation. Modules cannot supply their own script text.
PS_SCRIPTS = {
    "physical-disks": "Get-PhysicalDisk | Select-Object DeviceId,FriendlyName,SerialNumber,MediaType,BusType,HealthStatus,OperationalStatus,Size | ConvertTo-Json -Depth 3",
    "reliability": "Get-PhysicalDisk | ForEach-Object { $r = $_ | Get-StorageReliabilityCounter; [pscustomobject]@{DeviceId=$_.DeviceId; Temperature=$r.Temperature; Wear=$r.Wear; ReadErrorsTotal=$r.ReadErrorsTotal; WriteErrorsTotal=$r.WriteErrorsTotal; PowerOnHours=$r.PowerOnHours} } | ConvertTo-Json -Depth 3",
    "net-adapters": "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress | ConvertTo-Json -Depth 3",
    "hardware": "[pscustomobject]@{System=(Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory); Bios=(Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate); Board=(Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product); Cpu=(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores)} | ConvertTo-Json -Depth 4",
    "version": "$PSVersionTable.PSVersion.ToString()",
}


class Runner:
    def __init__(self, case, ui, kit_root, dry_run=False):
        self.case, self.ui, self.kit_root = case, ui, kit_root
        self.dry_run = dry_run
        self.repairs_enabled = False   # set by the repair menu only
        self.target_online = False     # True when the target is the running Windows: no repairs
        self.bcd_backup = None         # path of a verified BCD export made in this run
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

    def _refuse(self, argv, kind, reason, purpose):
        res = Result(list(argv), error="refused: " + reason, seq=self._next(), kind="refused")
        self._audit(res, purpose, note=kind)
        raise Refused(reason)

    # ---------------------------------------------------------------- execution
    def resolve(self, name):
        """Full path of a tool: verified tools/ binaries first, then PATH. None if absent."""
        return self.verified_tools.get(_base(name)) or shutil.which(name)

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
        res.out = "\n".join(chunks)
        res.seconds = time.monotonic() - t0
        return res

    def run(self, argv, purpose, timeout=120, retry_rc=(), secrets=()):
        """Run a read-only command. Raises Refused for anything not classified read.

        retry_rc: exit codes treated as transient and retried once (e.g. DISM error 32).
        A missing tool is not an exception: the Result has rc None and .error set.
        """
        kind, reason = classify(argv)
        if kind != READ:
            self._refuse(argv, kind, reason or "not a read-only command; use a repair step", purpose)
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
        exe = shutil.which("powershell") or shutil.which("pwsh")
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
        argv = ["diskpart"] + ["<" + ln.strip() + ">" for ln in lines]
        if kind != READ:
            self._refuse(argv, kind, reason or "diskpart script changes state; use a repair step", purpose)
        res = self._exec(["diskpart"], timeout, stdin_text="\r\n".join(lines) + "\r\nexit\r\n")
        res.argv, res.seq, res.kind = argv, self._next(), READ
        self._audit(res, purpose)
        return res

    # ---------------------------------------------------------------- repairs
    def note_bcd_backup(self, path):
        """Record that the BCD store was exported to `path` in this run (enables BCD repair steps)."""
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            self.bcd_backup = path
            LOG.info("BCD   | backup recorded: %s", path)
            return True
        return False

    def repair(self, step):
        """Show a repair step, ask for a typed yes, run it once. Returns Result, or None if declined.

        Refuses (raises Refused, audited) when: repairs are not enabled, the command is
        forbidden or unknown, the target is the running Windows, a BCD change has no prior
        export, or the target re-check fails.
        """
        if step.diskpart is not None:
            argv = ["diskpart"] + ["<" + ln.strip() + ">" for ln in step.diskpart]
            kind, reason = classify_diskpart(step.diskpart)
        else:
            argv = list(step.argv)
            kind, reason = classify(argv)
        purpose = "repair step %s: %s" % (step.id, step.title)
        if kind in (FORBIDDEN, UNKNOWN):
            self._refuse(argv, kind, reason, purpose)
        if kind == READ:
            self._refuse(argv, kind, "this is a read-only command; run it with run()", purpose)
        if not self.repairs_enabled:
            self._refuse(argv, kind, "repairs are not enabled in this session", purpose)
        if self.target_online and step.touches_target:
            self._refuse(argv, kind, "the target is the running Windows; repair helpers only work on offline targets", purpose)
        if reason == "needs-bcd-backup" and not self.bcd_backup:
            self._refuse(argv, kind, "no BCD export was made in this run; export the BCD first", purpose)
        if step.target_check is not None:
            ok, msg = step.target_check()
            LOG.info("REPAIR| target re-check: %s %s", ok, msg)
            if not ok:
                self._refuse(argv, kind, "target re-check failed: %s" % msg, purpose)

        shown = [("<hidden>" if any(s and s in str(a) for s in step.secrets) else str(a)) for a in argv]
        ui = self.ui
        ui.header("Repair step: %s" % step.title)
        if step.evidence:
            ui.say("Why:      %s" % step.evidence)
        ui.say("Command:  %s" % (subprocess.list2cmdline(shown) if step.diskpart is None else "diskpart script:"))
        if step.diskpart is not None:
            for ln in step.diskpart:
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
        if step.diskpart is not None:
            res = self._exec(["diskpart"], step.timeout, stdin_text="\r\n".join(step.diskpart) + "\r\nexit\r\n", live=True)
            res.argv = argv
        else:
            res = self._exec(argv, step.timeout, live=True)
        res.seq, res.kind = self._next(), kind
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
                if os.path.commonpath([os.path.abspath(p), tools_dir]) != tools_dir:
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
    for enc in ("utf-8", "oem"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1")
