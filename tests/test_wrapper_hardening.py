"""Command-wrapper hardening (security review 2026-11-19: C1-C6, C13, C15, S1).

Nothing here runs a repair command: everything goes through classify(), classify_diskpart()
and Runner(..., dry_run=True), or a Runner whose _exec is replaced.
"""
import hashlib
import json
import os
import random
import tempfile
import types
import unittest

from recoverykit.core.case import Case
from recoverykit.core.runner import (FORBIDDEN, HOST, READ, REPAIR, UNKNOWN, Refused, RepairStep, Result, Runner,
                                     classify, classify_diskpart, normalise_diskpart,
                                     read_manifest_lines, _redact)
from recoverykit.modules import repair
from tests.test_core import ROOT, ScriptedUI

NOT_RUNNABLE = (FORBIDDEN, UNKNOWN)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.case = Case(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.case.close)

    def audit(self):
        with open(self.case.path("audit.log"), encoding="utf-8") as f:
            return [json.loads(x) for x in f]


class DiskpartInjection(unittest.TestCase):        # C2
    def test_control_characters_and_non_text_are_forbidden(self):
        for bad in (["select disk 0\nclean"], ["list disk\r\nclean all"], ["rem x\nformat fs=ntfs quick"],
                    ["exit\nclean"], ["select disk 0\x0bclean"], ["select disk 0\x00"], ["list disk\x7f"],
                    ["list disk", None], [5], [b"list disk"]):
            self.assertEqual(classify_diskpart(bad)[0], FORBIDDEN, bad)

    def test_edge_whitespace_is_fine_and_normalised(self):
        lines = ["\tselect   disk 0 ", "  online  disk"]
        self.assertEqual(classify_diskpart(lines)[0], REPAIR)
        self.assertEqual(normalise_diskpart(lines), ["select disk 0", "online disk"])


class Classification(unittest.TestCase):
    def forbidden(self, *argvs, **kw):
        for argv in argvs:
            self.assertIn(classify(argv, **kw)[0], NOT_RUNNABLE, argv)

    def test_c3_review_table(self):
        self.forbidden(
            ["reg", "save", "HKLM\\SYSTEM", "W:\\Windows\\System32\\config\\SYSTEM", "/y"],
            ["reg", "export", "HKLM\\Software", "W:\\boot.ini", "/y"],
            ["wevtutil", "epl", "System", "W:\\Windows\\win.ini", "/ow:true"],
            ["wevtutil", "export-log", "System", "x"],
            ["wmic", "os", "get", "/format:\\\\evil\\share\\x.xsl"],
            ["wmic", "/output:W:\\x.txt", "os", "get"],
            ["wmic", "process", "where", "name='x'", "terminate"],
            ["wmic", "os", "get", "Status", "/format:x"],
            ["wmic", "os"],
            ["dism", "/Get-WimInfo", "/WimFile:x", "/LogPath:W:\\Windows\\x.log"],
            ["dism", "/Get-ImageInfo", "/ImageFile:x", "/Apply-Image", "/ApplyDir:W:\\", "/Index:1"],
            ["bcdedit", "/export", "W:\\Windows\\System32\\config\\SAM"],
            ["smartctl", "-l", "scterc,70,70", "/dev/pd0"],
            ["smartctl", "-lscterc,70,70", "/dev/pd0"],
            ["smartctl", "-l", "error,70", "/dev/pd0"],
            ["smartctl", "-l"],
            ["smartctl", "-d", "sat;x", "/dev/pd0"],
            ["smartctl", "-A", "/dev/pd0"],
            ["manage-bde", "-status", "C:", "-off"],
            ["manage-bde", "-unlock", "W:", "-RecoveryPassword", "1", "-off"],
            ["manage-bde", "-RecoveryPassword", "1", "-unlock", "W:"],
            ["manage-bde"],
        )
        self.forbidden(["bcdedit", "/export", "W:\\x"], case_dir=tempfile.gettempdir())

    def test_c4_review_table(self):
        self.forbidden(
            ["bcdedit", "-import", "x"], ["bcdedit", "-createstore", "x"], ["bcdedit", "-sysstore"],
            ["bootrec", "-fixmbr"], ["bootrec", "-FixBoot"],
            ["bcdboot", "W:\\Windows", "/s", "C:", "/bcdclean", "full"],
            ["bcdboot", "W:\\Windows", "-s", "S:", "-bcdclean"],
            ["bcdboot", "W:\\Windows", "/f", "UEFI"],
            ["bcdedit", "/set", "{default}", "x", "y"],
            ["bcdedit", "/deletevalue", "{default}", "x"],
            ["robocopy", "A", "W:\\", "/E", "/JOB:evil"], ["robocopy", "A", "W:\\", "/E", "/M"],
            ["robocopy", "A", "W:\\", "/E", "/LOG+:W:\\x"], ["robocopy", "A", "W:\\", "/E", "/COPY:DATS"],
            ["robocopy", "A", "W:\\", "/E", "/DCOPY:X"], ["robocopy", "A", "/E"], ["robocopy", "A", "B", "C", "/E"],
            ["robocopy", "A", "B", "/R:x"],
            ["drvload", "x.inf", "/offline=W:\\"], ["drvload", "x.inf", "/Foo"],
            ["dism", "/Image:W:\\", "/Remove-Package", "/PackageName:*"],
            ["dism", "/Image:W:\\", "/Remove-Package"],
            ["dism", "/Image:W:\\", "/Remove-Package", "/PackageName:a b;c"],
            ["dism", "/Image:W:\\", "/Remove-Driver", "/Driver:..\\x.inf"],
            ["dism", "/Image:W:\\", "/Remove-Driver", "/Driver:oem1.inf.exe"],
            ["dism", "/Image:W:\\", "/Remove-Driver"],
        )

    def test_c5_executable_identity(self):
        self.forbidden(["C:\\evil\\ipconfig.exe", "/all"], ["./ipconfig", "/all"], ["C:ipconfig", "/all"],
                       ["..\\reg", "query", "x"], ["format.com", "W:"], ["FORMAT.COM", "W:"], ["format.bat", "W:"],
                       ["dism.exe.", "/Image:W:\\", "/Cleanup-Image", "/ScanHealth"], ["reg.cmd", "query", "x"])
        self.assertEqual(classify(["ipconfig.EXE", "/all"])[0], READ)

    def test_s1_chkdsk(self):
        self.forbidden(["chkdsk", "W:/F"], ["chkdsk", "W:/r"], ["chkdsk", "/f"], ["chkdsk"], ["chkdsk", "W:", "X"],
                       ["chkdsk", "W:\\", "/f"], ["chkdsk", "W:", "/f/r"], ["chkdsk", "W:", "/f:x"],
                       ["chkdsk", "W:", "/r"])
        self.assertEqual(classify(["chkdsk", "W:"])[0], READ)
        self.assertEqual(classify(["chkdsk", "W:", "/f", "/x"])[0], REPAIR)

    def test_bcdedit_export_needs_case_dir(self):
        with tempfile.TemporaryDirectory() as d:
            inside = os.path.join(d, "exports", "bcd.bak")
            self.assertEqual(classify(["bcdedit", "/export", inside], case_dir=d)[0], READ)
            self.assertEqual(classify(["bcdedit", "/export", inside])[0], FORBIDDEN)
            self.assertEqual(classify(["bcdedit", "/export", os.path.join(d, "..", "x.bak")], case_dir=d)[0], FORBIDDEN)
            self.assertEqual(classify(["bcdedit", "/export", d + "2\\x"], case_dir=d)[0], FORBIDDEN)
            self.assertEqual(classify(["bcdedit", "/export"], case_dir=d)[0], FORBIDDEN)

    def test_legitimate_argv_still_classify(self):
        cdir = tempfile.gettempdir()
        log = os.path.join(cdir, "logs", "robocopy-1.log")
        table = [
            (["bcdedit", "/store", os.path.join(cdir, "w.work"), "/enum", "all", "/v"], READ),
            (["bcdedit", "/enum", "all", "/v"], READ),
            (["bcdedit", "/export", os.path.join(cdir, "exports", "bcd-live.bak")], READ),
            (["manage-bde", "-status"], READ),
            (["ipconfig", "/all"], READ),
            (["wevtutil", "qe", os.path.join(cdir, "x.evtx"), "/lf:true", "/q:*[System[(Level=1 or Level=2)]]",
              "/c:200", "/rd:true", "/f:text"], READ),
            (["wevtutil", "qe", "Microsoft-Windows-X/Operational", "/q:*", "/c:5", "/rd:true", "/f:text"], READ),
            (["smartctl", "--scan"], READ),
            (["smartctl", "-a", "-j", "/dev/pd0"], READ),
            (["smartctl", "-l", "error", "-d", "sat,12", "/dev/pd0"], READ),
            (["wmic", "diskdrive", "get", "Model,SerialNumber,Status,Size"], READ),
            (["wmic", "os", "get", "Caption", "/value"], READ),
            (["chkdsk", "W:"], READ),
            (["dism", "/English", "/Image:W:\\", "/Cleanup-Image", "/ScanHealth", "/ScratchDir:" + cdir], REPAIR),
            (["dism", "/English", "/Image:W:\\", "/Cleanup-Image", "/RestoreHealth", "/Source:wim:D:\\i.wim:1",
              "/LimitAccess"], REPAIR),
            (["dism", "/English", "/Image:W:\\", "/Get-Packages", "/Format:Table"], REPAIR),
            (["dism", "/English", "/Image:W:\\", "/Get-Drivers", "/Format:Table"], REPAIR),
            (["dism", "/English", "/Image:W:\\", "/Remove-Package", "/PackageName:Package_for_KB5000~31bf~amd64~~1.0"],
             REPAIR),
            (["dism", "/English", "/Image:W:\\", "/Remove-Driver", "/Driver:oem12.inf"], REPAIR),
            (["dism", "/English", "/Export-Image", "/SourceImageFile:a.swm", "/SWMFile:a*.swm", "/SourceIndex:1",
              "/DestinationImageFile:b.wim", "/Compress:max", "/CheckIntegrity"], REPAIR),
            (["dism", "/Get-WimInfo", "/WimFile:x.wim"], READ),
            (["sfc", "/scannow", "/offbootdir=W:\\", "/offwindir=W:\\Windows"], REPAIR),
            (["manage-bde", "-unlock", "W:", "-RecoveryPassword", "111111-222222"], HOST),
            (["robocopy", "W:\\Users", "E:\\b\\Users", "/E", "/COPY:DAT", "/DCOPY:DAT", "/R:1", "/W:1", "/XJ", "/NP",
              "/TEE", "/LOG:" + log], HOST),
            (["bcdboot", "W:\\Windows", "/s", "S:", "/f", "UEFI"], REPAIR),
            (["drvload", "x.inf"], HOST),
            (["wpeutil", "InitializeNetwork"], HOST),
        ]
        for argv, want in table:
            self.assertEqual(classify(argv, case_dir=cdir)[0], want, argv)
        self.assertEqual(classify(["bcdboot", "W:\\Windows", "/s", "S:"])[1], "needs-bcd-backup")
        self.assertEqual(classify(["bcdedit", "/store", "x", "/set", "{default}", "a", "b"]),
                         (REPAIR, "needs-bcd-backup"))


class Resolver(Tmp):
    def test_resolve_ignores_cwd_and_path(self):
        r = Runner(self.case, ScriptedUI([]), ROOT)
        old = os.getcwd()
        try:
            os.chdir(self.tmp.name)
            for n in ("reg.cmd", "zzfake.exe"):
                with open(os.path.join(self.tmp.name, n), "w") as f:
                    f.write("x")
            self.assertIsNone(r.resolve("zzfake"))
            self.assertIsNone(r.resolve("reg.cmd"))
            self.assertIsNone(r.resolve("C:\\Windows\\System32\\ipconfig.exe"))
            self.assertIsNone(r.resolve(os.path.join(self.tmp.name, "zzfake.exe")))
            exe = r.resolve("ipconfig")
        finally:
            os.chdir(old)
        self.assertTrue(exe and os.path.normcase(exe).startswith(os.path.normcase(
            os.path.join(os.environ["SystemRoot"], "System32"))))

    def test_verified_tools_win(self):
        r = Runner(self.case, ScriptedUI([]), ROOT)
        r.verified_tools["smartctl"] = "X:\\tools\\smartctl.exe"
        self.assertEqual(r.resolve("smartctl"), "X:\\tools\\smartctl.exe")

    def test_verify_tools_other_drive_does_not_crash(self):
        kit = tempfile.mkdtemp()
        os.makedirs(os.path.join(kit, "tools"))
        with open(os.path.join(kit, "tools", "manifest.sha256"), "w") as f:
            f.write("%s  Z:\\other\\evil.exe\n" % ("0" * 64))
        st = Runner(self.case, ScriptedUI([]), kit).verify_tools()
        self.assertEqual(list(st.values()), ["path escapes tools/"])


class RepairGates(Tmp):
    def step(self, **kw):
        d = dict(id="scanhealth", title="Scan", effect="reads",
                 argv=["dism", "/English", "/Image:W:\\", "/Cleanup-Image", "/ScanHealth"])
        d.update(kw)
        return RepairStep(**d)

    def runner(self, answers=("yes",) * 5, dry=True):
        r = Runner(self.case, ScriptedUI(list(answers)), ROOT, dry_run=dry)
        r.repairs_enabled, r.target_online = True, False
        return r

    def test_running_windows_guard(self):                    # C4
        r = self.runner()
        sysdrive = os.environ.get("SystemDrive", "C:")
        sysroot = os.environ["SystemRoot"]
        for argv in (["dism", "/English", "/Image:%s\\" % sysdrive, "/Cleanup-Image", "/ScanHealth"],
                     ["dism", "/English", "/Image:%s" % sysdrive, "/Cleanup-Image", "/ScanHealth"],
                     ["sfc", "/scannow", "/offbootdir=%s\\" % sysdrive, "/offwindir=%s" % sysroot],
                     ["bcdboot", sysroot, "/s", "S:", "/f", "UEFI"],
                     ["chkdsk", sysdrive, "/f"]):
            r.bcd_backup = os.path.join(self.tmp.name, "b.bak")
            with open(r.bcd_backup, "wb") as f:
                f.write(b"x")
            with self.assertRaises(Refused) as cm:
                r.repair(self.step(argv=argv, touches_target=False))
            self.assertIn("running Windows", str(cm.exception), argv)
        self.assertTrue(all(a["kind"] == "refused" for a in self.audit()))

    def test_offline_target_still_allowed(self):
        res = self.runner().repair(self.step())
        self.assertEqual(res.kind, "dry-run")

    def test_refuse_redacts_secrets(self):                   # C13
        key = "111111-222222-333333-444444-555555-666666-777777-888888"
        r = self.runner()
        r.repairs_enabled = False
        with self.assertRaises(Refused):
            r.repair(self.step(id="unlock", argv=["manage-bde", "-unlock", "W:", "-RecoveryPassword", key],
                               secrets=(key,)))
        with open(self.case.path("audit.log"), encoding="utf-8") as f:
            self.assertNotIn(key, f.read())
        r.repairs_enabled = True
        with self.assertRaises(Refused):                      # forbidden form: bad key position
            r.repair(self.step(argv=["manage-bde", "-unlock", "-off", key], secrets=(key,)))
        with open(self.case.path("audit.log"), encoding="utf-8") as f:
            self.assertNotIn(key, f.read())

    def test_diskpart_sends_normalised_lines(self):          # C2
        sent = {}
        r = self.runner(dry=False)
        r._exec = lambda argv, timeout, stdin_text=None, **kw: sent.update(stdin=stdin_text) or Result(list(argv), rc=0)
        r.repair(self.step(argv=None, diskpart=["  select   disk 1 ", "\tonline  disk"], touches_target=False))
        self.assertEqual(sent["stdin"], "select disk 1\r\nonline disk\r\nexit\r\n")
        with self.assertRaises(Refused):
            r.repair(self.step(argv=None, diskpart=["select disk 1\nclean"]))
        with self.assertRaises(Refused):
            r.run_diskpart(["list disk\r\nclean all"], "must not run")
        sent.clear()
        r.run_diskpart(["  list   disk "], "t")
        self.assertEqual(sent["stdin"], "list disk\r\nexit\r\n")

    def test_started_line_before_execution(self):            # C15
        r = self.runner(dry=False)
        seen = []
        r._exec = lambda argv, timeout, **kw: seen.append(self.audit()) or Result(list(argv), rc=0, out="ok")
        res = r.repair(self.step())
        self.assertEqual([a["kind"] for a in seen[0]], ["started"])     # written before the command ran
        a = self.audit()
        self.assertEqual([x["kind"] for x in a], ["started", "repair"])
        self.assertEqual(a[0]["seq"], a[1]["seq"])
        self.assertEqual((a[0]["exit_code"], a[0]["note"]), (None, "started"))
        self.assertEqual(res.seq, a[1]["seq"])

    def test_dry_run_and_decline_write_no_started_line(self):
        r = self.runner(("yes", "no"))
        r.repair(self.step())
        r.repair(self.step())
        self.assertEqual([x["kind"] for x in self.audit()], ["dry-run", "declined"])

    def test_bcd_backup_must_still_exist_and_reset(self):    # C6
        r = self.runner()
        step = self.step(argv=["bcdedit", "/store", "x", "/set", "{default}", "a", "b"])
        p = os.path.join(self.tmp.name, "b.bak")
        with open(p, "wb") as f:
            f.write(b"regf")
        self.assertTrue(r.note_bcd_backup(p, "GUID-1"))
        self.assertEqual((r.bcd_backup, r.bcd_backup_target), (p, "GUID-1"))
        os.remove(p)
        with self.assertRaises(Refused):
            r.repair(step)
        with open(p, "wb") as f:
            f.write(b"regf")
        r.note_bcd_backup(p)
        self.assertEqual(r.repair(step).kind, "dry-run")
        r.reset_for_scan()
        self.assertIsNone(r.bcd_backup)
        with self.assertRaises(Refused):
            r.repair(step)


class RecordRedaction(Tmp):                                  # C1
    KEY = "111111-222222-333333-444444-555555-666666-777777-888888"

    def test_key_never_stored(self):
        ctx = types.SimpleNamespace(
            case=self.case, target=types.SimpleNamespace(letter="W"), inventory={},
            ui=ScriptedUI([]), runner=None)
        step = repair.unlock_step(ctx, "w", self.KEY)
        self.assertEqual(step.secrets, (self.KEY,))
        dry = Result(list(step.argv), error="dry run: not executed", kind="dry-run")
        normal = Result(list(step.argv), rc=0, out="unlocked", kind="host")
        for res in (None, dry, normal):
            e = repair.record(ctx, step, res)
            self.assertNotIn(self.KEY, json.dumps(e))
            self.assertIn("<redacted>", e["command"])
        self.assertNotIn(self.KEY, json.dumps(self.case.data))
        self.case.close()
        with open(self.case.path("case.json"), encoding="utf-8") as f:
            self.assertNotIn(self.KEY, f.read())


class SecondReview(Tmp):
    """Second review 2026-11-19: A1, A6, A8, A9, A12, look-alike switches, A10 (runner part)."""

    def bad(self, *argvs, **kw):
        for argv in argvs:
            self.assertIn(classify(argv, **kw)[0], NOT_RUNNABLE, argv)

    def test_a6_malformed_and_lookalikes(self):
        self.bad([], ["bcdedit", "/export:foo", "bar"], ["ipconfig", "/all\x00"], ["ipconfig", "/all\n"],
                 ["ipconfig", "\x7f"], ["ipconfig", 'a"b'], ["ipconfig", None], ["ipconfig", b"/all"],
                 ["bcdedit", "\uFF0Fimport", "x"], ["bcdedit", "/store", "x", "/enum", "\uFF0Fimport", "y"],
                 ["ipconfig", "\uFF0Frelease"], ["manage-bde", "-status", "\u2013off"],
                 ["manage-bde", "-status", "\u2212off"], ["ipconfig", "/\u0430ll"], ["ipconfig", " /all"],
                 ["CH\u212aDS\u212a", "W:"], ["ipconfig", "\u2215all"], ["ipconfig", "\u2044all"],
                 ["ipconfig", "\u29f8all"], "ipconfig /all", None)
        self.assertEqual(classify(["ipconfig", 5])[0], UNKNOWN)       # an int is text, but not an ipconfig argument
        self.assertEqual(classify([os.fspath("ipconfig"), "/all"])[0], READ)

    def test_a1_bcdedit_store(self):
        d = self.tmp.name
        inside = os.path.join(d, "exports", "w.work")
        self.assertEqual(classify(["bcdedit", "/store", inside, "/enum", "all", "/v"], case_dir=d)[0], READ)
        self.assertEqual(classify(["bcdedit", "/store", inside, "/export", os.path.join(d, "a.bak")], case_dir=d)[0],
                         READ)
        self.bad(["bcdedit", "/store", "W:\\Boot\\BCD", "/enum", "all", "/v"],
                 ["bcdedit", "/store", "W:\\Boot\\BCD", "/enum"], ["bcdedit", "/store"], ["bcdedit", "/store", "/enum"],
                 ["bcdedit", "/store", "/v", "/enum"], ["bcdedit", "/store", inside, "/store", inside, "/enum"],
                 ["bcdedit", "/store", "W:\\Boot\\BCD", "/export", os.path.join(d, "a.bak")],
                 ["bcdedit", "/enum", "add"], ["bcdedit", "add"], ["bcdedit", "/export", "x", "y"],
                 ["bcdedit", "/store", "W:\\Boot\\BCD", "/export", "W:\\x"],
                 ["bcdedit", "/store", os.path.join(d + "2", "x"), "/enum"], case_dir=d)
        self.assertEqual(classify(["bcdedit", "/store", "W:\\Boot\\BCD", "/enum"], case_dir=d)[1],
                         "bcdedit may only open a copy of the store inside the case folder")
        self.assertEqual(classify(["bcdedit", "/store", "x", "/enum"])[0], FORBIDDEN)

    def test_a1_repair_store_on_system_drive_refused(self):
        r = Runner(self.case, ScriptedUI(["yes", "yes"]), ROOT, dry_run=True)
        r.repairs_enabled = True
        r.bcd_backup = os.path.join(self.tmp.name, "b.bak")
        with open(r.bcd_backup, "wb") as f:
            f.write(b"x")
        sysdrive = os.environ.get("SystemDrive", "C:")
        step = RepairStep(id="b", title="b", effect="e",
                          argv=["bcdedit", "/store", sysdrive + "\\Boot\\BCD", "/set", "{default}", "a", "b"])
        with self.assertRaises(Refused) as cm:
            r.repair(step)
        self.assertIn("running Windows", str(cm.exception))
        step.argv[2] = "\\Boot\\BCD"
        with self.assertRaises(Refused):
            r.repair(step)

    def test_a8_robocopy(self):
        d = self.tmp.name
        log = os.path.join(d, "logs", "r.log")
        ok = ["robocopy", "W:\\Users", "E:\\b\\Users", "/E", "/LOG:" + log]
        self.assertEqual(classify(ok, case_dir=d)[0], HOST)
        self.bad(ok)                                                                   # no case dir
        self.bad(["robocopy", "W:\\Users", "E:\\b", "/LOG:W:\\Windows\\x.log"],
                 ["robocopy", "W:\\Users", "E:\\b", "/LOG:"],
                 ["robocopy", "W:\\Users", "W:\\Users", "/E"],
                 ["robocopy", "W:\\Users", "w:\\users\\", "/E"],
                 ["robocopy", "W:\\Users", "W:\\Users\\sub", "/E"],
                 ["robocopy", "W:\\Users\\sub", "W:\\Users", "/E"], case_dir=d)
        self.assertEqual(classify(["robocopy", "W:\\Users", "W:\\Users2", "/E"], case_dir=d)[0], HOST)

    def test_a8_runner_passes_case_dir(self):
        r = Runner(self.case, ScriptedUI(["yes", "yes"]), ROOT, dry_run=True)
        r.repairs_enabled = True
        argv = ["robocopy", "W:\\Users", "E:\\b\\Users", "/E", "/LOG:" + self.case.path("logs", "r.log")]
        self.assertEqual(r.repair(RepairStep(id="c", title="c", effect="e", argv=argv)).kind, "dry-run")
        argv[-1] = "/LOG:W:\\Windows\\x.log"
        with self.assertRaises(Refused):
            r.repair(RepairStep(id="c", title="c", effect="e", argv=argv))

    def test_a9_network_reads(self):
        self.bad(["reg", "query", "\\\\remotehost\\HKLM\\Software"], ["reg", "query", "//host/x"],
                 ["reg", "query", "HKLM\\Software", "/s", "/y"], ["reg", "query"], ["reg", "query", "save"],
                 ["reg", "query", "HKLM\\x", "-v", "a"],
                 ["wevtutil", "qe", "System", "/r:otherhost", "/u:x", "/p:y"], ["wevtutil", "qe", "System", "/r:h"],
                 ["wevtutil", "qe", "\\\\evil\\share\\x.evtx"], ["wevtutil", "qe", "//evil/share/x.evtx"],
                 ["wevtutil", "qe", "System", "/lf"], ["wevtutil", "qe", "System", "/ow:true"],
                 ["wevtutil", "qe", "System", "/uni:true"], ["wevtutil", "qe", "a", "b"], ["wevtutil", "qe"],
                 ["wevtutil", "el", "/r:h"], ["wevtutil", "el", "x"], ["wevtutil", "gl", "System", "/r:h"],
                 ["wevtutil", "gli", "System", "/u:x"], ["wevtutil", "gl", "\\\\h\\x"],
                 ["reagentc", "/info", "/target", "W:\\Windows"], ["reagentc", "/info", "/x"], ["reagentc"])
        for argv in (["reg", "query", "HKLM\\Software\\X", "/v", "Name", "/reg:64"], ["wevtutil", "el"],
                     ["wevtutil", "gl", "System", "/lf:true"], ["wevtutil", "gli", "System"], ["reagentc", "/info"],
                     ["wevtutil", "qe", "System", "/q:*", "/c:5", "/rd:true", "/f:text", "/lf:false"]):
            self.assertEqual(classify(argv)[0], READ, argv)

    def test_a12_utf16_manifest(self):
        h = hashlib.sha256(b"x").hexdigest()
        text = "# c\r\n%s  a.py\r\nnothex  b.py\r\n%s *c.py\r\n" % (h, h.upper())
        for name, raw in (("le", b"\xff\xfe" + text.encode("utf-16-le")), ("be", b"\xfe\xff" + text.encode("utf-16-be")),
                          ("u8", b"\xef\xbb\xbf" + text.encode()), ("bad", b"\xff\xfe\x00\xd8x" + b"\x80\x81" * 3),
                          ("odd", b"\xff\xfe" + text.encode("utf-16-le") + b"\x41")):
            p = os.path.join(self.tmp.name, name + ".sha256")
            with open(p, "wb") as f:
                f.write(raw)
            self.assertIsInstance(read_manifest_lines(p), list)            # never raises
        self.assertEqual(read_manifest_lines(os.path.join(self.tmp.name, "le.sha256"))[1], "%s  a.py" % h)
        with self.assertRaises(OSError):
            read_manifest_lines(os.path.join(self.tmp.name, "missing"))
        kit = os.path.join(self.tmp.name, "kit")
        os.makedirs(os.path.join(kit, "tools"))
        os.makedirs(os.path.join(kit, "plugins"))
        data = b"tool"
        with open(os.path.join(kit, "tools", "good.exe"), "wb") as f:
            f.write(data)
        man = "%s  good.exe\r\nnothex  bad.exe\r\n" % hashlib.sha256(data).hexdigest()
        for sub in ("tools", "plugins"):
            with open(os.path.join(kit, sub, "manifest.sha256"), "wb") as f:
                f.write(b"\xff\xfe" + man.encode("utf-16-le"))
        r = Runner(self.case, ScriptedUI([]), kit)
        st = r.verify_tools()
        self.assertEqual(st["good.exe"], "ok")
        self.assertIn("ignored", st["bad.exe"])
        self.assertIn("good", r.verified_tools)
        from recoverykit.plugins import load_manifest
        self.assertEqual(list(load_manifest(os.path.join(kit, "plugins"))), ["good.exe"])

    def test_a10_redact_helper(self):
        key = "111111-222222-333333-444444-555555-666666-777777-888888"
        self.assertEqual(_redact("key %s ok %s" % (key, key), (key, "")), "key <redacted> ok <redacted>")
        self.assertEqual(_redact("plain", ("",)), "plain")

    def test_a10_repair_result_is_redacted(self):
        key = "111111-222222-333333-444444-555555-666666-777777-888888"
        r = Runner(self.case, ScriptedUI(["yes"]), ROOT)
        r.repairs_enabled = True
        r._exec = lambda argv, timeout, **kw: Result(list(argv), rc=0, out="echo " + key)
        res = r.repair(RepairStep(id="unlock", title="u", effect="e", secrets=(key,),
                                  argv=["manage-bde", "-unlock", "W:", "-RecoveryPassword", key]))
        self.assertNotIn(key, res.out)

    def test_exec_catches_value_error(self):
        r = Runner(self.case, ScriptedUI([]), ROOT)
        res = r._exec(["ipconfig", "/all\x00"], 5)
        self.assertTrue(res.error and res.rc is None)


WRITE_TOKENS = ["/set", "/delete", "/deletevalue", "/import", "/createstore", "/mir", "/purge", "/move", "/fixmbr",
                "/fixboot", "/rebuildbcd", "/off", "/r", "/offline", "/apply-image", "/remove-package",
                "/scannow", "save", "add", "call", "clean", "format", "restore", "delete", "export", "-unlock"]
CHKDSK_WRITE = {"/f", "/x", "/scan"}                 # chkdsk repair switches: REPAIR, never READ
TOOLS = ["bcdedit", "bcdboot", "bootrec", "dism", "sfc", "reg", "chkdsk", "wevtutil", "wmic", "smartctl",
         "robocopy", "ipconfig", "manage-bde", "reagentc", "diskpart", "format", "cmd", "powershell", "drvload",
         "BCDEDIT.EXE", "CH\u212aDS\u212a"]
VOCAB = TOOLS + ["/store", "/enum", "/v", "/export", "/all", "/info", "/status", "-status", "/Image:W:\\", "/E",
                 "/LOG:W:\\x.log", "W:", "W:\\Windows", "query", "qe", "el", "gl", "get", "all", "{default}",
                 "HKLM\\Software", "System", "/q:*", "/c:5", "/lf:true", "/dev/pd0", "-a", "-j", "--scan", "/l",
                 "\uFF0Fimport", "\u2013off", "\u2215set", "\u0430", "", " ", "\x00", "\n", "\x7f", '"', "a\x01b",
                 "\\\\host\\share", "//host/x", "\u00a0/set"] + WRITE_TOKENS + sorted(CHKDSK_WRITE)


class Property(unittest.TestCase):
    def test_20000_random_argvs(self):
        rng = random.Random(20261119)
        write_low = {t.lower() for t in WRITE_TOKENS}
        n_read = 0
        for _ in range(20000):
            argv = [rng.choice(VOCAB) for _ in range(rng.randint(0, 7))]
            if argv and rng.random() < 0.6:
                argv[0] = rng.choice(TOOLS)
            kind, why = classify(argv, case_dir=rng.choice([None, "W:\\case", os.path.abspath(".")]))   # never raises
            self.assertIn(kind, (READ, REPAIR, HOST, FORBIDDEN, UNKNOWN))
            self.assertIsInstance(why, str)
            if kind == READ:
                n_read += 1
                low = {str(a).lower() for a in argv[1:]}
                self.assertFalse(low & write_low, argv)
                if argv[0].lower().startswith("chkdsk"):
                    self.assertFalse(low & CHKDSK_WRITE, argv)
        self.assertGreater(n_read, 0)

    def test_never_raises_on_odd_types(self):
        for argv in ([None], [object()], [["a"]], ["bcdedit", "/export:foo", "bar"], ["bcdedit", "/export:", "/store"],
                     [1, 2], ["ipconfig", 1.5], "text", 5, {"a": 1}, ["wevtutil", "qe", "\u0000"]):
            self.assertIn(classify(argv)[0], NOT_RUNNABLE, argv)


class ThirdReview(Tmp):
    """Third review 2026-11-19: N11, N14 (runner part), N1 (runner part), S7, S10, smartctl whole tokens."""

    def bad(self, *argvs, **kw):
        for argv in argvs:
            self.assertIn(classify(argv, **kw)[0], NOT_RUNNABLE, argv)

    def test_n11_network_path_spellings(self):
        from recoverykit.core.runner import is_network_path
        for p in ("\\\\h\\s\\x", "//h/s/x", "\\/h\\s", "/\\h\\s", "  \\\\h\\s ", "\\\\?\\UNC\\h\\s\\x",
                  "\\\\?\\unc\\h\\s"):
            self.assertTrue(is_network_path(p), p)
        for p in ("C:\\x", "x.evtx", "\\\\?\\C:\\x", "\\\\?\\Volume{1234}\\x", "\\\\.\\C:", "\\x\\y", ""):
            self.assertFalse(is_network_path(p), p)
        self.bad(["wevtutil", "qe", "\\/evil\\share\\x.evtx", "/lf:true"], ["wevtutil", "gl", "//h/s/x.evtx", "/lf:true"],
                 ["wevtutil", "gli", "\\\\?\\UNC\\h\\s\\x.evtx", "/lf:true"],
                 ["reg", "query", "\\/host\\HKLM\\Software"],
                 ["dism", "/Get-WimInfo", "/WimFile:\\\\evil\\share\\x.wim"],
                 ["dism", "/Get-ImageInfo", "/ImageFile://evil/share/x.wim", "/Index:1"],
                 ["dism", "/Get-WimInfo", "/WimFile:\\/evil\\share\\x.wim"])
        self.assertEqual(classify(["dism", "/Get-WimInfo", "/WimFile:D:\\sources\\install.wim"])[0], READ)
        self.assertEqual(classify(["dism", "/Get-WimInfo", "/WimFile:\\\\?\\D:\\install.wim"])[0], READ)
        self.assertEqual(classify(["wevtutil", "qe", "\\\\?\\D:\\x.evtx", "/lf:true"])[0], READ)

    def test_s7_bcdedit_switches_are_exact(self):
        d = self.tmp.name
        store = os.path.join(d, "bcd.work")
        self.bad(["bcdedit", "/store", store, "/store:W:\\Boot\\BCD", "/enum"],
                 ["bcdedit", "/enum:x"], ["bcdedit", "/store", store, "/enum:all"],
                 ["bcdedit", "/store", store, "/v=y", "/enum"], ["bcdedit", "/store", store, "/enum", "/v:1"],
                 ["bcdedit", "/store:" + store, "/enum"], case_dir=d)
        self.assertEqual(classify(["bcdedit", "/store", store, "/enum", "all", "/v"], case_dir=d)[0], READ)
        self.assertEqual(classify(["bcdedit", "/STORE", store, "/ENUM"], case_dir=d)[0], READ)

    def test_smartctl_whole_tokens(self):
        self.bad(["smartctl", "-X:1", "/dev/pd0"], ["smartctl", "-l:scterc,70,70", "/dev/pd0"],
                 ["smartctl", "-a:1", "/dev/pd0"], ["smartctl", "--json=c", "/dev/pd0"], ["smartctl", "-a=1", "/dev/pd0"],
                 ["smartctl", "-x:", "/dev/pd0"], ["smartctl", "--scan=x"])
        self.assertEqual(classify(["smartctl", "-x", "-j", "/dev/pd0"])[0], READ)

    def test_s10_robocopy_destination_and_sources(self):
        d = self.tmp.name
        sysroot = os.environ.get("SystemRoot", "C:\\Windows")
        drive = os.environ.get("SystemDrive", "C:")
        bad = [["robocopy", "D:\\payload", sysroot + "\\System32", "/E"], ["robocopy", "D:\\payload", sysroot, "/E"],
               ["robocopy", "D:\\payload", drive + "\\", "/E"], ["robocopy", "D:\\payload", drive, "/E"],
               ["robocopy", "D:\\payload", "\\\\server\\share\\x", "/E"], ["robocopy", "\\\\server\\share", "D:\\x", "/E"],
               ["robocopy", "//server/share", "D:\\x"], ["robocopy", "\\/server\\share", "D:\\x"],
               ["robocopy", "@list.txt", "D:\\x"], ["robocopy", "D:\\x", "@list.txt"], ["robocopy", "-x", "D:\\x"]]
        for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            if os.environ.get(var):
                bad.append(["robocopy", "D:\\payload", os.path.join(os.environ[var], "Sub"), "/E"])
                bad.append(["robocopy", "D:\\payload", os.environ[var].lower() + "\\.\\x\\..\\y", "/E"])
        self.bad(*bad, case_dir=d)
        self.assertEqual(classify(["robocopy", "W:\\Users", "E:\\b\\Users", "/E"], case_dir=d)[0], HOST)

    def test_s10_drvload(self):
        for argv in (["drvload"], ["drvload", "a.inf", "b.inf"], ["drvload", "x.txt"], ["drvload", "x"],
                     ["drvload", "\\\\h\\s\\x.inf"], ["drvload", "//h/s/x.inf"], ["drvload", "@list.inf"],
                     ["drvload", "*.inf"], ["drvload", "x?.inf"], ["drvload", "-x.inf"], ["drvload", "x.inf", "/offline"]):
            self.assertEqual(classify(argv)[0], FORBIDDEN, argv)
        for argv in (["drvload", "D:\\drivers\\net.inf"], ["drvload", "X.INF"]):
            self.assertEqual(classify(argv)[0], HOST, argv)

    def test_n14_not_a_command_line_is_refused_and_audited(self):
        r = Runner(self.case, ScriptedUI(["yes"] * 4), ROOT, dry_run=True)
        r.repairs_enabled = True
        for bad in (None, 5, "ipconfig /all"):
            with self.assertRaises(Refused):
                r.run(bad, "bad")
            with self.assertRaises(Refused):
                r.run_diskpart(bad, "bad")
            with self.assertRaises(Refused):
                r.repair(RepairStep(id="x", title="t", effect="e", argv=bad))
            with self.assertRaises(Refused):
                r.repair(RepairStep(id="x", title="t", effect="e", argv=None, diskpart=bad))
        a = self.audit()
        self.assertEqual(len(a), 12)
        self.assertTrue(all(x["kind"] == "refused" and "not a command line" in x["error"] for x in a))

    def test_n1_lone_surrogate_in_argument_and_output(self):
        r = Runner(self.case, ScriptedUI([]), ROOT, dry_run=True)
        r._exec = lambda argv, timeout, **kw: Result(list(argv), rc=0, out="file crash\ud800.dmp ok")
        res = r.run(["wevtutil", "qe", "crash\ud800.evtx", "/lf:true"], "t")
        self.assertEqual(res.rc, 0)
        with self.assertRaises(Refused):
            r.run(["ipconfig", "/all", "\ud800x\x01"], "t")
        with open(self.case.path("audit.log"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("\\ud800", text)
        with open(self.case.path("audit", "0001-wevtutil.txt"), encoding="utf-8") as f:
            self.assertIn("crash\\ud800.dmp", f.read())


if __name__ == "__main__":
    unittest.main()
