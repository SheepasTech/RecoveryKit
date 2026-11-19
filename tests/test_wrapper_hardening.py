"""Command-wrapper hardening (security review 2026-11-19: C1-C6, C13, C15, S1).

Nothing here runs a repair command: everything goes through classify(), classify_diskpart()
and Runner(..., dry_run=True), or a Runner whose _exec is replaced.
"""
import json
import os
import tempfile
import types
import unittest

from recoverykit.core.case import Case
from recoverykit.core.runner import (FORBIDDEN, HOST, READ, REPAIR, UNKNOWN, Refused, RepairStep, Result, Runner,
                                     classify, classify_diskpart, normalise_diskpart)
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


if __name__ == "__main__":
    unittest.main()
