"""Core tests: command classification, forbidden list, audit, hive parser, case model, rules.

Nothing here runs a repair or writes outside a temp directory.
"""
import ast
import json
import os
import struct
import sys
import tempfile
import unittest

from recoverykit import plugins
from recoverykit.core import regf, winapi
from recoverykit.core.case import Case
from recoverykit.core.runner import (FORBIDDEN, HOST, READ, REPAIR, UNKNOWN, Refused, RepairStep, Runner, classify,
                                     classify_diskpart)
from recoverykit.core.ui import UI

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ScriptedUI(UI):
    def __init__(self, answers):
        super().__init__(auto=False)
        self.answers = list(answers)
        self.lines = []

    def say(self, text=""):
        self.lines.append(str(text))

    raw = say

    def ask(self, prompt, default="", secret=False):
        return self.answers.pop(0) if self.answers else default

    def confirm_yes(self, question):
        return (self.answers.pop(0) if self.answers else "") == "yes"


class Classify(unittest.TestCase):
    def test_forbidden_commands_from_spec(self):
        for argv in (["format", "C:"], ["format.com", "W:", "/q"], ["diskpart"], ["diskpart", "/s", "x.txt"],
                     ["bootrec", "/fixmbr"], ["bootrec", "/FixBoot"], ["bcdboot", "W:\\Windows"],
                     ["cmd", "/c", "format c:"], ["powershell", "-Command", "Clear-Disk 0"],
                     ["bcdedit", "/import", "x"], ["reg", "delete", "HKLM\\X"], ["reg", "load", "HKLM\\T", "f"],
                     ["sfc", "/scannow"], ["chkdsk", "C:", "/r"], ["wevtutil", "cl", "System"],
                     ["wmic", "diskdrive", "call", "x"], ["robocopy", "a", "b", "/MIR"],
                     ["robocopy", "a", "b", "/MOVE"], ["smartctl", "-s", "off", "/dev/pd0"],
                     ["dism", "/Online", "/Cleanup-Image", "/RestoreHealth"], ["manage-bde", "-off", "C:"],
                     ["wpeutil", "reboot"], ["fsutil", "dirty", "set", "C:"], ["mountvol", "S:", "/s"]):
            self.assertEqual(classify(argv)[0], FORBIDDEN, argv)

    def test_unknown_is_not_runnable(self):
        for argv in ([], ["notepad"], ["C:\\x\\evil.exe", "/enum"], ["dism", "/Image:W:\\", "/Apply-Image"],
                     ["bootrec", "/whatever"]):
            self.assertIn(classify(argv)[0], (UNKNOWN, FORBIDDEN), argv)

    def test_read_only(self):
        for argv in (["bcdedit", "/store", "x", "/enum", "all", "/v"], ["bcdedit", "/enum", "all"],
                     ["bcdedit", "/export", "x.bak"], ["manage-bde", "-status"], ["chkdsk", "W:"],
                     ["wevtutil", "qe", "f.evtx", "/lf:true", "/q:*", "/c:5"], ["ipconfig", "/all"],
                     ["reg", "query", "HKLM\\X"], ["dism", "/Get-WimInfo", "/WimFile:x.wim"],
                     ["smartctl", "-a", "-j", "/dev/pd0"], ["C:\\Windows\\System32\\BCDEDIT.EXE", "/enum"],
                     ["bootrec", "/scanos"], ["wmic", "diskdrive", "get", "Status"]):
            self.assertEqual(classify(argv)[0], READ, argv)

    def test_repair_and_host(self):
        self.assertEqual(classify(["dism", "/English", "/Image:W:\\", "/Cleanup-Image", "/RestoreHealth",
                                   "/Source:wim:D:\\i.wim:1", "/LimitAccess"])[0], REPAIR)
        self.assertEqual(classify(["sfc", "/scannow", "/offbootdir=W:\\", "/offwindir=W:\\Windows"])[0], REPAIR)
        self.assertEqual(classify(["bcdedit", "/set", "{default}", "recoveryenabled", "no"]), (REPAIR, "needs-bcd-backup"))
        self.assertEqual(classify(["bcdboot", "W:\\Windows", "/s", "S:", "/f", "UEFI"]), (REPAIR, "needs-bcd-backup"))
        self.assertEqual(classify(["robocopy", "W:\\Users", "E:\\b", "/E", "/XJ"])[0], HOST)
        self.assertEqual(classify(["manage-bde", "-unlock", "W:", "-RecoveryPassword", "1-2"])[0], HOST)

    def test_diskpart_scripts(self):
        self.assertEqual(classify_diskpart(["list disk", "select disk 0", "detail disk", "list volume"])[0], READ)
        self.assertEqual(classify_diskpart(["select disk 0", "online disk"])[0], REPAIR)
        self.assertEqual(classify_diskpart(["select disk 0", "select partition 4", "assign letter=W"])[0], REPAIR)
        for bad in (["select disk 0", "clean"], ["select volume 3", "format fs=ntfs quick"],
                    ["select partition 1", "delete partition override"], ["select disk 0", "convert gpt"],
                    ["list disk", "CLEAN ALL"], ["create partition primary"], ["select disk 0", "  Clean  "]):
            self.assertEqual(classify_diskpart(bad)[0], FORBIDDEN, bad)


class RunnerBehaviour(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.case = Case(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.case.close)

    def audit(self):
        with open(self.case.path("audit.log"), encoding="utf-8") as f:
            return [json.loads(x) for x in f]

    def test_read_command_is_audited_with_output(self):
        r = Runner(self.case, ScriptedUI([]), ROOT)
        res = r.run(["ipconfig", "/all"], "test")
        self.assertEqual(res.rc, 0)
        a = self.audit()[-1]
        self.assertEqual((a["kind"], a["exit_code"], a["purpose"]), ("read", 0, "test"))
        self.assertTrue(os.path.getsize(self.case.path(*a["output_file"].split("/"))) > 0)

    def test_run_refuses_everything_but_read_and_audits_the_refusal(self):
        r = Runner(self.case, ScriptedUI([]), ROOT)
        for argv in (["format", "C:"], ["sfc", "/scannow", "/offbootdir=W:\\", "/offwindir=W:\\Windows"], ["notepad"]):
            with self.assertRaises(Refused):
                r.run(argv, "must not run")
        self.assertEqual([a["kind"] for a in self.audit()], ["refused"] * 3)
        with self.assertRaises(Refused):
            r.run_diskpart(["select disk 0", "clean"], "must not run")

    def test_missing_tool_is_a_result_not_an_exception(self):
        r = Runner(self.case, ScriptedUI([]), ROOT)
        r.resolve = lambda name: None
        res = r.run(["wmic", "diskdrive", "get", "Status"], "t")
        self.assertIsNone(res.rc)
        self.assertIn("not available", res.error)

    def _step(self, **kw):
        d = dict(id="scanhealth", title="Scan", effect="reads the component store",
                 argv=["dism", "/English", "/Image:W:\\", "/Cleanup-Image", "/ScanHealth"])
        d.update(kw)
        return RepairStep(**d)

    def test_repair_gates(self):
        ui = ScriptedUI(["yes"] * 10)
        r = Runner(self.case, ui, ROOT, dry_run=True)
        with self.assertRaises(Refused):          # repairs not enabled
            r.repair(self._step())
        r.repairs_enabled = True
        r.target_online = True
        with self.assertRaises(Refused):          # target is the running Windows
            r.repair(self._step())
        r.target_online = False
        with self.assertRaises(Refused):          # target re-check fails
            r.repair(self._step(target_check=lambda: (False, "disk number changed")))
        with self.assertRaises(Refused):          # BCD change without an export
            r.repair(self._step(argv=["bcdedit", "/set", "{default}", "x", "y"]))
        with self.assertRaises(Refused):          # forbidden stays forbidden in repair mode
            r.repair(self._step(argv=["format", "W:"]))
        with self.assertRaises(Refused):
            r.repair(self._step(argv=None, diskpart=["select disk 0", "clean"]))
        res = r.repair(self._step())               # dry run: confirmed, recorded, not executed
        self.assertEqual((res.rc, res.kind), (None, "dry-run"))
        self.assertTrue(any("dism" in ln and "/ScanHealth" in ln for ln in ui.lines), "exact command must be shown")
        ui.answers = ["no"]
        self.assertIsNone(r.repair(self._step()))
        ui.answers = ["y"]                         # anything but the typed word yes is a no
        self.assertIsNone(r.repair(self._step()))
        kinds = [a["kind"] for a in self.audit()]
        self.assertEqual(kinds, ["refused"] * 6 + ["dry-run", "declined", "declined"])

    def test_bcd_backup_enables_bcd_step_and_auto_ui_never_confirms(self):
        r = Runner(self.case, UI(auto=True), ROOT, dry_run=True)
        r.repairs_enabled = True
        self.assertFalse(r.note_bcd_backup(self.case.path("exports", "nope.bak")))
        p = self.case.path("exports", "bcd.bak")
        with open(p, "wb") as f:
            f.write(b"regf")
        self.assertTrue(r.note_bcd_backup(p))
        self.assertIsNone(r.repair(self._step(argv=["bcdedit", "/set", "{default}", "x", "y"])))  # auto: declined

    def test_secrets_are_redacted(self):
        r = Runner(self.case, ScriptedUI(["yes"]), ROOT, dry_run=True)
        r.repairs_enabled = True
        key = "111111-222222-333333"
        r.repair(self._step(id="unlock", argv=["manage-bde", "-unlock", "W:", "-RecoveryPassword", key],
                            secrets=(key,), touches_target=False))
        self.case.close()
        for name in ("audit.log", "debug.log"):
            with open(self.case.path(name), encoding="utf-8") as f:
                self.assertNotIn(key, f.read(), name)

    def test_tools_manifest(self):
        kit = tempfile.mkdtemp()
        os.makedirs(os.path.join(kit, "tools"))
        import hashlib
        for name, data in (("good.exe", b"good"), ("bad.exe", b"tampered")):
            with open(os.path.join(kit, "tools", name), "wb") as f:
                f.write(data)
        with open(os.path.join(kit, "tools", "manifest.sha256"), "w") as f:
            f.write("%s  good.exe\n%s  bad.exe\n%s  ../evil.exe\n" % (
                hashlib.sha256(b"good").hexdigest(), hashlib.sha256(b"original").hexdigest(), "0" * 64))
        r = Runner(self.case, ScriptedUI([]), kit)
        st = r.verify_tools()
        self.assertEqual(st["good.exe"], "ok")
        self.assertIn("mismatch", st["bad.exe"])
        self.assertIn("escapes", st["../evil.exe"])
        self.assertEqual(list(r.verified_tools), ["good"])


class CaseModel(unittest.TestCase):
    def test_sections_files_and_move(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = Case(tmp)
            src = os.path.join(tmp, "src.log")
            with open(src, "w") as f:
                f.write("hello")
            with c.section("a", "A") as s:
                s.item("x", "missing", "not found")
            with c.section("b", "B"):
                raise RuntimeError("boom")
            with c.section("c", "C") as s:
                s.data = {"k": 1}
            e = c.collect_file(src, "logs/target-src.log")
            self.assertEqual((e["status"], e["size"]), ("ok", 5))
            self.assertEqual(c.collect_file(src + ".nope", "logs/x")["status"], "missing")
            self.assertEqual(c.collect_file(src, "logs/big", max_bytes=2)["status"], "skipped")
            self.assertEqual(c.verify_sources(), [])
            with open(src, "a") as f:
                f.write("changed")
            self.assertEqual(c.verify_sources(), [src, src])
            c.assign("ITW-1/..\\x-abc", "1")
            self.assertTrue(c.dir.startswith(os.path.join(os.path.abspath(tmp), "ITW-1x-abc")))
            c.close()
            with open(c.path("case.json"), encoding="utf-8") as f:
                d = json.load(f)
            self.assertEqual([d["sections"][k]["status"] for k in "abc"], ["ok", "error", "ok"])
            self.assertIn("boom", d["sections"]["b"]["reason"])
            self.assertTrue(os.path.exists(c.path("logs", "target-src.log")))
            with open(c.path("debug.log"), encoding="utf-8") as f:
                self.assertIn("RuntimeError: boom", f.read())


class HiveParser(unittest.TestCase):
    def test_synthetic_hive(self):
        from tests import fakewin
        from recoverykit.core.context import RegView
        with tempfile.TemporaryDirectory() as tmp:
            win = fakewin.make_target(tmp, pending=True)
            r = RegView(win, online=False)
            cv = r"Microsoft\Windows NT\CurrentVersion"
            self.assertEqual(r.get("SOFTWARE", cv, "currentbuild"), "26100")
            self.assertEqual(r.get("SOFTWARE", cv, "UBR"), 8875)
            self.assertEqual(r.control_set(), "ControlSet001")
            self.assertEqual(r.subkeys("SYSTEM", r"ControlSet001\Control\MUI\UILanguages"), ["en-US"])
            self.assertEqual(r.get("SYSTEM", r"ControlSet001\Control\Session Manager", "PendingFileRenameOperations"), ["a", "b"])
            self.assertTrue(r.exists("SOFTWARE", r"Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"))
            self.assertFalse(r.exists("SOFTWARE", r"Nope\Deeper"))
            self.assertIsNone(r.get("SOFTWARE", r"Nope\Deeper", "x"))
            self.assertEqual(r.dirty, {"SOFTWARE": False, "SYSTEM": False})
            self.assertEqual(r.errors, {})
            r.close()
            fakewin.make_hive(os.path.join(tmp, "D"), {"values": {"a": fakewin.dword(1)}}, dirty=True)
            with regf.Hive(os.path.join(tmp, "D")) as h:
                self.assertTrue(h.dirty)

    def test_garbage_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "x")
            with open(p, "wb") as f:
                f.write(b"not a hive" * 1000)
            with self.assertRaises(regf.HiveError):
                regf.Hive(p)

    @unittest.skipUnless(os.path.exists(r"C:\Users\Default\NTUSER.DAT"), "no default profile hive")
    def test_real_hive_on_this_pc(self):
        with regf.Hive(r"C:\Users\Default\NTUSER.DAT") as h:
            self.assertIn("Software", h.root().subkey_names())
            self.assertIsNotNone(h.open(r"Software\Microsoft\Windows\CurrentVersion"))
            self.assertIn("TEMP", h.open("Environment").values())


class DiskInventory(unittest.TestCase):
    def test_this_pc(self):
        disks, vols = winapi.disks(), winapi.volumes()
        self.assertTrue(disks and vols)
        sysdrive = os.environ["SystemDrive"][0].upper()
        v = next(v for v in vols if v["letter"] == sysdrive)
        d = next(d for d in disks if d["number"] == v["extents"][0]["disk"])
        self.assertTrue(any(p["offset"] == v["extents"][0]["offset"] for p in d["partitions"]))
        self.assertGreater(d["size"], v["size"] // 2)


class Rules(unittest.TestCase):
    """Spec: modules cannot call subprocess directly."""

    def test_modules_do_not_start_processes_or_call_native_code(self):
        mdir = os.path.join(ROOT, "recoverykit", "modules")
        files = [os.path.join(mdir, f) for f in os.listdir(mdir) if f.endswith(".py")]
        files.append(os.path.join(ROOT, "recoverykit", "wim.py"))
        for path in files:
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), path)
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                for n in names:
                    self.assertNotIn(n.split(".")[0], ("subprocess", "ctypes", "multiprocessing", "socket"),
                                     "%s imports %s" % (os.path.basename(path), n))
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
                    self.assertNotIn(node.attr, ("system", "popen", "startfile"), path)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ("print", "input", "eval", "exec"), "%s calls %s()" % (path, node.func.id))

    def test_only_runner_imports_subprocess(self):
        for root, _, files in os.walk(os.path.join(ROOT, "recoverykit")):
            for f in files:
                if f.endswith(".py") and f != "runner.py":
                    with open(os.path.join(root, f), encoding="utf-8") as fh:
                        self.assertNotIn("import subprocess", fh.read(), f)

    def test_plugin_source_check(self):
        self.assertEqual(plugins.check_source("def collect(ctx):\n    return {'a': 1}\n"), [])
        for bad in ("import subprocess", "from ctypes import windll", "import os\nos.system('x')",
                    "eval('1')", "import socket", "__import__('subprocess')", "def x(:"):
            self.assertTrue(plugins.check_source(bad), bad)

    def test_sources_are_ascii(self):
        for root, _, files in os.walk(os.path.join(ROOT, "recoverykit")):
            for f in files:
                if f.endswith(".py"):
                    with open(os.path.join(root, f), "rb") as fh:
                        data = fh.read()
                    self.assertTrue(all(b < 128 and b != 0 for b in data), "%s is not plain ASCII" % f)


if __name__ == "__main__":
    unittest.main()
