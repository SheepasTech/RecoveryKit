import os
import shutil
import tempfile
import unittest

from recoverykit.core import case as case_mod
from recoverykit.core import runner, ui
from recoverykit.core.context import Ctx, Target
from recoverykit.modules import logs

SECTIONS = ["logs_target", "event_logs", "bcd", "logs_host", "disk_health", "pending"]


class FakeReg:
    def __init__(self, exists=(), values=None):
        self._exists, self._values = set(exists), values or {}

    def exists(self, hive, path):
        return path.rsplit("\\", 1)[-1] in self._exists

    def get(self, hive, path, name, default=None):
        return self._values.get(name, default)

    def control_set(self):
        return "ControlSet001"


class FakeRunner:
    def __init__(self, tools=(), fail=()):
        self.calls, self.noted, self.verified_tools = [], [], {t: t for t in tools}
        self.fail = set(fail)

    def run(self, argv, purpose, timeout=120, **kw):
        self.calls.append((list(argv), timeout))
        if argv[0] in self.fail:
            return runner.Result(list(argv), error="not available in this environment: %s" % argv[0])
        out = "Event[0]:\n  x\nEvent[1]:\n  y\n" if argv[0] == "wevtutil" else "output of %s" % argv[0]
        return runner.Result(list(argv), rc=0, out=out)

    def run_ps(self, name, params=None, timeout=90):
        self.calls.append((["ps", name], timeout))
        return runner.Result(["ps", name], rc=0, out="{}")

    def note_bcd_backup(self, path):
        self.noted.append(path)
        return True

    def argvs(self, exe):
        return [a for a, _ in self.calls if a[0] == exe]


CFG = {"limits": {"max_log_mb": 1, "max_dump_mb": 1, "max_minidumps": 2, "event_max": 50, "chkdsk_timeout_s": 77},
       "logs": {"target": ["Logs/CBS/CBS.log", "Logs/DISM/dism.log", "big.log"],
                "target_root": ["$WINDOWS.~BT/Sources/Panther/setupact.log"],
                "event_logs": ["System", "Microsoft-Windows-Kernel-Boot%4Operational"],
                "host": ["Logs/CBS/CBS.log"]}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "target") + "\\"
        self.windir = self.root + "Windows"
        self.out = os.path.join(self.tmp, "out")
        self.case = case_mod.Case(self.out)
        self.addCleanup(self.case.close)

    def write(self, path, data=b"x"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)

    def ctx(self, rn=None, target=True, options=None, online=False, style="GPT", admin=True, reg=None, tools=None):
        t = Target(root=self.root, windir=self.windir, online=online, letter="W", volume={}, disk={"number": 3, "style": style},
                   partition=None, reg=reg or FakeReg()) if target else None
        c = Ctx(self.tmp, CFG, {"admin": admin, "windir": os.path.join(self.tmp, "host", "Windows"), "tools": tools or {},
                                "powershell": True}, self.case, ui.UI(auto=True), rn or FakeRunner(),
                options=options or {}, target=t)
        c.inventory = {"volumes": []}
        return c

    def sec(self, name):
        return self.case.data["sections"][name]

    def item(self, sname, iname):
        return next(i for i in self.sec(sname)["items"] if i["name"] == iname)


class TargetLogs(Base):
    def test_found_missing_too_large(self):
        self.write(self.windir + "\\Logs\\CBS\\CBS.log", b"hello")
        self.write(self.windir + "\\big.log", b"0" * (2 * 2 ** 20))
        logs.collect(self.ctx())
        self.assertEqual(self.item("logs_target", "Logs/CBS/CBS.log")["status"], "ok")
        self.assertTrue(os.path.isfile(self.case.path("logs", "target-Logs_CBS_CBS.log")))
        self.assertEqual(self.item("logs_target", "Logs/DISM/dism.log")["status"], "missing")
        big = self.item("logs_target", "big.log")
        self.assertEqual(big["status"], "skipped")
        self.assertIn("metadata only", big["reason"])

    def test_target_root_flattened(self):
        self.write(self.root + "$WINDOWS.~BT\\Sources\\Panther\\setupact.log")
        logs.collect(self.ctx())
        self.assertTrue(os.path.isfile(self.case.path("logs", "target-WINDOWS.BT_Sources_Panther_setupact.log")))

    def test_minidumps_and_memory_dmp(self):
        self.write(self.windir + "\\MEMORY.DMP", b"12345")
        for i, n in enumerate(("a.dmp", "b.dmp", "c.dmp")):
            p = self.windir + "\\Minidump\\" + n
            self.write(p)
            os.utime(p, (1000 + i, 1000 + i))
        logs.collect(self.ctx())
        self.assertEqual(self.item("logs_target", "MEMORY.DMP")["status"], "skipped")
        self.assertEqual(self.item("logs_target", "MEMORY.DMP")["size"], 5)
        self.assertTrue(os.path.isfile(self.case.path("logs", "target-minidump-c.dmp")))
        self.assertTrue(os.path.isfile(self.case.path("logs", "target-minidump-b.dmp")))
        self.assertFalse(os.path.exists(self.case.path("logs", "target-minidump-a.dmp")))

    def test_minidump_folder_absent(self):
        logs.collect(self.ctx())
        self.assertEqual(self.item("logs_target", "minidumps")["status"], "missing")
        self.assertEqual(self.item("logs_target", "MEMORY.DMP")["status"], "missing")


class EventLogs(Base):
    def test_filter_then_limit_and_copy_path(self):
        self.write(self.windir + "\\System32\\winevt\\Logs\\System.evtx")
        rn = FakeRunner()
        logs.collect(self.ctx(rn))
        argv = rn.argvs("wevtutil")[0]
        self.assertIn("/lf:true", argv)
        q = next(a for a in argv if a.startswith("/q:"))
        self.assertIn("Level=1 or Level=2 or Level=3", q)
        self.assertIn("/c:50", argv)
        self.assertLess(argv.index(q), argv.index("/c:50") + 1)
        copy = argv[2]
        self.assertTrue(os.path.abspath(copy).startswith(os.path.abspath(self.case.dir)))
        it = self.item("event_logs", "System")
        self.assertEqual(it["status"], "ok")
        self.assertEqual(it["events"], 2)
        self.assertTrue(os.path.isfile(self.case.path("logs", "target-events-System.txt")))

    def test_percent4_name_and_missing_offline(self):
        rn = FakeRunner()
        logs.collect(self.ctx(rn))
        self.assertEqual(rn.argvs("wevtutil"), [])
        it = self.item("event_logs", "Microsoft-Windows-Kernel-Boot%4Operational")
        self.assertEqual(it["status"], "missing")
        self.assertIn("offline", it["reason"])

    def test_online_fallback_uses_channel_name(self):
        rn = FakeRunner()
        logs.collect(self.ctx(rn, online=True))
        argvs = rn.argvs("wevtutil")
        self.assertIn("Microsoft-Windows-Kernel-Boot/Operational", [a[2] for a in argvs])
        self.assertTrue(all("/lf:true" not in a for a in argvs))

    def test_wevtutil_missing_is_explained(self):
        self.write(self.windir + "\\System32\\winevt\\Logs\\System.evtx")
        logs.collect(self.ctx(FakeRunner(fail=("wevtutil",))))
        it = self.item("event_logs", "System")
        self.assertEqual(it["status"], "ok")
        self.assertIn("raw .evtx", it["reason"])


class Bcd(Base):
    def make_efi(self, content=True):
        vol = os.path.join(self.tmp, "efi") + "\\"
        if content:
            self.write(vol + "EFI\\Microsoft\\Boot\\BCD", b"bcd")
        self.case.data["sections"]["boot_structure"] = {"data": {"efi_partitions": [
            {"disk": 3, "partition": 1, "volume": vol, "on_target_disk": True},
            {"disk": 9, "partition": 2, "volume": None, "on_target_disk": False}]}}

    def test_bcdedit_only_on_case_copy_and_backup_noted(self):
        self.make_efi()
        rn = FakeRunner()
        logs.collect(self.ctx(rn))
        argvs = rn.argvs("bcdedit")
        self.assertEqual(len(argvs), 1)
        self.assertEqual(argvs[0][1], "/store")
        self.assertTrue(os.path.abspath(argvs[0][2]).startswith(os.path.abspath(self.case.dir)))
        self.assertTrue(argvs[0][2].endswith("bcd-disk3-part1.work"))
        self.assertEqual(rn.noted, [self.case.path("exports", "bcd-disk3-part1.bak")])
        self.assertTrue(os.path.isfile(self.case.path("logs", "target-bcd-disk3-part1.txt")))
        self.assertEqual(self.item("bcd", "bcd-disk9-part2")["status"], "error")

    def test_missing_bcd_explained(self):
        self.make_efi(content=False)
        rn = FakeRunner()
        logs.collect(self.ctx(rn, admin=False))
        self.assertEqual(rn.argvs("bcdedit"), [])
        self.assertNotEqual(self.sec("bcd")["status"], "ok")
        self.assertIn("administrator", self.sec("bcd")["reason"])

    def test_live_fallback_needs_admin_and_online(self):
        self.make_efi(content=False)
        rn = FakeRunner()
        logs.collect(self.ctx(rn, online=True, admin=False))
        self.assertEqual(rn.argvs("bcdedit"), [])
        logs.collect(self.ctx(rn, online=True, admin=True))
        self.assertEqual(len(rn.argvs("bcdedit")), 2)


class HostAndHealth(Base):
    def test_host_skipped_when_online_and_collected_otherwise(self):
        self.write(os.path.join(self.tmp, "host", "Windows", "Logs", "CBS", "CBS.log"))
        logs.collect(self.ctx(online=True))
        self.assertEqual(self.sec("logs_host")["status"], "skipped")
        logs.collect(self.ctx())
        self.assertEqual(self.item("logs_host", "Logs/CBS/CBS.log")["status"], "ok")
        self.assertTrue(os.path.isfile(self.case.path("logs", "host-Logs_CBS_CBS.log")))

    def test_smartctl_method(self):
        rn = FakeRunner(tools=("smartctl",))
        logs.collect(self.ctx(rn))
        self.assertEqual(self.sec("disk_health")["data"]["method"], "smartctl")
        self.assertIn(["smartctl", "-a", "-j", "/dev/pd3"], rn.argvs("smartctl"))
        self.assertTrue(os.path.isfile(self.case.path("inventory", "smart-disk3.json")))

    def test_powershell_method(self):
        rn = FakeRunner()
        logs.collect(self.ctx(rn))
        self.assertEqual(self.sec("disk_health")["data"]["method"], "powershell")

    def test_chkdsk_only_when_requested_and_no_switches(self):
        rn = FakeRunner()
        logs.collect(self.ctx(rn))
        self.assertEqual(rn.argvs("chkdsk"), [])
        self.assertEqual(self.item("disk_health", "chkdsk")["status"], "skipped")
        logs.collect(self.ctx(rn, options={"chkdsk": True}))
        self.assertEqual(rn.argvs("chkdsk"), [["chkdsk", "W:"]])
        self.assertEqual([t for a, t in rn.calls if a[0] == "chkdsk"], [77])


class Pending(Base):
    def test_pending_flags(self):
        self.write(self.windir + "\\WinSxS\\pending.xml", b"<x/>")
        reg = FakeReg(exists={"RebootPending"}, values={"PendingFileRenameOperations": ["a", "", "b", ""]})
        logs.collect(self.ctx(reg=reg))
        d = self.sec("pending")["data"]
        self.assertTrue(d["reboot_pending"])
        self.assertFalse(d["packages_pending"])
        self.assertEqual(d["pending_file_rename_count"], 2)
        self.assertTrue(d["any_pending"])
        self.assertEqual(self.item("pending", "reboot.xml")["reason"], "not present (normal)")

    def test_nothing_pending(self):
        logs.collect(self.ctx())
        self.assertFalse(self.sec("pending")["data"]["any_pending"])


class Resilience(Base):
    def test_no_target_skips_everything(self):
        rn = FakeRunner()
        logs.collect(self.ctx(rn, target=False))
        for n in SECTIONS:
            self.assertEqual(self.sec(n)["status"], "skipped")
            self.assertEqual(self.sec(n)["reason"], "no target")
        self.assertEqual(rn.calls, [])

    def test_exception_in_one_section_does_not_stop_others(self):
        class Boom(FakeRunner):
            def run(self, argv, purpose, timeout=120, **kw):
                if argv[0] == "wevtutil":
                    raise RuntimeError("boom")
                return super().run(argv, purpose, timeout)
        self.write(self.windir + "\\System32\\winevt\\Logs\\System.evtx")
        logs.collect(self.ctx(Boom()))
        self.assertEqual(self.sec("event_logs")["status"], "error")
        self.assertIn("boom", self.sec("event_logs")["reason"])
        for n in ("bcd", "logs_host", "disk_health", "pending"):
            self.assertIn(n, self.case.data["sections"])
        self.assertEqual(self.sec("pending")["status"], "ok")


if __name__ == "__main__":
    unittest.main()
