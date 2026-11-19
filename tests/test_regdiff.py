"""Tests for recoverykit.modules.regdiff (offline fake hives, real Case in a temp dir)."""
import copy
import json
import os
import shutil
import tempfile
import unittest

from recoverykit.core.case import Case
from recoverykit.core.context import RegView
from recoverykit.core.ui import UI
from recoverykit.modules import regdiff
from tests.fakewin import dword, make_hive, multi, sz


class FakeUI(UI):
    def __init__(self):
        super().__init__(auto=True)
        self.lines = []

    def say(self, text=""):
        self.lines.append(text)


class FakeTarget:
    def __init__(self, reg):
        self.reg = reg


class FakeCtx:
    def __init__(self, case, target):
        self.case, self.target, self.ui = case, target, FakeUI()


def _svc(start, image=None, typ=1):
    vals = {"Start": dword(start), "Type": dword(typ), "ErrorControl": dword(1)}
    if image is not None:
        vals["ImagePath"] = sz(image)
    return {"values": vals}


def build_target(root, bad=False, extra_service=False, run_extra=False, drop_service=False):
    cfg = os.path.join(root, "Windows", "System32", "config")
    cbs = {"keys": {"RebootPending": {}, "PackagesPending": {}, "SessionsPending": {}} if bad else {}}
    run = {"values": {"Updater": sz("c:\\x\\updater.exe")}}
    if run_extra:
        run["values"]["NewThing"] = sz("c:\\x\\new.exe")
    cur = "Microsoft\\Windows\\CurrentVersion"
    software = {"keys": {"Microsoft": {"keys": {
        "Windows NT": {"keys": {"CurrentVersion": {
            "values": {"CurrentBuild": sz("26100"), "UBR": dword(8875), "EditionID": sz("Core"),
                       "DisplayVersion": sz("24H2")},
            "keys": {"Winlogon": {"values": {
                "Shell": sz("cmd.exe" if bad else "Explorer.exe"),
                "Userinit": sz("c:\\evil\\u.exe," if bad else "C:\\Windows\\system32\\userinit.exe,")}}}}}},
        "Windows": {"keys": {"CurrentVersion": {"keys": {
            "Component Based Servicing": cbs, "Run": run}}}},
    }}}}
    services = {"Tcpip": _svc(0, "System32\\drivers\\tcpip.sys"),
                "Spooler": _svc(2, "%SystemRoot%\\System32\\spoolsv.exe", 16),
                "Odd": _svc(0 if bad else 3, "\\??\\C:\\ProgramData\\odd.sys"),
                "NoPath": _svc(1 if bad else 3)}
    if drop_service:
        del services["Spooler"]
    if extra_service:
        services["NewSvc"] = _svc(3, "System32\\drivers\\new.sys")
    control = {"keys": {
        "Session Manager": {"values": {"BootExecute": multi(["autocheck autochk /r" if bad else "autocheck autochk *"]),
                                       "PendingFileRenameOperations": multi(["a", "b"])}},
        "CrashControl": {"values": {"CrashDumpEnabled": dword(7), "AutoReboot": dword(1)}},
    }}
    if bad:
        control["keys"]["SafeBoot"] = {"keys": {"Option": {"values": {"OptionValue": dword(1)}}}}
    system = {"keys": {
        "Select": {"values": {"Current": dword(1), "Default": dword(2 if bad else 1),
                              "LastKnownGood": dword(2), "Failed": dword(1 if bad else 0)}},
        "Setup": {"values": {"SystemSetupInProgress": dword(1 if bad else 0), "SetupType": dword(0),
                             "CmdLine": sz("oobe\\setup.exe" if bad else ""), "OOBEInProgress": dword(0)}},
        "ControlSet001": {"keys": {"Control": control, "Services": {"keys": services}}},
    }}
    make_hive(os.path.join(cfg, "SOFTWARE"), software)
    make_hive(os.path.join(cfg, "SYSTEM"), system)
    return os.path.join(root, "Windows")


def run_case(out_root, case_id, windir, mutate=None):
    """One collect() run in a fresh Case moved under case_id. Returns (case, ctx)."""
    case = Case(out_root)
    case.assign(case_id)
    reg = RegView(windir, online=False)
    ctx = FakeCtx(case, FakeTarget(reg))
    regdiff.collect(ctx)
    reg.close()
    case.close()
    return case, ctx


class RegdiffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rk_regdiff_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def snap(self, name, **kw):
        root = os.path.join(self.tmp, name)
        reg = RegView(build_target(root, **kw), online=False)
        try:
            return regdiff.snapshot(reg)
        finally:
            reg.close()

    def test_snapshot_contents(self):
        s = self.snap("clean")
        json.dumps(s)
        self.assertEqual(s["services"]["Tcpip"], {"start": 0, "type": 1, "image_path": "System32\\drivers\\tcpip.sys",
                                                  "error_control": 1})
        self.assertIsNone(s["services"]["NoPath"]["image_path"])
        self.assertEqual(s["control"]["BootExecute"], ["autocheck autochk *"])
        self.assertEqual(s["control"]["PendingFileRenameOperations_count"], 2)
        self.assertEqual(s["control"]["Select_Current"], 1)
        self.assertEqual(s["control"]["CrashDumpEnabled"], 7)
        self.assertFalse(any(s["servicing"].values()))
        self.assertEqual(s["version"]["CurrentBuild"], "26100")
        self.assertEqual(s["version"]["UBR"], 8875)
        self.assertEqual(s["winlogon"]["Shell"], "Explorer.exe")
        self.assertEqual(s["run"][regdiff.RUN_KEYS[0] + "\\Updater"], "c:\\x\\updater.exe")

    def test_notable_clean_is_empty(self):
        self.assertEqual(regdiff.notable(self.snap("clean")), [])

    def test_notable_bad_fires_every_rule(self):
        text = "\n".join(regdiff.notable(self.snap("bad", bad=True)))
        for needle in ("SafeBoot", "setup is in progress", "control sets do not match", "RebootPending",
                       "PackagesPending", "SessionsPending", "BootExecute", "Winlogon Shell", "Userinit",
                       "boot/system-start service Odd has an unusual image path"):
            self.assertIn(needle, text)
        self.assertNotIn("service NoPath", text)   # in-box kernel drivers have no ImagePath: not a finding
        self.assertNotIn("service Tcpip", text)
        self.assertNotIn("service Spooler", text)
        text.encode("ascii")

    def test_notable_userinit_without_comma_ok_and_unusual_cap(self):
        s = self.snap("clean")
        s["winlogon"]["Userinit"] = "C:\\Windows\\system32\\USERINIT.EXE"
        for i in range(25):
            s["services"]["bad%d" % i] = {"start": 1, "type": 1, "image_path": "d:\\x%d.sys" % i, "error_control": 1}
        out = regdiff.notable(s)
        self.assertEqual(len([x for x in out if "unusual image path" in x and x.startswith("boot")]), 20)
        self.assertFalse(any("Userinit" in x for x in out))

    def test_diff(self):
        old = self.snap("a")
        new = self.snap("b", extra_service=True, run_extra=True, drop_service=True)
        new["services"]["Tcpip"]["start"] = 4
        new["control"]["CrashDumpEnabled"] = 0
        d = "\n".join(regdiff.diff(old, new))
        self.assertIn("service NewSvc added (image path System32\\drivers\\new.sys)", d)
        self.assertIn("service Spooler removed", d)
        self.assertIn("service Tcpip start 0 -> 4", d)
        self.assertIn("control CrashDumpEnabled: 7 -> 0", d)
        self.assertIn("run entry added: " + regdiff.RUN_KEYS[0] + "\\NewThing", d)
        self.assertEqual(regdiff.diff(old, copy.deepcopy(old)), [])

    def test_diff_cap(self):
        old, new = self.snap("a"), self.snap("b")
        for i in range(250):
            new["services"]["x%d" % i] = {"start": 3, "type": 1, "image_path": None, "error_control": 1}
        out = regdiff.diff(old, new)
        self.assertEqual(len(out), 201)
        self.assertIn("50 more", out[-1])

    def test_two_runs_same_case(self):
        out_root = os.path.join(self.tmp, "cases")
        w1 = build_target(os.path.join(self.tmp, "t1"))
        c1, ctx1 = run_case(out_root, "CASE1", w1)
        sec1 = c1.data["sections"]["registry"]
        self.assertEqual(sec1["status"], "ok")
        self.assertIsNone(sec1["data"]["previous_run"])
        self.assertEqual(sec1["data"]["changes"], [])
        self.assertTrue(os.path.isfile(c1.path("inventory", "registry-snapshot.json")))
        self.assertFalse(os.path.exists(c1.path("inventory", "registry-changes.txt")))
        self.assertEqual(sec1["data"]["counts"]["services"], 4)

        w2 = build_target(os.path.join(self.tmp, "t2"), extra_service=True)
        c2, ctx2 = run_case(out_root, "CASE1", w2)
        self.assertNotEqual(c1.dir, c2.dir)
        sec2 = c2.data["sections"]["registry"]
        self.assertEqual(sec2["data"]["previous_run"], os.path.basename(c1.dir))
        self.assertTrue(any("NewSvc added" in x for x in sec2["data"]["changes"]))
        with open(c2.path("inventory", "registry-changes.txt"), encoding="utf-8") as f:
            self.assertIn("NewSvc", f.read())

    def test_bad_hive_notable_said_and_dirty_item(self):
        root = os.path.join(self.tmp, "t")
        windir = build_target(root, bad=True)
        make_hive(os.path.join(windir, "System32", "config", "SOFTWARE"), {}, dirty=True)
        c, ctx = run_case(os.path.join(self.tmp, "cases"), "CASE2", windir)
        sec = c.data["sections"]["registry"]
        self.assertTrue(any(l.startswith("  ! ") for l in ctx.ui.lines))
        self.assertTrue(any(i["name"] == "hive SOFTWARE" and i["status"] == "ok" and "not cleanly flushed" in i["reason"]
                            for i in sec["items"]))

    def test_missing_hive_is_error_item(self):
        windir = os.path.join(self.tmp, "empty", "Windows")
        os.makedirs(os.path.join(windir, "System32", "config"))
        c, _ = run_case(os.path.join(self.tmp, "cases"), "CASE3", windir)
        sec = c.data["sections"]["registry"]
        self.assertEqual({i["name"] for i in sec["items"] if i["status"] == "error"}, {"hive SOFTWARE", "hive SYSTEM"})

    def test_no_target(self):
        case = Case(os.path.join(self.tmp, "cases"))
        regdiff.collect(FakeCtx(case, None))
        case.close()
        sec = case.data["sections"]["registry"]
        self.assertEqual((sec["status"], sec["reason"]), ("skipped", "no target"))

    def test_pending_case_has_no_previous(self):
        case = Case(os.path.join(self.tmp, "cases"))
        reg = RegView(build_target(os.path.join(self.tmp, "t")), online=False)
        regdiff.collect(FakeCtx(case, FakeTarget(reg)))
        reg.close()
        case.close()
        self.assertIsNone(case.data["sections"]["registry"]["data"]["previous_run"])

    def test_corrupt_previous_snapshot(self):
        out_root = os.path.join(self.tmp, "cases")
        w = build_target(os.path.join(self.tmp, "t1"))
        c1, _ = run_case(out_root, "CASE4", w)
        with open(c1.path("inventory", "registry-snapshot.json"), "w") as f:
            f.write("{not json")
        c2, _ = run_case(out_root, "CASE4", w)
        sec = c2.data["sections"]["registry"]
        self.assertEqual(sec["status"], "ok")
        errs = [i for i in sec["items"] if i["status"] == "error"]
        self.assertEqual(len(errs), 1)
        self.assertIn("previous snapshot", errs[0]["name"])
        self.assertIsNone(sec["data"]["previous_run"])
        self.assertFalse(os.path.exists(c2.path("inventory", "registry-changes.txt")))


if __name__ == "__main__":
    unittest.main()
