"""Tests for modules/drivers.py. Nothing here runs a real program: classify() and a dry-run Runner only."""
import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from recoverykit.core.case import Case
from recoverykit.core.context import Ctx, Target
from recoverykit.core.runner import Runner, Refused, classify, REPAIR
from recoverykit.modules import drivers, repair
from tests.test_repair import ScriptedUI

GUID = "\\\\?\\Volume{aaaa-bbbb}\\"
DAY = 86400
NOW = time.time()


def inf(provider="Acme", cls="Net", ver="10/21/2025,1.2.3.4", extra=""):
    return ("; comment\n[Version]\nSignature=\"$WINDOWS NT$\"\nProvider=%s\nClass=%s\n"
            "ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\nDriverVer=%s\nCatalogFile=acme.cat\n%s"
            % (provider, cls, ver, extra))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rk-drv-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.case = Case(os.path.join(self.tmp, "cases"))
        self.addCleanup(self.case.close)
        self.root = os.path.join(self.tmp, "target") + os.sep
        self.windir = os.path.join(self.root, "Windows")
        self.infdir = os.path.join(self.windir, "INF")
        os.makedirs(self.infdir)
        os.makedirs(os.path.join(self.windir, "System32", "config"))

        self.put("oem1.inf", inf("Acme", "Net"), age=100)
        self.put("oem2.inf", inf("StorCo", "SCSIAdapter", "03/04/2024,9.0"), age=40)
        self.put("oem3.inf", inf("Realtek", "Net", "11/01/2026,10.1.2.3"), age=5)
        self.put("oem12.inf", inf("Gfx", "Display"), age=2)
        self.put("oem4.inf", inf("Wide", "HDC"), age=20, enc="utf-16")
        self.put("oem5.inf", inf("%Mfg%", "%Cls%", "%Dv%", '\n[Strings]\nMfg="Tokens Inc"\nCls = "System"\nDv=\"01/02/2025,7.7\"\n'),
                 age=10)
        self.put("oem6.inf", None, age=50)  # garbage
        self.put("netrt.inf", inf("Microsoft"), age=0)  # inbox style: ignored but newest mtime of all
        self.put("oemx.inf", inf("Nope"), age=1)  # not oem<digits>: ignored
        self.put("oem7.txt", "x", age=1)

    def put(self, name, text, age, enc="utf-8"):
        p = os.path.join(self.infdir, name)
        with open(p, "wb") as f:
            if text is None:
                f.write(b"\xff\xfe\x00garbage\x80\x81\x00\xff")
                f.write(os.urandom(0))
            elif enc == "utf-16":
                f.write(b"\xff\xfe" + text.encode("utf-16-le"))
            else:
                f.write(text.encode(enc))
        ts = NOW - age * DAY
        os.utime(p, (ts, ts))


class Ctxed(Base):
    def setUp(self):
        super().setUp()
        self.ui = ScriptedUI()
        self.runner = Runner(self.case, self.ui, self.tmp, dry_run=True)
        vol = {"guid_path": GUID, "letter": "W", "fs": "NTFS", "extents": [{"disk": 1}]}
        disk = {"number": 1, "style": "GPT", "partitions": []}
        self.target = Target(root=self.root, windir=self.windir, online=False, letter="W", volume=vol, disk=disk,
                             partition=None, info={})
        self.ctx = Ctx(kit_root=self.tmp, cfg={}, env={}, case=self.case, ui=self.ui, runner=self.runner,
                       inventory={"volumes": []}, target=self.target)
        p = mock.patch.object(repair.winapi, "volumes", return_value=[dict(vol)])
        p.start()
        self.addCleanup(p.stop)

    def audit(self):
        with open(self.case.path("audit.log"), encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]


class InventoryTests(Base):
    def test_only_oem_numbered_inf_listed_newest_first(self):
        inv = drivers.inventory(self.windir)
        self.assertEqual([d["inf"] for d in inv],
                         ["oem12.inf", "oem3.inf", "oem5.inf", "oem4.inf", "oem2.inf", "oem6.inf", "oem1.inf"])
        self.assertEqual(sorted([d["installed_ts"] for d in inv], reverse=True), [d["installed_ts"] for d in inv])

    def test_parsing_utf8(self):
        d = next(x for x in drivers.inventory(self.windir) if x["inf"] == "oem3.inf")
        self.assertEqual((d["provider"], d["class"], d["driver_date"], d["driver_version"]),
                         ("Realtek", "Net", "2026-11-01", "10.1.2.3"))
        self.assertEqual(d["catalog"], "acme.cat")
        self.assertEqual(d["class_guid"], "{4d36e972-e325-11ce-bfc1-08002be10318}")
        self.assertGreater(d["size"], 0)
        self.assertRegex(d["installed"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d$")
        self.assertFalse(d["boot_critical"])
        self.assertNotIn("error", d)

    def test_utf16_bom(self):
        d = next(x for x in drivers.inventory(self.windir) if x["inf"] == "oem4.inf")
        self.assertEqual(d["provider"], "Wide")
        self.assertTrue(d["boot_critical"])  # HDC

    def test_strings_tokens_resolved(self):
        d = next(x for x in drivers.inventory(self.windir) if x["inf"] == "oem5.inf")
        self.assertEqual((d["provider"], d["class"], d["driver_date"], d["driver_version"]),
                         ("Tokens Inc", "System", "2025-01-02", "7.7"))
        self.assertTrue(d["boot_critical"])

    def test_boot_critical_flag(self):
        inv = {d["inf"]: d for d in drivers.inventory(self.windir)}
        self.assertTrue(inv["oem2.inf"]["boot_critical"])   # SCSIAdapter, case-insensitive
        self.assertFalse(inv["oem1.inf"]["boot_critical"])  # Net
        self.assertFalse(inv["oem12.inf"]["boot_critical"])  # Display

    def test_garbage_listed_without_crash(self):
        d = next(x for x in drivers.inventory(self.windir) if x["inf"] == "oem6.inf")
        self.assertIsNone(d["provider"])
        self.assertFalse(d["boot_critical"])

    def test_unreadable_file_has_error(self):
        real = drivers._read_text

        def bad(path):
            if path.endswith("oem1.inf"):
                raise PermissionError(13, "Access is denied")
            return real(path)
        with mock.patch.object(drivers, "_read_text", bad):
            d = next(x for x in drivers.inventory(self.windir) if x["inf"] == "oem1.inf")
        self.assertIn("Access is denied", d["error"])
        self.assertIsNotNone(d["installed"])

    def test_oversized_file_is_skipped_not_an_error_entry(self):
        with open(os.path.join(self.infdir, "oem9.inf"), "wb") as f:
            f.write(b"x" * (drivers.MAX_INF_BYTES + 10))
        d = next(x for x in drivers.inventory(self.windir) if x["inf"] == "oem9.inf")
        self.assertEqual(d["skipped"], "larger than 2 MB")
        self.assertNotIn("error", d)

    def test_missing_folder_raises(self):
        with self.assertRaises(OSError):
            drivers.inventory(os.path.join(self.tmp, "nowhere"))


class CollectTests(Ctxed):
    def test_collect_writes_json_and_section(self):
        drivers.collect(self.ctx)
        sec = self.case.data["sections"]["drivers"]
        self.assertEqual(sec["status"], "ok")
        data = sec["data"]
        self.assertEqual(data["count"], 7)
        self.assertEqual(data["recent_days"], 30)
        self.assertEqual(len(data["newest"]), 7)
        self.assertEqual(data["newest"][0]["inf"], "oem12.inf")
        self.assertNotIn("installed_ts", data["newest"][0])
        with open(self.case.path("inventory", "drivers.json"), encoding="utf-8") as f:
            self.assertEqual(len(json.load(f)), 7)
        self.assertIn("  oem3.inf  ", self.ui.text)
        self.assertIn("Realtek  Net  10.1.2.3", self.ui.text)
        self.assertNotIn("oem3.inf  %s  Realtek  Net  10.1.2.3 [boot", self.ui.text)

    def test_recent_is_relative_to_newest_inf_not_today(self):
        # newest INF anywhere is netrt.inf (age 0); 30 days back includes oem12, oem3, oem5, oem4(20d); not oem2 (40d)
        drivers.collect(self.ctx)
        self.assertEqual(self.case.data["sections"]["drivers"]["data"]["recent"],
                         ["oem12.inf", "oem3.inf", "oem5.inf", "oem4.inf"])
        self.assertIn("[boot-critical class]", self.ui.text)

    def test_recent_when_machine_was_off_for_months(self):
        for n in os.listdir(self.infdir):
            p = os.path.join(self.infdir, n)
            ts = os.stat(p).st_mtime - 200 * DAY
            os.utime(p, (ts, ts))
        drivers.collect(self.ctx)
        self.assertEqual(len(self.case.data["sections"]["drivers"]["data"]["recent"]), 4)

    def test_inbox_newest_sets_the_reference(self):
        p = os.path.join(self.infdir, "netrt.inf")
        os.utime(p, (NOW - 3 * DAY, NOW - 3 * DAY))
        # newest is now oem12 (2d); oem4 (20d) still within 30d, oem2 (40d) not
        drivers.collect(self.ctx)
        self.assertNotIn("oem2.inf", self.case.data["sections"]["drivers"]["data"]["recent"])

    def test_no_target_skipped(self):
        self.ctx.target = None
        drivers.collect(self.ctx)
        self.assertEqual(self.case.data["sections"]["drivers"]["status"], "skipped")

    def test_missing_inf_folder(self):
        shutil.rmtree(self.infdir)
        drivers.collect(self.ctx)
        self.assertEqual(self.case.data["sections"]["drivers"]["status"], "missing")


class StepTests(Ctxed):
    def test_remove_driver_step(self):
        s = drivers.remove_driver_step(self.ctx, "oem3.inf")
        self.assertEqual(s.id, "remove_driver")
        self.assertEqual(s.argv, ["dism", "/English", "/Image:W:\\", "/Remove-Driver", "/Driver:oem3.inf"])
        self.assertEqual(classify(s.argv)[0], REPAIR)
        self.assertIn("Realtek", s.evidence)
        self.assertIn("Net", s.evidence)
        self.assertNotIn("HIGH", s.risk)
        self.assertTrue(s.effect)
        self.assertTrue(s.target_check()[0])

    def test_case_insensitive_name(self):
        self.assertEqual(drivers.remove_driver_step(self.ctx, "OEM3.INF").argv[-1], "/Driver:oem3.inf")

    def test_boot_critical_warning(self):
        s = drivers.remove_driver_step(self.ctx, "oem2.inf")
        self.assertIn("HIGH", s.risk)
        self.assertIn("unbootable", s.risk)

    def test_validation(self):
        for bad in ("", "oem.inf", "oem3.inf ", "netrt.inf", "oem3.inf;x", "..\\oem3.inf", "oem3", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                drivers.remove_driver_step(self.ctx, bad)
        with self.assertRaises(ValueError) as cm:
            drivers.remove_driver_step(self.ctx, "oem99.inf")  # valid name, not installed
        self.assertIn("not an installed", str(cm.exception))
        self.target.letter = None
        with self.assertRaises(ValueError) as cm:
            drivers.remove_driver_step(self.ctx, "oem3.inf")
        self.assertIn("no drive letter", str(cm.exception))
        with self.assertRaises(ValueError):
            drivers.list_drivers_step(self.ctx)

    def test_list_drivers_step(self):
        s = drivers.list_drivers_step(self.ctx)
        self.assertEqual(s.id, "list_drivers")
        self.assertEqual(s.argv, ["dism", "/English", "/Image:W:\\", "/Get-Drivers", "/Format:Table"])
        self.assertEqual(classify(s.argv)[0], REPAIR)


class RunnerIntegrationTests(Ctxed):
    def test_dry_run_and_audit(self):
        step = drivers.remove_driver_step(self.ctx, "oem3.inf")
        self.runner.repairs_enabled = True
        self.ui.answers = ["yes"]
        res = self.runner.repair(step)
        self.assertEqual(res.kind, "dry-run")
        last = self.audit()[-1]
        self.assertEqual(last["kind"], "dry-run")
        self.assertIn("/Remove-Driver", last["command"])

    def test_online_target_refused(self):
        step = drivers.remove_driver_step(self.ctx, "oem3.inf")
        self.runner.repairs_enabled = True
        self.runner.target_online = True
        with self.assertRaises(Refused):
            self.runner.repair(step)
        self.assertEqual(self.audit()[-1]["kind"], "refused")

    def test_not_enabled_refused(self):
        with self.assertRaises(Refused):
            self.runner.repair(drivers.remove_driver_step(self.ctx, "oem3.inf"))


class MenuTests(Ctxed):
    def test_remove_through_menu_dry_run(self):
        # choose remove, number 1 (oem12.inf), enable repairs yes, runner yes, back
        self.ui.answers = ["remove", "1", "yes", "yes", "back"]
        drivers.run_menu(self.ctx)
        self.assertFalse(self.runner.repairs_enabled)
        self.assertIn("oem12.inf", self.ui.text)
        log = self.case.data["repair_log"]
        self.assertEqual([e["id"] for e in log], ["remove_driver"])
        self.assertEqual(log[0]["kind"], "dry-run")

    def test_declined_enable_runs_nothing(self):
        self.ui.answers = ["remove", "1", "no", "back"]
        drivers.run_menu(self.ctx)
        self.assertFalse(os.path.exists(self.case.path("audit.log")))
        self.assertFalse(self.runner.repairs_enabled)

    def test_refused_shown_and_flag_reset(self):
        self.runner.target_online = True
        self.ui.answers = ["dism", "yes", "back"]
        drivers.run_menu(self.ctx)
        self.assertIn("Refused:", self.ui.text)
        self.assertFalse(self.runner.repairs_enabled)

    def test_bad_number(self):
        self.ui.answers = ["remove", "99", "back"]
        drivers.run_menu(self.ctx)
        self.assertIn("Not a number", self.ui.text)

    def test_no_target_and_online(self):
        self.ctx.target = None
        drivers.run_menu(self.ctx)
        self.assertIn("no target", self.ui.text)
        self.ctx.target = self.target
        self.target.online = True
        drivers.run_menu(self.ctx)
        self.assertIn("running Windows", self.ui.text)
        self.assertEqual(self.ui.answers, [])


class SourceRuleTests(unittest.TestCase):
    def test_module_source_rules(self):
        p = os.path.join(os.path.dirname(drivers.__file__), "drivers.py")
        with open(p, "rb") as f:
            src = f.read()
        src.decode("ascii")
        text = src.decode("ascii")
        for bad in ("import subprocess", "import ctypes", "print(", "input(", "os.system"):
            self.assertNotIn(bad, text)


if __name__ == "__main__":
    unittest.main()
