"""Tests for modules/repair.py. Nothing here runs a real program: dry-run Runner or no Runner call at all."""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from recoverykit.core.case import Case
from recoverykit.core.context import Ctx, Target
from recoverykit.core.runner import Runner, Result, RepairStep, Refused, classify, classify_diskpart, REPAIR, HOST
from recoverykit.core.ui import UI
from recoverykit.modules import repair
from tests.test_wim import make_wim, img

GUID = "\\\\?\\Volume{aaaa-bbbb}\\"


class ScriptedUI(UI):
    def __init__(self, answers=()):
        super().__init__(auto=False)
        self.answers = list(answers)
        self.said = []

    def say(self, text=""):
        self.said.append(str(text))

    def raw(self, line):
        self.said.append(line)

    def _pop(self):
        return self.answers.pop(0)

    def ask(self, prompt, default="", secret=False):
        return self._pop()

    def choose(self, title, options, default=None):
        return self._pop()

    def confirm_yes(self, question):
        return self._pop() == "yes"

    @property
    def text(self):
        return "\n".join(self.said)


class Base(unittest.TestCase):
    letter = "W"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rk-repair-")
        self.case = Case(os.path.join(self.tmp, "cases"))
        self.addCleanup(self._cleanup)
        self.root = os.path.join(self.tmp, "target") + os.sep
        os.makedirs(os.path.join(self.root, "Windows", "System32", "config"))
        os.makedirs(os.path.join(self.root, "Users", "bob"))
        with open(os.path.join(self.root, "Users", "bob", "a.txt"), "wb") as f:
            f.write(b"x" * 1000)
        self.ui = ScriptedUI()
        self.runner = Runner(self.case, self.ui, self.tmp, dry_run=True)
        disk = {"number": 1, "style": "GPT", "partitions": [
            {"number": 1, "type": "EFI System", "letter": None},
            {"number": 3, "type": "Basic data", "letter": self.letter}]}
        vol = {"guid_path": GUID, "letter": self.letter, "fs": "NTFS", "extents": [{"disk": 1}]}
        self.target = Target(root=self.root, windir=os.path.join(self.root, "Windows"), online=False,
                             letter=self.letter, volume=vol, disk=disk, partition=disk["partitions"][1],
                             info={"build": "26100", "edition": "Core", "architecture": "x64",
                                   "language": "en-US", "ui_languages": ["en-US"]})
        self.ctx = Ctx(kit_root=self.tmp, cfg={}, env={"firmware": "UEFI"}, case=self.case, ui=self.ui,
                       runner=self.runner, inventory={"volumes": [{"letter": "C", "fs": "NTFS"}]}, target=self.target)
        p = mock.patch.object(repair.winapi, "volumes", return_value=[dict(vol)])
        p.start()
        self.addCleanup(p.stop)

    def _cleanup(self):
        self.case.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ids(self, steps):
        return [s.id for s in steps]

    def step(self, steps, sid):
        return next(s for s in steps if s.id == sid)

    def audit(self):
        with open(self.case.path("audit.log"), encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]


def kind_of(step):
    if step.diskpart is not None:
        return classify_diskpart(step.diskpart)[0]
    # The wrapper is given the case folder at run time (robocopy /LOG must be inside it): derive it
    # here from the step's own /LOG:<case>\logs\<file> argument, as Runner.repair would know it.
    case_dir = None
    for a in step.argv:
        if str(a).upper().startswith("/LOG:"):
            case_dir = os.path.dirname(os.path.dirname(str(a)[5:]))
    return classify(step.argv, case_dir=case_dir)[0]


class SourceTests(Base):
    def wim(self, name, images, **kw):
        return make_wim(os.path.join(self.tmp, name), images, **kw)

    def test_mismatch_refused_and_restorehealth_without_source(self):
        p = self.wim("lt.wim", [img(build=26200, languages=("lt-LT",))])
        res = repair.check_source(self.ctx, p)
        self.assertFalse(res["ok"])
        self.assertIn("REFUSED", self.ui.text)
        self.assertIn("0x800f0915", self.ui.text)
        self.assertEqual(self.case.data["source_check"]["ok"], False)
        self.assertEqual(self.case.data["sections"]["source_check"]["status"], "ok")
        rh = self.step(repair.repair_steps(self.ctx), "restorehealth")
        self.assertFalse([a for a in rh.argv if a.lower().startswith("/source")])
        self.assertNotIn("/LimitAccess", rh.argv)
        self.assertIn("refused", rh.evidence)
        self.assertIn("language", rh.evidence)

    def test_matching_source_adds_source_and_limitaccess(self):
        p = self.wim("ok.wim", [img(edition="Professional"), img()])
        res = repair.check_source(self.ctx, p)
        self.assertTrue(res["ok"])
        self.assertEqual(res["index"], 2)  # picked by edition, no question asked
        rh = self.step(repair.repair_steps(self.ctx), "restorehealth")
        self.assertIn("/Source:wim:%s:2" % p, rh.argv)
        self.assertIn("/LimitAccess", rh.argv)

    def test_esd_prefix(self):
        p = self.wim("ok.esd", [img()])
        repair.check_source(self.ctx, p)
        rh = self.step(repair.repair_steps(self.ctx), "restorehealth")
        self.assertIn("/Source:esd:%s:1" % p, rh.argv)

    def test_split_source_adds_export_before_restorehealth(self):
        p = self.wim("install.swm", [img()], part=1, total=2)
        res = repair.check_source(self.ctx, p)
        self.assertTrue(res["is_split"])
        steps = repair.repair_steps(self.ctx)
        ids = self.ids(steps)
        self.assertLess(ids.index("export_source"), ids.index("restorehealth"))
        ex = self.step(steps, "export_source")
        self.assertFalse(ex.touches_target)
        self.assertIn("/SourceImageFile:%s" % p, ex.argv)
        self.assertIn("/SWMFile:%s" % os.path.join(self.tmp, "install*.swm"), ex.argv)
        dest = self.case.path("exports", "repair-source.wim")
        self.assertIn("/DestinationImageFile:%s" % dest, ex.argv)
        rh = self.step(steps, "restorehealth")
        self.assertIn("/Source:wim:%s:1" % dest, rh.argv)

    def test_garbage_file_refused_without_exception(self):
        p = os.path.join(self.tmp, "junk.wim")
        with open(p, "wb") as f:
            f.write(b"junk")
        res = repair.check_source(self.ctx, p)
        self.assertFalse(res["ok"])
        self.assertTrue(res["errors"])

    def test_given_index_unknown(self):
        p = self.wim("ok.wim", [img()])
        self.assertFalse(repair.check_source(self.ctx, p, index=7)["ok"])

    def test_choose_when_no_edition_matches(self):
        p = self.wim("two.wim", [img(edition="Professional"), img(edition="Enterprise")])
        self.ui.answers = [2]
        res = repair.check_source(self.ctx, p)
        self.assertEqual(res["index"], 2)
        self.assertFalse(res["ok"])


class StepTests(Base):
    def test_step_order_and_contract(self):
        steps = repair.repair_steps(self.ctx)
        self.assertEqual(self.ids(steps), ["scanhealth", "restorehealth", "sfc", "list_packages"])
        for s in steps:
            self.assertIsNotNone(s.target_check)
            self.assertTrue(s.effect)
            self.assertTrue(s.risk)
        self.assertIn("/Image:W:\\", self.step(steps, "scanhealth").argv)
        self.assertIn("does not prove", self.step(steps, "sfc").effect)
        self.assertNotIn("chkdsk_fix", self.ids(steps))

    def test_no_letter_only_assign_letter(self):
        self.target.letter = None
        self.target.volume["letter"] = None
        self.ctx.inventory["volumes"] = [{"letter": "W"}, {"letter": "C"}]
        steps = repair.repair_steps(self.ctx)
        self.assertEqual(self.ids(steps), ["assign_letter"])
        self.assertEqual(steps[0].diskpart, ["select disk 1", "select partition 3", "assign letter=V"])
        self.assertIn("no data is changed", steps[0].effect)

    def test_scratch_dir_rules(self):
        self.ctx.inventory["volumes"] = []
        self.assertIsNone(repair.scratch_dir(self.ctx))  # case volume not in inventory
        drive = os.path.splitdrive(self.case.dir)[0][:1].upper()
        self.ctx.inventory["volumes"].append({"letter": drive, "fs": "NTFS"})
        with mock.patch.object(repair.shutil, "disk_usage", return_value=mock.Mock(free=10 * 1024 ** 3)):
            d = repair.scratch_dir(self.ctx)
            self.assertEqual(d, self.case.path("scratch"))
            self.assertTrue(os.path.isdir(d))
            sc = self.step(repair.repair_steps(self.ctx), "scanhealth")
            self.assertIn("/ScratchDir:%s" % d, sc.argv)
        with mock.patch.object(repair.shutil, "disk_usage", return_value=mock.Mock(free=1024 ** 3)):
            self.assertIsNone(repair.scratch_dir(self.ctx))
        self.ctx.inventory["volumes"][-1]["fs"] = "FAT32"
        with mock.patch.object(repair.shutil, "disk_usage", return_value=mock.Mock(free=10 * 1024 ** 3)):
            self.assertIsNone(repair.scratch_dir(self.ctx))

    def test_remove_package(self):
        s = repair.remove_package_step(self.ctx, "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.8875.1.0")
        self.assertEqual(s.id, "remove_package")
        self.assertEqual(kind_of(s), REPAIR)
        for bad in ("", "a b", "x;y", "a\\b", "a&b", "x\n", '"q"'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                repair.remove_package_step(self.ctx, bad)

    def test_copy_out(self):
        dest = os.path.join(self.tmp, "backup")
        os.makedirs(dest)
        s = repair.copy_out_step(self.ctx, dest)
        self.assertEqual(s.id, "copy_out")
        self.assertFalse(s.touches_target)
        self.assertEqual(s.argv[:3], ["robocopy", self.root + "Users", os.path.join(dest, "Users")])
        self.assertEqual(kind_of(s), HOST)
        pre = repair.copy_out_precheck(self.ctx, dest)
        self.assertEqual(pre["needed"], 1000)
        self.assertTrue(pre["fits"])
        self.assertEqual(pre["errors"], 0)

    def test_copy_out_refuses_target_volume_and_missing_dest(self):
        inside = os.path.join(self.root, "Users", "bob")
        with self.assertRaises(ValueError) as cm:
            repair.copy_out_step(self.ctx, inside)
        self.assertIn("target volume", str(cm.exception))
        with self.assertRaises(ValueError):
            repair.copy_out_step(self.ctx, os.path.join(self.tmp, "nope"))
        # same drive letter as the target is also refused
        self.target.letter = os.path.splitdrive(self.tmp)[0][:1]
        with self.assertRaises(ValueError):
            repair.copy_out_step(self.ctx, self.tmp)

    def test_precheck_not_fitting(self):
        dest = os.path.join(self.tmp, "small")
        os.makedirs(dest)
        with mock.patch.object(repair.shutil, "disk_usage", return_value=mock.Mock(free=10)):
            self.assertFalse(repair.copy_out_precheck(self.ctx, dest)["fits"])

    def test_bcd_blockers_and_steps(self):
        self.assertTrue(any("export" in b for b in repair.bcd_blockers(self.ctx)))
        self.assertEqual(repair.bcd_steps(self.ctx), [])
        self.runner.bcd_backup = os.path.join(self.tmp, "bcd.export")
        self.assertEqual(repair.bcd_blockers(self.ctx), [])
        steps = repair.bcd_steps(self.ctx)
        self.assertEqual(self.ids(steps), ["assign_efi_letter", "bcdboot"])
        self.assertEqual(steps[0].diskpart, ["select disk 1", "select partition 1", "assign letter=S"])
        self.assertEqual(steps[1].argv, ["bcdboot", "W:\\Windows", "/s", "S:", "/f", "UEFI"])
        self.assertIn("bcd.export", steps[1].risk)
        # two EFI partitions -> blocked
        self.target.disk["partitions"].append({"number": 5, "type": "EFI System", "letter": None})
        self.assertEqual(repair.bcd_steps(self.ctx), [])
        self.assertTrue(any("EFI" in b for b in repair.bcd_blockers(self.ctx)))

    def test_bcd_blocked_on_mbr_and_no_letter(self):
        self.runner.bcd_backup = "x"
        self.target.disk["style"] = "MBR"
        self.assertEqual(repair.bcd_steps(self.ctx), [])
        self.target.disk["style"] = "GPT"
        self.target.letter = None
        self.assertTrue(any("letter" in b for b in repair.bcd_blockers(self.ctx)))

    def test_every_step_classifies_as_repair_or_host(self):
        dest = os.path.join(self.tmp, "backup")
        os.makedirs(dest)
        p = make_wim(os.path.join(self.tmp, "install.swm"), [img()], part=1, total=2)
        repair.check_source(self.ctx, p)
        self.runner.bcd_backup = "x"
        steps = repair.repair_steps(self.ctx) + repair.bcd_steps(self.ctx)
        steps += [repair.remove_package_step(self.ctx, "Pkg~1.0"), repair.copy_out_step(self.ctx, dest)]
        self.target.letter = None
        self.ctx.inventory["volumes"] = []
        steps += repair.repair_steps(self.ctx)
        self.assertIn("export_source", self.ids(steps))
        self.assertIn("assign_letter", self.ids(steps))
        for s in steps:
            self.assertIn(kind_of(s), (REPAIR, HOST), "%s: %s" % (s.id, s.argv or s.diskpart))

    def test_guidance(self):
        self.assertEqual(len(repair.GUIDANCE), 3)
        for g in repair.GUIDANCE:
            g.encode("ascii")
            self.assertIn("Test boot after it, and record the exact result", g)


class TargetCheckTests(Base):
    def test_ok(self):
        self.assertTrue(repair.target_check(self.ctx)[0])

    def test_changes_detected(self):
        vol = {"guid_path": GUID, "letter": "W", "extents": [{"disk": 1}]}
        for change, word in (({"extents": [{"disk": 2}]}, "disk"), ({"letter": "X"}, "letter")):
            with mock.patch.object(repair.winapi, "volumes", return_value=[dict(vol, **change)]):
                ok, msg = repair.target_check(self.ctx)
                self.assertFalse(ok)
                self.assertIn(word, msg)
        with mock.patch.object(repair.winapi, "volumes", return_value=[]):
            self.assertFalse(repair.target_check(self.ctx)[0])
        shutil.rmtree(os.path.join(self.root, "Windows", "System32", "config"))
        ok, msg = repair.target_check(self.ctx)
        self.assertFalse(ok)
        self.assertIn("System32", msg)


class RunnerIntegrationTests(Base):
    def setUp(self):
        super().setUp()
        self.runner.repairs_enabled = True

    def test_yes_gives_dry_run(self):
        self.ui.answers = ["yes"]
        step = self.step(repair.repair_steps(self.ctx), "scanhealth")
        res = self.runner.repair(step)
        self.assertEqual(res.error, "dry run: not executed")
        self.assertIsNone(res.rc)
        self.assertEqual(self.audit()[-1]["kind"], "dry-run")

    def test_no_gives_declined(self):
        self.ui.answers = ["no"]
        step = self.step(repair.repair_steps(self.ctx), "sfc")
        self.assertIsNone(self.runner.repair(step))
        self.assertEqual(self.audit()[-1]["kind"], "declined")

    def test_online_target_refused(self):
        self.runner.target_online = True
        step = self.step(repair.repair_steps(self.ctx), "scanhealth")
        with self.assertRaises(Refused):
            self.runner.repair(step)
        self.assertEqual(self.audit()[-1]["kind"], "refused")

    def test_target_recheck_failure_refused(self):
        step = self.step(repair.repair_steps(self.ctx), "scanhealth")
        with mock.patch.object(repair.winapi, "volumes", return_value=[]):
            with self.assertRaises(Refused):
                self.runner.repair(step)

    def test_bcdboot_refused_without_backup_then_allowed(self):
        backup = os.path.join(self.tmp, "b")
        with open(backup, "wb") as f:
            f.write(b"bcd export")
        self.assertTrue(self.runner.note_bcd_backup(backup))
        self.ui.answers = ["yes", "yes"]
        for s in repair.bcd_steps(self.ctx):
            self.assertEqual(self.runner.repair(s).error, "dry run: not executed")


class RecordTests(Base):
    def rec(self, out, rc=0, kind="repair", sid="scanhealth"):
        step = self.step(repair.repair_steps(self.ctx), sid)
        return repair.record(self.ctx, step, Result(step.argv, rc=rc, out=out, kind=kind))

    def test_findings(self):
        cases = [("The component store is repairable.", "repairable"),
                 ("No component store corruption detected.", "healthy"),
                 ("The component store cannot be repaired.", "not_repairable"),
                 ("The restore operation completed successfully.", "restored"),
                 ("Windows Resource Protection did not find any integrity violations.", "sfc_clean"),
                 ("Windows Resource Protection found corrupt files and successfully repaired them.", "sfc_repaired"),
                 ("found corrupt files but was unable to fix some of them.", "sfc_unrepaired"),
                 ("something else", None)]
        for out, want in cases:
            self.assertEqual(self.rec(out)["finding"], want, out)

    def test_error_code_and_section(self):
        e = self.rec("Error: 0x800f0915\nThe source files could not be found.", rc=1)
        self.assertEqual(e["error_code"], "0x800f0915")
        self.assertEqual(e["rc"], 1)
        self.assertIsNone(self.rec("fine")["error_code"])
        sec = self.case.data["sections"]["repairs"]
        self.assertEqual(sec["status"], "ok")
        self.assertIn("boot not confirmed", sec["reason"])
        self.assertEqual(len(sec["data"]["log"]), 2)
        self.assertEqual(len(self.case.data["repair_log"]), 2)

    def test_declined_and_note(self):
        step = self.step(repair.repair_steps(self.ctx), "sfc")
        e = repair.record(self.ctx, step, None, note="operator said no")
        self.assertEqual(e["kind"], "declined")
        self.assertEqual(e["note"], "operator said no")
        for k in ("id", "title", "command", "kind", "rc", "error", "time", "finding", "error_code", "note"):
            self.assertIn(k, e)

    def test_scan_finding_becomes_restorehealth_evidence(self):
        self.rec("The component store is repairable.")
        rh = self.step(repair.repair_steps(self.ctx), "restorehealth")
        self.assertIn("repairable", rh.evidence)


class MenuTests(Base):
    def test_not_entered_when_not_confirmed(self):
        self.ui.answers = ["no"]
        repair.run_menu(self.ctx)
        self.assertFalse(self.runner.repairs_enabled)

    def test_guidance_boot_and_reset(self):
        self.ui.answers = ["yes", "guidance", "boot", "no", "black screen", "back"]
        repair.run_menu(self.ctx)
        self.assertFalse(self.runner.repairs_enabled)
        self.assertIn("Startup Repair", self.ui.text)
        self.assertIs(self.case.data["booted_after_repair"], False)
        self.assertEqual(self.case.data["boot_note"], "black screen")

    def test_run_step_through_menu_dry_run(self):
        # confirm repair mode, step menu, pick scanhealth, type yes to the runner, back
        self.ui.answers = ["yes", "step", "scanhealth", "yes", "back"]
        repair.run_menu(self.ctx)
        log = self.case.data["repair_log"]
        self.assertEqual([e["id"] for e in log], ["scanhealth"])
        self.assertEqual(log[0]["kind"], "dry-run")
        self.assertIn("Test boot before the next step", self.ui.text)
        self.assertFalse(self.runner.repairs_enabled)

    def test_refused_is_shown_not_retried(self):
        self.runner.target_online = True
        self.ui.answers = ["yes", "step", "scanhealth", "back"]
        repair.run_menu(self.ctx)
        self.assertIn("Refused:", self.ui.text)
        self.assertEqual(self.case.data.get("repair_log", []), [])
        self.assertEqual(len([a for a in self.audit() if a["kind"] == "refused"]), 1)

    def test_online_target_offers_only_data_and_source(self):
        self.target.online = True
        self.ui.answers = ["yes", "back"]
        repair.run_menu(self.ctx)
        self.assertIn("running Windows", self.ui.text)

    def test_copy_out_refuses_when_not_fitting(self):
        dest = os.path.join(self.tmp, "backup")
        os.makedirs(dest)
        self.ui.answers = ["yes", "copy", dest, "back"]
        with mock.patch.object(repair.shutil, "disk_usage", return_value=mock.Mock(free=5)):
            repair.run_menu(self.ctx)
        self.assertIn("does not fit", self.ui.text)
        self.assertEqual(self.case.data.get("repair_log", []), [])


if __name__ == "__main__":
    unittest.main()
