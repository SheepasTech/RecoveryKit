"""Security review 2026-11-19: discovery (S2), output location, Case.assign/new_run, hive handles, S3, device.py."""
import json
import os
import tempfile
import types
import unittest
from unittest import mock

from recoverykit.core import case as case_mod
from recoverykit.core.case import Case
from recoverykit.core.context import RegView, Target
from recoverykit.core.ui import UI
from recoverykit.modules import device, discovery
from tests import fakewin


class QuietUI(UI):
    def __init__(self):
        super().__init__(auto=True)
        self.lines = []

    def say(self, text=""):
        self.lines.append(str(text))


def volume(letter, root, drive_type="fixed", number=0):
    return {"letter": letter, "guid_path": "\\\\?\\Volume{%s}\\" % letter, "fs": "NTFS", "label": "", "size": 10 ** 11,
            "free": 10 ** 10, "drive_type": drive_type, "extents": [], "disk": number, "partition": None,
            "errors": [], "_root": root}


def ctx_for(tmp, kind, vols, host_windir="", options=None):
    case = Case(os.path.join(tmp, "cases"))
    ctx = types.SimpleNamespace(
        case=case, ui=QuietUI(), env={"kind": kind, "windir": host_windir}, options=options or {},
        inventory={"disks": [], "volumes": vols}, runner=types.SimpleNamespace(target_online=False), target=None,
        cfg={})
    return ctx


class FakeLetters:
    """Maps the fake volumes' drive letters onto temp folders so find_installs can look inside them."""

    def __init__(self, mapping):
        self.mapping = mapping

    def __enter__(self):
        real = discovery._is_windows_dir
        self._p = mock.patch.object(discovery, "_is_windows_dir", lambda w: real(self._map(w)))
        self._p.start()
        return self

    def _map(self, path):
        for letter, root in self.mapping.items():
            if path.upper().startswith(letter + ":\\"):
                return os.path.join(root, path[3:])
        return path

    def __exit__(self, *a):
        self._p.stop()


class FindInstalls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.x = os.path.join(self.tmp.name, "X")
        self.c = os.path.join(self.tmp.name, "C")
        self.w = os.path.join(self.tmp.name, "W")
        for r in (self.x, self.c, self.w):
            fakewin.make_target(r)

    def run_find(self, kind, vols, host, same=None, sysdrive="X"):
        ctx = ctx_for(self.tmp.name, kind, vols, host_windir=host)
        self.addCleanup(ctx.case.close)

        def samefile(a, b):
            if same is None:
                raise OSError("no")
            return same(a, b)
        with FakeLetters({"X": self.x, "C": self.c, "W": self.w}), \
                mock.patch.object(discovery.os.path, "samefile", samefile), \
                mock.patch.dict(os.environ, {"SystemDrive": sysdrive + ":"}), \
                mock.patch.object(discovery, "install_info", lambda t: {"errors": []}), \
                mock.patch.object(discovery, "RegView", lambda w, o: types.SimpleNamespace(close=lambda: None)):
            return ctx, discovery.find_installs(ctx)

    def test_winre_own_windows_is_excluded_with_a_note(self):
        vols = [volume("X", self.x, "ramdisk"), volume("C", self.c)]
        # X: is a ramdisk volume: skipped outright
        ctx, installs = self.run_find("winre", vols, "X:\\Windows", same=lambda a, b: a.upper() == b.upper())
        self.assertEqual([t.root for t in installs], ["C:\\"])
        # the same without the ramdisk flag: found by samefile against the host windir, excluded, with a note
        vols = [volume("X", self.x), volume("C", self.c)]
        ctx, installs = self.run_find("winre", vols, "X:\\Windows", same=lambda a, b: a.upper() == b.upper())
        self.assertEqual([t.root for t in installs], ["C:\\"])
        self.assertEqual(ctx.inventory["excluded_installs"],
                         [("X:\\", "X:\\ is the recovery environment itself, not a target")])

    def test_samefile_failure_falls_back_to_system_drive_letter(self):
        vols = [volume("X", self.x), volume("C", self.c)]
        ctx, installs = self.run_find("winpe", vols, "X:\\Windows", same=None, sysdrive="X")
        self.assertEqual([t.root for t in installs], ["C:\\"])
        self.assertTrue(ctx.inventory["excluded_installs"])

    def test_online_is_computed_in_every_environment_but_only_excluded_in_recovery(self):
        vols = [volume("C", self.c), volume("W", self.w)]
        ctx, installs = self.run_find("windows", vols, "C:\\Windows", same=lambda a, b: a.upper() == b.upper(),
                                      sysdrive="C")
        self.assertEqual({t.root: t.online for t in installs}, {"C:\\": True, "W:\\": False})
        # an unknown kind with the same host windir also flags it online
        ctx, installs = self.run_find("other", vols, "C:\\Windows", same=lambda a, b: a.upper() == b.upper(),
                                      sysdrive="C")
        self.assertEqual({t.root: t.online for t in installs}, {"C:\\": True, "W:\\": False})
        self.assertEqual(ctx.inventory.get("excluded_installs", []), [])

    def test_auto_still_picks_the_only_running_windows_on_a_normal_windows(self):
        ctx, installs = self.run_find("windows", [volume("C", self.c)], "C:\\Windows",
                                      same=lambda a, b: a.upper() == b.upper(), sysdrive="C")
        ctx.inventory["installs"] = installs
        ctx.ui.auto = True
        t = discovery.choose_target(ctx)
        self.assertIsNotNone(t)
        self.assertTrue(t.online)

    def test_recovery_with_only_itself_gives_no_target(self):
        ctx, installs = self.run_find("winre", [volume("X", self.x)], "X:\\Windows",
                                      same=lambda a, b: a.upper() == b.upper())
        ctx.inventory["installs"] = installs
        self.assertEqual(installs, [])
        self.assertIsNone(discovery.choose_target(ctx))


class OutputLocation(unittest.TestCase):
    def make(self, tmp, online=False, letter=None, root=None):
        case = Case(os.path.join(tmp, "cases"))
        self.addCleanup(case.close)
        root = root or os.path.join(tmp, "t") + os.sep
        t = Target(root=root, windir=root + "Windows", online=online, letter=letter, volume={}, disk=None,
                   partition=None)
        return types.SimpleNamespace(case=case, target=t, options={}, ui=QuietUI())

    def test_output_inside_target_root_is_refused(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ctx = self.make(tmp, root=tmp + os.sep)        # cases/ lives inside the "target volume"
            self.assertIn("case output is on the target volume", discovery.check_output_location(ctx))

    def test_output_on_same_drive_letter_is_refused(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            drive = os.path.splitdrive(os.path.abspath(tmp))[0][:1]
            ctx = self.make(tmp, letter=drive, root=os.path.join(tmp, "elsewhere") + os.sep)
            self.assertIsNotNone(discovery.check_output_location(ctx))

    def test_output_elsewhere_and_running_windows_are_fine(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ctx = self.make(tmp)
            with mock.patch.object(discovery.os.path, "samefile", side_effect=OSError("no")):
                self.assertIsNone(discovery.check_output_location(ctx))
            ctx = self.make(tmp, online=True, root=tmp + os.sep)
            self.assertIsNone(discovery.check_output_location(ctx))

    def test_collect_sets_abort_scan_and_does_not_raise_or_move_the_case(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ctx = self.make(tmp, root=tmp + os.sep)
            ctx.env = {"kind": "winre", "windir": "", "tools": {}, "admin": True, "firmware": "UEFI"}
            ctx.inventory = {}
            ctx.cfg = {}
            ctx.runner = types.SimpleNamespace(target_online=False,
                                               run=lambda *a, **k: types.SimpleNamespace(error="n/a", rc=None, ok=False),
                                               run_ps=lambda n: types.SimpleNamespace(ok=False, error="n/a", rc=None))
            ctx.target = None
            pending = ctx.case.dir
            with mock.patch.object(discovery.winapi, "disks", return_value=[]), \
                    mock.patch.object(discovery.winapi, "volumes", return_value=[]), \
                    mock.patch.object(discovery, "choose_target", return_value=ctx.target or self.make(tmp, root=tmp + os.sep).target):
                target = discovery.collect(ctx)
            self.assertIsNotNone(target)
            self.assertIn("case output is on the target volume", ctx.options["abort_scan"])
            sec = ctx.case.data["sections"]["output_location"]
            self.assertEqual(sec["status"], "error")
            self.assertEqual(ctx.case.dir, pending)        # not moved: moving it would write to the target
            self.assertIsNone(ctx.case.data["case_id"])


class CaseRobustness(unittest.TestCase):
    def test_assign_survives_a_failing_rename(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            c = Case(os.path.join(tmp, "cases"))
            self.addCleanup(c.close)
            before = c.dir
            with mock.patch.object(case_mod.os, "rename", side_effect=PermissionError("file in use")):
                self.assertFalse(c.assign("T-aaaa1111", "7"))
            self.assertEqual(c.dir, before)
            self.assertEqual((c.data["case_id"], c.data["ticket"]), ("T-aaaa1111", "7"))
            self.assertIn("run folder could not be moved to", c.data["folder_note"])
            self.assertIn("file in use", c.data["folder_note"])
            self.assertIn(before, c.data["folder_note"])
            c.write_text("logs/still-works.txt", "x")      # debug.log handler and folder still usable
            self.assertTrue(c.assign("T-bbbb2222"))
            self.assertNotIn("folder_note", c.data)

    def test_discovery_and_device_show_the_folder_note(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            c = Case(os.path.join(tmp, "cases"))
            self.addCleanup(c.close)
            ui = QuietUI()
            ctx = types.SimpleNamespace(case=c, ui=ui, options={"ticket": "55"}, target=object())
            with mock.patch.object(discovery, "target_id", return_value="abcd1234"), \
                    mock.patch.object(case_mod.os, "rename", side_effect=PermissionError("in use")):
                discovery._assign_case(ctx)
            self.assertTrue(any("could not be moved" in ln and "in use" in ln for ln in ui.lines))
            # device.apply_settings: ticket from settings, assign fails
            c2 = Case(os.path.join(tmp, "cases2"))
            self.addCleanup(c2.close)
            c2.data["case_id"] = "T-abcd1234"
            ui2 = QuietUI()
            with mock.patch.object(case_mod.os, "rename", side_effect=PermissionError("busy")):
                device.apply_settings(types.SimpleNamespace(case=c2, ui=ui2), {"ticket": "16028"})
            self.assertTrue(any("could not be moved" in ln and "busy" in ln for ln in ui.lines + ui2.lines))

    def test_new_run_keeps_scan_a_in_its_own_folder(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            c = Case(os.path.join(tmp, "cases"), kit_version="9.9")
            c.data["tools_manifest"] = {"x": "ok"}
            c.write_text("logs/a.txt", "scan A")
            with c.section("one", "One"):
                pass
            c.assign("T-aaaaaaaa")
            a_dir = c.dir
            # scan B onto another target
            c.new_run()
            self.assertNotEqual(c.dir, a_dir)
            self.assertIn("_pending", c.dir)
            self.assertEqual((c.data["kit_version"], c.data["tools_manifest"], c.data["previous_run"]),
                             ("9.9", {"x": "ok"}, a_dir))
            self.assertIsNone(c.data["case_id"])
            self.assertEqual(c.data["sections"], {})
            for sub in ("inventory", "logs", "exports", "audit"):
                self.assertTrue(os.path.isdir(c.path(sub)))
            c.write_text("logs/b.txt", "scan B")
            c.assign("T-bbbbbbbb")
            b_dir = c.dir
            c.write_text("logs/after.txt", "x")
            c.close()
            self.assertEqual(os.path.basename(os.path.dirname(a_dir)), "T-aaaaaaaa")
            self.assertEqual(os.path.basename(os.path.dirname(b_dir)), "T-bbbbbbbb")
            self.assertTrue(os.path.exists(os.path.join(a_dir, "logs", "a.txt")))
            self.assertFalse(os.path.exists(os.path.join(a_dir, "logs", "b.txt")))
            self.assertFalse(os.path.exists(os.path.join(a_dir, "logs", "after.txt")))
            self.assertTrue(os.path.exists(os.path.join(b_dir, "logs", "b.txt")))
            with open(os.path.join(a_dir, "case.json"), encoding="utf-8") as f:
                da = json.load(f)
            with open(os.path.join(b_dir, "case.json"), encoding="utf-8") as f:
                db = json.load(f)
            self.assertEqual((da["case_id"], db["case_id"]), ("T-aaaaaaaa", "T-bbbbbbbb"))
            self.assertIn("one", da["sections"])
            self.assertNotIn("one", db["sections"])
            self.assertTrue(os.path.exists(os.path.join(a_dir, "debug.log")))
            self.assertTrue(os.path.exists(os.path.join(b_dir, "debug.log")))

    def test_assign_case_switches_run_when_the_target_changes(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            c = Case(os.path.join(tmp, "cases"))
            self.addCleanup(c.close)
            ctx = types.SimpleNamespace(case=c, ui=QuietUI(), options={"ticket": ""}, target=object(),
                                        inventory={"disks": [], "volumes": [], "installs": []})
            with mock.patch.object(discovery, "target_id", return_value="aaaaaaaa"):
                discovery._assign_case(ctx)
            a_dir = c.dir
            with mock.patch.object(discovery, "target_id", return_value="bbbbbbbb"):
                discovery._assign_case(ctx)
            self.assertNotEqual(c.dir, a_dir)
            self.assertEqual(c.data["case_id"], "T-bbbbbbbb")
            self.assertEqual(os.path.basename(os.path.dirname(a_dir)), "T-aaaaaaaa")
            self.assertEqual(c.data["previous_run"], a_dir)

    def test_collect_closes_hive_handles_of_the_previous_scan(self):
        closed = []
        mk = lambda n: types.SimpleNamespace(root=n, reg=types.SimpleNamespace(close=lambda: closed.append(n)))
        bad = types.SimpleNamespace(root="bad", reg=types.SimpleNamespace(close=mock.Mock(side_effect=OSError("x"))))
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ctx = ctx_for(tmp, "winre", [])
            self.addCleanup(ctx.case.close)
            ctx.inventory["installs"] = [mk("A"), bad, mk("B")]
            ctx.target = mk("T")
            ctx.cfg = {}
            ctx.env = {"kind": "winre", "windir": "", "tools": {}, "admin": True, "firmware": "UEFI"}
            ctx.runner = types.SimpleNamespace(target_online=False,
                                               run=lambda *a, **k: types.SimpleNamespace(error="n/a", rc=None, ok=False),
                                               run_ps=lambda n: types.SimpleNamespace(ok=False, error="n/a", rc=None))
            with mock.patch.object(discovery.winapi, "disks", return_value=[]), \
                    mock.patch.object(discovery.winapi, "volumes", return_value=[]):
                discovery.collect(ctx)
            self.assertEqual(closed, ["A", "B", "T"])


class CollectFileLinks(unittest.TestCase):
    def test_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            secret = os.path.join(tmp, "secret.txt")
            with open(secret, "w") as f:
                f.write("bench pc data")
            link = os.path.join(tmp, "link.log")
            try:
                os.symlink(secret, link)
            except (OSError, NotImplementedError) as e:
                self.skipTest("cannot create symlinks here: %s" % e)
            c = Case(os.path.join(tmp, "cases"))
            self.addCleanup(c.close)
            e = c.collect_file(link, "logs/target-link.log")
            self.assertEqual((e["status"], e["reason"]), ("skipped", "link or reparse point: not followed"))
            self.assertFalse(os.path.exists(c.path("logs", "target-link.log")))
            self.assertEqual(c.collect_file(secret, "logs/plain.txt")["status"], "ok")

    def test_reparse_point_attribute_is_not_followed(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            src = os.path.join(tmp, "f.log")
            with open(src, "w") as f:
                f.write("x")
            c = Case(os.path.join(tmp, "cases"))
            self.addCleanup(c.close)
            real = os.lstat(src)
            fake = types.SimpleNamespace(st_mode=real.st_mode, st_file_attributes=0x400 | 0x20, st_size=1,
                                         st_mtime=real.st_mtime, st_mtime_ns=real.st_mtime_ns)
            with mock.patch.object(case_mod.os, "lstat", return_value=fake):
                e = c.collect_file(src, "logs/target-f.log")
            self.assertEqual((e["status"], e["reason"]), ("skipped", "link or reparse point: not followed"))
            self.assertFalse(os.path.exists(c.path("logs", "target-f.log")))
            self.assertEqual(c.collect_file(src, "logs/target-f.log")["status"], "ok")


class DeviceSettings(unittest.TestCase):
    def ctx(self, tmp):
        case = Case(os.path.join(tmp, "cases"))
        case.assign("T-abcd1234")
        self.addCleanup(case.close)
        return types.SimpleNamespace(case=case, ui=QuietUI(), options={}, env={"kind": "winre"})

    def test_settings_that_are_not_a_dict_are_moved_aside(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ddir = os.path.join(tmp, "devices")
            did = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"
            os.makedirs(os.path.join(ddir, did))
            spath = os.path.join(ddir, did, "settings.json")
            for payload in ("[1, 2]", '"text"', "7"):
                with open(spath, "w") as f:
                    f.write(payload)
                settings, notes = device.remember(ddir, did, [], {}, {"time": "t"})
                self.assertEqual(settings, device.DEFAULT_SETTINGS)
                self.assertTrue(os.path.exists(spath + ".bad"))
                self.assertTrue(any("settings.json" in n for n in notes), notes)
                os.remove(spath + ".bad")
            for name in ("components.json", os.path.join(did, "device.json")):
                with open(os.path.join(ddir, name), "w") as f:
                    f.write("[]")
            settings, notes = device.remember(ddir, did, [], {}, {"time": "t"})
            self.assertTrue(os.path.exists(os.path.join(ddir, "components.json.bad")))
            self.assertTrue(os.path.exists(os.path.join(ddir, did, "device.json.bad")))
            self.assertEqual(len(notes), 2)

    def test_answers_are_validated_and_text_is_cleaned(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ctx = self.ctx(tmp)
            settings = {"notes": "line\x1b[31mred\x07 " + "x" * 600, "ticket": "ab-12!" + "9" * 40,
                        "answers": {"symptom": "repair_loop", "evil": "yes", "data_backed_up": "<script>",
                                    "firmware_sees_disk": 5, 3: "yes"}}
            device.apply_settings(ctx, settings)
            shown = "\n".join(ctx.ui.lines)
            note_line = next(ln for ln in ctx.ui.lines if "Notes for this device" in ln)
            self.assertNotIn("\x1b", note_line)
            self.assertNotIn("\x07", note_line)
            self.assertLessEqual(len(note_line.split(": ", 1)[1]), 500)
            self.assertEqual(ctx.case.data["ticket"], "ab129999999999999999")       # 20 alphanumerics
            self.assertEqual(ctx.case.data["operator_answers"], {"symptom": "repair_loop"})
            self.assertIn("Ignored invalid saved answers", shown)
            self.assertIn("evil", shown)
            self.assertIn("data_backed_up", shown)

    def test_non_dict_settings_do_not_raise(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ctx = self.ctx(tmp)
            device.apply_settings(ctx, ["not", "a", "dict"])
            device.apply_settings(ctx, {"answers": ["x"], "notes": None, "ticket": None})


if __name__ == "__main__":
    unittest.main()
