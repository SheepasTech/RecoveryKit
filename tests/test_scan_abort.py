"""A scan whose output folder is on the target volume stops after discovery, collects nothing further and writes
no report into that folder."""
import ctypes
import os
import shutil
import subprocess
import tempfile
import unittest

from recoverykit.engine import Engine
from tests import fakewin
from tests.test_net import ROOT, QuietUI


def volume_guid_path(drive):
    """'\\\\?\\Volume{...}\\' of a drive such as 'C:' (None when Windows will not say)."""
    buf = ctypes.create_unicode_buffer(64)
    try:
        ok = ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(drive + "\\", buf, 64)
    except (AttributeError, OSError):
        return None
    return buf.value if ok else None


class ScanAbort(unittest.TestCase):
    def target(self):
        td = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(td.cleanup)
        target = os.path.join(td.name, "target")
        fakewin.make_target(target)
        return td, target

    def scan_with_out(self, target, out):
        engine = Engine(ROOT, out, QuietUI(), dry_run=True,
                        options={"ticket": "4242", "target_path": target, "answers": {}})
        self.addCleanup(engine.close)
        return engine, engine.scan()

    def test_output_on_target_stops_scan(self):
        td, target = self.target()
        engine, secs = self.scan_with_out(target, os.path.join(target, "cases"))
        self.assertEqual(secs["output_location"]["status"], "error")
        reason = engine.ctx.options.get("abort_scan")
        self.assertTrue(reason)
        for name in ("logs_target", "device", "registry"):
            self.assertNotIn(name, secs)
        self.assertFalse(engine.scanned)
        logs = engine.ctx.case.path("logs")
        names = os.listdir(logs) if os.path.isdir(logs) else []
        self.assertEqual([n for n in names if n.startswith("target-")], [])
        self.assertFalse(os.path.exists(engine.ctx.case.path("report.md")))     # nothing further is written there
        self.assertTrue(os.path.isfile(engine.ctx.case.path("debug.log")))       # what was written before the check
        self.assertIn("debug.log", reason)             # says what had already been written, and where
        self.assertIn("Nothing further was written", reason)
        self.assertIn(".rk-write-test", reason)
        self.assertIn(engine.ctx.case.dir, reason)
        lines = engine.ctx.ui.lines
        self.assertTrue(any("Scan stopped" in ln and "on the target volume" in ln for ln in lines), lines)

    def test_check_that_raises_fails_closed(self):
        from unittest import mock
        td, target = self.target()
        with mock.patch("recoverykit.modules.discovery._resolve", side_effect=OSError("boom")):
            engine, secs = self.scan_with_out(target, os.path.join(td.name, "cases"))
        self.assertEqual(secs["output_location"]["status"], "error")
        reason = engine.ctx.options.get("abort_scan")
        self.assertIn("could not verify that the case output is off the target volume: boom", reason)
        for name in ("logs_target", "device", "registry"):
            self.assertNotIn(name, secs)
        self.assertFalse(engine.scanned)

    def test_nothing_is_run_after_the_check_fails(self):
        td, target = self.target()
        engine = Engine(ROOT, os.path.join(target, "cases"), QuietUI(), dry_run=True,
                        options={"ticket": "4242", "target_path": target, "answers": {},
                                 "abort_scan": "stale verdict of an earlier scan"})
        self.addCleanup(engine.close)
        ran = []
        real = engine.ctx.runner.run
        engine.ctx.runner.run = lambda *a, **k: (ran.append(a), real(*a, **k))[1]
        engine.scan()
        self.assertEqual(ran, [])
        self.assertNotIn("stale", engine.ctx.options["abort_scan"])
        for name in ("bitlocker", "hardware", "operator", "free_space"):
            self.assertNotIn(name, engine.ctx.case.data["sections"])
        inv = engine.ctx.case.path("inventory")
        self.assertFalse(os.path.exists(os.path.join(inv, "network.txt")))
        self.assertFalse(os.path.exists(engine.ctx.case.path("report.md")))

    def test_junction_to_the_target_is_caught(self):
        td, target = self.target()
        link = os.path.join(td.name, "innocent")
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True, text=True)
        if r.returncode != 0 or not os.path.isdir(link):
            self.skipTest("cannot create a junction here: %s" % (r.stdout + r.stderr).strip())
        self.addCleanup(lambda: os.rmdir(link))
        engine, secs = self.scan_with_out(target, os.path.join(link, "cases"))
        self.assertEqual(secs["output_location"]["status"], "error")
        self.assertTrue(engine.ctx.options.get("abort_scan"))

    def spelled(self, target, how):
        """The target folder written in another way, or a skip reason."""
        drive, rest = os.path.splitdrive(os.path.abspath(target))
        if how == "verbatim":
            return "\\\\?\\" + target
        if how == "volume-guid":
            guid = volume_guid_path(drive)
            return (guid + rest.lstrip("\\")) if guid else None
        if how in ("localhost", "loopback"):
            host = "localhost" if how == "localhost" else "127.0.0.1"
            p = "\\\\" + host + "\\" + drive[:1] + "$" + rest
            return p if os.path.isdir(p) else None
        raise AssertionError(how)

    def test_other_spellings_of_the_target_are_caught(self):
        for how in ("verbatim", "volume-guid", "localhost", "loopback"):
            with self.subTest(spelling=how):
                td, target = self.target()
                spelled = self.spelled(target, how)
                if not spelled or not os.path.isdir(spelled):
                    self.skipTest("%s spelling cannot be resolved on this PC (admin shares disabled?)" % how)
                engine, secs = self.scan_with_out(target, spelled + "\\cases")
                self.assertEqual(secs["output_location"]["status"], "error", spelled)
                self.assertTrue(engine.ctx.options.get("abort_scan"), spelled)
                self.assertFalse(os.path.exists(os.path.join(target, "cases", "report.md")))

    def test_output_elsewhere_in_another_spelling_is_not_a_hit(self):
        from recoverykit.modules import discovery
        td, target = self.target()
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, True)
        engine = Engine(ROOT, "\\\\?\\" + other, QuietUI(), dry_run=True,
                        options={"ticket": "1", "target_path": target, "answers": {}})
        self.addCleanup(engine.close)
        engine.ctx.target = discovery.explicit_target(engine.ctx, target, {})
        self.assertIsNone(discovery.check_output_location(engine.ctx))


if __name__ == "__main__":
    unittest.main()
