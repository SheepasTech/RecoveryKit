"""A scan whose output folder is on the target volume stops after discovery and collects nothing further."""
import os
import subprocess
import tempfile
import unittest

from recoverykit.core import mdsafe
from recoverykit.engine import Engine
from tests import fakewin
from tests.test_net import ROOT, QuietUI


class ScanAbort(unittest.TestCase):
    def test_output_on_target_stops_scan(self):
        td = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(td.cleanup)
        target = os.path.join(td.name, "target")
        fakewin.make_target(target)
        engine = Engine(ROOT, os.path.join(target, "cases"), QuietUI(), dry_run=True,
                        options={"ticket": "4242", "target_path": target, "answers": {}})
        self.addCleanup(engine.close)
        secs = engine.scan()
        self.assertEqual(secs["output_location"]["status"], "error")
        reason = engine.ctx.options.get("abort_scan")
        self.assertTrue(reason)
        for name in ("logs_target", "device", "registry"):
            self.assertNotIn(name, secs)
        self.assertFalse(engine.scanned)
        logs = engine.ctx.case.path("logs")
        names = os.listdir(logs) if os.path.isdir(logs) else []
        self.assertEqual([n for n in names if n.startswith("target-")], [])
        report = engine.ctx.case.path("report.md")
        self.assertTrue(os.path.isfile(report))
        with open(report, encoding="utf-8", errors="replace") as f:
            self.assertIn(mdsafe.text(reason, 700), f.read())
        self.assertIn("debug.log", reason)             # says what had already been written, and where
        self.assertIn(".rk-write-test", reason)
        self.assertIn(engine.ctx.case.dir, reason)
        self.assertTrue(any("Scan stopped" in ln for ln in engine.ctx.ui.lines))

    def test_nothing_is_run_after_the_check_fails(self):
        td = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(td.cleanup)
        target = os.path.join(td.name, "target")
        fakewin.make_target(target)
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

    def test_junction_to_the_target_is_caught(self):
        td = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(td.cleanup)
        target = os.path.join(td.name, "target")
        fakewin.make_target(target)
        link = os.path.join(td.name, "innocent")
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True, text=True)
        if r.returncode != 0 or not os.path.isdir(link):
            self.skipTest("cannot create a junction here: %s" % (r.stdout + r.stderr).strip())
        self.addCleanup(lambda: os.rmdir(link))
        engine = Engine(ROOT, os.path.join(link, "cases"), QuietUI(), dry_run=True,
                        options={"ticket": "4242", "target_path": target, "answers": {}})
        self.addCleanup(engine.close)
        secs = engine.scan()
        self.assertEqual(secs["output_location"]["status"], "error")
        self.assertTrue(engine.ctx.options.get("abort_scan"))


if __name__ == "__main__":
    unittest.main()
