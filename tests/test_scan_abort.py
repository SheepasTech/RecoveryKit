"""A scan whose output folder is on the target volume stops after discovery and collects nothing further."""
import os
import tempfile
import unittest

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
            self.assertIn(reason, f.read())
        self.assertTrue(any("Scan stopped" in ln for ln in engine.ctx.ui.lines))


if __name__ == "__main__":
    unittest.main()
