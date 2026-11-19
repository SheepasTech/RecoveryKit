"""Tests of the built-in .evtx reader against real logs exported with wevtutil (temp dir only)."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

from recoverykit.core import evtx
from recoverykit.modules import logs
from tests import test_logs

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
CHANNELS = ("Application", "Windows PowerShell", "Setup", "System")
TMP = None
EXPORTS = {}      # channel -> path of the exported copy
STATS = {}        # channel -> [compared, matched]


def _wev(args, timeout=180):
    return subprocess.run(["wevtutil"] + args, capture_output=True, timeout=timeout)


def _reference(path, levels, limit):
    q = "*[System[(%s)]]" % " or ".join("Level=%d" % x for x in levels)
    r = _wev(["qe", path, "/lf:true", "/f:xml", "/e:Events", "/q:" + q, "/c:%d" % limit, "/rd:true"])
    if r.returncode != 0:
        raise unittest.SkipTest("wevtutil qe failed: %s" % r.stderr[:100])
    out = []
    for ev in ET.fromstring(r.stdout.decode("utf-8", "replace")):
        s = ev.find(NS + "System")
        out.append({"record_id": int(s.findtext(NS + "EventRecordID")),
                    "event_id": int(s.findtext(NS + "EventID")),
                    "level": int(s.findtext(NS + "Level") or 0),
                    "provider": s.find(NS + "Provider").get("Name"),
                    "channel": s.findtext(NS + "Channel"),
                    "computer": s.findtext(NS + "Computer"),
                    "time": s.find(NS + "TimeCreated").get("SystemTime")[:19] + "Z"})
    return out


def setUpModule():
    global TMP
    TMP = tempfile.mkdtemp(prefix="evtxtest")
    for ch in CHANNELS:
        dest = os.path.join(TMP, ch.replace(" ", "_") + ".evtx")
        try:
            r = _wev(["epl", ch, dest, "/ow:true"])
        except (OSError, subprocess.SubprocessError):
            break
        if r.returncode == 0 and os.path.isfile(dest):
            EXPORTS[ch] = dest
    sys.stderr.write("\nevtx test channels exported: %s\n" % (sorted(EXPORTS) or "none"))


def tearDownModule():
    shutil.rmtree(TMP, True)
    for ch, (c, m) in sorted(STATS.items()):
        sys.stderr.write("evtx comparison %s: %d events compared, %d fully matched\n" % (ch, c, m))


class RealLogs(unittest.TestCase):
    def check(self, ch, levels, limit):
        if ch not in EXPORTS:
            self.skipTest("channel %s could not be exported with wevtutil" % ch)
        ref = _reference(EXPORTS[ch], levels, limit)
        got, st = evtx.read_events(EXPORTS[ch], levels=levels, limit=limit)
        self.assertEqual(st["chunks_bad"], 0, st["errors"])
        self.assertEqual(len(got), len(ref))
        keys = ("record_id", "event_id", "level", "provider", "channel", "computer", "time")
        c = STATS.setdefault(ch, [0, 0])
        for g, r in zip(got, ref):
            c[0] += 1
            if all(g[k] == r[k] for k in keys):
                c[1] += 1
            else:
                self.assertEqual({k: g[k] for k in keys}, r)
        self.assertLessEqual(len(got), limit)
        return got, st

    def test_default_levels_all_channels(self):
        if not EXPORTS:
            self.skipTest("wevtutil not available or export failed")
        for ch in EXPORTS:
            with self.subTest(ch):
                self.check(ch, (1, 2, 3), 200)

    def test_limit_five_newest(self):
        if not EXPORTS:
            self.skipTest("wevtutil not available or export failed")
        for ch in EXPORTS:
            with self.subTest(ch):
                got, _ = self.check(ch, (1, 2, 3), 5)
                self.assertLessEqual(len(got), 5)

    def test_information_only(self):
        if not EXPORTS:
            self.skipTest("wevtutil not available or export failed")
        for ch in EXPORTS:
            with self.subTest(ch):
                got, _ = self.check(ch, (4,), 50)
                self.assertTrue(all(e["level"] == 4 for e in got))

    def test_filter_before_limit_and_stats(self):
        if "Application" not in EXPORTS:
            self.skipTest("no Application export")
        t = time.time()
        got, st = evtx.read_events(EXPORTS["Application"], limit=3)
        self.assertLess(time.time() - t, 60)
        self.assertLessEqual(len(got), 3)
        self.assertGreaterEqual(st["records_seen"], st["records_matched"])
        self.assertTrue(all(e["level"] in (1, 2, 3) for e in got))
        ids = [e["record_id"] for e in got]
        self.assertEqual(ids, sorted(ids, reverse=True))
        old, _ = evtx.read_events(EXPORTS["Application"], limit=3, newest_first=False)
        self.assertEqual([e["record_id"] for e in old], sorted(e["record_id"] for e in old))

    def test_format_text(self):
        if "Application" not in EXPORTS:
            self.skipTest("no Application export")
        got, _ = evtx.read_events(EXPORTS["Application"], limit=4)
        text = evtx.format_text(got)
        starts = [ln for ln in text.splitlines() if ln.startswith("Event[")]
        self.assertEqual(len(starts), len(got))
        text.encode("ascii")
        self.assertEqual(evtx.format_text([]), "")

    def damaged(self, mutate):
        if "Application" not in EXPORTS:
            self.skipTest("no Application export")
        with open(EXPORTS["Application"], "rb") as f:
            data = bytearray(f.read())
        _, base = evtx.read_events(EXPORTS["Application"], limit=1)
        p = os.path.join(TMP, "damaged.evtx")
        with open(p, "wb") as f:
            f.write(mutate(data))
        t = time.time()
        got, st = evtx.read_events(p, limit=10)
        self.assertLess(time.time() - t, 10)
        self.assertTrue(st["chunks_bad"] > 0 or st["records_seen"] < base["records_seen"], st)
        return got, st

    def test_truncated_mid_chunk(self):
        self.damaged(lambda d: d[:0x1000 + 0x10000 * 5 + 0x4321])

    def test_chunk_zeroed(self):
        def zero(d):
            d[0x1000 + 0x10000 * 3:0x1000 + 0x10000 * 4] = bytes(0x10000)
            return d
        _, st = self.damaged(zero)
        self.assertGreater(st["chunks_bad"], 0)


class Basics(unittest.TestCase):
    def test_garbage_and_missing(self):
        p = os.path.join(tempfile.mkdtemp(), "g.evtx")
        self.addCleanup(shutil.rmtree, os.path.dirname(p), True)
        with open(p, "wb") as f:
            f.write(b"not an event log" * 1000)
        with self.assertRaises(evtx.EvtxError):
            evtx.read_events(p)
        open(p, "wb").close()
        with self.assertRaises(evtx.EvtxError):
            evtx.read_events(p)
        with self.assertRaises(evtx.EvtxError):
            evtx.read_events(p + ".nope")

    def test_format_text_synthetic(self):
        ev = {"record_id": 1, "time": "2026-11-19T17:01:02Z", "provider": "Prové", "event_id": 41, "level": 2,
              "channel": "System", "computer": "PC", "data": ["a\nb", "c"]}
        text = evtx.format_text([ev])
        self.assertTrue(text.startswith("Event[0]: 2026-11-19T17:01:02Z  Level 2 (Error)  ID 41  Prov?  [System]"))
        text.encode("ascii")


class LogsFallback(test_logs.Base):
    def test_builtin_reader_used_when_wevtutil_missing(self):
        if "Application" not in EXPORTS:
            self.skipTest("no Application export")
        dst = self.windir + "\\System32\\winevt\\Logs\\System.evtx"
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(EXPORTS["Application"], "rb") as f:     # first 15 chunks: stays under the 1 MB limit of test_logs.CFG
            head = f.read(0x1000 + 0x10000 * 15)
        with open(dst, "wb") as f:
            f.write(head)
        logs.collect(self.ctx(test_logs.FakeRunner(fail=("wevtutil",))))
        it = self.item("event_logs", "System")
        self.assertEqual(it["status"], "ok")
        self.assertIn("export by built-in reader", it["reason"])
        self.assertIn("wevtutil not available", it["reason"])
        self.assertGreater(it["events"], 0)
        self.assertLessEqual(it["events"], 50)
        with open(self.case.path("logs", "target-events-System.txt")) as f:
            n = sum(1 for ln in f if ln.startswith("Event["))
        self.assertEqual(n, it["events"])


if __name__ == "__main__":
    unittest.main()
