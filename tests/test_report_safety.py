"""B6/B7: strings from the target, operator, remote clients and logs cannot change the structure of report.md or
devices/index.md (headings, tables, HTML, embeds, links, code blocks), and B15 console control characters."""
import json
import os
import re
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from recoverykit.core import mdsafe
from recoverykit.core.ui import UI
from recoverykit.core.runner import RepairStep
from recoverykit.engine import API, route
from recoverykit.modules import device, repair, report
from tests.test_net import Base

FENCE = "`" * 3
PAYLOADS = [
    "ok\n# Injected heading",
    '<iframe src="http://evil.example/">',
    FENCE + "dataviewjs\ndv.pages().forEach(p => eval(p))\n" + FENCE,
    "![](http://evil.example/beacon.png)",
    "[click](obsidian://x)",
    "<img src=http://evil.example/b.png>",
    "cmd /c echo `calc` & x",
    "a | b | c",
    "ok\r# heading from a CR",
    "line\u2028# heading from LS",
    "http://evil.example/auto and https://x.example",
    "- list item\n> quote\n1. numbered",
]


def case(v, clean=False):
    """A case dict in which every field that can come from outside holds v."""
    lst = [v]
    return {
        "case_id": v, "ticket": v, "started": "2026-11-19 10:00", "kit_version": "1", "schema": 2,
        "environment": {"kind": v, "firmware": v, "os": {"product": v}, "admin": True},
        "device": {"id": v, "segments": [{"code": v, "label": v, "detail": v, "segment": "CPU"}]},
        "target": {"root": v, "online": False,
                   "disk": {"number": v, "model": v, "size": 2 ** 38, "bus": v, "style": v},
                   "partition": {"number": v, "size": 2 ** 37, "type": v},
                   "volume": {"fs": v, "free": 2 ** 36, "size": 2 ** 37},
                   "info": {"product": v, "edition": v, "display_version": v, "build_full": v, "architecture": v,
                            "language": v, "ui_languages": lst, "errors": lst}},
        "operator_answers": {"symptom": v, "stop_code": v, v: v},
        "booted_after_repair": None,
        "repair_log": [{"id": v, "kind": v, "rc": v, "finding": v, "error_code": v, "note": v}],
        "source_check": {"path": v, "index": v, "ok": False,
                         "mismatches": [{"field": v, "target": v, "source": v}]},
        "files": [{"status": "ok"}],
        "read_only_check": {"summary": v},
        "sections": {
            "boot_structure": {"title": "Boot structure", "status": "ok", "reason": v, "items": [], "data": {
                "note": v, "efi_partitions": [{"disk": v, "partition": v, "size": 2 ** 28, "on_target_disk": True}],
                "recovery_partitions": [{"disk": v, "partition": v, "size": 2 ** 28}]}},
            "demo": {"title": v, "status": v, "reason": v,
                     "items": [{"name": v, "status": "error", "reason": v}]},
            "log_findings": {"title": "Logs", "status": "ok", "reason": "", "items": [], "data": {"headline": lst}},
            "registry": {"title": "Registry", "status": "ok", "reason": "", "items": [], "data": {"notable": lst}},
            "drivers": {"title": "Drivers", "status": "ok", "reason": "", "items": [],
                        "data": {"recent": lst, "recent_days": v}},
            "assistant": {"title": "A", "status": "ok", "reason": "", "items": [], "data": {
                "suggestions": [{"branch": v, "title": v, "text": v, "evidence": {v: v}}],
                "what_changed": lst}},
        },
    }


def audit(v):
    return [{"seq": v, "kind": v, "command": v, "exit_code": v, "note": v, "error": v, "timed_out": True},
            {"seq": 2, "kind": "read", "command": "sfc /verifyonly", "exit_code": 0}]


def outside_code(line):
    """The line without its code spans (an unescaped backtick opens one, the next backtick closes it)."""
    out, i = [], 0
    while i < len(line):
        ch = line[i]
        if ch == "\\":
            out.append(line[i:i + 2])
            i += 2
        elif ch == "`":
            j = line.find("`", i + 1)
            i = len(line) if j < 0 else j + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def split_cells(line):
    """Number of unescaped | in a line, outside code spans."""
    line = outside_code(line)
    n, i = 0, 0
    while i < len(line):
        if line[i] == "\\":
            i += 2
            continue
        if line[i] == "|":
            n += 1
        i += 1
    return n


class Structure:
    """Assertions shared by the report and the device index."""

    def check(self, clean_lines, lines, payload):
        msg = repr(payload)
        self.assertEqual(len(lines), len(clean_lines), msg)
        clean_heads = {ln for ln in clean_lines if ln.startswith("#")}
        for ln in lines:
            if ln.startswith("#"):
                self.assertTrue(ln in clean_heads or ln.startswith("# RecoveryKit case "), "heading: %r (%s)" % (ln, msg))
            self.assertFalse(ln.lstrip().startswith(FENCE), "fence: %r (%s)" % (ln, msg))
            bare = outside_code(ln)
            self.assertIsNone(re.search(r"(?<!\\)<", bare), "raw <: %r (%s)" % (ln, msg))
            self.assertIsNone(re.search(r"(?<!\\)!\[", bare), "raw ![: %r (%s)" % (ln, msg))
            self.assertIsNone(re.search(r"(?<!\\)\]\(", bare), "raw ](: %r (%s)" % (ln, msg))
            self.assertNotIn("://", bare.replace(":\\//", ""), "autolink: %r (%s)" % (ln, msg))
        # every table row has as many separators as the header row of its table
        header = None
        for ln in lines:
            if not ln.startswith("|"):
                header = None
                continue
            if header is None:
                header = split_cells(ln)
            self.assertEqual(split_cells(ln), header, "table row: %r (%s)" % (ln, msg))


class ReportSafety(unittest.TestCase, Structure):
    def test_hostile_values_cannot_change_the_structure(self):
        clean = report.render(case("X"), audit("X")).split("\n")
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                out = report.render(case(payload), audit(payload))
                self.check(clean, out.split("\n"), payload)

    def test_hostile_values_in_small_corners(self):
        data = case("X")
        data["case_id"] = "T-1\n## Injected"
        data["operator_answers"] = {"symptom": "# x", "firmware_sees_disk": "yes"}
        out = report.render(data, [])
        self.assertNotIn("\n## Injected", out)
        self.assertNotIn("\n# x", out)

    def test_clean_realistic_case_stays_readable(self):
        data = case("X")
        data.update(case_id="ITW-4242-ab12cd34", ticket="4242")
        data["target"].update(root="C:\\")
        data["target"]["disk"].update(number=0, model="Samsung SSD 970 EVO 500GB", bus="NVMe", style="GPT")
        data["target"]["info"].update(product="Windows 11 Home", edition="Core", display_version="24H2",
                                      build_full="10.0.26100.8875", architecture="x64", language="en-US",
                                      ui_languages=["en-US", "lt-LT"], errors=[])
        data["sections"]["demo"] = {"title": "Free space", "status": "ok", "reason": "40.0 GB free of 100.0 GB (40%)",
                                    "items": []}
        data["device"] = {"id": "AAAA-BBBB", "segments": [{"code": "AAAA", "label": "Processor", "detail": "Intel Core i5-12400"}]}
        data["operator_answers"] = {"symptom": "repair_loop"}
        data["source_check"] = {"path": "D:\\sources\\install.wim", "index": 3, "ok": True, "mismatches": []}
        out = report.render(data, [{"seq": 1, "kind": "read", "command": "C:\\Windows\\System32\\sfc.exe /scannow",
                                    "exit_code": 0}])
        for fact in ("Windows 11 Home", "10.0.26100.8875", "Samsung SSD 970 EVO 500GB", "en-US, lt-LT",
                     "Intel Core i5-12400", "`C:\\`", "`C:\\Windows\\System32\\sfc.exe /scannow`",
                     "`D:\\sources\\install.wim`", "`AAAA-BBBB`", "40.0 GB free of 100.0 GB \\(40%\\)".replace("\\(", "(").replace("\\)", ")")):
            self.assertIn(fact, out)
        self.assertIn("# RecoveryKit case ITW-4242-ab12cd34", out)


class MdsafeUnits(unittest.TestCase):
    def test_text(self):
        self.assertEqual(mdsafe.text(None), "")
        self.assertEqual(mdsafe.text("a\tb\r\nc  d\u2028e\x85f"), "a b c d e f")
        self.assertEqual(mdsafe.text("x" * 400, 20), "x" * 17 + "...")
        self.assertEqual(mdsafe.text("C:\\Windows"), "C:\\\\Windows")
        self.assertEqual(mdsafe.text("http://x"), "http:\\//x")
        self.assertEqual(mdsafe.text("- a"), "\\- a")
        self.assertEqual(mdsafe.text("3. a"), "\\3. a")
        self.assertEqual(mdsafe.text("> q"), "\\> q")
        self.assertEqual(mdsafe.text("a|b"), "a\\|b")
        self.assertEqual(mdsafe.text("", empty="-"), "-")

    def test_code(self):
        self.assertEqual(mdsafe.code("a`b|c\nd"), "`a'b/c d`")
        self.assertEqual(mdsafe.code("C:\\Windows"), "`C:\\Windows`")
        self.assertEqual(mdsafe.code(None, empty="-"), "-")
        self.assertEqual(mdsafe.code("y" * 50, 10), "`" + "y" * 7 + "...`")


class DeviceIndexSafety(unittest.TestCase, Structure):
    def make(self, tmp, name, v):
        d = os.path.join(tmp, name)
        os.makedirs(d)
        segs = [{"segment": s, "code": "AAAA", "label": s, "detail": v} for s in ("CPU", "GPU", "USER", "DISK")]
        with open(os.path.join(d, "device.json"), "w", encoding="utf-8") as f:
            json.dump({"id": v, "last_seen": v, "segments": segs, "runs": [{}, {}]}, f)

    def index(self, name, v):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            self.make(tmp, name, v)
            device._write_index(tmp)
            with open(os.path.join(tmp, "index.md"), encoding="utf-8") as f:
                return f.read().split("\n")

    def test_hostile_device_details(self):
        clean = self.index("AAAA-BBBB", "X")
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                self.check(clean, self.index("AAAA-BBBB", payload), payload)

    def test_hostile_folder_name_as_id(self):
        clean = self.index("AAAA-BBBB", "X")
        lines = self.index("evil`[x](y)!#", "X")
        self.assertEqual(len(lines), len(clean))
        self.check(clean, lines, "folder")


class QuietStream(UI):
    pass


class ConsoleControlCharacters(unittest.TestCase):
    def test_say_raw_and_prompt_strip_controls(self):
        import io
        from contextlib import redirect_stdout
        ui = UI(auto=True)
        evil = "name\x1b[2J\x07\x9b31m\x7f end"
        buf = io.StringIO()
        with redirect_stdout(buf):
            ui.say(evil)
            ui.raw(evil)
            self.assertEqual(ui.ask("q " + evil, "d" + evil), "d" + "name[2J31m end")
        out = buf.getvalue()
        for bad in ("\x1b", "\x07", "\x9b", "\x7f"):
            self.assertNotIn(bad, out)
        self.assertEqual(out.count("name[2J31m end"), 2)

    def test_newlines_survive_in_say(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            UI(auto=True).say("a\nb\x1b")
        self.assertEqual(buf.getvalue(), "a\nb\n")


class EngineHardening(Base):
    """A10, A11, B16 and the live-scan reads of the engine."""

    def call(self, method, path, body=None, query=None, remote=False):
        return route(self.engine, method, API + path, query, body, remote=remote, operator="tester")

    def listed(self, steps):
        e = self.engine
        self.call("POST", "/scan")
        e.allow_repairs = True
        with mock.patch.object(repair, "online_disk_steps", lambda ctx: steps):
            with mock.patch.object(repair, "repair_steps", lambda ctx: []),                     mock.patch.object(repair, "bcd_steps", lambda ctx: []):
                return self.call("GET", "/repair/steps")[1]

    def test_concurrent_identical_posts_run_once(self):
        step = RepairStep(id="s1", title="t", effect="e", argv=["chkdsk", "C:"], touches_target=False)
        listing = self.listed([step])
        body = {"id": "s1", "token": listing["steps"][0]["token"], "confirm": "yes"}
        calls, results = [], []

        def slow(st):
            calls.append(st.id)
            time.sleep(0.3)
            return types.SimpleNamespace(out="done", ok=True, rc=0)
        self.engine.ctx.runner.repair = slow
        gate = threading.Barrier(2)

        def post():
            gate.wait()
            results.append(self.call("POST", "/repair/run", dict(body))[0])
        with mock.patch.object(repair, "record", lambda *a, **k: {}):
            ts = [threading.Thread(target=post) for _ in range(2)]
            for t in ts:
                t.start()
            for t in ts:
                t.join(30)
        self.assertEqual(calls, ["s1"])
        self.assertEqual(sorted(results)[0], 200)
        self.assertIn(sorted(results)[1], (404, 409))

    def test_secrets_are_redacted_in_listing_token_and_output(self):
        step = RepairStep(id="unlock", title="t", effect="e", argv=["manage-bde", "-unlock", "C:", "-password", "hunter2xyz"],
                          secrets=("hunter2xyz",), touches_target=False)
        listing = self.listed([step])
        s = listing["steps"][0]
        self.assertNotIn("hunter2xyz", json.dumps(listing))
        self.assertIn("<hidden>", s["command"])
        self.engine.ctx.runner.repair = lambda st: types.SimpleNamespace(out="password hunter2xyz accepted", ok=True, rc=0)
        with mock.patch.object(repair, "record", lambda *a, **k: {}):
            status, res = self.call("POST", "/repair/run", {"id": "unlock", "token": s["token"], "confirm": "yes"})
        self.assertEqual(status, 200, res)
        self.assertNotIn("hunter2xyz", res["output"])
        self.assertIn("<hidden>", res["output"])

    def test_relayed_repair_source_path_rules(self):
        for path in (chr(92) * 2 + 'host' + chr(92) + 'share' + chr(92) + 'install.wim', '//host/share/install.wim'):
            self.assertEqual(self.call('POST', '/repair/source', {'path': path}, remote=True)[0], 403, path)
        for path in ('D:/a' + chr(10) + 'b.wim', 'D:/a' + chr(27) + '[2J.wim', 'D:/a' + chr(0) + '.wim', 'D:/a' + chr(13) + 'b.wim'):
            self.assertEqual(self.call('POST', '/repair/source', {'path': path}, remote=True)[0], 400, repr(path))
            self.assertEqual(self.call('POST', '/repair/source', {'path': path})[0], 400, repr(path))

    def test_bad_numbers_are_400(self):
        self.assertEqual(self.call("GET", "/audit", query={"since": "abc"})[0], 400)
        self.assertEqual(self.call("GET", "/log", query={"offset": "1e3"})[0], 400)
        self.assertEqual(self.call("GET", "/audit", query={"since": "0"})[0], 200)

    def test_reads_during_a_running_scan_never_fail(self):
        done = threading.Event()
        bad = []

        def hammer():
            n = 0
            while not done.is_set():
                for path in ("/sections", "/case", "/status"):
                    st, res = self.call("GET", path)
                    n += 1
                    if st >= 500:
                        bad.append((path, st, res))
            self.reads = n
        t = threading.Thread(target=hammer)
        t.start()
        try:
            for _ in range(3):
                self.engine.scan()
        finally:
            done.set()
            t.join(30)
        self.assertEqual(bad, [])
        self.assertGreater(self.reads, 10)


if __name__ == "__main__":
    unittest.main()
