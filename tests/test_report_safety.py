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
                     "`D:\\sources\\install.wim`", "`AAAA-BBBB`", "40.0 GB free of 100.0 GB (40\\%)"):
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

    def test_dataview_field_and_bare_www(self):
        self.assertEqual(mdsafe.text("key:: value"), "key:\\: value")
        self.assertNotIn("::", mdsafe.text("a::b:::c"))
        self.assertEqual(mdsafe.text("see www.evil.com"), "see www\\.evil.com")
        self.assertEqual(mdsafe.text("awww.x"), "awww.x")

    def test_code(self):
        self.assertEqual(mdsafe.code("a`b|c\nd"), "`a'b|c d`")
        self.assertEqual(mdsafe.code("a`b|c\nd", table=True), "`a'b\\|c d`")
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
        for path in (chr(92) * 2 + 'host' + chr(92) + 'share' + chr(92) + 'install.wim', '//host/share/install.wim',
                     chr(92) + '/host' + chr(92) + 'share' + chr(92) + 'install.wim',
                     '/' + chr(92) + 'host/share/install.wim', chr(92) * 2 + '?' + chr(92) + 'UNC' + chr(92) + 'h' + chr(92) + 's' + chr(92) + 'x.wim'):
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


class ThirdReviewMarkdown(unittest.TestCase):
    """Third review 2026-11-19: S1, S2, S3, N13, N14 (report part)."""

    @staticmethod
    def unescaped_pipes(line):
        return len(re.findall(r"(?<!\\)\|", line))

    def test_percent_comments_cannot_hide_text_between_two_fields(self):       # S1
        out = report.render(case("%%hidden%%"), audit("%%hidden%%"))
        for ln in out.split("\n"):
            self.assertIsNone(re.search(r"(?<!\\)%", outside_code(ln)), ln)    # every % in prose/cells is escaped
        self.assertIn("- hidden: hidden", out.replace("\\%\\%hidden\\%\\%", "hidden"))
        self.assertEqual(mdsafe.text("a %%b%% c"), "a \\%\\%b\\%\\% c")
        self.assertEqual(mdsafe.text("40%"), "40\\%")

    def test_dataview_and_templater_in_code_spans(self):                       # S2
        for v in ("= this.file.path", "$= dv.current()", "  = x"):
            self.assertTrue(mdsafe.code(v).startswith("`'"), mdsafe.code(v))
        self.assertEqual(mdsafe.code("= this.file.path"), "`'= this.file.path`")
        self.assertEqual(mdsafe.code("<% tp.file.title %>"), "`< % tp.file.title %>`")
        out = report.render(case("= this.file.path"), audit("$= dv.current()"))
        self.assertNotIn("`=", out)
        self.assertNotIn("`$=", out)
        out = report.render(case("<% tp.file.title %>"), audit("<% tp.file.title %>"))
        self.assertNotIn("<%", out)

    def test_bidi_zero_width_bom_and_surrogates_are_dropped(self):             # S3
        for ch in ("‮", "​", "‍", "﻿", "⁦", ""):
            self.assertEqual(mdsafe.text("a%sb" % ch), "ab", hex(ord(ch)))
            self.assertEqual(mdsafe.code("a%sb" % ch), "`ab`", hex(ord(ch)))
        self.assertEqual(mdsafe.text("a\ud800b"), "a�b")
        self.assertEqual(mdsafe.code("a\udfffb"), "`a�b`")
        v = "x‮​﻿\ud800y"
        out = report.render(case(v), audit(v))
        for ch in ("‮", "​", "﻿", "\ud800"):
            self.assertNotIn(ch, out)
        out.encode("utf-8")                                                    # writable as strict UTF-8

    def test_horizontal_rule_value_in_a_list_item(self):
        for v in ("---", "***", "___", "----", "---x"):
            t = mdsafe.text(v)
            self.assertNotIn(t[:3], ("---", "***", "___"), v)
            self.assertTrue(t.startswith("\\"), t)
        data = case("X")
        data["operator_answers"] = {"symptom": "---"}
        out = report.render(data, [])
        self.assertIn("- What happens at boot: \\---", out)

    def test_pipe_in_a_command_keeps_the_table_and_the_pipe(self):             # N13
        cmd = "Get-PhysicalDisk | Select-Object FriendlyName"
        out = report.render(case("X"), [{"seq": 1, "kind": "read", "command": cmd, "exit_code": 0}])
        lines = out.split("\n")
        i = next(n for n, ln in enumerate(lines) if ln.startswith("| # | Kind | Command"))
        header, row = lines[i], lines[i + 2]
        self.assertIn("Get-PhysicalDisk \\| Select-Object FriendlyName", row)   # shown with its pipe, not a slash
        self.assertNotIn("Get-PhysicalDisk / Select-Object", row)
        self.assertEqual(self.unescaped_pipes(row), self.unescaped_pipes(header))
        self.assertEqual(mdsafe.code(cmd), "`%s`" % cmd)                      # outside a table the pipe is as typed

    def test_device_index_pipe_in_id_keeps_the_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, "A_B")
            os.makedirs(d)
            with open(os.path.join(d, "device.json"), "w", encoding="utf-8") as f:
                json.dump({"id": "A|B", "segments": [], "runs": []}, f)
            device._write_index(tmp)
            with open(os.path.join(tmp, "index.md"), encoding="utf-8") as f:
                lines = f.read().split("\n")
        rows = [ln for ln in lines if ln.startswith("|")]
        self.assertGreater(len(rows), 2)
        self.assertEqual(len({self.unescaped_pipes(r) for r in rows}), 1, rows)
        self.assertIn("A\\|B", rows[-1])

    def test_none_evidence_prints_absent(self):                                # N14
        data = case("X")
        data["sections"]["assistant"]["data"]["suggestions"][0]["evidence"] = {"booted": None}
        out = report.render(data, [])
        self.assertIn("booted = absent", out)


if __name__ == "__main__":
    unittest.main()
