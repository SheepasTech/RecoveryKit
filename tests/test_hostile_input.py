"""Regression tests: everything read from a target disk is attacker-controlled.

Each test reproduces the trigger of a finding of .project/reviews/2026-11-19-second-review.md (B1-B5, B8,
B9, B11-B13 and the parent-junction / destination-traversal items) and asserts the parser or collector
stays bounded and raises nothing unexpected.
"""
import json
import os
import random
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from recoverykit import wim
from recoverykit.core import case as case_mod
from recoverykit.core import evtx, regf, ui
from recoverykit.core.context import Ctx, RegView, Target
from recoverykit.modules import drivers, loganalysis, logs, triage
from tests import fakewin

NONE = 0xFFFFFFFF
TASK_XML = ('<?xml version="1.0"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Actions><Exec><Command>c:\\x\\a.exe</Command></Exec></Actions></Task>')


class RawHive:
    """Hand-built hive: arbitrary cells, so hostile structures can be written."""

    def __init__(self):
        self.cells = bytearray()

    def cell(self, data):
        off = 32 + len(self.cells)
        size = (len(data) + 4 + 7) & ~7
        self.cells += struct.pack("<i", -size) + data + b"\x00" * (size - 4 - len(data))
        return off

    def nk(self, name="K", nsub=0, sublist=NONE, nval=0, vallist=NONE):
        b = bytearray(76)
        b[0:2] = b"nk"
        struct.pack_into("<H", b, 2, 0x20)
        struct.pack_into("<I", b, 20, nsub)
        struct.pack_into("<I", b, 28, sublist)
        struct.pack_into("<I", b, 36, nval)
        struct.pack_into("<I", b, 40, vallist)
        struct.pack_into("<H", b, 72, len(name))
        return self.cell(bytes(b) + name.encode("ascii"))

    def vk(self, name, dsize, doff, vtype=3):
        return self.cell(b"vk" + struct.pack("<HIIIHH", len(name), dsize, doff, vtype, 1, 0) + name.encode("ascii"))

    def write(self, path, root):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        header = bytearray(0x1000)
        header[0:4] = b"regf"
        struct.pack_into("<II", header, 4, 7, 7)
        struct.pack_into("<I", header, 36, root)
        with open(path, "wb") as f:
            f.write(bytes(header) + bytes(32) + bytes(self.cells) + bytes(0x100))


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.links = []

    def junction(self, link, target):
        """Create a directory junction (or directory symlink). Skips the test when neither works."""
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True)
        if r.returncode != 0 or not os.path.exists(link):
            try:
                os.symlink(target, link, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("cannot create a junction or a directory symlink here")
        self.links.append(link)
        self.addCleanup(self._unlink, link)

    @staticmethod
    def _unlink(link):
        try:
            os.rmdir(link)
        except OSError:
            pass


# ---------------------------------------------------------------- B1 + B2: registry hives
class HiveHostile(TmpCase):
    def regview(self, root, raw):
        win = os.path.join(self.tmp, "Windows")
        raw.write(os.path.join(win, "System32", "config", "SOFTWARE"), root)
        rv = RegView(win, online=False)
        self.addCleanup(rv.close)
        return rv

    def timed(self, fn):
        t0 = time.time()
        res = fn()
        self.assertLess(time.time() - t0, 2.0)
        return res

    def test_ri_pointing_repeatedly_at_one_huge_lf(self):
        raw = RawHive()
        leaf = raw.nk("leaf")
        lf = raw.cell(b"lf" + struct.pack("<H", 65535) + struct.pack("<II", leaf, 0) * 65535)
        ri = raw.cell(b"ri" + struct.pack("<H", 65535) + struct.pack("<I", lf) * 65535)
        root = raw.nk("ROOT", nsub=4000000000, sublist=ri)
        rv = self.regview(root, raw)
        self.assertEqual(self.timed(lambda: rv.get("SOFTWARE", "No\\Such\\Key", "x", "dflt")), "dflt")
        names = self.timed(lambda: rv.subkeys("SOFTWARE", ""))
        self.assertLessEqual(len(names), 200000)
        self.assertEqual(self.timed(lambda: rv.values("SOFTWARE", "")), {})

    def test_ri_cycle_and_depth(self):
        raw = RawHive()
        # an ri that lists itself: the cell offset is known only after it is written, so patch afterwards
        ri = raw.cell(b"ri" + struct.pack("<H", 3) + struct.pack("<III", 0, 0, 0))
        data_at = ri + 4 - 32                        # index in raw.cells where the cell data starts
        raw.cells[data_at + 4:data_at + 16] = struct.pack("<III", ri, ri, ri)
        root = raw.nk("ROOT", nsub=10, sublist=ri)
        rv = self.regview(root, raw)
        self.assertEqual(self.timed(lambda: rv.subkeys("SOFTWARE", "")), [])

    def test_db_with_65535_segments_shared_by_many_values(self):
        raw = RawHive()
        seg = raw.cell(b"\x01" * 16344)
        lst = raw.cell(struct.pack("<I", seg) * 65535)
        db = raw.cell(b"db" + struct.pack("<H", 65535) + struct.pack("<I", lst))
        vks = [raw.vk("v%d" % i, 0x01000000, db) for i in range(400)]
        too_big = raw.vk("huge", 0x10000001, db)
        vks.append(too_big)
        vl = raw.cell(b"".join(struct.pack("<I", o) for o in vks))
        root = raw.nk("ROOT", nval=len(vks), vallist=vl)
        rv = self.regview(root, raw)
        one = self.timed(lambda: rv.get("SOFTWARE", "", "v399"))
        self.assertEqual(len(one), 1 << 20)                       # capped to 1 MiB, not 16 MiB
        vals = self.timed(lambda: rv.values("SOFTWARE", ""))
        self.assertEqual(len(vals), 401)
        self.assertEqual(vals["huge"], b"")                       # above 16 MiB: not built
        self.assertTrue(all(len(v) <= 1 << 20 for v in vals.values()))
        h = regf.Hive(os.path.join(self.tmp, "Windows", "System32", "config", "SOFTWARE"))
        self.addCleanup(h.close)
        self.assertEqual(h.root().value("huge"), b"")
        self.assertTrue(any("not read" in n for n in h.notes))

    def test_value_lookup_decodes_only_the_requested_value(self):
        raw = RawHive()
        good = raw.vk("good", 0x80000004, 7, vtype=4)
        bad = raw.vk("bad", 100, 0x7FFFFFF0)                      # data cell far outside the file
        vl = raw.cell(struct.pack("<II", bad, good))
        root = raw.nk("ROOT", nval=2, vallist=vl)
        rv = self.regview(root, raw)
        with mock.patch.object(regf.Key, "_data", autospec=True, side_effect=regf.Key._data) as spy:
            self.assertEqual(rv.get("SOFTWARE", "", "good"), 7)
        self.assertEqual(spy.call_count, 1)

    def test_truncated_nk_at_eof_is_hive_error(self):
        win = fakewin.make_target(self.tmp)
        path = os.path.join(win, "System32", "config", "SOFTWARE")
        data = open(path, "rb").read()
        used = max(i for i, b in enumerate(data) if b) + 1
        for cut in range(0x1000 + 40, used, 7):
            with open(path, "wb") as f:
                f.write(data[:cut])
            try:
                with regf.Hive(path) as h:
                    h.root().subkey_names()
                    h.open(r"Microsoft\Windows NT\CurrentVersion")
            except (regf.HiveError, OSError):
                pass

    def test_regview_catches_every_parser_exception(self):
        win = fakewin.make_target(self.tmp)
        for exc in (struct.error("x"), MemoryError(), ValueError("v"), OverflowError("o"), RecursionError("r"),
                    IndexError("i")):
            rv = RegView(win, online=False)
            with mock.patch.object(regf.Hive, "open", side_effect=exc):
                self.assertEqual(rv.get("SOFTWARE", "A", "b", "d"), "d")
                self.assertEqual(rv.subkeys("SOFTWARE", "A"), [])
                self.assertEqual(rv.values("SOFTWARE", "A"), {})
                self.assertFalse(rv.exists("SOFTWARE", "A"))
            self.assertIn(type(exc).__name__, rv.errors["SOFTWARE"])
            rv.close()

    def test_fuzz_only_hive_error(self):
        win = fakewin.make_target(self.tmp)
        src = os.path.join(win, "System32", "config", "SOFTWARE")
        base = open(src, "rb").read()
        used = max(i for i, b in enumerate(base) if b) + 1
        path = os.path.join(self.tmp, "fuzz.hive")
        paths = (r"Microsoft\Windows NT\CurrentVersion", r"Microsoft\Cryptography",
                 r"Microsoft\Windows\CurrentVersion\Component Based Servicing")
        rng = random.Random(20261119)
        t0 = time.time()
        for i in range(3000):
            data = bytearray(base)
            for _ in range(rng.randint(1, 8)):
                pos = rng.randrange(0x1000, used) if rng.random() < 0.9 else rng.randrange(0, 0x100)
                if rng.random() < 0.3 and pos + 1 < len(data):
                    data[pos:pos + 2] = b"\xff\xff"
                else:
                    data[pos] = rng.randrange(256)
            if rng.random() < 0.15:
                data = data[:rng.randrange(0, len(data))]
            with open(path, "wb") as f:
                f.write(data)
            try:
                with regf.Hive(path) as h:
                    stack, budget = [h.root()], 200
                    while stack and budget:
                        budget -= 1
                        k = stack.pop()
                        k.values()
                        stack.extend(k.subkeys())
                    for p in paths:
                        key = h.open(p)
                        if key:
                            key.values()
                            key.value("ProductName")
                    h.get(paths[0], "UBR")
            except (regf.HiveError, OSError):
                pass
            except Exception as e:  # noqa: BLE001
                self.fail("mutation %d raised %s: %s" % (i, type(e).__name__, e))
        self.assertLess(time.time() - t0, 60)


# ---------------------------------------------------------------- B4: evtx
class EvtxHostile(unittest.TestCase):
    def fragment_buffer(self, levels):
        buf = bytearray(0x10000)
        body = b"\x0d\x00\x00\x21" * 8 + b"\x00"                 # 8 references to substitution 0
        struct.pack_into("<I", buf, 0x100 + 20, len(body))
        buf[0x100 + 24:0x100 + 24 + len(body)] = body
        frag = b"\x05\x01" + struct.pack("<H", 1) + "a".encode("utf-16-le")
        for _ in range(levels):
            frag = (b"\x0c" + b"\x00" * 5 + struct.pack("<I", 0x100) + struct.pack("<I", 1)
                    + struct.pack("<HBB", len(frag), 0x21, 0) + frag)
        buf[0x400:0x400 + len(frag)] = frag
        return buf, 0x400, len(frag)

    def test_nested_substitutions_hit_the_work_budget(self):
        buf, start, n = self.fragment_buffer(7)                  # 8**7 resolutions without a budget
        chunk = evtx._Chunk(buf)
        t0 = time.time()
        with self.assertRaises(evtx._BinXmlError):
            chunk.resolve(chunk.parse_stream(start, start + n, 0), None, 0, [])
        self.assertLess(time.time() - t0, 5)

    def test_small_nesting_still_resolves(self):
        buf, start, n = self.fragment_buffer(1)
        chunk = evtx._Chunk(buf)
        out = []
        chunk.resolve(chunk.parse_stream(start, start + n, 0), None, 0, out)
        self.assertEqual("".join(out), "a" * 8)

    def test_bounded_event_heap(self):
        for newest in (True, False):
            keep = evtx._Keep(5, newest)
            ids = list(range(1, 1001))
            random.Random(1).shuffle(ids)
            for rid in ids:
                keep.append({"record_id": rid})
            self.assertEqual(keep.matched, 1000)
            self.assertLessEqual(len(keep.heap), 5)
            got = sorted(e["record_id"] for e in keep.events())
            self.assertEqual(got, [996, 997, 998, 999, 1000] if newest else [1, 2, 3, 4, 5])


# ---------------------------------------------------------------- B3 + B12: log analysis
class LogAnalysisHostile(TmpCase):
    LINES = {
        "srt-name": ("Name: ", loganalysis.analyse_srttrail),
        "srt-root": ("Root cause found: ", loganalysis.analyse_srttrail),
        "srt-result": ("Result: ", loganalysis.analyse_srttrail),
        "setupapi-section": (">>> Section start ", loganalysis.analyse_setupapi),
        "setupapi-header": (">>> [Device Install ", loganalysis.analyse_setupapi),
        "events-header": ("Event[0]: ", loganalysis.analyse_events),
        "events-long": ("Event[0]: 2024-01-01T00:00:00Z Level 2 (Error) ID 41 ", loganalysis.analyse_events),
        "cbs-error": ("2024-01-01 00:00:00, Error ", loganalysis.analyse_cbs),
        "dism-error": ("2024-01-01 00:00:00, Error ", loganalysis.analyse_dism),
        "setup-phase": ("SETUPPHASE = ", loganalysis.analyse_setup),
        "bcd": ("Windows Boot Loader\n-----------\nidentifier ", loganalysis.analyse_bcd),
    }

    def test_one_8mb_line_is_fast(self):
        for filler in (" a", "] ", "\t ", " ["):
            for key, (prefix, fn) in self.LINES.items():
                path = os.path.join(self.tmp, "big.txt")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(prefix + filler * ((8 * 2 ** 20) // len(filler)))
                t0 = time.time()
                res = fn(path)
                self.assertLess(time.time() - t0, 3.0, "%s with filler %r" % (key, filler))
                self.assertIn("size", res)

    def test_clipped_lines_are_counted_and_reported(self):
        path = os.path.join(self.tmp, "CBS.log")
        with open(path, "w") as f:
            f.write("2024-01-01 00:00:00, Error x" + "y" * 10000 + "\nshort\n")
        res = loganalysis.analyse_cbs(path)
        self.assertEqual(res["clipped_lines"], 1)
        case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(case.close)
        with case.section("log_findings", "x") as sec:
            loganalysis._run(sec, "CBS.log", path, loganalysis.analyse_cbs, "missing")
        self.assertIn("clipped", sec.items[0]["reason"])

    def test_5000_digit_repair_attempts_does_not_raise(self):
        path = os.path.join(self.tmp, "SrtTrail.txt")
        with open(path, "w") as f:
            f.write("Startup Repair diagnosis\nNumber of repair attempts: " + "9" * 5000 + "\n")
        res = loganalysis.analyse_srttrail(path)
        self.assertEqual(res["attempts"], 999999999)


# ---------------------------------------------------------------- B5, B9, B13: triage
class FakeEntry:
    def __init__(self, name, path, regular=False, is_dir=False):
        self.name, self.path, self._regular, self._dir = name, path, regular, is_dir

    def is_symlink(self):
        return False

    def is_dir(self, follow_symlinks=True):
        return self._dir

    def is_file(self, follow_symlinks=True):
        return self._regular

    def stat(self, follow_symlinks=True):
        return SimpleNamespace(st_mtime=1.0, st_file_attributes=0, st_mode=0o100644)


class FakeScandir:
    def __init__(self, entries):
        self.entries = entries

    def __enter__(self):
        return iter(self.entries)

    def __exit__(self, *a):
        return False


class TriageHostile(TmpCase):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp, "target") + "\\"
        self.windir = self.root + "Windows"
        self.tasks = os.path.join(self.windir, "System32", "Tasks")
        os.makedirs(self.tasks)
        self.case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(self.case.close)
        self.ctx = SimpleNamespace(case=self.case, ui=SimpleNamespace(say=lambda *a: None),
                                   target=SimpleNamespace(root=self.root, windir=self.windir, online=False))

    def write(self, path, data=TASK_XML):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)

    def run_tasks(self):
        with self.case.section("tasks", "t") as sec:
            out = triage._tasks(self.ctx, sec)
        return out, self.case.data["sections"]["tasks"]

    def test_junctions_back_to_tasks_are_not_followed(self):
        self.write(os.path.join(self.tasks, "good"))
        self.junction(os.path.join(self.tasks, "a"), self.tasks)
        self.junction(os.path.join(self.tasks, "b"), self.tasks)
        t0 = time.time()
        out, sec = self.run_tasks()
        self.assertLess(time.time() - t0, 5)
        self.assertEqual([e["path"] for e in out], ["good"])
        names = [i["name"] for i in sec["items"]]
        self.assertTrue("tasks links" in names or "tasks cap" in names, names)
        self.assertEqual(sec["data"]["links_skipped"], 2)

    def test_file_and_folder_caps(self):
        for i in range(30):
            self.write(os.path.join(self.tasks, "t%02d" % i))
        with mock.patch.object(triage, "TASK_FILES", 10):
            out, sec = self.run_tasks()
        self.assertEqual(len(out), 10)
        self.assertTrue(any(i["name"] == "tasks cap" for i in sec["items"]))
        deep = os.path.join(self.tasks, "d")
        for i in range(6):
            deep = os.path.join(deep, "d")
        self.write(os.path.join(deep, "x"))
        with mock.patch.object(triage, "TASK_DEPTH", 3):
            out, sec = self.run_tasks()
        self.assertTrue(any("nested deeper" in i["reason"] for i in sec["items"]))

    def test_device_or_pipe_entries_are_never_opened(self):
        entries = [FakeEntry("pipe", "\\\\.\\pipe\\x"), FakeEntry("ok", os.path.join(self.tasks, "ok"), regular=True)]
        self.write(os.path.join(self.tasks, "ok"))
        opened = []
        real_open = open

        def spy(path, *a, **k):
            opened.append(str(path))
            return real_open(path, *a, **k)

        with mock.patch.object(triage.os, "scandir", return_value=FakeScandir(entries)), \
                mock.patch("builtins.open", spy):
            out, sec = self.run_tasks()
        self.assertFalse(any("pipe" in p for p in opened))
        self.assertTrue(any(i["name"] == "tasks other" for i in sec["items"]))
        self.assertEqual([e["path"] for e in out], ["ok"])

    def test_strings_and_lists_are_clipped(self):
        cmd = "x" * 50000
        execs = "".join("<Exec><Command>%s</Command></Exec>" % cmd for _ in range(50))
        trig = "<Triggers>" + "<TimeTrigger/>" * 60 + "</Triggers>"
        xml = ('<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Author>%s'
               '</Author></RegistrationInfo>%s<Actions>%s</Actions></Task>' % ("A" * 50000, trig, execs))
        p = os.path.join(self.tasks, "big")
        self.write(p, xml)
        ent = triage._read_task(p, "big", (self.root, self.windir))
        self.assertLessEqual(len(ent["actions"]), triage.MAX_LIST)
        self.assertLessEqual(len(ent["triggers"]), triage.MAX_LIST)
        self.assertLessEqual(len(ent["author"]), triage.MAX_FIELD + 3)
        self.assertTrue(all(len(a) <= triage.MAX_FIELD + 3 for a in ent["actions"]))

    def test_flagged_list_in_section_data_is_capped(self):
        ents = [{"flags": ["f"], "n": i} for i in range(500)]
        shown, more = triage._capped(ents)
        self.assertEqual((len(shown), more), (200, 300))

    def test_task_with_out_of_range_mtime_is_still_read(self):
        p = os.path.join(self.tasks, "old")
        self.write(p)
        for stamp in (-11644473600, 253402300799):
            try:
                os.utime(p, (stamp, stamp))
            except (OSError, OverflowError, ValueError):
                continue
            ent = triage._read_task(p, "old", (self.root, self.windir))
            self.assertEqual(ent["actions"], ["c:\\x\\a.exe"])
            return
        self.skipTest("this OS refuses out-of-range timestamps")


# ---------------------------------------------------------------- B13 + junctions: case.collect_file
class CollectHostile(TmpCase):
    def setUp(self):
        super().setUp()
        self.case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(self.case.close)
        self.target = os.path.join(self.tmp, "target")
        self.outside = os.path.join(self.tmp, "outside")
        os.makedirs(self.target)
        os.makedirs(self.outside)
        with open(os.path.join(self.outside, "secret.txt"), "w") as f:
            f.write("not on the target")

    def test_parent_junction_pointing_outside_is_not_followed(self):
        self.junction(os.path.join(self.target, "link"), self.outside)
        e = self.case.collect_file(os.path.join(self.target, "link", "secret.txt"), "logs/x.txt", root=self.target)
        self.assertEqual(e["status"], "skipped")
        self.assertIn("resolves outside the target", e["reason"])
        self.assertFalse(os.path.exists(self.case.path("logs", "x.txt")))
        e = self.case.collect_file(os.path.join(self.target, "link"), "logs/y.txt", root=self.target)
        self.assertEqual(e["status"], "skipped")

    def test_file_inside_root_is_copied(self):
        p = os.path.join(self.target, "a.log")
        with open(p, "w") as f:
            f.write("hello")
        e = self.case.collect_file(p, "logs/a.log", root=self.target)
        self.assertEqual(e["status"], "ok")
        self.assertTrue(os.path.isfile(self.case.path("logs", "a.log")))

    def test_destination_outside_case_folder_is_refused(self):
        p = os.path.join(self.target, "a.log")
        with open(p, "w") as f:
            f.write("hello")
        e = self.case.collect_file(p, "logs/../../../evil.txt")
        self.assertEqual(e["status"], "error")
        self.assertFalse(os.path.exists(os.path.join(self.case.out_root, "evil.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil.txt")))

    def test_out_of_range_mtime_is_still_copied(self):
        p = os.path.join(self.target, "old.log")
        with open(p, "w") as f:
            f.write("data")
        done = 0
        for stamp in (-11644473600, 253402300799):
            try:
                os.utime(p, (stamp, stamp))
            except (OSError, OverflowError, ValueError):
                continue
            done += 1
            e = self.case.collect_file(p, "logs/old-%d.log" % done, root=self.target)
            self.assertEqual(e["status"], "ok", e)
            self.assertTrue(os.path.isfile(self.case.path("logs", "old-%d.log" % done)))
        if not done:
            self.skipTest("this OS refuses out-of-range timestamps")


# ---------------------------------------------------------------- B8, B9: logs.py
class LogsHostile(TmpCase):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp, "target") + "\\"
        self.windir = self.root + "Windows"
        os.makedirs(self.windir)
        self.case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(self.case.close)
        cfg = {"limits": {"max_log_mb": 1, "max_dump_mb": 1, "max_minidumps": 10}, "logs": {}}
        t = Target(root=self.root, windir=self.windir, online=False, letter="W", volume={}, disk=None, partition=None)
        self.ctx = Ctx(self.tmp, cfg, {"admin": True}, self.case, ui.UI(auto=True), mock.Mock(), target=t)

    def test_unsafe_leaf_names(self):
        for name in ("CON.dmp", "nul", "COM1.txt", "lpt9.dmp", "a..b.dmp", "..\\evil.dmp", "x/y.dmp", "c:evil.dmp"):
            leaf, replaced = logs._safe_leaf(name, 3)
            self.assertTrue(replaced, name)
            self.assertTrue(leaf.startswith("file-3"), leaf)
        for name in ("Mini010120-01.dmp", "console.dmp", "comx.dmp"):
            self.assertEqual(logs._safe_leaf(name, 1), (name, False))

    def test_minidump_named_con_or_with_dotdot(self):
        real = os.path.join(self.windir, "Minidump", "real.dmp")
        os.makedirs(os.path.dirname(real))
        with open(real, "wb") as f:
            f.write(b"MDMP")
        entries = [FakeEntry("CON.dmp", real, regular=True), FakeEntry("..\\..\\evil.dmp", real, regular=True),
                   FakeEntry("link.dmp", real, regular=False)]
        with mock.patch.object(logs.os, "scandir", return_value=FakeScandir(entries)):
            with self.case.section("logs_target", "t") as sec:
                logs._logs_target(self.ctx, sec)
        names = sorted(os.listdir(self.case.path("logs")))
        self.assertEqual([n for n in names if n.startswith("target-minidump")],
                         ["target-minidump-file-1.dmp", "target-minidump-file-2.dmp"])
        self.assertFalse(os.path.exists(os.path.join(self.case.out_root, "evil.dmp")))
        reasons = " ".join(i["reason"] for i in sec.items)
        self.assertIn("unsafe file name replaced", reasons)
        self.assertTrue(any(i["name"] == "minidumps not regular" for i in sec.items))

    def test_minidump_listing_is_capped(self):
        entries = [FakeEntry("m%d.dmp" % i, "x", regular=True) for i in range(logs.MAX_DUMP_ENTRIES + 50)]
        with mock.patch.object(logs.os, "scandir", return_value=FakeScandir(entries)):
            with self.case.section("logs_target", "t") as sec:
                logs._logs_target(self.ctx, sec)
        self.assertTrue(any(i["name"] == "minidumps cap" for i in sec.items))

    def test_oversized_bcd_is_not_copied_or_enumerated(self):
        p = os.path.join(self.tmp, "BCD")
        with open(p, "wb") as f:
            f.truncate(64 * 2 ** 20 + 1)           # sparse
        with self.case.section("bcd", "t") as sec:
            ok = logs._bcd_store(self.ctx, sec, "x", p, True, root=self.tmp)
        self.assertFalse(ok)
        self.ctx.runner.run.assert_not_called()
        self.assertFalse(os.path.exists(self.case.path("exports", "bcd-x.work")))
        self.assertIn("enumeration skipped", sec.items[0]["reason"])


# ---------------------------------------------------------------- B9: drivers
class DriversHostile(TmpCase):
    def test_strings_clipped_and_file_count_capped(self):
        win = os.path.join(self.tmp, "Windows")
        inf = os.path.join(win, "INF")
        os.makedirs(inf)
        with open(os.path.join(inf, "oem1.inf"), "w") as f:
            f.write("[Version]\nProvider=%%p%%\nClass=%s\nDriverVer=01/02/2020,%s\n[Strings]\np=%s\n"
                    % ("C" * 5000, "9" * 5000, "P" * 5000))
        d = drivers.inventory(win)[0]
        self.assertLessEqual(len(d["provider"]), drivers.MAX_STR)
        self.assertLessEqual(len(d["class"]), drivers.MAX_STR)
        self.assertLessEqual(len(d["driver_version"]), drivers.MAX_STR)
        for i in range(2, 30):
            with open(os.path.join(inf, "oem%d.inf" % i), "w") as f:
                f.write("[Version]\n")
        with mock.patch.object(drivers, "MAX_INF_FILES", 10):
            self.assertEqual(len(drivers.inventory(win)), 10)

    def test_linked_inf_is_not_read(self):
        win = os.path.join(self.tmp, "Windows")
        inf = os.path.join(win, "INF")
        os.makedirs(inf)
        elsewhere = os.path.join(self.tmp, "else")
        os.makedirs(elsewhere)
        self.junction(os.path.join(inf, "oem7.inf"), elsewhere)
        self.assertEqual(drivers.inventory(win), [])


# ---------------------------------------------------------------- B11: wim
class WimHostile(TmpCase):
    def header(self, offset, csize, orig):
        head = bytearray(208)
        head[0:8] = b"MSWIM\x00\x00\x00"
        struct.pack_into("<HH", head, 40, 1, 1)
        head[72:79] = csize.to_bytes(7, "little")
        struct.pack_into("<QQ", head, 80, offset, orig)
        return head

    def test_huge_offsets_do_not_raise(self):
        for off in (2 ** 63, 2 ** 64 - 1, 2 ** 63 - 1):
            path = os.path.join(self.tmp, "w.wim")
            with open(path, "wb") as f:
                f.write(self.header(off, 100, 100))
            info = wim.read_info(path)
            self.assertEqual(info["images"], [])
            self.assertTrue(info["errors"], off)

    def test_xml_resource_size_is_capped_at_16_mib(self):
        path = os.path.join(self.tmp, "w.wim")
        with open(path, "wb") as f:
            f.write(self.header(208, 17 * 2 ** 20, 17 * 2 ** 20))
        info = wim.read_info(path)
        self.assertIn("implausible", info["errors"][0])

    def test_images_without_integer_index_are_dropped_and_strings_clipped(self):
        xml = ('<WIM><IMAGE><NAME>noindex</NAME></IMAGE><IMAGE INDEX="x"><NAME>bad</NAME></IMAGE>'
               '<IMAGE INDEX="2"><NAME>%s</NAME></IMAGE></WIM>' % ("N" * 5000))
        raw = b"\xff\xfe" + xml.encode("utf-16-le")
        path = os.path.join(self.tmp, "w.wim")
        with open(path, "wb") as f:
            f.write(self.header(208, len(raw), len(raw)) + raw)
        info = wim.read_info(path)
        self.assertEqual([i["index"] for i in info["images"]], [2])
        self.assertEqual(len(info["images"][0]["name"]), 200)
        self.assertTrue(any("INDEX" in e for e in info["errors"]))


# ---------------------------------------------------------------- third review N1: lone surrogates in names
class SurrogateNames(TmpCase):
    BAD = "crash\ud800.dmp"
    USER = "bob\udfff"

    def make(self, *parts, data=b"MDMP"):
        p = os.path.join(*parts)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
        except (OSError, UnicodeError, ValueError) as e:
            self.skipTest("this file system refuses a lone surrogate in a name: %s" % e)
        return p

    def assert_case_json(self, case, needle):
        with open(case.path("case.json"), encoding="utf-8") as f:
            raw = f.read()
        self.assertIsInstance(json.loads(raw), dict)
        self.assertIn(needle, raw)
        self.assertFalse(os.path.exists(case.path("case.json.tmp")))

    def test_unit_surrogates_in_data_item_json_text_and_log(self):
        case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(case.close)
        case.data["target"]["name"] = "a\ud800b"
        with case.section("one", "One") as sec:
            sec.item("minidump " + self.BAD, "ok", "copied \udfff")
        p = case.write_json("inventory/x.json", {"n": [self.USER]})
        t = case.write_text("logs/x.txt", "line \ud800\n")
        case_mod.LOG.info("name %s", self.BAD)
        self.assert_case_json(case, r"\ud800")
        with open(p, encoding="utf-8") as f:
            raw = f.read()
        self.assertEqual(json.loads(raw), {"n": ["bob\udfff"]})
        self.assertIn(r"\udfff", raw)
        with open(t, encoding="utf-8") as f:
            self.assertIn(r"\ud800", f.read())
        with open(case.path("debug.log"), encoding="utf-8") as f:
            self.assertIn(r"crash\ud800.dmp", f.read())

    def test_section_survives_a_failing_save(self):
        case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(case.close)
        with mock.patch.object(case, "save", side_effect=UnicodeEncodeError("utf-8", "x", 0, 1, "boom")):
            with case.section("a", "A") as sec:
                sec.item("x", "ok")
        self.assertEqual(case.data["sections"]["a"]["status"], "ok")
        with case.section("b", "B"):
            pass
        self.assertIn("b", case.data["sections"])

    def make_ctx(self, with_user=True):
        win = fakewin.make_target(os.path.join(self.tmp, "target"))
        root = os.path.join(self.tmp, "target") + "\\"
        self.make(win, "Minidump", self.BAD)
        self.make(root, "Users", self.USER, "NTUSER.DAT", data=b"not a hive")
        case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(case.close)
        reg = RegView(win, online=False)
        self.addCleanup(reg.close)
        t = Target(root=root, windir=win, online=False, letter="W", volume={}, disk=None, partition=None, reg=reg)
        runner = mock.Mock()
        runner.verified_tools = {}
        cfg = {"limits": {"max_log_mb": 1, "max_dump_mb": 1, "max_minidumps": 10}, "logs": {}}
        ctx = Ctx(self.tmp, cfg, {"admin": True}, case, SimpleNamespace(say=lambda *a, **k: None), runner, target=t)
        return ctx, case

    def test_minidump_and_profile_names_with_surrogates_do_not_end_the_scan(self):
        ctx, case = self.make_ctx()
        logs.collect(ctx)
        triage.collect(ctx)
        secs = case.data["sections"]
        for name in ("logs_target", "event_logs", "bcd", "logs_host", "disk_health", "pending",
                     "autoruns", "services", "tasks"):
            self.assertIn(name, secs)
        self.assertEqual(secs["logs_target"]["status"], "ok")
        self.assertTrue(any(self.BAD in i["name"] for i in secs["logs_target"]["items"]))
        self.assertTrue(any(self.USER in i["name"] for i in secs["autoruns"]["items"]))
        self.assert_case_json(case, r"crash\ud800.dmp")
        self.assert_case_json(case, r"bob\udfff")


# ---------------------------------------------------------------- third review N2 + N4: hive lookups and budgets
class HiveLookups(TmpCase):
    def start_value(self, raw, n=2):
        vk = raw.vk("Start", 0x80000004, n, vtype=4)
        return raw.cell(struct.pack("<I", vk)), 1

    def services_hive(self, count):
        """SYSTEM hive whose Services list points `count` times at one nk named 'a/b' (the review's trigger)."""
        raw = RawHive()
        vl, nval = self.start_value(raw)
        leaf = raw.nk("a/b", nval=nval, vallist=vl)
        lst = raw.cell(b"lf" + struct.pack("<H", count) + struct.pack("<II", leaf, 0) * count)
        services = raw.nk("Services", nsub=count, sublist=lst)
        cs_list = raw.cell(b"lf" + struct.pack("<H", 1) + struct.pack("<II", services, 0))
        cs = raw.nk("ControlSet001", nsub=1, sublist=cs_list)
        root_list = raw.cell(b"lf" + struct.pack("<H", 1) + struct.pack("<II", cs, 0))
        root = raw.nk("ROOT", nsub=1, sublist=root_list)
        win = os.path.join(self.tmp, "Windows")
        raw.write(os.path.join(win, "System32", "config", "SYSTEM"), root)
        return win

    def test_regdiff_snapshot_with_4000_services_pointing_at_one_key_is_fast(self):
        from recoverykit.modules import regdiff
        rv = RegView(self.services_hive(4000), online=False)
        self.addCleanup(rv.close)
        t0 = time.time()
        snap = regdiff.snapshot(rv)
        took = time.time() - t0
        print("regdiff.snapshot, 4000 services -> one key: %.3f s" % took)
        self.assertLess(took, 3.0)
        self.assertEqual(snap["services"], {"a/b": {"start": 2, "type": None, "image_path": None,
                                                    "error_control": None}})

    def test_triage_services_with_4000_services_pointing_at_one_key_is_fast(self):
        win = self.services_hive(4000)
        reg = RegView(win, online=False)
        self.addCleanup(reg.close)
        case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(case.close)
        ctx = SimpleNamespace(case=case, ui=SimpleNamespace(say=lambda *a: None),
                              target=SimpleNamespace(root=self.tmp + "\\", windir=win, online=False, reg=reg))
        t0 = time.time()
        with case.section("services", "s") as sec:
            out = triage._services(ctx, sec)
        took = time.time() - t0
        print("triage._services, 4000 services -> one key: %.3f s" % took)
        self.assertLess(took, 3.0)
        self.assertEqual(len(out), 4000)

    def test_truncated_enumeration_is_noted_and_reported_as_item(self):
        win = self.services_hive(5001)
        reg = RegView(win, online=False)
        self.addCleanup(reg.close)
        kids = reg.children("SYSTEM", r"ControlSet001\Services", max_children=3)
        self.assertEqual(len(kids), 3)
        self.assertTrue(kids.truncated)
        self.assertEqual(reg.children("SYSTEM", r"ControlSet001\Services", max_children=5001).truncated, False)
        case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(case.close)
        ctx = SimpleNamespace(case=case, ui=SimpleNamespace(say=lambda *a: None),
                              target=SimpleNamespace(root=self.tmp + "\\", windir=win, online=False, reg=reg))
        with case.section("services", "s") as sec:
            out = triage._services(ctx, sec)
        self.assertEqual(len(out), 5000)
        msg = "more than 5000 entries: only the first 5000 were read"
        self.assertIn(msg, reg.notes["SYSTEM"])
        item = [i for i in sec.items if i["reason"] == msg]
        self.assertTrue(item and item[0]["status"] == "ok", sec.items)

    def test_key_named_with_a_slash_is_found_and_openable(self):
        win = self.services_hive(1)
        path = os.path.join(win, "System32", "config", "SYSTEM")
        with regf.Hive(path) as h:
            services = h.open(r"ControlSet001\Services")
            self.assertEqual([k.name for k in services.children()], ["a/b"])
            self.assertEqual(h.open("ControlSet001\\Services\\a/b").value("Start"), 2)
            self.assertIsNone(h.open("ControlSet001/Services"))
            names_values = services.child_values()
            self.assertEqual(names_values, ([("a/b", {"Start": 2})], False))

    def children_hive(self, count, vks_fn):
        raw = RawHive()
        vks = vks_fn(raw)
        vl = raw.cell(b"".join(struct.pack("<I", o) for o in vks))
        leaf = raw.nk("a", nval=len(vks), vallist=vl)
        lst = raw.cell(b"lf" + struct.pack("<H", count) + struct.pack("<II", leaf, 0) * count)
        services = raw.nk("Services", nsub=count, sublist=lst)
        cs_list = raw.cell(b"lf" + struct.pack("<H", 1) + struct.pack("<II", services, 0))
        cs = raw.nk("ControlSet001", nsub=1, sublist=cs_list)
        root_list = raw.cell(b"lf" + struct.pack("<H", 1) + struct.pack("<II", cs, 0))
        root = raw.nk("ROOT", nsub=1, sublist=root_list)
        win = os.path.join(self.tmp, "Windows")
        raw.write(os.path.join(win, "System32", "config", "SYSTEM"), root)
        return win

    def children_peak(self, win):
        import tracemalloc
        rv = RegView(win, online=False)
        self.addCleanup(rv.close)
        t0 = time.time()
        tracemalloc.start()
        try:
            kids = rv.children("SYSTEM", r"ControlSet001\Services")
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        return kids, peak, time.time() - t0

    def test_children_share_one_byte_budget(self):
        def vks(raw):
            cell = raw.cell(bytes(1 << 20))
            return [raw.vk("v%03d" % i, 1 << 20, cell) for i in range(300)]
        kids, peak, took = self.children_peak(self.children_hive(60, vks))
        print("RegView.children, 60 x 300 values on one 1 MiB cell: peak %.1f MiB, %.2f s" % (peak / 2 ** 20, took))
        self.assertLess(peak, 100 * 2 ** 20)
        self.assertLess(took, 3.0)
        self.assertEqual(len(kids), 60)
        full = sum(1 for _, v in kids for x in v.values() if len(x) == 1 << 20)
        self.assertLessEqual(full, 64)

    def test_multi_sz_is_capped_by_decoded_size(self):
        def vks(raw):
            cell = raw.cell(b"a\x00b\x00\x00\x00" * ((1 << 20) // 6))
            return [raw.vk("m%04d" % i, 1 << 20, cell, vtype=7) for i in range(300)]
        kids, peak, took = self.children_peak(self.children_hive(1, vks))
        print("RegView.children, MULTI_SZ 1 MiB cell x 300: peak %.1f MiB, %.2f s" % (peak / 2 ** 20, took))
        self.assertLess(peak, 20 * 2 ** 20)
        for _, v in kids:
            for x in v.values():
                self.assertLessEqual(len(x), 4096)

    def test_values_stops_at_16_mib_and_keeps_memory_low(self):
        import tracemalloc
        raw = RawHive()
        cell = raw.cell(bytes(1 << 20))
        vks = [raw.vk("v%03d" % i, 1 << 20, cell) for i in range(300)]
        vl = raw.cell(b"".join(struct.pack("<I", o) for o in vks))
        root = raw.nk("ROOT", nval=len(vks), vallist=vl)
        path = os.path.join(self.tmp, "big.hive")
        raw.write(path, root)
        with regf.Hive(path) as h:
            tracemalloc.start()
            try:
                vals = h.root().values()
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            print("Key.values(), 300 vk -> one 1 MiB cell: peak %.1f MiB" % (peak / 2 ** 20))
            self.assertLess(peak, 40 * 2 ** 20)
            self.assertEqual(len(vals), 300)
            full = [n for n, v in vals.items() if len(v) == 1 << 20]
            self.assertEqual(len(full), 16)
            self.assertTrue(all(v == b"" for n, v in vals.items() if n not in full))
            self.assertTrue(any("more than" in n for n in h.notes), h.notes)
            self.assertEqual(len(h.root().value("v299")), 1 << 20)     # a named lookup is not budgeted away


# ---------------------------------------------------------------- third review N3: evtx per-file budget
class EvtxFileBudget(TmpCase):
    @staticmethod
    def name_struct(name):
        return struct.pack("<IHH", 0, 0, len(name)) + name.encode("utf-16-le") + b"\x00\x00"

    def element(self, base, name, kids_fn):
        """BinXml element (no attributes) built to sit at chunk offset `base`; names are inline."""
        ns = self.name_struct(name)
        head = b"\x01" + b"\x00\x00" + b"\x00\x00\x00\x00" + struct.pack("<I", base + 11) + ns
        kids = kids_fn(base + len(head) + 1)
        return head + b"\x02" + kids + b"\x04"

    @staticmethod
    def text(s):
        return b"\x05\x01" + struct.pack("<H", len(s)) + s.encode("utf-16-le")

    def event_definition(self, refs):
        """Template body: <Event><System><Level>2</Level><Channel>{sub 0} x refs</Channel></System></Event>."""
        ref = b"\x0d\x00\x00\x01"

        def channel(base):
            return self.element(base, "Channel", lambda b: ref * refs)

        def system(base):
            lvl = self.element(base, "Level", lambda b: self.text("2"))
            return lvl + channel(base + len(lvl))

        return self.element(0x100 + 24, "Event", lambda base: self.element(base, "System", system))

    def chunk(self, records, definition=None, def_body=None):
        buf = bytearray(0x10000)
        buf[0:8] = evtx.CHUNK_MAGIC
        body = def_body if def_body is not None else definition
        struct.pack_into("<I", buf, 0x100 + 20, len(body))
        buf[0x100 + 24:0x100 + 24 + len(body)] = body
        off = 0x200
        for rid, payload in records:
            size = 24 + len(payload) + 4
            buf[off:off + 4] = evtx.REC_MAGIC
            struct.pack_into("<IQQ", buf, off + 4, size, rid, 132000000000000000)
            buf[off + 24:off + 24 + len(payload)] = payload
            struct.pack_into("<I", buf, off + size - 4, size)
            off += size
        struct.pack_into("<I", buf, 0x30, off)
        return bytes(buf)

    @staticmethod
    def instance(sub):
        """Template instance of the definition at 0x100 with one string substitution."""
        return (b"\x0c" + b"\x00" * 5 + struct.pack("<I", 0x100) + struct.pack("<I", 1)
                + struct.pack("<HBB", len(sub), 0x01, 0) + sub)

    def write(self, chunks):
        path = os.path.join(self.tmp, "t.evtx")
        head = bytearray(0x1000)
        head[0:8] = evtx.FILE_MAGIC
        struct.pack_into("<H", head, 0x2A, len(chunks))
        with open(path, "wb") as f:
            f.write(bytes(head) + b"".join(chunks))
        return path

    def test_hand_built_event_parses(self):
        chunk = self.chunk([(7, self.instance("Application".encode("utf-16-le")))], self.event_definition(1))
        evs, st = evtx.read_events(self.write([chunk]), levels=(2,))
        self.assertEqual(st["errors"], [])
        self.assertEqual([e["channel"] for e in evs], ["Application"])

    def test_huge_channel_text_is_bounded_in_memory(self):
        import tracemalloc
        big = ("A" * 30000).encode("utf-16-le")                # 60 KB value
        chunk = self.chunk([(1, self.instance(big))], self.event_definition(800))     # 800 x 30000 = 24M chars
        path = self.write([chunk])
        tracemalloc.start()
        try:
            evs, st = evtx.read_events(path, levels=(2,))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        print("evtx Channel expanding to 24M characters: peak %.1f MiB" % (peak / 2 ** 20))
        self.assertLess(peak, 40 * 2 ** 20)
        self.assertEqual(evs, [])
        self.assertTrue(st["errors"])

    def test_channel_provider_and_computer_are_clipped(self):
        big = ("B" * 30000).encode("utf-16-le")
        chunk = self.chunk([(1, self.instance(big))], self.event_definition(20))      # 600,000 characters
        evs, st = evtx.read_events(self.write([chunk]), levels=(2,))
        self.assertEqual(len(evs), 1)
        self.assertEqual(len(evs[0]["channel"]), evtx.MAX_DATA_LEN)
        self.assertLessEqual(len(evtx._text(evtx._El("x"))), evtx.MAX_TEXT)
        el = evtx._El("x")
        el.kids.append("z" * 200000)
        self.assertEqual(len(evtx._text(el)), evtx.MAX_TEXT)

    def expensive_chunk(self, records=300):
        """Chunk of tiny records that all instantiate one definition that blows the per-record budget."""
        body = b"\x0d\x00\x00\x21" * 8 + b"\x00"                # 8 references to substitution 0, a BinXml fragment
        frag = b"\x05\x01" + struct.pack("<H", 1) + "a".encode("utf-16-le")
        for _ in range(7):                                       # 8**7 resolutions without a budget
            frag = (b"\x0c" + b"\x00" * 5 + struct.pack("<I", 0x100) + struct.pack("<I", 1)
                    + struct.pack("<HBB", len(frag), 0x21, 0) + frag)
        return self.chunk([(i + 1, frag) for i in range(records)], def_body=body)

    def test_many_tiny_records_sharing_an_expensive_definition_finish_fast(self):
        path = self.write([self.expensive_chunk() for _ in range(20)])
        t0 = time.time()
        evs, st = evtx.read_events(path)
        took = time.time() - t0
        print("evtx 20 chunks x 300 records on one expensive definition: %.2f s, seen %d, truncated %r"
              % (took, st["records_seen"], st.get("truncated")))
        self.assertLess(took, 5.0)
        self.assertEqual(evs, [])
        self.assertTrue(st["errors"])

    def test_per_file_step_budget_stops_and_says_so(self):
        path = self.write([self.expensive_chunk(50) for _ in range(6)])
        with mock.patch.object(evtx, "MAX_FILE_STEPS", 150000):
            evs, st = evtx.read_events(path)
        self.assertIn("steps", st["truncated"])
        self.assertLess(st["records_seen"], 300)

    def test_per_file_time_budget_stops_and_says_so(self):
        path = self.write([self.expensive_chunk(50) for _ in range(6)])
        with mock.patch.object(evtx, "MAX_FILE_SECONDS", -1.0):
            evs, st = evtx.read_events(path)
        self.assertIn("time budget", st["truncated"])
        self.assertEqual(evs, [])

    def test_logs_item_says_stopped_early(self):
        path = self.write([self.expensive_chunk(50) for _ in range(6)])
        case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(case.close)
        win = os.path.join(self.tmp, "Windows")
        logdir = os.path.join(win, "System32", "winevt", "Logs")
        os.makedirs(logdir)
        shutil.copy(path, os.path.join(logdir, "System.evtx"))
        runner = mock.Mock()
        runner.run.return_value = SimpleNamespace(error="no wevtutil", rc=None, out="", ok=False)
        t = Target(root=self.tmp + "\\", windir=win, online=False, letter="W", volume={}, disk=None, partition=None)
        cfg = {"limits": {}, "logs": {"event_logs": ["System"]}}
        ctx = Ctx(self.tmp, cfg, {"admin": True}, case, SimpleNamespace(say=lambda *a, **k: None), runner, target=t)
        with mock.patch.object(evtx, "MAX_FILE_STEPS", 150000):
            with case.section("event_logs", "e") as sec:
                logs._event_logs(ctx, sec)
        self.assertIn("stopped early: ", sec.items[0]["reason"])


# ---------------------------------------------------------------- third review N14: oversized INF
class DriversOversized(TmpCase):
    def test_inf_over_the_cap_is_skipped_not_an_error(self):
        win = os.path.join(self.tmp, "Windows")
        inf = os.path.join(win, "INF")
        os.makedirs(inf)
        with open(os.path.join(inf, "oem1.inf"), "wb") as f:
            f.write(b"; " + b"x" * (drivers.MAX_INF_BYTES + 10))
        with open(os.path.join(inf, "oem2.inf"), "w") as f:
            f.write("[Version]\nProvider=P\n")
        case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(case.close)
        t = Target(root=self.tmp + "\\", windir=win, online=False, letter="W", volume={}, disk=None, partition=None)
        ctx = Ctx(self.tmp, {}, {}, case, SimpleNamespace(say=lambda *a, **k: None), mock.Mock(), target=t)
        drivers.collect(ctx)
        sec = case.data["sections"]["drivers"]
        big = [i for i in sec["items"] if i["name"] == "oem1.inf"]
        self.assertEqual([(i["status"], i["reason"]) for i in big], [("skipped", "larger than 2 MB")])
        self.assertEqual(sec["status"], "ok")
        self.assertEqual(sec["reason"], "")
        listed = {d["inf"]: d for d in drivers.inventory(win)}
        self.assertEqual(listed["oem1.inf"]["skipped"], "larger than 2 MB")
        self.assertNotIn("error", listed["oem1.inf"])


if __name__ == "__main__":
    unittest.main()
