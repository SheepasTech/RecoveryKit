"""Log analysis tests. Run: python -m unittest tests.test_loganalysis -v"""
import copy
import json
import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace

from recoverykit.core.case import Case
from recoverykit.modules import assistant as A
from recoverykit.modules import loganalysis as L
from tests.test_assistant import ROOT, idea1, ids, rules

SRT_FAIL = (
    "Startup Repair diagnosis and repair log\n---------------------------\n"
    "Number of repair attempts: 1\n\n"
    "Test Performed:\n---------------------------\n"
    "Name: Check for updates\nResult: Completed successfully. Error code = 0x0\nTime taken = 0 ms\n\n"
    "Name: System disk test\nResult: Completed successfully. Error code = 0x0\n\n"
    "Name: Disk failure diagnosis\nResult: Failed. Error code = 0x490\n\n"
    "Root cause found:\n---------------------------\n"
    "Boot critical file c:\\windows\\system32\\drivers\\x.sys is corrupt.\n\n"
    "Repair action: File repair\nResult: Failed. Error code =  0x2\nTime taken = 1000 ms\n")
SRT_OK = ("Startup Repair diagnosis and repair log\n---------------------------\n"
          "Boot status indicates that the OS booted successfully\n"
          "Name: Check for updates\nResult: Completed successfully. Error code = 0x0\n")
CBS = (
    "2026-11-19 10:00:00, Info                  CSI    00000001 starting\n"
    "2026-11-19 10:00:01, Error                 CSI    00000002 (F) HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) 0x80070002 failed\n"
    "2026-11-19 10:00:02, Error                 CSI    00000003 (F) 0x800f0915 repair failed\n"
    "2026-11-19 10:00:03, Error                 CSI    00000004 (F) 0x800f0915 repair failed again\n"
    "2026-11-19 10:00:04, Info                  CSI    00000005 Cannot repair member file [l:20]'bad.dll' of x\n"
    "2026-11-19 10:00:05, Info                  CSI    00000006 (p)\tCSI Payload Corrupt\t\t\\SystemRoot\\other.sys\n")
DISM = (
    "2026-11-19 10:00:00, Info                  DISM   DISM.EXE: Executing command line: dism /online /cleanup-image /restorehealth\n"
    "2026-11-19 10:00:09, Error                 DISM   DISM Package Manager: failed 0x800f081f\n")
SETUPAPI = (
    ">>>  [Device Install (Hardware initiated) - PCI\\VEN_8086&DEV_1234]\n>>>  Section start 2026/11/19 10:00:00.100\n"
    "     ndv: done\n"
    ">>>  [Setup online Device Install - USB\\VID_1&PID_2]\n>>>  Section start 2026/11/19 10:05:00.200\n"
    "!!!  dvi: Device not started: Device has problem: 0x0a\n")
EV_LONG = (
    "Event[0]:\n  Log Name: System\n  Source: Microsoft-Windows-Kernel-Power\n  Date: 2026-11-19T10:00:00.000\n"
    "  Event ID: 41\n  Level: Critical\n  Description:\n  The system rebooted without cleanly shutting down.\n\n"
    + "".join("Event[%d]:\n  Log Name: System\n  Source: disk\n  Date: 2026-11-19T10:0%d:00.000\n  Event ID: 7\n"
              "  Level: Error\n  Description:\n  The device has a bad block.\n\n" % (i + 1, i) for i in range(3))
    + "Event[4]:\n  Log Name: System\n  Source: Microsoft-Windows-WHEA-Logger\n  Date: 2026-11-19T11:00:00.000\n"
      "  Event ID: 18\n  Level: Critical\n  Description:\n  A fatal hardware error.\n\n"
    "Event[5]:\n  Log Name: System\n  Source: BugCheck\n  Date: 2026-11-19T11:30:00.000\n  Event ID: 1001\n"
    "  Level: Error\n  Description:\n  The bugcheck was: 0x0000009f (0x3, 0x1).\n\n"
    "Event[6]:\n  Log Name: System\n  Source: Boring-Provider\n  Date: 2026-11-19T12:00:00.000\n  Event ID: 5\n"
    "  Level: Warning\n  Description:\n  nothing special\n")
EV_SHORT = (
    "Event[0]: 2026-11-19T17:01:02Z  Level 1 (Critical)  ID 41  Microsoft-Windows-Kernel-Power  [System]\n"
    + "".join("Event[%d]: 2026-11-19T17:0%d:02Z  Level 2 (Error)  ID 7  disk  [System]\n" % (i + 1, i) for i in range(3))
    + "Event[4]: 2026-11-19T18:00:00Z  Level 2 (Error)  ID 18  Microsoft-Windows-WHEA-Logger  [System]\n"
    "Event[5]: 2026-11-19T18:01:00Z  Level 3 (Warning)  ID 7026  Service Control Manager  [System]\n"
    "Event[6]: 2026-11-19T18:02:00Z  Level 4 (Information)  ID 5  Boring Provider  [System]\n")
BCD_BAD = (
    "Windows Boot Manager\n--------------------\nidentifier              {9dea862c-5cdd-4e70-acc1-f32b344d4795}\n"
    "device                  partition=\\Device\\HarddiskVolume1\ndefault                 {aaaa0000-0000-0000-0000-000000000001}\n"
    "displayorder            {aaaa0000-0000-0000-0000-000000000001}\n\n"
    "Windows Boot Loader\n-------------------\nidentifier              {bbbb0000-0000-0000-0000-000000000002}\n"
    "device                  unknown\npath                    \\Windows\\system32\\winload.efi\n"
    "description             Windows 11\nosdevice                unknown\nrecoveryenabled         Yes\n")
BCD_GOOD = (
    "Windows Boot Manager\n--------------------\nidentifier              {9dea862c-5cdd-4e70-acc1-f32b344d4795}\n"
    "default                 {bbbb0000-0000-0000-0000-000000000002}\n\n"
    "Windows Boot Loader\n-------------------\nidentifier              {bbbb0000-0000-0000-0000-000000000002}\n"
    "device                  partition=C:\npath                    \\Windows\\system32\\winload.efi\n"
    "description             Windows 11\nosdevice                partition=C:\nrecoveryenabled         Yes\n")


class UI:
    def __init__(self):
        self.lines = []

    def say(self, t=""):
        self.lines.append(t)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.case = Case(os.path.join(self.tmp, "cases"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(self.case.close)
        self.ctx = SimpleNamespace(case=self.case, ui=UI())

    def put(self, name, content, encoding="utf-8", register=True):
        rel = "logs/" + name
        p = self.case.path("logs", name)
        data = content if isinstance(content, bytes) else content.encode(encoding)
        with open(p, "wb") as f:
            f.write(data)
        if register:
            self.case.data["files"].append({"dest": rel, "status": "ok", "size": len(data), "src": "X:\\t"})
        return p

    def run_collect(self):
        L.collect(self.ctx)
        sec = self.case.data["sections"]["log_findings"]
        return sec, {i["name"]: i for i in sec["items"]}


class Analysers(Base):
    def test_srttrail_failure(self):
        r = L.analyse_srttrail(self.put("target-System32_LogFiles_Srt_SrtTrail.txt", SRT_FAIL))
        self.assertEqual(r["root_cause"], "Boot critical file c:\\windows\\system32\\drivers\\x.sys is corrupt.")
        self.assertEqual(r["repair_action"], "File repair")
        self.assertEqual(r["result"], "Failed. Error code = 0x2")
        self.assertEqual(r["error_code"], "0x490")
        self.assertFalse(r["boot_status_ok"])
        self.assertEqual(r["tests_failed"], ["Disk failure diagnosis"])
        self.assertEqual(r["attempts"], 1)

    def test_srttrail_booted(self):
        r = L.analyse_srttrail(self.put("SrtTrail.txt", SRT_OK))
        self.assertTrue(r["boot_status_ok"])
        self.assertIsNone(r["root_cause"])
        self.assertEqual(r["tests_failed"], [])

    def test_srttrail_utf16_same(self):
        a = L.analyse_srttrail(self.put("a-SrtTrail.txt", SRT_FAIL))
        b = L.analyse_srttrail(self.put("b-SrtTrail.txt", b"\xff\xfe" + SRT_FAIL.encode("utf-16-le")))
        self.assertEqual({k: v for k, v in a.items() if k not in ("size",)},
                         {k: v for k, v in b.items() if k not in ("size",)})

    def test_cbs(self):
        r = L.analyse_cbs(self.put("c-CBS.log", CBS))
        self.assertEqual(r["error_count"], 3)
        self.assertEqual(r["hresults"], {"0x800f0915": 2, "0x80070002": 1})
        self.assertEqual(r["corrupt_files"], ["bad.dll", "\\SystemRoot\\other.sys"])
        self.assertEqual(r["last_line_time"], "2026-11-19 10:00:05")
        self.assertEqual(len(r["errors"]), 3)

    def test_dism(self):
        r = L.analyse_dism(self.put("d-dism.log", DISM))
        self.assertEqual(r["error_count"], 1)
        self.assertEqual(r["hresults"], {"0x800f081f": 1})
        self.assertEqual(r["last_operation"], "dism /online /cleanup-image /restorehealth")

    def test_setupapi(self):
        r = L.analyse_setupapi(self.put("s-setupapi.dev.log", SETUPAPI))
        self.assertEqual(len(r["last_installs"]), 2)
        self.assertEqual(r["last_installs"][1]["start"], "2026/11/19 10:05:00.200")
        self.assertTrue(r["last_installs"][1]["header"].startswith("Setup online Device Install"))
        self.assertEqual(len(r["failures"]), 1)

    def test_events_both_formats(self):
        for text in (EV_LONG, EV_SHORT):
            r = L.analyse_events(self.put("e.txt", text))
            self.assertEqual(r["by_source_id"]["disk 7"], 3)
            summ = {(s["source"], s["id"]): s for s in r["notable_summary"]}
            self.assertEqual(summ[("disk", 7)]["count"], 3)
            self.assertEqual(summ[("disk", 7)]["category"], "storage")
            self.assertEqual(summ[("Microsoft-Windows-WHEA-Logger", 18)]["category"], "hardware")
            self.assertEqual(summ[("Microsoft-Windows-Kernel-Power", 41)]["category"], "shutdown")
            self.assertFalse(any("Boring" in k[0] for k in summ))
            self.assertEqual(len(r["notable"]), 6)
        self.assertEqual(L.analyse_events(self.put("e.txt", EV_LONG))["count"], 7)
        bc = [s for s in L.analyse_events(self.put("e.txt", EV_LONG))["notable_summary"] if s["id"] == 1001][0]
        self.assertEqual(bc["codes"], ["0x0000009f"])

    def test_bcd_bad_and_good(self):
        b = L.analyse_bcd(self.put("b.txt", BCD_BAD))
        self.assertTrue(b["has_bootmgr"])
        self.assertEqual(b["entries"], 2)
        self.assertEqual(b["default"], "{aaaa0000-0000-0000-0000-000000000001}")
        self.assertEqual(b["os_loaders"][0]["osdevice"], "unknown")
        txt = " ".join(b["problems"])
        self.assertIn("device = unknown", txt)
        self.assertIn("osdevice = unknown", txt)
        self.assertIn("not among the OS loaders", txt)
        g = L.analyse_bcd(self.put("g.txt", BCD_GOOD))
        self.assertEqual(g["problems"], [])
        self.assertEqual(g["os_loaders"][0]["path"], "\\Windows\\system32\\winload.efi")

    def test_bcd_no_bootmgr_no_loader(self):
        t = "Firmware Application\n--------------------\nidentifier              {fwbootmgr}\n"
        p = L.analyse_bcd(self.put("n.txt", t))["problems"]
        self.assertEqual(len(p), 2)

    def test_tail_of_huge_file(self):
        p = self.put("big-CBS.log", b"", register=False)
        line = b"2026-01-01 00:00:00, Info                  CSI    filler filler filler filler\n"
        with open(p, "wb") as f:
            f.write(b"2026-01-01 00:00:00, Error                 CSI    EARLY 0x80070001\n")
            f.write(line * (9 * 2 ** 20 // len(line)))
            f.write(b"2026-01-02 00:00:00, Error                 CSI    LATE 0x80070002\n")
        r = L.analyse_cbs(p)
        self.assertTrue(r["truncated"])
        self.assertEqual(r["error_count"], 1)
        self.assertEqual(r["hresults"], {"0x80070002": 1})


class Collect(Base):
    def full(self):
        self.put("target-System32_LogFiles_Srt_SrtTrail.txt", b"\xff\xfe" + SRT_FAIL.encode("utf-16-le"))
        self.put("target-Logs_CBS_CBS.log", CBS)
        self.put("target-Logs_DISM_dism.log", DISM)
        self.put("target-Panther_setuperr.log", "2026-11-19 10:00:00, Error SP boom 0x80070005\n")
        self.put("target-Panther_setupact.log", "2026-11-19 10:00:00, Info SP Setup phase = Online\nFatalError here\n")
        self.put("target-inf_setupapi.dev.log", SETUPAPI)
        self.put("target-events-System.txt", EV_LONG, register=False)  # like write_text: not in files[]
        self.put("target-events-short.txt", EV_SHORT)
        self.put("target-bcd-disk0-part1.txt", BCD_BAD, register=False)
        self.put("target-bcd-live.txt", BCD_GOOD)

    def test_full_collect(self):
        self.full()
        sec, items = self.run_collect()
        self.assertEqual(sec["status"], "ok")
        for n in ("SrtTrail.txt", "CBS.log", "dism.log", "setuperr.log", "setupact.log", "setupapi.dev.log",
                  "events-System", "events-short", "bcd-disk0-part1", "bcd-live"):
            self.assertEqual(items[n]["status"], "ok", n)
        d = sec["data"]
        self.assertEqual(d["srttrail"]["error_code"], "0x490")
        self.assertEqual(d["setup"]["setupact"]["phase"], "Online")
        self.assertEqual(d["setup"]["setupact"]["error_count"], 1)
        self.assertEqual(d["setup"]["setuperr"]["hresults"], {"0x80070005": 1})
        self.assertIn("System", d["events"])
        self.assertNotIn("notable", d["events"]["System"])
        self.assertEqual(len(d["bcd"]["disk0-part1"]["problems"]), 3)
        h = d["headline"]
        self.assertLessEqual(len(h), 12)
        self.assertTrue(h[0].startswith("Startup Repair log root cause: Boot critical file"), h[0])
        self.assertTrue(any("BCD listing disk0-part1" in x for x in h))
        self.assertTrue(any("storage event disk 7" in x and "6 time" in x for x in h))
        self.assertTrue(any("0x800f0915 x2" in x for x in h))
        self.assertTrue(any("2 corrupt" in x for x in h))
        self.assertLess(h.index(next(x for x in h if "BCD listing" in x)), h.index(next(x for x in h if "CBS.log errors" in x)))
        for x in h:
            x.encode("ascii")
            self.assertNotIn("fixed", x.lower())
        self.assertEqual(["  * " + x for x in h], self.ctx.ui.lines)
        with open(self.case.path("inventory", "log-findings.json"), encoding="utf-8") as fh:
            j = json.load(fh)
        self.assertEqual(j["headline"], h)
        self.assertIn("notable", j["events"]["System"])
        self.assertEqual(j["cbs"]["error_count"], 3)

    def test_missing_logs_no_crash(self):
        sec, items = self.run_collect()
        self.assertEqual(sec["status"], "ok")
        for n in ("SrtTrail.txt", "CBS.log", "dism.log", "setuperr.log", "setupact.log", "setupapi.dev.log",
                  "events", "bcd"):
            self.assertEqual(items[n]["status"], "missing", n)
        self.assertEqual(sec["data"]["headline"], [])

    def test_only_case_files_with_status_ok(self):
        p = self.put("target-Logs_CBS_CBS.log", CBS)
        self.case.data["files"][-1]["status"] = "skipped"
        self.assertEqual(self.run_collect()[1]["CBS.log"]["status"], "missing")
        self.assertTrue(os.path.exists(p))

    def test_truncation_noted_in_item(self):
        p = self.put("target-Logs_CBS_CBS.log", b"")
        with open(p, "wb") as f:
            f.write(b"x" * (9 * 2 ** 20) + b"\n2026-01-02 00:00:00, Error CSI 0x80070002\n")
        item = self.run_collect()[1]["CBS.log"]
        self.assertEqual(item["status"], "ok")
        self.assertIn("truncated", item["reason"])

    def test_unrecognised_bcd(self):
        self.put("target-bcd-x.txt", "Windows-Start-Manager\n---\nkennung   {x}\n")
        item = self.run_collect()[1]["bcd-x"]
        self.assertEqual(item["status"], "error")
        self.assertIn("not in English or empty", item["reason"])

    def test_broken_file_is_an_item_error(self):
        self.case.data["files"].append({"dest": "logs/target-Logs_CBS_CBS.log", "status": "ok"})
        os.makedirs(self.case.path("logs", "target-Logs_CBS_CBS.log"))  # a directory, not a file: ignored
        self.assertEqual(self.run_collect()[1]["CBS.log"]["status"], "missing")

    def test_module_rules(self):
        with open(os.path.join(ROOT, "recoverykit", "modules", "loganalysis.py"), "rb") as fh:
            src = fh.read().decode("ascii")
        for bad in ("subprocess", "ctypes", "winreg", "print(", "input("):
            self.assertNotIn(bad, src)


class AssistantIntegration(Base):
    def case_with_logs(self):
        self.full = Collect.full
        Collect.full(self)
        self.run_collect()
        c = idea1()
        c["sections"]["log_findings"] = self.case.data["sections"]["log_findings"]
        return c

    def test_facts(self):
        f = A.facts(self.case_with_logs())
        self.assertIn("Boot critical file", f["logs.srt_root_cause"])
        self.assertIs(f["logs.srt_boot_ok"], False)
        self.assertEqual(f["logs.bcd_problem_count"], 3)
        self.assertEqual(f["logs.storage_event_count"], 6)
        self.assertEqual(f["logs.hardware_event_count"], 2)
        self.assertEqual(f["logs.unexpected_shutdowns"], 2)
        self.assertEqual(f["logs.cbs_corrupt_count"], 2)
        self.assertGreater(f["logs.headline_count"], 3)

    def test_no_log_findings_no_facts(self):
        f = A.facts(idea1())
        self.assertFalse([k for k in f if k.startswith("logs.")])

    def test_rules_fire(self):
        got = ids(A.suggest(self.case_with_logs(), rules()))
        for want in ("C-srt-root-cause", "D-bcd-problems", "E-storage-events", "E-hardware-events",
                     "B-cbs-corrupt", "E-unexpected-shutdowns"):
            self.assertIn(want, got)
        s = next(x for x in A.suggest(self.case_with_logs(), rules()) if x["id"] == "C-srt-root-cause")
        self.assertIn("x.sys is corrupt", s["text"])

    def test_rules_do_not_fire_when_clean_or_booted(self):
        new = ("C-srt-root-cause", "D-bcd-problems", "E-storage-events", "E-hardware-events",
               "B-cbs-corrupt", "E-unexpected-shutdowns")
        self.assertFalse(set(new) & set(ids(A.suggest(idea1(), rules()))))
        c = idea1()
        c["sections"]["log_findings"] = {"status": "ok", "data": {
            "srttrail": {"boot_status_ok": True}, "bcd": {"a": {"problems": []}},
            "events": {"System": {"notable_summary": [{"category": "app", "count": 4}]}},
            "cbs": {"corrupt_count": 0}, "headline": []}}
        self.assertFalse(set(new) & set(ids(A.suggest(c, rules()))))
        b = copy.deepcopy(self.case_with_logs())
        b["booted_after_repair"] = True
        self.assertEqual(ids(A.suggest(b, rules())), ["X-booted"])


if __name__ == "__main__":
    unittest.main()
