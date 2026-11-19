"""Phase 3 assistant tests. Run: python -m unittest tests.test_assistant -v"""
import copy
import json
import os
import shutil
import tempfile
import unittest

from recoverykit.modules import assistant as A

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "idea1-case.json")


def idea1():
    with open(FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


def rules():
    r, errors = A.load_rules(ROOT)
    assert not errors, errors
    return r


def ids(sugg):
    return [s["id"] for s in sugg]


class Idea1(unittest.TestCase):
    def setUp(self):
        self.sugg = A.suggest(idea1(), rules())
        self.ids = ids(self.sugg)

    def test_branch_sequence_is_a_to_e(self):
        order = [s["branch"] for s in self.sugg if s["branch"] != "X"]
        self.assertEqual(order, sorted(order), order)
        self.assertEqual(sorted(set(order)), ["A", "B", "C", "D", "E"])

    def test_branch_a(self):
        a = [s["id"] for s in self.sugg if s["branch"] == "A"]
        self.assertEqual(a, ["A-backup", "A-firmware-sees-disk", "A-boot-menu-wbm", "A-symptom", "A-recent-change"])

    def test_branch_b_names_mismatch(self):
        b = {s["id"]: s for s in self.sugg if s["branch"] == "B"}
        self.assertIn("B-source-mismatch", b)
        self.assertIn("B-source-missing-0x800f0915", b)
        self.assertIn("B-restorehealth-source", b)
        m = b["B-source-mismatch"]
        self.assertEqual(m["evidence"]["source.mismatch_fields"], ["build", "language"])
        self.assertIn("build, language", m["text"])

    def test_branch_c_order(self):
        c = [s["id"] for s in self.sugg if s["branch"] == "C"]
        self.assertEqual(c[:3], ["C-uninstall-updates", "C-system-restore", "C-startup-repair"])

    def test_branch_d_inspect_not_rewrite(self):
        d = [s["id"] for s in self.sugg if s["branch"] == "D"]
        self.assertIn("D-inspect-bcd", d)
        self.assertIn("D-no-blind-bcd", d)
        self.assertNotIn("D-which-efi", d)  # one EFI partition only

    def test_branch_e(self):
        e = [s["id"] for s in self.sugg if s["branch"] == "E"]
        self.assertIn("E-chkdsk-scan", e)
        self.assertIn("E-disk-health", e)
        self.assertNotIn("E-hardware-first", e)

    def test_sfc_notice_and_never_fixed(self):
        self.assertIn("X-sfc-clean", self.ids)
        self.assertIn("X-not-fixed", self.ids)
        self.assertNotIn("X-booted", self.ids)
        self.assertNotIn("X-online", self.ids)

    def test_evidence_cited(self):
        s = next(x for x in self.sugg if x["id"] == "A-symptom")
        self.assertEqual(s["evidence"], {"operator.symptom": "unknown"})

    def test_same_result_is_deterministic(self):
        self.assertEqual(self.ids, ids(A.suggest(idea1(), rules())))


class Facts(unittest.TestCase):
    def test_idea1_facts(self):
        f = A.facts(idea1())
        self.assertIs(f["target.present"], True)
        self.assertIs(f["target.online"], False)
        self.assertEqual((f["target.edition"], f["target.build"], f["target.language"]), ("Core", "26100", "en-US"))
        self.assertEqual(f["repair.restorehealth.error_code"], "0x800f0915")
        self.assertEqual(f["repair.restorehealth.rc"], 1)
        self.assertIs(f["repair.sfc.done"], True)
        self.assertEqual(f["boot.efi_count"], 1)
        self.assertEqual(f["boot.efi_on_target_disk"], 1)
        self.assertIs(f["bcd.captured"], False)
        self.assertIs(f["source.checked"], True)
        self.assertEqual(f["section.disk_health.status"], "missing")
        self.assertNotIn("booted", f)

    def test_empty_case_is_tolerated(self):
        f = A.facts({})
        self.assertIs(f["target.present"], False)
        self.assertNotIn("free_space.low", f)
        self.assertIs(f["source.checked"], False)

    def test_last_executed_repair_wins_and_dry_run_ignored(self):
        d = {"repair_log": [
            {"id": "restorehealth", "rc": 1, "finding": "not_repairable", "error_code": "0x800F0915", "kind": "executed"},
            {"id": "restorehealth", "rc": 0, "finding": "restored", "error_code": None, "kind": "executed"},
            {"id": "restorehealth", "rc": 5, "finding": "not_repairable", "error_code": "0x1", "kind": "dry-run"},
            {"id": "sfc", "rc": 0, "finding": "sfc_clean", "error_code": None, "kind": "declined"}]}
        f = A.facts(d)
        self.assertEqual(f["repair.restorehealth.finding"], "restored")
        self.assertNotIn("repair.restorehealth.error_code", f)
        self.assertNotIn("repair.sfc.done", f)

    def test_misc_facts(self):
        d = {"sections": {
            "pending": {"status": "ok", "data": {"any_pending": True}},
            "bitlocker": {"status": "ok", "data": {"unreadable_volumes": ["\\\\?\\Volume{x}\\"]}},
            "logs_target": {"status": "ok", "items": [{"name": "Windows/System32/Logfiles/Srt/SrtTrail.txt", "status": "missing"}]},
            "assistant": {"status": "ok", "data": {}}},
            "files": [{"dest": "exports/bcd-store.txt", "status": "ok"}]}
        f = A.facts(d)
        self.assertIs(f["pending.any"], True)
        self.assertIs(f["bitlocker.unreadable"], True)
        self.assertEqual(f["log.srttrail"], "missing")
        self.assertIs(f["bcd.captured"], True)
        self.assertNotIn("section.assistant.status", f)


class Evaluator(unittest.TestCase):
    F = {"a": "yes", "n": 3, "t": True, "fl": False, "lst": ["build", "language"], "q": "two words"}

    def ev(self, cond, f=None):
        return A.compile_condition(cond)(self.F if f is None else f)

    def test_equality(self):
        self.assertTrue(self.ev("a == yes"))
        self.assertTrue(self.ev("a == 'YES'"))
        self.assertFalse(self.ev("a == no"))
        self.assertTrue(self.ev("a != no"))
        self.assertFalse(self.ev("a != yes"))
        self.assertTrue(self.ev('q == "two words"'))
        self.assertTrue(self.ev("n == 3"))

    def test_absent_fact(self):
        self.assertFalse(self.ev("zz == yes"))
        self.assertTrue(self.ev("zz != yes"))
        self.assertTrue(self.ev("missing zz"))
        self.assertFalse(self.ev("exists zz"))
        self.assertFalse(self.ev("zz > 1"))
        self.assertFalse(self.ev("zz in [a, b]"))
        self.assertFalse(self.ev("zz contains a"))
        self.assertFalse(self.ev("zz is true"))

    def test_exists_missing(self):
        self.assertTrue(self.ev("exists a"))
        self.assertFalse(self.ev("missing a"))

    def test_in(self):
        self.assertTrue(self.ev("a in [no, yes]"))
        self.assertTrue(self.ev("a in ['yes']"))
        self.assertFalse(self.ev("a in [no, unknown]"))

    def test_contains(self):
        self.assertTrue(self.ev("lst contains build"))
        self.assertFalse(self.ev("lst contains edition"))
        self.assertTrue(self.ev("q contains words"))

    def test_is_bool(self):
        self.assertTrue(self.ev("t is true"))
        self.assertFalse(self.ev("t is false"))
        self.assertTrue(self.ev("fl is false"))
        self.assertFalse(self.ev("fl is true"))

    def test_numeric(self):
        self.assertTrue(self.ev("n > 2"))
        self.assertFalse(self.ev("n > 3"))
        self.assertTrue(self.ev("n >= 3"))
        self.assertTrue(self.ev("n < 4"))
        self.assertTrue(self.ev("n <= 3"))
        self.assertFalse(self.ev("a > 1"))  # non-numeric fact

    def test_bad_conditions(self):
        for bad in ("", "a ~ b", "n > many", "import os", "__import__('os')", "a ==", "a in yes"):
            with self.assertRaises(ValueError, msg=bad):
                A.compile_condition(bad)

    def test_no_eval(self):
        # the tail is only ever a literal value to compare against, never executed
        self.assertFalse(self.ev("a == yes or __import__('os')"))


class RuleLoading(unittest.TestCase):
    def good(self, **kw):
        r = {"id": "R1", "branch": "A", "order": 1, "title": "t", "text": "x", "when": [], "evidence": []}
        r.update(kw)
        return r

    def test_malformed_rules_reported(self):
        raw = [self.good(), self.good(id="bad-cond", when=["a ~ b"]), self.good(id="bad-branch", branch="Q"),
               self.good(id="bad-order", order="1"), {"id": "notitle", "branch": "A", "order": 2, "text": "x"},
               self.good(id="R1")]
        ok, errors = A.check_rules(raw)
        self.assertEqual([r["id"] for r in ok], ["R1"])
        self.assertEqual(len(errors), 5, errors)
        self.assertTrue(any("bad-cond" in e for e in errors))
        self.assertTrue(any("duplicate" in e for e in errors))

    def test_load_rules_from_file_reports_bad_rule(self):
        tmp = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(tmp, "config"))
            with open(os.path.join(tmp, "config", "assistant.toml"), "w", encoding="ascii") as fh:
                fh.write('[[rule]]\nid="ok"\nbranch="A"\norder=1\ntitle="t"\ntext="x"\nwhen=[]\nevidence=[]\n'
                         '[[rule]]\nid="broken"\nbranch="A"\norder=2\ntitle="t"\ntext="x"\nwhen=["zzz zzz zzz"]\n')
            ok, errors = A.load_rules(tmp)
            self.assertEqual([r["id"] for r in ok], ["ok"])
            self.assertEqual(len(errors), 1)
            self.assertIn("broken", errors[0])
        finally:
            shutil.rmtree(tmp)

    def test_missing_and_invalid_file(self):
        tmp = tempfile.mkdtemp()
        try:
            self.assertEqual(A.load_rules(tmp)[0], [])
            self.assertTrue(A.load_rules(tmp)[1])
            os.makedirs(os.path.join(tmp, "config"))
            with open(os.path.join(tmp, "config", "assistant.toml"), "w") as fh:
                fh.write("[[rule\n")
            self.assertTrue(A.load_rules(tmp)[1])
        finally:
            shutil.rmtree(tmp)

    def test_shipped_rules_all_valid_and_ascii(self):
        r, errors = A.load_rules(ROOT)
        self.assertEqual(errors, [])
        self.assertGreater(len(r), 20)
        with open(os.path.join(ROOT, "config", "assistant.toml"), "rb") as fh:
            fh.read().decode("ascii")


class Symptoms(unittest.TestCase):
    def case(self, **ans):
        c = idea1()
        c["operator_answers"].update(ans)
        return c

    def test_no_boot_device_firmware_no_hardware_first_in_e(self):
        s = A.suggest(self.case(symptom="no_boot_device", firmware_sees_disk="no"), rules())
        e = [x["id"] for x in s if x["branch"] == "E"]
        self.assertEqual(e[0], "E-hardware-first")
        self.assertNotIn("D-firmware-sees-disk", ids(s))
        self.assertNotIn("A-symptom", ids(s))
        self.assertNotIn("A-firmware-sees-disk", ids(s))

    def test_no_boot_device_firmware_yes_strengthens_d(self):
        s = A.suggest(self.case(symptom="no_boot_device", firmware_sees_disk="yes"), rules())
        d = [x["id"] for x in s if x["branch"] == "D"]
        self.assertEqual(d[0], "D-firmware-sees-disk")
        self.assertNotIn("E-hardware-first", ids(s))

    def test_symptom_rules_only_for_their_symptom(self):
        self.assertNotIn("A-stop-code", ids(A.suggest(idea1(), rules())))
        self.assertIn("A-stop-code", ids(A.suggest(self.case(symptom="stop_code"), rules())))
        self.assertIn("A-repair-loop-log", ids(A.suggest(self.case(symptom="repair_loop"), rules())))
        self.assertIn("A-spinning-log", ids(A.suggest(self.case(symptom="spinning"), rules())))

    def test_recent_update_puts_uninstall_first(self):
        s = A.suggest(self.case(recent_change="update"), rules())
        c = [x["id"] for x in s if x["branch"] == "C"]
        self.assertEqual(c[0], "C-uninstall-updates-first")
        self.assertNotIn("C-uninstall-updates", c)

    def test_backed_up_drops_backup_and_reset_warning(self):
        s = ids(A.suggest(self.case(data_backed_up="yes"), rules()))
        self.assertNotIn("A-backup", s)
        self.assertNotIn("C-avoid-reset", s)

    def test_state_driven_e_rules(self):
        c = idea1()
        c["target"]["disk"]["offline"] = True
        c["sections"]["free_space"]["data"]["low"] = True
        c["sections"]["pending"] = {"status": "ok", "data": {"any_pending": True}}
        c["sections"]["bitlocker"]["data"] = {"unreadable_volumes": ["v"]}
        c["sections"]["logs_target"] = {"status": "ok", "items": [{"name": "SrtTrail.txt", "status": "missing"}]}
        c["sections"]["boot_structure"]["data"]["efi_partitions"].append({"disk": 1, "on_target_disk": False})
        c["files"].append({"dest": "exports/bcd-store.txt", "status": "ok"})
        s = ids(A.suggest(c, rules()))
        for want in ("E-disk-offline", "E-free-space", "E-pending", "E-bitlocker", "E-no-srttrail", "D-which-efi"):
            self.assertIn(want, s)
        self.assertNotIn("D-inspect-bcd", s)

    def test_online_target_notice(self):
        c = idea1()
        c["target"]["online"] = True
        s = A.suggest(c, rules())
        n = next(x for x in s if x["id"] == "X-online")
        self.assertIn("not of an offline install", n["text"])

    def test_booted_true_notice(self):
        c = idea1()
        c["booted_after_repair"] = True
        s = A.suggest(c, rules())
        self.assertIn("X-booted", ids(s))
        self.assertIn("No further steps", [x for x in s if x["id"] == "X-booted"][0]["text"])
        self.assertEqual(ids(s), ["X-booted"])  # everything else is suppressed
        self.assertNotIn("X-not-fixed", ids(s))

    def test_assistant_section_not_fed_back(self):
        c = idea1()
        c["sections"]["assistant"] = {"status": "ok", "data": {"suggestions": [{"id": "x"}]}}
        self.assertEqual(ids(A.suggest(c, rules())), ids(A.suggest(idea1(), rules())))


class WhatChanged(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.base = os.path.join(self.tmp, "T-abc")

    def run_dir(self, name, data=None):
        p = os.path.join(self.base, name)
        os.makedirs(p)
        if data is not None:
            with open(os.path.join(p, "case.json"), "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        return p

    def test_no_previous_run(self):
        cur = self.run_dir("20260101-1000", idea1())
        self.assertEqual(A.what_changed(cur, idea1()), [])

    def test_diff_against_latest_earlier_run(self):
        old = idea1()
        old["sections"]["event_logs"] = {"status": "ok", "items": [{"name": "System", "events": 10}]}
        older = copy.deepcopy(old)
        older["target"]["info"]["build"] = "19045"  # must NOT be used: not the latest earlier run
        self.run_dir("20260101-0900", older)
        self.run_dir("20260101-1000", old)
        self.run_dir("20260101-1000-2", old)  # later than the previous one but earlier than current
        cur = self.run_dir("20260101-1000-3")
        self.run_dir("20260102-0800", idea1())  # later than current: ignored
        new = copy.deepcopy(old)
        new["sections"]["disk_health"]["status"] = "ok"
        new["target"]["info"]["ubr"] = 9000
        new["sections"]["free_space"]["data"]["free"] = old["sections"]["free_space"]["data"]["free"] - 5 * 2 ** 30
        new["sections"]["pending"] = {"status": "ok", "data": {"any_pending": True}}
        new["sections"]["event_logs"]["items"][0]["events"] = 25
        new["sections"]["disks"]["data"]["disk_count"] = 2
        new["operator_answers"]["symptom"] = "repair_loop"
        out = "\n".join(A.what_changed(cur, new))
        for want in ("section disk_health status: missing -> ok", "target ubr: 8875 -> 9000", "free space",
                     "section pending status: absent -> ok", "pending servicing: absent -> True",
                     "event log System events: 10 -> 25", "disk count: 1 -> 2",
                     "operator answer symptom: unknown -> repair_loop"):
            self.assertIn(want, out)
        self.assertNotIn("target build", out)

    def test_small_free_space_change_ignored_and_identical_is_empty(self):
        self.run_dir("20260101-1000", idea1())
        cur = self.run_dir("20260101-1100")
        new = idea1()
        new["sections"]["free_space"]["data"]["free"] -= 2 ** 29
        self.assertEqual(A.what_changed(cur, new), [])

    def test_unreadable_previous_is_reported(self):
        self.run_dir("20260101-1000")  # no case.json
        cur = self.run_dir("20260101-1100")
        out = A.what_changed(cur, idea1())
        self.assertEqual(len(out), 1)
        self.assertIn("no readable case.json", out[0])

    def test_non_run_folder_name(self):
        cur = os.path.join(self.base, "weird")
        os.makedirs(cur)
        self.assertEqual(A.what_changed(cur, idea1()), [])


class Output(unittest.TestCase):
    class FakeUI:
        def __init__(self):
            self.lines = []

        def say(self, t=""):
            self.lines.append(t)

    class FakeCase:
        def __init__(self, data, d):
            self.data, self.dir = data, d

        def section(self, name, title):
            import contextlib

            case = self

            class Sec:
                data = {}
                items = []

                def item(self, *a, **k):
                    pass
            sec = Sec()

            @contextlib.contextmanager
            def cm():
                yield sec
                case.data["sections"][name] = {"title": title, "status": "ok", "data": sec.data}
            return cm()

    def test_collect_and_show(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)

        class Ctx:
            pass
        ctx = Ctx()
        ctx.kit_root, ctx.ui = ROOT, self.FakeUI()
        ctx.case = self.FakeCase(idea1(), os.path.join(tmp, "T-x", "20260101-1000"))
        A.collect(ctx)
        d = ctx.case.data["sections"]["assistant"]["data"]
        self.assertEqual(set(d), {"suggestions", "what_changed", "rule_errors"})
        self.assertEqual(d["rule_errors"], [])
        A.show(ctx)
        text = "\n".join(ctx.ui.lines)
        text.encode("ascii")
        self.assertIn(" 1. Back up the customer's data", text)
        self.assertIn("Because: operator.symptom = unknown", text)
        self.assertLess(text.index("A. Preserve"), text.index("B. DISM"))
        self.assertLess(text.index("B. DISM"), text.index("E. Storage"))
        print("\n" + text)


if __name__ == "__main__":
    unittest.main()
