"""Graceful degradation: the kit must keep working, and say why, when the tools it likes are missing.

Spec rule: "Everything degrades. If a section cannot run, the report says why. A failed section never
aborts the others, and nothing fails silently."

Scenarios (one shared scan each, see setUpClass): no tools at all through the real launcher path, only
some tools missing, a broken config, an unwritable output folder, no target, damaged registry hives, and
a hash check that the scanned target was not touched. The target is a fake offline Windows folder
(tests/fakewin.py). Nothing here runs a repair.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from recoverykit.core import env as envmod
from recoverykit.core import runner as runnermod
from recoverykit.core.ui import UI
from recoverykit.engine import Engine
from tests import fakewin

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLED = os.path.join(ROOT, "python", "python.exe")
STATUSES = ("ok", "missing", "error", "skipped")
KEEP_ENV = ("SystemRoot", "SystemDrive", "TEMP", "TMP", "USERPROFILE", "COMSPEC", "PATHEXT")
MISSING_TOOLS = ("powershell", "pwsh", "wmic", "wevtutil")


class QuietUI(UI):
    def __init__(self):
        super().__init__(auto=True)
        self.lines = []

    def say(self, text=""):
        self.lines.append(str(text))

    raw = say


# ---------------------------------------------------------------- helpers
def violations(case):
    """Every section/item with an invalid status or a non-ok status without a reason."""
    bad = []
    for sname, sec in case["sections"].items():
        if sec.get("status") not in STATUSES:
            bad.append("section %s has status %r" % (sname, sec.get("status")))
        elif sec["status"] != "ok" and not (sec.get("reason") or "").strip():
            bad.append("section %s is %s without a reason" % (sname, sec["status"]))
        for it in sec.get("items") or []:
            if it.get("status") not in STATUSES:
                bad.append("item %s/%s has status %r" % (sname, it.get("name"), it.get("status")))
            elif it["status"] != "ok" and not (it.get("reason") or "").strip():
                bad.append("item %s/%s is %s without a reason" % (sname, it.get("name"), it["status"]))
    return bad


def find_case_dir(out_root):
    for root, _dirs, files in os.walk(out_root):
        if "case.json" in files:
            return root
    return None


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def load_case(case_dir):
    with open(os.path.join(case_dir, "case.json"), encoding="utf-8") as f:
        return json.load(f)


def folder_from_stdout(stdout):
    for line in stdout.splitlines():
        if line.startswith("Folder:"):
            return line.split(":", 1)[1].strip()
    return None


def kit_env(tmp, path_dir=None, keep_only=False):
    if keep_only:
        env = {k: os.environ[k] for k in KEEP_ENV if k in os.environ}
    else:
        env = dict(os.environ)
    env["TEMP"] = env["TMP"] = tmp
    if path_dir is not None:
        env["PATH"] = path_dir
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


# Child bootstrap for "no tools at all": an empty PATH no longer hides tools (the runner only looks in
# System32), so the resolver is patched before the kit starts. PowerShell 7's fallback path is hidden too.
NO_TOOLS_BOOTSTRAP = (
    "import os, sys, shutil\n"
    "import recoverykit.core.runner as r\n"
    "r.Runner.resolve = lambda self, name: None\n"
    "shutil.which = lambda *a, **k: None\n"
    "_isfile = os.path.isfile\n"
    "os.path.isfile = lambda p: False if str(p).lower().endswith('pwsh.exe') else _isfile(p)\n"
    "import recoverykit.__main__ as m\n"
    "sys.exit(m.main(sys.argv[1:]))\n")


def run_kit(args, env, timeout=420, bootstrap=None):
    cmd = [BUNDLED, "-c", bootstrap] if bootstrap else [BUNDLED, "-m", "recoverykit"]
    return subprocess.run(cmd + args, cwd=ROOT, env=env, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=timeout)


def section(case, name):
    return case["sections"].get(name)


def all_text(sec):
    return " ".join([sec.get("reason") or ""] + [(i.get("reason") or "") + " " + str(i.get("name")) for i in sec.get("items") or []]).lower()


def hash_tree(root):
    out = {}
    for d, _dirs, files in os.walk(root):
        for n in files:
            p = os.path.join(d, n)
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            out[os.path.relpath(p, root)] = (h.hexdigest(), os.path.getsize(p))
    return out


class TmpMixin:
    @classmethod
    def mk_tmp(cls):
        cls._td = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.addClassCleanup(cls._td.cleanup)
        return cls._td.name


def fake_which_factory(missing):
    real = shutil.which

    def which(cmd, *a, **k):
        base = os.path.basename(str(cmd)).lower()
        for ext in (".exe", ".com", ".cmd", ".bat"):
            if base.endswith(ext):
                base = base[:-len(ext)]
        return None if base in missing else real(cmd, *a, **k)
    return which


# ---------------------------------------------------------------- 1. no tools at all
@unittest.skipUnless(os.path.isfile(BUNDLED), "bundled interpreter python\\python.exe is not present in this kit copy")
class NoToolsAtAll(TmpMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = cls.mk_tmp()
        empty_path = os.path.join(tmp, "emptypath")
        os.makedirs(empty_path)
        cls.target = os.path.join(tmp, "target")
        fakewin.make_target(cls.target)
        cls.out = os.path.join(tmp, "cases")
        cls.proc = run_kit(["--scan", "--auto", "--target-path", cls.target, "--out", cls.out, "--ticket", "5"],
                           kit_env(tmp, empty_path, keep_only=True), bootstrap=NO_TOOLS_BOOTSTRAP)
        cls.case_dir = find_case_dir(cls.out)
        cls.case = load_case(cls.case_dir) if cls.case_dir else None

    def ctx(self):
        return "\nstdout:\n%s\nstderr:\n%s" % (self.proc.stdout[-3000:], self.proc.stderr[-2000:])

    def test_exit_and_no_traceback(self):
        self.assertEqual(self.proc.returncode, 0, self.ctx())
        self.assertNotIn("Traceback", self.proc.stdout + self.proc.stderr)

    def test_case_json_and_invariant(self):
        self.assertIsNotNone(self.case, "no case.json written" + self.ctx())
        bad = violations(self.case)
        self.assertEqual(bad, [], "silent or malformed sections:\n  " + "\n  ".join(bad))

    def test_tool_dependent_sections_explain(self):
        secs = self.case["sections"]
        bl = secs.get("bitlocker")
        self.assertIsNotNone(bl, "no bitlocker section; have %s" % list(secs))
        self.assertIn(bl["status"], ("missing", "error"), bl)
        self.assertRegex(all_text(bl), r"manage-bde|not available", bl)
        dh = secs.get("disk_health")
        self.assertIsNotNone(dh, "no disk_health section; have %s" % list(secs))
        self.assertIn(dh["status"], ("missing", "error", "skipped"), dh)
        self.assertRegex(all_text(dh), r"powershell|smartctl|not available|wmic", dh)
        hw = [(s, i) for s, sec in secs.items() for i in sec.get("items") or [] if "hardware" in (i.get("name") or "").lower()]
        self.assertTrue(hw, "no hardware item found in any section")
        for s, i in hw:
            if i["status"] != "ok":
                self.assertRegex((i["reason"] or "").lower(), r"powershell|wmic|not available", "%s/%s" % (s, i))

    def test_tool_free_sections_still_work(self):
        secs = self.case["sections"]
        for name in ("disks", "installs", "target", "device", "logs_target", "registry", "assistant"):
            self.assertIn(name, secs)
            self.assertIn(secs[name]["status"], ("ok",), "%s: %s" % (name, secs[name]))
        info = self.case["target"]["info"]
        self.assertEqual(info["build_full"], "10.0.26100.8875")
        files = [f["dest"] for f in self.case["files"] if f.get("status") == "ok"]
        self.assertTrue(any(f.replace("\\", "/").endswith("CBS.log") for f in files), files)
        self.assertTrue(secs["assistant"]["data"]["suggestions"])

    def test_report(self):
        text = read(os.path.join(self.case_dir, "report.md"))
        for h in ("## 1. Confirmed facts", "## 2.", "## 3.", "## 4.", "## 5. Suggested next steps"):
            self.assertIn(h, text)
        self.assertIn("does not claim the target is fixed", text)

    def test_audit_and_debug_logs(self):
        lines = [json.loads(l) for l in read(os.path.join(self.case_dir, "audit.log")).splitlines() if l.strip()]
        self.assertTrue(lines, "audit.log is empty")
        notrun = [e for e in lines if e["kind"] != "refused"]
        wrong = [e for e in notrun if "not available" not in (e.get("error") or "") or e.get("exit_code") is not None]
        self.assertEqual(wrong, [], "commands that ran or lack a clear error: %s" % [(e["command"], e["error"], e["exit_code"]) for e in wrong][:10])
        self.assertNotIn("Traceback", read(os.path.join(self.case_dir, "debug.log")))


# ---------------------------------------------------------------- 2. some tools missing, in process
class SomeToolsMissing(TmpMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = cls.mk_tmp()
        cls.target = os.path.join(tmp, "target")
        fakewin.make_target(cls.target)
        fake = types.SimpleNamespace(which=fake_which_factory(MISSING_TOOLS))
        real_resolve, real_isfile = runnermod.Runner.resolve, os.path.isfile
        hide = mock.patch.object(runnermod.Runner, "resolve", autospec=True,
                                 side_effect=lambda self, name: None if runnermod._base(name) in MISSING_TOOLS
                                 else real_resolve(self, name))
        # run_ps() falls back to %ProgramFiles%\PowerShell\7\pwsh.exe: hide that one path too
        no_pwsh = mock.patch.object(os.path, "isfile", side_effect=lambda p: False if str(p).lower().endswith("pwsh.exe")
                                    else real_isfile(p))
        with hide, no_pwsh, mock.patch.object(envmod, "shutil", fake):
            cls.engine = Engine(ROOT, os.path.join(tmp, "cases"), QuietUI(), dry_run=True,
                                options={"ticket": "5", "target_path": cls.target, "answers": {}})
            cls.addClassCleanup(cls.engine.close)
            cls.engine.scan()
        cls.case = cls.engine.ctx.case.data

    def test_env_sees_missing_tools(self):
        for t in MISSING_TOOLS:
            self.assertIsNone(self.engine.ctx.env["tools"][t], t)

    def test_no_silent_failure(self):
        bad = violations(self.case)
        self.assertEqual(bad, [], "\n  " + "\n  ".join(bad))

    def test_no_missing_tool_ever_ran(self):
        audit = [json.loads(l) for l in read(self.engine.ctx.case.path("audit.log")).splitlines() if l.strip()]
        for e in audit:
            exe = os.path.basename(e["argv"][0]).lower() if e["argv"] else ""
            if exe.removesuffix(".exe") in MISSING_TOOLS:
                self.assertIsNone(e["exit_code"], e)
                self.assertIn("not available", e["error"], e)

    def test_event_logs_explain(self):
        sec = section(self.case, "event_logs")
        self.assertIsNotNone(sec, list(self.case["sections"]))
        items = sec.get("items") or []
        if sec["status"] != "ok":
            self.assertTrue((sec["reason"] or "").strip(), sec)
        self.assertTrue(items or sec["reason"], "event_logs has neither items nor a reason")
        for it in items:
            if it["status"] != "ok":
                self.assertRegex((it["reason"] or "").lower(), r"evtx|export|wevtutil|not available|not found|kept|missing", it)

    def test_other_sections_unaffected(self):
        for name in ("target", "logs_target", "assistant"):
            self.assertEqual(self.case["sections"][name]["status"], "ok", self.case["sections"][name])


# ---------------------------------------------------------------- 3. broken config
class BrokenConfig(TmpMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = cls.mk_tmp()
        kit = os.path.join(tmp, "kit")
        os.makedirs(os.path.join(kit, "config"))
        with open(os.path.join(kit, "config", "kit.toml"), "w") as f:
            f.write("this is [[ not toml = = \n\x00garbage")
        cls.target = os.path.join(tmp, "target")
        fakewin.make_target(cls.target)
        cls.engine = Engine(kit, os.path.join(tmp, "cases"), QuietUI(), dry_run=True,
                            options={"ticket": "5", "target_path": cls.target, "answers": {}})
        cls.addClassCleanup(cls.engine.close)
        cls.engine.scan()
        cls.case = cls.engine.ctx.case.data

    def test_cfg_error_reported(self):
        self.assertTrue(self.engine.cfg_error)
        self.assertIn("kit.toml", self.engine.cfg_error)

    def test_scan_completed_with_defaults(self):
        self.assertTrue(self.engine.scanned)
        self.assertEqual(self.case["sections"]["logs_target"]["status"], "ok", self.case["sections"]["logs_target"])
        self.assertEqual(self.case["sections"]["target"]["status"], "ok")
        self.assertEqual(violations(self.case), [])
        self.assertTrue(os.path.isfile(self.engine.ctx.case.path("report.md")))

    def test_assistant_reports_missing_rules(self):
        sec = self.case["sections"].get("assistant")
        self.assertIsNotNone(sec, list(self.case["sections"]))
        self.assertNotIn("module_assistant", self.case["sections"], "assistant crashed")
        bad_items = [i for i in sec["items"] if i["status"] != "ok"]
        self.assertTrue(bad_items, "assistant does not report the missing rules file: %s" % sec)
        self.assertEqual(sec["data"]["suggestions"], [])
        self.assertRegex(all_text(sec), r"assistant\.toml|rules", sec)


# ---------------------------------------------------------------- 4. unwritable output
@unittest.skipUnless(os.path.isfile(BUNDLED), "bundled interpreter python\\python.exe is not present in this kit copy")
class UnwritableOutput(TmpMixin, unittest.TestCase):
    def test_falls_back_to_temp(self):
        tmp = self.mk_tmp()
        blocker = os.path.join(tmp, "iamafile")
        with open(blocker, "w") as f:
            f.write("x")
        target = os.path.join(tmp, "target")
        fakewin.make_target(target)
        fake_temp = os.path.join(tmp, "temp")
        os.makedirs(fake_temp)
        p = run_kit(["--scan", "--auto", "--target-path", target, "--out", os.path.join(blocker, "cases")],
                    kit_env(fake_temp))
        info = "\nstdout:\n%s\nstderr:\n%s" % (p.stdout[-3000:], p.stderr[-2000:])
        self.assertEqual(p.returncode, 0, info)
        self.assertNotIn("Traceback", p.stdout + p.stderr)
        self.assertIn("Cannot write cases to", p.stdout)
        expected = os.path.join(fake_temp, "RecoveryKit", "cases")
        self.assertIn("Using %s instead" % expected, p.stdout, info)
        folder = folder_from_stdout(p.stdout)
        self.assertTrue(folder and os.path.isfile(os.path.join(folder, "case.json")), info)
        self.assertTrue(os.path.normcase(folder).startswith(os.path.normcase(expected)), folder)
        self.assertTrue(os.path.isfile(blocker) and read(blocker) == "x")


# ---------------------------------------------------------------- 5. no target
@unittest.skipUnless(os.path.isfile(BUNDLED), "bundled interpreter python\\python.exe is not present in this kit copy")
class NoTarget(TmpMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = cls.mk_tmp()
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        cls.out = os.path.join(tmp, "cases")
        cls.proc = run_kit(["--scan", "--auto", "--target-path", empty, "--target", "Q", "--out", cls.out, "--ticket", "5"],
                           kit_env(tmp))
        cls.case_dir = find_case_dir(cls.out)
        cls.case = load_case(cls.case_dir) if cls.case_dir else None

    def ctx(self):
        return "\nstdout:\n%s\nstderr:\n%s" % (self.proc.stdout[-3000:], self.proc.stderr[-2000:])

    def test_exit_and_structure(self):
        self.assertEqual(self.proc.returncode, 0, self.ctx())
        self.assertNotIn("Traceback", self.proc.stdout + self.proc.stderr)
        self.assertIsNotNone(self.case, self.ctx())
        bad = violations(self.case)
        self.assertEqual(bad, [], "\n  " + "\n  ".join(bad))

    def test_no_section_silently_empty(self):
        for name, sec in self.case["sections"].items():
            self.assertIn(sec["status"], STATUSES, name)
            if sec["status"] == "ok":
                self.assertTrue(sec.get("items") or sec.get("data") or sec.get("reason") or sec.get("title"),
                                "%s is ok but carries nothing" % name)

    def test_target_handling(self):
        secs = self.case["sections"]
        report = read(os.path.join(self.case_dir, "report.md"))
        tgt = self.case.get("target")
        if secs["target"]["status"] == "ok" and tgt and (tgt.get("info") or tgt.get("online")):
            # the running Windows on the dev PC was picked as the only install: it must be flagged
            self.assertTrue(tgt.get("online"), tgt)
            self.assertIn("RUNNING Windows", report + self.proc.stdout)
        else:
            for name in ("target", "free_space", "logs_target"):
                if name in secs:
                    self.assertIn(secs[name]["status"], ("missing", "skipped", "error"), "%s: %s" % (name, secs[name]))
                    self.assertTrue((secs[name]["reason"] or "").strip(), name)
            self.assertRegex(report.lower(), r"no target|not identified|no windows|not found")


# ---------------------------------------------------------------- 6. interrupted hive
class DamagedHives(TmpMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = cls.mk_tmp()
        cls.target = os.path.join(tmp, "target")
        fakewin.make_target(cls.target)
        cfg = os.path.join(cls.target, "Windows", "System32", "config")
        sw = os.path.join(cfg, "SOFTWARE")
        with open(sw, "rb") as f:
            data = f.read(2000)
        with open(sw, "wb") as f:
            f.write(data)
        with open(os.path.join(cfg, "SYSTEM"), "wb") as f:
            f.write(b"garbage, this is not a registry hive " * 40)
        cls.engine = Engine(ROOT, os.path.join(tmp, "cases"), QuietUI(), dry_run=True,
                            options={"ticket": "5", "target_path": cls.target, "answers": {}})
        cls.addClassCleanup(cls.engine.close)
        cls.engine.scan()
        cls.case = cls.engine.ctx.case.data

    def test_scan_completes_without_silence(self):
        self.assertTrue(self.engine.scanned)
        bad = violations(self.case)
        self.assertEqual(bad, [], "\n  " + "\n  ".join(bad))
        self.assertTrue(os.path.isfile(self.engine.ctx.case.path("report.md")))
        self.assertFalse([n for n in self.case["sections"] if n.startswith("module_")],
                         "a module crashed: %s" % [n for n in self.case["sections"] if n.startswith("module_")])

    def test_fields_not_invented(self):
        info = (self.case.get("target") or {}).get("info") or {}
        for k in ("build", "build_full", "ubr", "edition", "product", "language", "computer_name"):
            if k in info:
                self.assertIsNone(info[k], "%s invented as %r" % (k, info[k]))
        self.assertNotEqual(info.get("build_full"), "10.0.26100.8875")

    def test_unreadable_hive_is_named(self):
        text = " ".join(all_text(s) for n, s in self.case["sections"].items() if n in ("installs", "target")).lower()
        self.assertIn("software", text, text[:800])
        self.assertIn("system", text, text[:800])

    def test_device_and_registry_do_not_crash(self):
        for name in ("device", "registry"):
            sec = self.case["sections"].get(name)
            self.assertIsNotNone(sec, name)
            self.assertIn(sec["status"], STATUSES)


# ---------------------------------------------------------------- 7. read-only
class ReadOnly(TmpMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = cls.mk_tmp()
        cls.target = os.path.join(tmp, "target")
        fakewin.make_target(cls.target)
        cls.before = hash_tree(cls.target)
        cls.engine = Engine(ROOT, os.path.join(tmp, "cases"), QuietUI(), dry_run=True,
                            options={"ticket": "5", "target_path": cls.target, "answers": {}})
        cls.addClassCleanup(cls.engine.close)
        cls.engine.scan()
        cls.engine.ctx.target.reg.close() if cls.engine.ctx.target and cls.engine.ctx.target.reg else None
        cls.after = hash_tree(cls.target)
        cls.case = cls.engine.ctx.case.data

    def test_case_json_check(self):
        self.assertEqual(self.case["read_only_check"]["changed"], [])
        with open(self.engine.ctx.case.path("case.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["read_only_check"]["changed"], [])

    def test_target_hashes_unchanged(self):
        self.assertGreater(len(self.before), 5)
        self.assertEqual(sorted(set(self.after) - set(self.before)), [], "new files appeared in the target")
        self.assertEqual(sorted(set(self.before) - set(self.after)), [], "files vanished from the target")
        self.assertEqual({k: v for k, v in self.after.items() if self.before[k] != v}, {})


if __name__ == "__main__":
    unittest.main()
