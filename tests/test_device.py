"""Device ID: per-component codes, the reference files on the stick and device-specific settings."""
import json
import os
import struct
import tempfile
import types
import unittest

from recoverykit.core import hwinfo
from recoverykit.core.case import Case
from recoverykit.core.context import RegView
from recoverykit.core.ui import UI
from recoverykit.modules import device
from tests import fakewin

HW = {"cpu": {"name": "AMD Ryzen 5 5600X 6-Core Processor", "sockets": 1},
      "memory": [{"size_mb": 8192, "speed": 3600, "configured_speed": 2133, "part": "F4-3600C16-8GVKC", "type": "DDR4"},
                 {"size_mb": 8192, "speed": 3600, "configured_speed": 2133, "part": "F4-3600C16-8GVKC", "type": "DDR4"}],
      "board": {"manufacturer": "ASUSTeK COMPUTER INC.", "product": "PRIME B350M-A", "serial": "B123"},
      "system": {"manufacturer": "", "product": "", "uuid": "11111111-2222-3333-4444-555555555555"},
      "bios": {"version": "6254"}, "gpus": [{"id": "VEN_10DE&DEV_2504&SUBSYS_00001043", "name": "NVIDIA GeForce RTX 3060"}],
      "memory_total_mb": 16300, "errors": []}


class QuietUI(UI):
    def __init__(self):
        super().__init__(auto=True)
        self.lines = []

    def say(self, text=""):
        self.lines.append(str(text))


def target(tmp, user="Jonas"):
    win = fakewin.make_target(os.path.join(tmp, "t"))
    fakewin.make_hive(os.path.join(win, "System32", "config", "SOFTWARE"), {"keys": {"Microsoft": {"keys": {"Windows": {
        "keys": {"CurrentVersion": {"keys": {"Authentication": {"keys": {"LogonUI": {"values": {
            "LastLoggedOnSAMUser": fakewin.sz(".\\" + user)}}}}}}}}}}}})
    return types.SimpleNamespace(root=os.path.join(tmp, "t") + os.sep, windir=win, online=False, letter=None,
                                 reg=RegView(win, online=False), volume={},
                                 disk={"model": "KINGSTON SA400S37120G", "size": 120 * 2**30, "number": 0}, partition=None)


class Codes(unittest.TestCase):
    def test_code_is_stable_letters_and_per_segment(self):
        c = device.code("CPU", "AMD Ryzen 5 5600X 6-Core Processor")
        self.assertRegex(c, r"^[A-Z]{4}$")
        self.assertEqual(c, device.code("CPU", "  amd ryzen 5 5600x   6-core processor "))   # case and spacing do not matter
        self.assertNotEqual(c, device.code("GPU", "AMD Ryzen 5 5600X 6-Core Processor"))
        self.assertNotEqual(c, device.code("CPU", "AMD Ryzen 7 5800X 8-Core Processor"))
        self.assertEqual(device.code("CPU", ""), "XXXX")
        self.assertEqual(device.code("CPU", None), "XXXX")

    def test_build_and_what_changes_what(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = target(tmp)
            did, segs = device.build(HW, t)
            t.reg.close()
            self.assertRegex(did, r"^([A-Z]{4}-){7}[A-Z]{4}$")
            self.assertEqual([s["segment"] for s in segs], ["CPU", "RAM", "RSPD", "MOBO", "GPU", "USER", "DISK", "UNIT"])
            by = {s["segment"]: s for s in segs}
            self.assertEqual(by["USER"]["value"], "Jonas")
            self.assertIn("rated 3600 MT/s, running 2133 MT/s", by["RSPD"]["value"])       # profile not enabled is visible
            self.assertIn("16 GB", by["RAM"]["value"])
            self.assertIn("PRIME B350M-A", by["MOBO"]["value"])
            self.assertIn("RTX 3060", by["GPU"]["detail"])
            self.assertNotIn("XXXX", did)
            # enabling the memory profile changes only the speed code
            hw2 = json.loads(json.dumps(HW))
            for m in hw2["memory"]:
                m["configured_speed"] = 3600
            t2 = target(os.path.join(tmp, "b"))
            did2, _ = device.build(hw2, t2)
            t2.reg.close()
            diff = [i for i, (a, b) in enumerate(zip(did.split("-"), did2.split("-"))) if a != b]
            self.assertEqual(diff, [2])
            # a BIOS update changes nothing; no target leaves USER and DISK unknown
            hw3 = json.loads(json.dumps(HW))
            hw3["bios"]["version"] = "9999"
            did3, segs3 = device.build(hw3, None)
            self.assertEqual(did3.split("-")[:5], did.split("-")[:5])
            self.assertEqual(did3.split("-")[5:7], ["XXXX", "XXXX"])

    def test_user_falls_back_to_newest_profile_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            win = fakewin.make_target(os.path.join(tmp, "t"))      # its Users folder has "Customer"
            os.makedirs(os.path.join(tmp, "t", "Users", "Public"))
            t = types.SimpleNamespace(root=os.path.join(tmp, "t") + os.sep, reg=RegView(win, online=False))
            self.assertEqual(device.target_user(t), "Customer")
            t.reg.close()
            self.assertEqual(device.target_user(None), "")


class Store(unittest.TestCase):
    def ctx(self, tmp, hw=HW, ticket=None):
        case = Case(os.path.join(tmp, "cases"))
        case.assign("T-abcd1234")
        if ticket:
            case.data["ticket"] = ticket
        self.addCleanup(case.close)
        t = target(tmp)
        self.addCleanup(t.reg.close)
        original = hwinfo.collect
        hwinfo.collect = lambda: json.loads(json.dumps(hw))
        self.addCleanup(lambda: setattr(hwinfo, "collect", original))
        return types.SimpleNamespace(case=case, ui=QuietUI(), target=t, env={"kind": "winre"}, options={})

    def test_files_on_the_stick_and_settings(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ctx = self.ctx(tmp)
            did = device.collect(ctx)
            ddir = os.path.join(tmp, "devices")
            self.assertEqual(ctx.case.data["device"]["id"], did)
            self.assertEqual(ctx.case.data["sections"]["device"]["status"], "ok")
            reg = json.load(open(os.path.join(ddir, "components.json"), encoding="utf-8"))
            cpu_code = did.split("-")[0]
            self.assertEqual(reg["CPU"][cpu_code]["value"], "AMD Ryzen 5 5600X 6-Core Processor")
            self.assertEqual(reg["CPU"][cpu_code]["devices"], [did])
            dev = json.load(open(os.path.join(ddir, did, "device.json"), encoding="utf-8"))
            self.assertEqual((dev["id"], len(dev["runs"]), dev["runs"][0]["case_id"]), (did, 1, "T-abcd1234"))
            self.assertEqual(dev["hardware"]["board"]["product"], "PRIME B350M-A")
            index = open(os.path.join(ddir, "index.md"), encoding="utf-8").read()
            self.assertIn(did, index)
            self.assertIn("RTX 3060", index)
            self.assertTrue(any(did in ln for ln in ctx.ui.lines))
            self.assertEqual([s["value"] for s in device.decode(ddir, did)][0], "AMD Ryzen 5 5600X 6-Core Processor")
            self.assertIsNone(device.decode(ddir, "AAAA-" + did[5:])[0]["value"])
            # device-specific settings saved on the stick are applied at the next scan
            spath = os.path.join(ddir, did, "settings.json")
            settings = json.load(open(spath, encoding="utf-8"))
            self.assertEqual(settings, device.DEFAULT_SETTINGS)
            settings.update(notes="Customer wants data kept", ticket="12345", answers={"symptom": "repair_loop"})
            json.dump(settings, open(spath, "w", encoding="utf-8"))
            ctx.ui.lines.clear()
            device.collect(ctx)
            self.assertEqual(ctx.case.data["ticket"], "12345")
            self.assertEqual(ctx.case.data["case_id"], "ITW-12345-abcd1234")
            self.assertEqual(ctx.case.data["operator_answers"]["symptom"], "repair_loop")
            self.assertTrue(any("Customer wants data kept" in ln for ln in ctx.ui.lines))
            self.assertEqual(len(json.load(open(os.path.join(ddir, did, "device.json"), encoding="utf-8"))["runs"]), 2)

    def test_unreadable_hardware_gives_xxxx_and_reasons(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            empty = {"cpu": {}, "memory": [], "board": {}, "system": {}, "bios": {}, "gpus": [], "memory_total_mb": None,
                     "errors": ["SMBIOS table empty or not available"]}
            ctx = self.ctx(tmp, hw=empty)
            did = device.collect(ctx)
            self.assertEqual(did.split("-")[:5], ["XXXX"] * 5)
            items = ctx.case.data["sections"]["device"]["items"]
            self.assertTrue(any(i["name"] == "hardware" and i["status"] == "error" for i in items))
            self.assertTrue(any(i["name"] == "CPU" and i["status"] == "missing" for i in items))

    def test_corrupt_registry_file_is_kept_aside(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ddir = os.path.join(tmp, "devices")
            os.makedirs(ddir)
            with open(os.path.join(ddir, "components.json"), "w") as f:
                f.write("{not json")
            ctx = self.ctx(tmp)
            device.collect(ctx)
            self.assertTrue(os.path.exists(os.path.join(ddir, "components.json.bad")))
            json.load(open(os.path.join(ddir, "components.json"), encoding="utf-8"))

    def test_unit_value_is_kept_in_device_json_only(self):
        uuid = HW["system"]["uuid"]
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            ctx = self.ctx(tmp)
            did = device.collect(ctx)
            ddir = os.path.join(tmp, "devices")
            unit = {s["segment"]: s for s in ctx.case.data["device"]["segments"]}["UNIT"]
            self.assertEqual((unit["detail"], unit["value"]), (device.HIDDEN, device.HIDDEN))
            self.assertEqual(device.HIDDEN, "(kept in device.json)")
            self.assertNotEqual(unit["code"], device.UNKNOWN)
            self.assertTrue(any(device.HIDDEN in ln for ln in ctx.ui.lines))
            self.assertFalse(any(uuid in ln for ln in ctx.ui.lines))
            self.assertNotIn(uuid, json.dumps(ctx.case.data))
            self.assertNotIn(uuid, json.dumps(ctx.case.data["sections"]["device"]))
            with open(os.path.join(ddir, "index.md"), encoding="utf-8") as f:
                self.assertNotIn(uuid, f.read())
            # the report shows the code and the hidden text, not the UUID
            from recoverykit.modules import report
            text = report.render(ctx.case.data, [])
            self.assertNotIn(uuid, text)
            self.assertIn(unit["code"], text)
            self.assertIn("kept in device.json", text)
            # the raw value stays where it is needed
            with open(os.path.join(ddir, did, "device.json"), encoding="utf-8") as f:
                dev = json.load(f)
            self.assertEqual(dev["hardware"]["system"]["uuid"], uuid)
            self.assertNotIn(uuid, json.dumps(dev["segments"]))
            with open(os.path.join(ddir, "components.json"), encoding="utf-8") as f:
                reg = json.load(f)
            self.assertEqual(reg["UNIT"][unit["code"]]["value"], uuid)
            with open(ctx.case.path("inventory", "device.json"), encoding="utf-8") as f:
                self.assertIn(uuid, f.read())
            # --decode-id prints `detail or value`: the hidden text, and the raw value only under raw_value
            by = {s["segment"]: s for s in device.decode(ddir, did)}
            self.assertEqual(by["UNIT"]["detail"], device.HIDDEN)
            self.assertEqual(by["UNIT"]["value"], device.HIDDEN)
            self.assertEqual(by["UNIT"]["raw_value"], uuid)
            self.assertNotIn("raw_value", by["CPU"])

    def test_lone_surrogate_in_a_device_detail_is_written(self):
        hw = json.loads(json.dumps(HW))
        hw["cpu"]["name"] = "Intel\ud800 CPU"
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            t = target(tmp)
            self.addCleanup(t.reg.close)
            did, segs = device.build(hw, t)
            ddir = os.path.join(tmp, "devices")
            device.remember(ddir, did, segs, hw, {"time": "now", "case_id": "T-1", "environment": "winre", "run": "r"})
            for name in ("components.json", os.path.join(did, "device.json")):
                with open(os.path.join(ddir, name), encoding="utf-8") as f:
                    self.assertIn("ud800", f.read(), name)
            with open(os.path.join(ddir, "index.md"), encoding="utf-8") as f:     # the Markdown escaper replaces it
                self.assertIn("Intel� CPU", f.read())
            device._save(os.path.join(ddir, "x.json"), {"k": "a\udfffb"})
            self.assertTrue(os.path.isfile(os.path.join(ddir, "x.json")))


class Smbios(unittest.TestCase):
    def test_parse_synthetic_table(self):
        def struct_(stype, formatted, strings):
            body = bytes([stype, 4 + len(formatted), 0, 0]) + formatted
            tail = b"".join(s.encode() + b"\x00" for s in strings) + b"\x00" if strings else b"\x00\x00"
            return body + tail
        board = struct_(2, bytes([1, 2, 0, 3]) + b"\x00" * 4, ["ASUSTeK COMPUTER INC.", "PRIME B350M-A", "SN1"])
        mem = bytearray(0x24 - 4)
        struct.pack_into("<H", mem, 0x0C - 4, 8192)
        mem[0x12 - 4] = 0x1A
        struct.pack_into("<H", mem, 0x15 - 4, 3600)
        mem[0x1A - 4] = 1
        struct.pack_into("<H", mem, 0x20 - 4, 2133)
        empty_slot = bytearray(0x24 - 4)
        table = board + struct_(17, bytes(mem), ["F4-3600C16-8GVKC"]) + struct_(17, bytes(empty_slot), []) + struct_(127, b"", [])
        hw = hwinfo.from_smbios(table)
        self.assertEqual(hw["board"]["product"], "PRIME B350M-A")
        self.assertEqual(len(hw["memory"]), 1)
        m = hw["memory"][0]
        self.assertEqual((m["size_mb"], m["speed"], m["configured_speed"], m["part"], m["type"]),
                         (8192, 3600, 2133, "F4-3600C16-8GVKC", "DDR4"))
        self.assertEqual(hwinfo.from_smbios(b"garbage")["memory"], [])
        self.assertEqual(hwinfo.clean("To Be Filled By O.E.M."), "")

    def test_this_pc(self):
        hw = hwinfo.collect()
        self.assertTrue(hw["cpu"].get("name"))
        self.assertTrue(hw["memory_total_mb"])


if __name__ == "__main__":
    unittest.main()
