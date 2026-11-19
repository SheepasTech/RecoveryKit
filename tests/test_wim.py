"""Tests for recoverykit.wim with synthetic WIM files (header + UTF-16LE XML only)."""
import os
import shutil
import struct
import tempfile
import unittest

from recoverykit import wim

ARCH_CODE = {"x86": 0, "x64": 9, "arm64": 12}


def image_xml(index, name, edition, arch, major, minor, build, spbuild, languages, default=None):
    langs = "".join("<LANGUAGE>%s</LANGUAGE>" % l for l in languages)
    return ('<IMAGE INDEX="%d"><NAME>%s</NAME><WINDOWS><ARCH>%d</ARCH><EDITIONID>%s</EDITIONID>'
            '<VERSION><MAJOR>%d</MAJOR><MINOR>%d</MINOR><BUILD>%d</BUILD><SPBUILD>%d</SPBUILD></VERSION>'
            '<LANGUAGES>%s<DEFAULT>%s</DEFAULT></LANGUAGES></WINDOWS></IMAGE>'
            % (index, name, ARCH_CODE[arch], edition, major, minor, build, spbuild, langs, default or languages[0]))


def make_wim(path, images, part=1, total=1, bom=True):
    """images: list of dicts for image_xml. Returns path."""
    xml = "<WIM><TOTALBYTES>1</TOTALBYTES>%s</WIM>" % "".join(
        image_xml(i + 1, **img) for i, img in enumerate(images))
    raw = (b"\xff\xfe" if bom else b"") + xml.encode("utf-16-le")
    head = bytearray(208)
    head[0:8] = b"MSWIM\x00\x00\x00"
    struct.pack_into("<I", head, 8, 208)
    struct.pack_into("<HH", head, 40, part, total)
    struct.pack_into("<I", head, 44, len(images))
    head[72:79] = len(raw).to_bytes(7, "little")
    head[79] = 0x02
    struct.pack_into("<QQ", head, 80, 208, len(raw))
    with open(path, "wb") as f:
        f.write(head)
        f.write(raw)
    return path


def img(edition="Core", arch="x64", build=26100, spbuild=8875, languages=("en-US",), name="Windows 11 Home"):
    return dict(name=name, edition=edition, arch=arch, major=10, minor=0, build=build, spbuild=spbuild,
                languages=list(languages))


TARGET = {"build": "26100", "edition": "Core", "architecture": "x64", "language": "en-US",
          "ui_languages": ["en-US"]}


class WimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rk-wim-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def p(self, name):
        return os.path.join(self.tmp, name)

    def test_read_info_fields(self):
        path = make_wim(self.p("install.wim"), [img(), img(edition="Professional", name="Windows 11 Pro",
                                                           languages=("en-US", "lt-LT"))])
        info = wim.read_info(path)
        self.assertEqual(info["errors"], [])
        self.assertEqual((info["part"], info["total_parts"]), (1, 1))
        self.assertEqual(len(info["images"]), 2)
        a, b = info["images"]
        self.assertEqual((a["index"], a["edition"], a["architecture"]), (1, "Core", "x64"))
        self.assertEqual((a["build"], a["spbuild"], a["version"]), (26100, 8875, "10.0.26100.8875"))
        self.assertEqual(a["languages"], ["en-US"])
        self.assertEqual(b["languages"], ["en-US", "lt-LT"])
        self.assertEqual(b["default_language"], "en-US")

    def test_no_bom_and_architectures(self):
        path = make_wim(self.p("a.wim"), [img(arch="arm64"), img(arch="x86")], bom=False)
        info = wim.read_info(path)
        self.assertEqual([i["architecture"] for i in info["images"]], ["arm64", "x86"])

    def test_split_part_numbers(self):
        path = make_wim(self.p("install.swm"), [img()], part=1, total=3)
        info = wim.read_info(path)
        self.assertEqual((info["part"], info["total_parts"]), (1, 3))

    def test_spec_case_lt_source_against_en_target(self):
        path = make_wim(self.p("lt.wim"), [img(build=26200, spbuild=8875, languages=("lt-LT",))])
        image = wim.read_info(path)["images"][0]
        self.assertEqual(image["version"], "10.0.26200.8875")
        res = wim.compare_source(TARGET, image)
        self.assertFalse(res["ok"])
        fields = {m["field"] for m in res["mismatches"]}
        self.assertIn("build", fields)
        self.assertIn("language", fields)
        self.assertNotIn("edition", fields)
        self.assertNotIn("architecture", fields)
        for m in res["mismatches"]:
            self.assertTrue(m["why"])

    def test_matching_image_ok(self):
        path = make_wim(self.p("ok.wim"), [img(edition="core", languages=("en-US", "lt-LT"))])
        res = wim.compare_source(TARGET, wim.read_info(path)["images"][0])
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["mismatches"], [])

    def test_edition_and_arch_mismatch(self):
        path = make_wim(self.p("e.wim"), [img(edition="Professional", arch="arm64")])
        res = wim.compare_source(TARGET, wim.read_info(path)["images"][0])
        self.assertEqual({m["field"] for m in res["mismatches"]}, {"edition", "architecture"})

    def test_unknown_target_value_is_mismatch(self):
        path = make_wim(self.p("u.wim"), [img()])
        image = wim.read_info(path)["images"][0]
        for field in ("build", "edition", "architecture", "language"):
            t = dict(TARGET, **{field: None})
            res = wim.compare_source(t, image)
            self.assertFalse(res["ok"], field)
            m = [x for x in res["mismatches"] if x["field"] == field]
            self.assertEqual(len(m), 1, field)
            self.assertEqual(m[0]["why"], "target value unknown")

    def test_garbage_and_truncated_files(self):
        with open(self.p("garbage.wim"), "wb") as f:
            f.write(b"this is not a wim file at all" * 10)
        with open(self.p("empty.wim"), "wb"):
            pass
        good = make_wim(self.p("good.wim"), [img()])
        with open(good, "rb") as f:
            data = f.read()
        with open(self.p("trunc.wim"), "wb") as f:
            f.write(data[:-40])
        with open(self.p("badxml.wim"), "wb") as f:
            f.write(data[:208] + b"\xff\xfe" + b"<\x00W\x00I\x00M\x00")  # xml cut short, size mismatch
        for name in ("garbage.wim", "empty.wim", "trunc.wim", "badxml.wim", "missing.wim"):
            info = wim.read_info(self.p(name))
            self.assertEqual(info["images"], [], name)
            self.assertTrue(info["errors"], name)

    def test_unparsable_xml_reports_error(self):
        raw = b"\xff\xfe" + "<WIM><IMAGE".encode("utf-16-le")
        head = bytearray(208)
        head[0:8] = b"MSWIM\x00\x00\x00"
        struct.pack_into("<HH", head, 40, 1, 1)
        head[72:79] = len(raw).to_bytes(7, "little")
        struct.pack_into("<QQ", head, 80, 208, len(raw))
        with open(self.p("x.wim"), "wb") as f:
            f.write(head + raw)
        info = wim.read_info(self.p("x.wim"))
        self.assertEqual(info["images"], [])
        self.assertTrue(info["errors"])


if __name__ == "__main__":
    unittest.main()
