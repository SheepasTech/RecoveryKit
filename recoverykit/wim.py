"""Pure-Python reader of WIM/ESD/SWM metadata (no dism, locale independent).

Only the header and the uncompressed UTF-16LE XML block are read. Nothing is
extracted and the file is opened read-only.
"""
import os
import struct
import xml.etree.ElementTree as ET

MAGIC = b"MSWIM\x00\x00\x00"
ARCH = {0: "x86", 9: "x64", 12: "arm64"}
MAX_XML = 16 * 1024 * 1024
MAX_STR = 200


def _text(node, path):
    if node is None:
        return None
    n = node.find(path)
    if n is None or n.text is None:
        return None
    return n.text.strip()[:MAX_STR] or None


def _int(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _image(node):
    win = node.find("WINDOWS")
    arch = _int(_text(win, "ARCH"))
    ver = win.find("VERSION") if win is not None else None
    major, minor = _text(ver, "MAJOR"), _text(ver, "MINOR")
    build, spbuild = _int(_text(ver, "BUILD")), _int(_text(ver, "SPBUILD"))
    version = None
    if major is not None and minor is not None and build is not None:
        version = "%s.%s.%s%s" % (major, minor, build, ".%s" % spbuild if spbuild is not None else "")
    langs = []
    if win is not None:
        langs = [(n.text or "").strip()[:MAX_STR] for n in win.findall("LANGUAGES/LANGUAGE")
                 if (n.text or "").strip()][:50]
    return {"index": _int(node.get("INDEX")), "name": _text(node, "NAME"),
            "edition": _text(win, "EDITIONID"), "architecture": ARCH.get(arch),
            "build": build, "spbuild": spbuild, "version": version,
            "languages": langs, "default_language": _text(win, "LANGUAGES/DEFAULT")}


def read_info(path):
    """Metadata of a WIM/ESD/SWM. Never raises for bad files: images [] and an error string."""
    info = {"path": path, "part": None, "total_parts": None, "images": [], "errors": []}
    try:
        with open(path, "rb") as f:
            head = f.read(208)
            if len(head) < 96 or head[:8] != MAGIC:
                info["errors"].append("not a WIM file (bad or truncated header)")
                return info
            info["part"], info["total_parts"] = struct.unpack_from("<HH", head, 40)
            size_flag = struct.unpack_from("<Q", head, 72)[0]
            csize = size_flag & 0x00FFFFFFFFFFFFFF   # high byte is the flag byte
            offset, orig = struct.unpack_from("<QQ", head, 80)
            if csize == 0 or orig == 0:
                info["errors"].append("no XML metadata in this file (split part other than the first?)")
                return info
            if csize > MAX_XML or orig > MAX_XML:
                info["errors"].append("XML block size is implausible: %d bytes" % csize)
                return info
            f.seek(offset)
            raw = f.read(orig)
            if len(raw) != orig:
                info["errors"].append("file is truncated: XML block needs %d bytes at offset %d, got %d" % (orig, offset, len(raw)))
                return info
    except OSError as e:
        info["errors"].append("cannot read: %s" % e)
        return info
    except (ValueError, OverflowError, struct.error, MemoryError) as e:
        info["errors"].append("header is damaged: %s: %s" % (type(e).__name__, e))
        return info
    try:
        if raw[:2] == b"\xff\xfe":
            raw = raw[2:]
        text = raw.decode("utf-16-le")
        root = ET.fromstring(text)
        images = []
        for n in root.findall("IMAGE")[:1000]:
            img = _image(n)
            if img["index"] is None:
                info["errors"].append("image without an integer INDEX dropped")
                continue
            images.append(img)
    except (ValueError, ET.ParseError, OverflowError, MemoryError, RecursionError) as e:
        info["errors"].append("XML metadata is unreadable: %s" % e)
        return info
    info["images"] = images
    if not images:
        info["errors"].append("XML metadata lists no images")
    return info


def compare_source(target_info, image):
    """Compare a repair source image with the target. ok only if nothing mismatches."""
    ti = target_info or {}
    mism = []

    def add(field, tval, sval, why):
        mism.append({"field": field, "target": tval, "source": sval, "why": why})

    def unknown(field, sval):
        add(field, None, sval, "target value unknown")

    tb = _int(ti.get("build"))
    if ti.get("build") is None or tb is None:
        unknown("build", image.get("build"))
    elif image.get("build") is None:
        add("build", tb, None, "source build unknown")
    elif tb != image["build"]:
        add("build", tb, image["build"],
            "source build %s is not target build %s (the build must be identical)" % (image["build"], tb))

    te, se = ti.get("edition"), image.get("edition")
    if te is None:
        unknown("edition", se)
    elif se is None or te.lower() != se.lower():
        add("edition", te, se, "source edition %s differs from target edition %s" % (se, te))

    ta, sa = ti.get("architecture"), image.get("architecture")
    if ta is None:
        unknown("architecture", sa)
    elif ta != sa:
        add("architecture", ta, sa, "source architecture %s differs from target architecture %s" % (sa, ta))

    tl = ti.get("language")
    langs = image.get("languages") or []
    if tl is None:
        unknown("language", langs)
    elif tl.lower() not in [l.lower() for l in langs]:
        add("language", tl, langs,
            "target language %s is not among the source languages %s (DISM error 0x800f0915 is typical)"
            % (tl, ", ".join(langs) or "none listed"))
    return {"ok": not mism, "mismatches": mism}
