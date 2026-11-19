"""Test helper: build a fake offline Windows folder with real (minimal) registry hive files.

Lets the offline code path (hive parser, log collection, repair proposals) run on the
development PC without a second disk and without administrator rights.
"""
import os
import struct

REG_SZ, REG_DWORD, REG_MULTI_SZ = 1, 4, 7


def sz(text):
    return (REG_SZ, text.encode("utf-16-le") + b"\x00\x00")


def dword(n):
    return (REG_DWORD, struct.pack("<I", n))


def multi(items):
    return (REG_MULTI_SZ, ("\x00".join(items) + "\x00\x00").encode("utf-16-le"))


def make_hive(path, tree, dirty=False):
    """tree = {"values": {name: (type, bytes)}, "keys": {name: tree}}. Writes a valid regf file."""
    cells = bytearray()

    def cell(data):
        off = 32 + len(cells)                       # offsets are relative to the first hbin (0x1000)
        size = (len(data) + 4 + 7) & ~7
        cells.extend(struct.pack("<i", -size) + data + b"\x00" * (size - 4 - len(data)))
        return off

    def build(name, node):
        subs = [build(n, t) for n, t in (node.get("keys") or {}).items()]
        sublist = 0xFFFFFFFF
        if subs:
            sublist = cell(b"lf" + struct.pack("<H", len(subs)) + b"".join(struct.pack("<II", o, 0) for o in subs))
        voffs = []
        for vname, (vtype, data) in (node.get("values") or {}).items():
            if len(data) <= 4:
                dsize, doff = len(data) | 0x80000000, struct.unpack("<I", data.ljust(4, b"\x00"))[0]
            else:
                dsize, doff = len(data), cell(data)
            voffs.append(cell(b"vk" + struct.pack("<HIIIHH", len(vname), dsize, doff, vtype, 1, 0) + vname.encode("ascii")))
        vlist = cell(b"".join(struct.pack("<I", o) for o in voffs)) if voffs else 0xFFFFFFFF
        b = bytearray(76)
        b[0:2] = b"nk"
        struct.pack_into("<H", b, 2, 0x20)
        struct.pack_into("<I", b, 20, len(subs))
        struct.pack_into("<I", b, 28, sublist)
        struct.pack_into("<I", b, 36, len(voffs))
        struct.pack_into("<I", b, 40, vlist)
        struct.pack_into("<H", b, 72, len(name))
        return cell(bytes(b) + name.encode("ascii"))

    root = build("ROOT", tree)
    size = (32 + len(cells) + 0xFFF) & ~0xFFF
    header = bytearray(0x1000)
    header[0:4] = b"regf"
    struct.pack_into("<II", header, 4, 8 if dirty else 7, 7)
    struct.pack_into("<II", header, 20, 1, 5)
    struct.pack_into("<I", header, 36, root)
    struct.pack_into("<I", header, 40, size)
    hbin = bytearray(32)
    hbin[0:4] = b"hbin"
    struct.pack_into("<II", hbin, 4, 0, size)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(bytes(header) + bytes(hbin) + bytes(cells) + b"\x00" * (size - 32 - len(cells)))


def make_target(root, build="26100", ubr=8875, edition="Core", lang="en-US", lcid="0409", pending=False,
                srttrail=True):
    """Create <root>/Windows with SOFTWARE and SYSTEM hives and a few logs. Returns the Windows dir."""
    win = os.path.join(root, "Windows")
    cfg = os.path.join(win, "System32", "config")
    cbs = {"values": {}, "keys": {"RebootPending": {}} if pending else {}}
    make_hive(os.path.join(cfg, "SOFTWARE"), {"keys": {"Microsoft": {"keys": {
        "Windows NT": {"keys": {"CurrentVersion": {"values": {
            "ProductName": sz("Windows 10 Home"), "EditionID": sz(edition), "CurrentBuild": sz(build),
            "UBR": dword(ubr), "DisplayVersion": sz("24H2")}}}},
        "Cryptography": {"values": {"MachineGuid": sz("11111111-2222-3333-4444-555555555555")}},
        "Windows": {"keys": {"CurrentVersion": {"keys": {"Component Based Servicing": cbs}}}},
    }}}})
    make_hive(os.path.join(cfg, "SYSTEM"), {"keys": {
        "Select": {"values": {"Current": dword(1)}},
        "ControlSet001": {"keys": {"Control": {"keys": {
            "Nls": {"keys": {"Language": {"values": {"InstallLanguage": sz(lcid)}}}},
            "MUI": {"keys": {"UILanguages": {"keys": {lang: {}}}}},
            "ComputerName": {"keys": {"ComputerName": {"values": {"ComputerName": sz("FAKE-PC")}}}},
            "Session Manager": {"values": {"PendingFileRenameOperations": multi(["a", "b"])} if pending else {},
                                "keys": {"Environment": {"values": {"PROCESSOR_ARCHITECTURE": sz("AMD64")}}}},
        }}}},
    }})
    files = {"System32/ntoskrnl.exe": b"MZ", "Logs/CBS/CBS.log": b"cbs line\n" * 50,
             "Logs/DISM/dism.log": b"dism line\n", "Panther/setupact.log": b"setup\n"}
    if srttrail:
        files["System32/LogFiles/Srt/SrtTrail.txt"] = b"Startup Repair diagnosis\n"
    if pending:
        files["WinSxS/pending.xml"] = b"<pending/>"
    for rel, data in files.items():
        p = os.path.join(win, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
    os.makedirs(os.path.join(root, "Users", "Customer", "Documents"), exist_ok=True)
    with open(os.path.join(root, "Users", "Customer", "Documents", "letter.txt"), "w") as f:
        f.write("customer data")
    return win
