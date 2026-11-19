"""Hardware of the machine the kit is running on, read without WMI or PowerShell.

Sources that also exist in WinRE: the SMBIOS table (GetSystemFirmwareTable),
the volatile HKLM\\HARDWARE registry key and the PCI device list under
HKLM\\SYSTEM\\CurrentControlSet\\Enum. Read-only, no administrator needed.
"""
import ctypes
import struct
import uuid
import winreg
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetSystemFirmwareTable.argtypes = [wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
k32.GetSystemFirmwareTable.restype = wintypes.UINT
RSMB = 0x52534D42
JUNK = {"", "to be filled by o.e.m.", "default string", "none", "not specified", "system product name",
        "system manufacturer", "unknown", "n/a", "0", "undefined", "empty", "not available", "oem", "no dimm"}


def clean(s):
    s = " ".join(str(s or "").split())
    return "" if s.lower() in JUNK else s


def raw_smbios():
    size = k32.GetSystemFirmwareTable(RSMB, 0, None, 0)
    if not size:
        return b""
    buf = ctypes.create_string_buffer(size)
    got = k32.GetSystemFirmwareTable(RSMB, 0, buf, size)
    return buf.raw[8:got] if got >= 8 else b""


def parse_smbios(data):
    """Split the raw table into structures: [(type, formatted_bytes, [strings])]."""
    out, i, n = [], 0, len(data)
    while i + 4 <= n:
        stype, length = data[i], data[i + 1]
        if length < 4 or i + length > n:
            break
        formatted = data[i:i + length]
        j = i + length
        strings = []
        while j < n and data[j] != 0:
            end = data.find(b"\x00", j)
            if end < 0:
                end = n
            strings.append(data[j:end].decode("latin-1", "replace"))
            j = end + 1
        j += 1 if strings else 2
        out.append((stype, formatted, strings))
        if stype == 127:
            break
        i = j
    return out


def _s(formatted, strings, off):
    if off >= len(formatted):
        return ""
    idx = formatted[off]
    return clean(strings[idx - 1]) if 0 < idx <= len(strings) else ""


def _w(formatted, off):
    return struct.unpack_from("<H", formatted, off)[0] if off + 2 <= len(formatted) else 0


def from_smbios(data):
    """{"system", "board", "bios", "cpu", "memory": [modules]} from a raw SMBIOS table."""
    hw = {"system": {}, "board": {}, "bios": {}, "cpu": {}, "memory": []}
    for stype, f, st in parse_smbios(data):
        if stype == 0:
            hw["bios"] = {"vendor": _s(f, st, 4), "version": _s(f, st, 5), "date": _s(f, st, 8)}
        elif stype == 1 and not hw["system"]:
            uid = ""
            if len(f) >= 0x18:
                raw = f[8:24]
                if raw not in (b"\x00" * 16, b"\xff" * 16):
                    uid = str(uuid.UUID(bytes_le=bytes(raw)))
            hw["system"] = {"manufacturer": _s(f, st, 4), "product": _s(f, st, 5), "serial": _s(f, st, 7), "uuid": uid}
        elif stype == 2 and not hw["board"]:
            hw["board"] = {"manufacturer": _s(f, st, 4), "product": _s(f, st, 5), "version": _s(f, st, 6),
                           "serial": _s(f, st, 7)}
        elif stype == 4 and not hw["cpu"]:
            hw["cpu"] = {"name": _s(f, st, 0x10), "manufacturer": _s(f, st, 7),
                         "cores": f[0x23] if len(f) > 0x23 else None, "sockets": 1}
        elif stype == 4:
            hw["cpu"]["sockets"] = hw["cpu"].get("sockets", 1) + 1
        elif stype == 17:
            size = _w(f, 0x0C)
            if size in (0, 0xFFFF):
                continue  # empty slot or unknown
            if size == 0x7FFF and len(f) >= 0x20:
                mb = struct.unpack_from("<I", f, 0x1C)[0] & 0x7FFFFFFF
            elif size & 0x8000:
                mb = (size & 0x7FFF) // 1024
            else:
                mb = size
            hw["memory"].append({"slot": _s(f, st, 0x10), "size_mb": mb, "speed": _w(f, 0x15) or None,
                                 "configured_speed": _w(f, 0x20) or None, "manufacturer": _s(f, st, 0x17),
                                 "part": _s(f, st, 0x1A), "serial": _s(f, st, 0x18),
                                 "type": {0x18: "DDR3", 0x1A: "DDR4", 0x22: "DDR5", 0x1B: "LPDDR", 0x1C: "LPDDR2",
                                          0x1D: "LPDDR3", 0x1E: "LPDDR4", 0x23: "LPDDR5"}.get(f[0x12] if len(f) > 0x12 else 0, "")})
    return hw


def _reg(path, name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _subkeys(path):
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def gpus():
    """Display adapters from the PCI device list: stable hardware IDs, plus a name when a driver gave one."""
    out = []
    base = r"SYSTEM\CurrentControlSet\Enum\PCI"
    for dev in _subkeys(base):
        for inst in _subkeys(base + "\\" + dev):
            p = base + "\\" + dev + "\\" + inst
            compat = _reg(p, "CompatibleIDs") or []
            cls = str(_reg(p, "Class") or "")
            is_display = cls.lower() == "display" or any("CC_03" in str(c).upper() for c in compat)
            if not is_display:
                continue
            desc = str(_reg(p, "DeviceDesc") or "")
            name = clean(desc.split(";")[-1])
            ident = dev.upper().split("&REV_")[0]
            if not any(g["id"] == ident for g in out):
                out.append({"id": ident, "name": name})
    return out


def collect():
    """Hardware description of this machine. Missing parts are empty strings / lists, with reasons in errors."""
    errors = []
    try:
        hw = from_smbios(raw_smbios())
    except Exception as e:  # noqa: BLE001 - a firmware table must never stop the kit
        hw = {"system": {}, "board": {}, "bios": {}, "cpu": {}, "memory": []}
        errors.append("SMBIOS not readable: %s: %s" % (type(e).__name__, e))
    if not any(hw[k] for k in ("system", "board", "cpu")) and not hw["memory"]:
        errors.append("SMBIOS table empty or not available")
    bios_key = r"HARDWARE\DESCRIPTION\System\BIOS"
    cpu = clean(_reg(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"))
    if cpu:
        hw["cpu"]["name"] = cpu  # the registry name is the marketing name; SMBIOS can be padded or generic
    for part, field, value in (("board", "manufacturer", "BaseBoardManufacturer"), ("board", "product", "BaseBoardProduct"),
                               ("system", "manufacturer", "SystemManufacturer"), ("system", "product", "SystemProductName"),
                               ("bios", "version", "BIOSVersion")):
        if not hw[part].get(field):
            hw[part][field] = clean(_reg(bios_key, value))
    try:
        hw["gpus"] = gpus()
    except Exception as e:  # noqa: BLE001
        hw["gpus"] = []
        errors.append("display adapters not readable: %s" % e)

    class MEMSTAT(ctypes.Structure):
        _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD)] + [
            (n, ctypes.c_ulonglong) for n in ("total", "avail", "tpf", "apf", "tv", "av", "aev")]
    ms = MEMSTAT()
    ms.dwLength = ctypes.sizeof(MEMSTAT)
    hw["memory_total_mb"] = int(ms.total // 2**20) if k32.GlobalMemoryStatusEx(ctypes.byref(ms)) else None
    hw["errors"] = errors
    return hw
