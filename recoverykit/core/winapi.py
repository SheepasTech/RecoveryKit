"""Read-only Windows API access through ctypes: disks, partitions, volumes.

Locale-independent replacement for parsing diskpart/wmic output, and it works in
WinRE where PowerShell does not exist. Every handle is opened with access 0
(query only) so nothing here can write to a disk. Only core may import ctypes.
"""
import ctypes
import struct
import uuid
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

INVALID = wintypes.HANDLE(-1).value
OPEN_EXISTING = 3
SHARE_RW = 0x1 | 0x2

IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x700A0
IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x70050
IOCTL_DISK_GET_DISK_ATTRIBUTES = 0x700F0
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x560000

BUS_TYPES = {1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394", 6: "Fibre", 7: "USB", 8: "RAID", 9: "iSCSI",
             10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual", 15: "FileBackedVirtual",
             16: "Spaces", 17: "NVMe", 18: "SCM", 19: "UFS"}
DRIVE_TYPES = {0: "unknown", 1: "no-root", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}
GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Basic data",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows Recovery",
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "LDM metadata",
    "af9b60a0-1431-4f62-bc68-3311714a69ad": "LDM data",
}
MBR_TYPES = {0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32 LBA", 0x0E: "FAT16 LBA", 0x27: "Windows Recovery",
             0xEE: "GPT protective", 0xEF: "EFI System", 0x05: "Extended", 0x0F: "Extended LBA", 0x42: "LDM"}

k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.FindFirstVolumeW.restype = wintypes.HANDLE
k32.FindNextVolumeW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD]
k32.FindVolumeClose.argtypes = [wintypes.HANDLE]


class WinError(OSError):
    pass


def _open(path):
    """Open a device for query only (desired access 0). Never grants read or write of data."""
    h = k32.CreateFileW(path, 0, SHARE_RW, None, OPEN_EXISTING, 0, None)
    if h == INVALID or h is None:
        err = ctypes.get_last_error()
        raise WinError(err, "%s: %s" % (path, ctypes.FormatError(err).strip()))
    return h


def _ioctl(h, code, inbuf=None, outsize=4096):
    out = ctypes.create_string_buffer(outsize)
    ret = wintypes.DWORD(0)
    inp = ctypes.create_string_buffer(inbuf) if inbuf else None
    ok = k32.DeviceIoControl(h, code, inp, len(inbuf) if inbuf else 0, out, outsize, ctypes.byref(ret), None)
    if not ok:
        err = ctypes.get_last_error()
        raise WinError(err, "DeviceIoControl 0x%x: %s" % (code, ctypes.FormatError(err).strip()))
    return out.raw[:ret.value]


def is_admin():
    try:
        return bool(ctypes.WinDLL("shell32").IsUserAnAdmin())
    except Exception:
        return False


def firmware_type():
    """'UEFI', 'BIOS' or 'unknown' for the running environment."""
    t = wintypes.DWORD(0)
    try:
        if k32.GetFirmwareType(ctypes.byref(t)):
            return {1: "BIOS", 2: "UEFI"}.get(t.value, "unknown")
    except Exception:
        pass
    return "unknown"


def _cstr(buf, off):
    if not off or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    return buf[off:end if end >= 0 else len(buf)].decode("latin-1").strip()


def _guid(b):
    return str(uuid.UUID(bytes_le=bytes(b)))


def disk(number):
    """Describe \\\\.\\PhysicalDrive<number>. Raises WinError if it does not exist."""
    h = _open(r"\\.\PhysicalDrive%d" % number)
    d = {"number": number, "errors": []}
    try:
        try:
            buf = _ioctl(h, IOCTL_STORAGE_QUERY_PROPERTY, struct.pack("<II4x", 0, 0), 2048)
            removable = buf[10]
            vo, po, ro, so, bus = struct.unpack_from("<IIIII", buf, 12)
            d.update(vendor=_cstr(buf, vo), model=_cstr(buf, po), revision=_cstr(buf, ro),
                     serial=_cstr(buf, so), bus=BUS_TYPES.get(bus, "type %d" % bus), removable=bool(removable))
        except WinError as e:
            d["errors"].append("identity: %s" % e)
        try:
            buf = _ioctl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, None, 256)
            d["bytes_per_sector"] = struct.unpack_from("<I", buf, 20)[0]
            d["size"] = struct.unpack_from("<q", buf, 24)[0]
        except WinError as e:
            d["errors"].append("size: %s" % e)
        try:
            buf = _ioctl(h, IOCTL_DISK_GET_DISK_ATTRIBUTES, None, 64)
            attrs = struct.unpack_from("<Q", buf, 8)[0]
            d["offline"] = bool(attrs & 1)
            d["read_only"] = bool(attrs & 2)
        except WinError as e:
            d["errors"].append("attributes: %s" % e)
        try:
            d.update(_layout(_ioctl(h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, None, 48 + 144 * 128)))
        except WinError as e:
            d["errors"].append("partition layout: %s" % e)
            d["partitions"] = []
    finally:
        k32.CloseHandle(h)
    return d


def _layout(buf):
    style, count = struct.unpack_from("<II", buf, 0)
    out = {"style": {0: "MBR", 1: "GPT", 2: "RAW"}.get(style, "unknown"), "partitions": []}
    if style == 1:
        out["disk_id"] = _guid(buf[8:24])
    elif style == 0:
        out["disk_id"] = "%08x" % struct.unpack_from("<I", buf, 8)[0]
    for i in range(count):
        o = 48 + i * 144
        if o + 144 > len(buf):
            break
        pstyle, = struct.unpack_from("<I", buf, o)
        start, length, num = struct.unpack_from("<qqI", buf, o + 8)
        if length <= 0:
            continue
        p = {"number": num, "offset": start, "size": length}
        u = o + 32
        if pstyle == 1:
            tg = _guid(buf[u:u + 16])
            p.update(type_id=tg, type=GPT_TYPES.get(tg, "other"), id=_guid(buf[u + 16:u + 32]),
                     attributes="0x%x" % struct.unpack_from("<Q", buf, u + 32)[0],
                     name=buf[u + 40:u + 112].decode("utf-16-le", "replace").split("\x00", 1)[0])
        elif pstyle == 0:
            t = buf[u]
            p.update(type_id="0x%02x" % t, type=MBR_TYPES.get(t, "other"), active=bool(buf[u + 1]))
        out["partitions"].append(p)
    return out


def disks(max_number=32):
    out = []
    for n in range(max_number):
        try:
            out.append(disk(n))
        except WinError:
            continue
    return out


def _volume_names():
    buf = ctypes.create_unicode_buffer(260)
    h = k32.FindFirstVolumeW(buf, 260)
    if h == INVALID or h is None:
        return []
    names = [buf.value]
    while k32.FindNextVolumeW(h, buf, 260):
        names.append(buf.value)
    k32.FindVolumeClose(h)
    return names


def _mount_points(vol):
    buf = ctypes.create_unicode_buffer(1024)
    n = wintypes.DWORD(0)
    if not k32.GetVolumePathNamesForVolumeNameW(vol, buf, 1024, ctypes.byref(n)):
        return []
    return [s for s in buf[:n.value].split("\x00") if s]


def volumes():
    """All volumes, with or without a drive letter.

    Each: guid_path (\\\\?\\Volume{..}\\), mounts, letter, label, fs, drive_type,
    size, free, extents [{disk, offset, length}], errors.
    """
    out = []
    for vol in _volume_names():
        v = {"guid_path": vol, "errors": []}
        v["mounts"] = _mount_points(vol)
        v["letter"] = next((m[0].upper() for m in v["mounts"] if len(m) == 3 and m[1] == ":"), None)
        v["drive_type"] = DRIVE_TYPES.get(k32.GetDriveTypeW(vol), "unknown")
        label = ctypes.create_unicode_buffer(261)
        fs = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD(0)
        old = k32.SetErrorMode(1)  # no "insert disk" popups
        try:
            if k32.GetVolumeInformationW(vol, label, 261, ctypes.byref(serial), None, None, fs, 261):
                v.update(label=label.value, fs=fs.value, serial="%08X" % serial.value)
            else:
                err = ctypes.get_last_error()
                v.update(label="", fs="")
                v["errors"].append("volume information: %s" % ctypes.FormatError(err).strip())
            free = ctypes.c_ulonglong(0)
            total = ctypes.c_ulonglong(0)
            if k32.GetDiskFreeSpaceExW(vol, None, ctypes.byref(total), ctypes.byref(free)):
                v.update(size=total.value, free=free.value)
        finally:
            k32.SetErrorMode(old)
        v["extents"] = []
        try:
            h = _open(vol.rstrip("\\"))
            try:
                buf = _ioctl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, None, 8 + 24 * 32)
                cnt, = struct.unpack_from("<I", buf, 0)
                for i in range(cnt):
                    dn, off, ln = struct.unpack_from("<I4xqq", buf, 8 + i * 24)
                    v["extents"].append({"disk": dn, "offset": off, "length": ln})
            finally:
                k32.CloseHandle(h)
        except WinError as e:
            v["errors"].append("extents: %s" % e)
        out.append(v)
    return out
