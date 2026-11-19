"""Read-only parser for Windows registry hive files (regf).

Used instead of `reg load` so that inspecting an offline install never writes to
the target disk (reg load replays logs and marks the hive dirty) and needs no
PowerShell or admin-only privilege beyond read access to the file.

Limits: transaction logs (.LOG1/.LOG2) are not replayed. `Hive.dirty` is True
when the header says the hive was not cleanly flushed; values may then be stale.
"""
import mmap
import struct
from datetime import datetime, timedelta, timezone

REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD = 0, 1, 2, 3, 4
REG_DWORD_BE, REG_LINK, REG_MULTI_SZ, REG_QWORD = 5, 6, 7, 11
BASE = 0x1000
NO_OFFSET = 0xFFFFFFFF


class HiveError(Exception):
    pass


def _filetime(v):
    if not v:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10)).isoformat()
    except OverflowError:
        return None


class Hive:
    def __init__(self, path):
        self.path = str(path)
        self._f = open(self.path, "rb")
        try:
            self._m = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError) as e:
            self._f.close()
            raise HiveError("cannot map %s: %s" % (self.path, e))
        m = self._m
        if len(m) < BASE or m[0:4] != b"regf":
            self.close()
            raise HiveError("%s is not a registry hive (no regf signature)" % self.path)
        seq1, seq2 = struct.unpack_from("<II", m, 4)
        self.dirty = seq1 != seq2
        self.last_written = _filetime(struct.unpack_from("<Q", m, 12)[0])
        self.major, self.minor = struct.unpack_from("<II", m, 20)
        self._root = struct.unpack_from("<I", m, 36)[0]

    def close(self):
        try:
            self._m.close()
        except Exception:
            pass
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # -- cells
    def _cell(self, off):
        """Return (start, length) of the data of the cell at hive offset `off`."""
        pos = BASE + off
        if off == NO_OFFSET or pos + 4 > len(self._m):
            raise HiveError("cell offset 0x%x outside hive" % off)
        size = struct.unpack_from("<i", self._m, pos)[0]
        length = abs(size) - 4
        if length < 0 or pos + 4 + length > len(self._m):
            raise HiveError("bad cell size at 0x%x" % off)
        return pos + 4, length

    def root(self):
        return Key(self, self._root)

    def open(self, path):
        """Return the Key at backslash-separated `path` (case-insensitive) or None."""
        key = self.root()
        for part in [p for p in path.replace("/", "\\").split("\\") if p]:
            key = key.subkey(part)
            if key is None:
                return None
        return key

    def get(self, path, name, default=None):
        key = self.open(path)
        if key is None:
            return default
        return key.value(name, default)


class Key:
    def __init__(self, hive, off):
        self.hive = hive
        m = hive._m
        s, n = hive._cell(off)
        if m[s:s + 2] != b"nk":
            raise HiveError("expected nk cell at 0x%x" % off)
        self._s = s
        flags = struct.unpack_from("<H", m, s + 2)[0]
        self.timestamp = _filetime(struct.unpack_from("<Q", m, s + 4)[0])
        self._nsub, = struct.unpack_from("<I", m, s + 20)
        self._sublist, = struct.unpack_from("<I", m, s + 28)
        self._nval, = struct.unpack_from("<I", m, s + 36)
        self._vallist, = struct.unpack_from("<I", m, s + 40)
        nlen, = struct.unpack_from("<H", m, s + 72)
        raw = bytes(m[s + 76:s + 76 + nlen])
        self.name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace")

    def _sub_offsets(self, off=None, depth=0):
        if off is None:
            if not self._nsub or self._sublist == NO_OFFSET:
                return
            off = self._sublist
        if depth > 8:
            raise HiveError("subkey list nested too deep")
        m = self.hive._m
        s, n = self.hive._cell(off)
        sig = bytes(m[s:s + 2])
        count, = struct.unpack_from("<H", m, s + 2)
        if sig in (b"lf", b"lh"):
            for i in range(count):
                yield struct.unpack_from("<I", m, s + 4 + i * 8)[0]
        elif sig == b"li":
            for i in range(count):
                yield struct.unpack_from("<I", m, s + 4 + i * 4)[0]
        elif sig == b"ri":
            for i in range(count):
                yield from self._sub_offsets(struct.unpack_from("<I", m, s + 4 + i * 4)[0], depth + 1)
        else:
            raise HiveError("unknown subkey list type %r" % sig)

    def subkeys(self):
        out = []
        for off in self._sub_offsets():
            try:
                out.append(Key(self.hive, off))
            except HiveError:
                continue
        return out

    def subkey_names(self):
        return [k.name for k in self.subkeys()]

    def subkey(self, name):
        low = name.lower()
        for off in self._sub_offsets():
            try:
                k = Key(self.hive, off)
            except HiveError:
                continue
            if k.name.lower() == low:
                return k
        return None

    def _values_raw(self):
        """Yield (name, type, bytes)."""
        if not self._nval or self._vallist == NO_OFFSET:
            return
        m = self.hive._m
        ls, ln = self.hive._cell(self._vallist)
        for i in range(min(self._nval, ln // 4)):
            voff, = struct.unpack_from("<I", m, ls + i * 4)
            try:
                s, n = self.hive._cell(voff)
            except HiveError:
                continue
            if m[s:s + 2] != b"vk":
                continue
            nlen, dsize, doff, vtype, vflags = struct.unpack_from("<HIIIH", m, s + 2)
            raw = bytes(m[s + 20:s + 20 + nlen])
            name = raw.decode("latin-1") if vflags & 1 else raw.decode("utf-16-le", "replace")
            try:
                data = self._data(s, dsize, doff)
            except HiveError:
                data = b""
            yield name, vtype, data

    def _data(self, vk_start, dsize, doff):
        m = self.hive._m
        if dsize & 0x80000000:
            size = dsize & 0x7FFFFFFF
            return bytes(m[vk_start + 8:vk_start + 8 + min(size, 4)])
        if dsize == 0:
            return b""
        s, n = self.hive._cell(doff)
        if dsize > 16344 and m[s:s + 2] == b"db":
            count, = struct.unpack_from("<H", m, s + 2)
            lst, = struct.unpack_from("<I", m, s + 4)
            ls, ln = self.hive._cell(lst)
            out = bytearray()
            for i in range(count):
                seg, = struct.unpack_from("<I", m, ls + i * 4)
                ss, sn = self.hive._cell(seg)
                out += m[ss:ss + min(sn, 16344)]
            return bytes(out[:dsize])
        return bytes(m[s:s + min(dsize, n)])

    def values(self):
        return {name: decode(vtype, data) for name, vtype, data in self._values_raw()}

    def value(self, name, default=None):
        low = name.lower()
        for n, vtype, data in self._values_raw():
            if n.lower() == low:
                return decode(vtype, data)
        return default


def decode(vtype, data):
    if vtype in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
        return data.decode("utf-16-le", "replace").split("\x00", 1)[0]
    if vtype == REG_MULTI_SZ:
        return [s for s in data.decode("utf-16-le", "replace").split("\x00") if s]
    if vtype == REG_DWORD and len(data) >= 4:
        return struct.unpack_from("<I", data)[0]
    if vtype == REG_DWORD_BE and len(data) >= 4:
        return struct.unpack_from(">I", data)[0]
    if vtype == REG_QWORD and len(data) >= 8:
        return struct.unpack_from("<Q", data)[0]
    return data
