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
        self.notes = []
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
        if off == NO_OFFSET or off < 0 or pos + 4 > len(self._m):
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
        for part in [p for p in path.split("\\") if p]:
            key = key.subkey(part)
            if key is None:
                return None
        return key

    def get(self, path, name, default=None):
        key = self.open(path)
        if key is None:
            return default
        return key.value(name, default)


MAX_SUBKEYS = 200000
MAX_VALUES = 4096
MAX_VALUE_BYTES = 1 << 20
MAX_BIG_DATA = 16 << 20
VALUES_BUDGET = 16 << 20   # data bytes one Key.values() call may read
CHILDREN_BUDGET = 64 << 20  # data bytes one children()/child_values() call may read in total
MAX_MULTI_SZ_BYTES = 256 << 10
MAX_MULTI_SZ_ITEMS = 4096
DB_SEGMENT = 16344
_PARSE_ERRORS = (struct.error, IndexError, ValueError, OverflowError, MemoryError, RecursionError)


def _u(fmt, m, pos, limit):
    """struct.unpack_from that stays inside [.., limit) and reports HiveError only."""
    if pos < 0 or pos + struct.calcsize(fmt) > limit:
        raise HiveError("structure at 0x%x runs past its cell" % pos)
    try:
        return struct.unpack_from(fmt, m, pos)
    except _PARSE_ERRORS as e:
        raise HiveError("unreadable structure: %s" % e)


class Key:
    def __init__(self, hive, off):
        self.hive = hive
        m = hive._m
        s, n = hive._cell(off)
        if n < 76 or m[s:s + 2] != b"nk":
            raise HiveError("expected nk cell at 0x%x" % off)
        self._s = s
        end = s + n
        flags = _u("<H", m, s + 2, end)[0]
        self.timestamp = _filetime(_u("<Q", m, s + 4, end)[0])
        self._nsub, = _u("<I", m, s + 20, end)
        self._sublist, = _u("<I", m, s + 28, end)
        self._nval, = _u("<I", m, s + 36, end)
        self._vallist, = _u("<I", m, s + 40, end)
        nlen, = _u("<H", m, s + 72, end)
        if 76 + nlen > n:
            raise HiveError("key name runs past its cell at 0x%x" % off)
        raw = bytes(m[s + 76:s + 76 + nlen])
        self.name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace")

    def _sub_offsets(self):
        if not self._nsub or self._sublist == NO_OFFSET:
            return
        limit = min(self._nsub, MAX_SUBKEYS)
        m = self.hive._m
        seen = set()
        yielded = 0
        stack = [(self._sublist, 0)]
        try:
            while stack:
                off, depth = stack.pop()
                if depth > 8:
                    raise HiveError("subkey list nested too deep")
                if off in seen:
                    continue
                seen.add(off)
                if len(seen) > MAX_SUBKEYS:
                    raise HiveError("too many subkey lists")
                s, n = self.hive._cell(off)
                end = s + n
                if n < 4:
                    raise HiveError("subkey list too short")
                sig = bytes(m[s:s + 2])
                count = _u("<H", m, s + 2, end)[0]
                if sig in (b"lf", b"lh"):
                    esz = 8
                elif sig in (b"li", b"ri"):
                    esz = 4
                else:
                    raise HiveError("unknown subkey list type %r" % sig)
                count = min(count, (n - 4) // esz)
                if sig == b"ri":
                    for i in reversed(range(count)):
                        stack.append((_u("<I", m, s + 4 + i * 4, end)[0], depth + 1))
                    continue
                for i in range(count):
                    yield _u("<I", m, s + 4 + i * esz, end)[0]
                    yielded += 1
                    if yielded >= limit:
                        return
        except _PARSE_ERRORS as e:
            raise HiveError("bad subkey list: %s" % e)

    def subkeys(self):
        out = []
        for off in self._sub_offsets():
            try:
                out.append(Key(self.hive, off))
            except HiveError:
                continue
        return out

    def children(self):
        """Yield the subkeys one by one, walking the subkey list once (same caps as subkeys())."""
        for off in self._sub_offsets():
            try:
                yield Key(self.hive, off)
            except HiveError:
                continue

    def child_values(self, max_children=5000):
        """Return (list of (name, values dict), truncated) for the subkeys, one walk, at most max_children."""
        out, truncated = [], False
        shared = [CHILDREN_BUDGET]
        for k in self.children():
            if len(out) >= max_children:
                truncated = True
                break
            try:
                vals = k.values(shared)
            except HiveError:
                vals = {}
            out.append((k.name, vals))
        return out, truncated

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

    def _vk_records(self):
        """Yield (name, vtype, vk_start, dsize, doff) without touching the data cells."""
        if not self._nval or self._vallist == NO_OFFSET:
            return
        m = self.hive._m
        try:
            ls, ln = self.hive._cell(self._vallist)
            end = ls + ln
            for i in range(min(self._nval, ln // 4, MAX_VALUES)):
                voff, = _u("<I", m, ls + i * 4, end)
                try:
                    s, n = self.hive._cell(voff)
                except HiveError:
                    continue
                if n < 20 or m[s:s + 2] != b"vk":
                    continue
                nlen, dsize, doff, vtype, vflags = _u("<HIIIH", m, s + 2, s + n)
                if 20 + nlen > n:
                    continue
                raw = bytes(m[s + 20:s + 20 + nlen])
                name = raw.decode("latin-1") if vflags & 1 else raw.decode("utf-16-le", "replace")
                yield name, vtype, s, dsize, doff
        except _PARSE_ERRORS as e:
            raise HiveError("bad value list: %s" % e)

    def _values_raw(self, budget=None):
        """Yield (name, type, bytes). With `budget` (bytes), data past it comes back empty."""
        used, noted = 0, False
        for name, vtype, s, dsize, doff in self._vk_records():
            if budget is not None and used >= budget:
                if not noted:
                    noted = True
                    self.hive.notes.append("values of key %s: more than %d bytes of data, the rest not read"
                                           % (self.name, budget))
                yield name, vtype, b""
                continue
            try:
                data = self._data(s, dsize, doff)
            except HiveError:
                data = b""
            used += len(data)
            yield name, vtype, data

    def _data(self, vk_start, dsize, doff, cap=None):
        m = self.hive._m
        try:
            if dsize & 0x80000000:
                size = dsize & 0x7FFFFFFF
                return bytes(m[vk_start + 8:vk_start + 8 + min(size, 4)])
            if dsize == 0:
                return b""
            if dsize > MAX_BIG_DATA:
                self.hive.notes.append("value data of %d bytes not read (limit %d)" % (dsize, MAX_BIG_DATA))
                return b""
            want = min(dsize, MAX_VALUE_BYTES, cap or MAX_VALUE_BYTES)
            s, n = self.hive._cell(doff)
            if dsize > DB_SEGMENT and n >= 8 and m[s:s + 2] == b"db":
                count, = _u("<H", m, s + 2, s + n)
                lst, = _u("<I", m, s + 4, s + n)
                count = min(count, -(-dsize // DB_SEGMENT))
                ls, ln = self.hive._cell(lst)
                count = min(count, ln // 4)
                out = bytearray()
                for i in range(count):
                    seg, = _u("<I", m, ls + i * 4, ls + ln)
                    ss, sn = self.hive._cell(seg)
                    out += m[ss:ss + min(sn, DB_SEGMENT)]
                    if len(out) >= want:
                        break
                return bytes(out[:want])
            return bytes(m[s:s + min(want, n)])
        except _PARSE_ERRORS as e:
            raise HiveError("bad value data: %s" % e)

    def values(self, shared=None):
        """{name: decoded value}. `shared` is a one-item list [bytes left] spanning several calls
        (children()); the per-call budget still applies. Budgets count DECODED size."""
        out, used, noted = {}, 0, False
        for name, vtype, s, dsize, doff in self._vk_records():
            left = VALUES_BUDGET - used
            if shared is not None:
                left = min(left, shared[0])
            if left <= 0:
                if not noted:
                    noted = True
                    if used >= VALUES_BUDGET or shared is None:
                        self.hive.notes.append("values of key %s: more than %d bytes of data, the rest not read"
                                               % (self.name, VALUES_BUDGET))
                    else:
                        note = ("values of the subkeys: more than %d bytes of data in one pass, the rest not read"
                                % CHILDREN_BUDGET)
                        if note not in self.hive.notes:
                            self.hive.notes.append(note)
                out[name] = b""
                continue
            try:
                data = self._data(s, dsize, doff, MAX_MULTI_SZ_BYTES if vtype == REG_MULTI_SZ else None)
            except HiveError:
                data = b""
            val = decode(vtype, data)
            if isinstance(val, list):
                if len(val) > MAX_MULTI_SZ_ITEMS:
                    val = val[:MAX_MULTI_SZ_ITEMS]
                cost = sum(len(x) * 2 + 64 for x in val)
            elif isinstance(val, str):
                cost = len(val) * 2
            elif isinstance(val, bytes):
                cost = len(val)
            else:
                cost = 8
            used += cost
            if shared is not None:
                shared[0] -= cost
            out[name] = val
        return out

    def value(self, name, default=None):
        low = name.lower()
        for n, vtype, s, dsize, doff in self._vk_records():
            if n.lower() == low:
                try:
                    data = self._data(s, dsize, doff)
                except HiveError:
                    data = b""
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
