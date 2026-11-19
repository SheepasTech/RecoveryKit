"""Read-only parser for Windows event log files (.evtx), stdlib only.

Used when wevtutil.exe is not available (WinRE). It extracts the System fields and the
EventData/UserData strings of each record; it does not render message text.

Never raises on a damaged chunk or record: the damaged part is counted in the stats and
skipped. `EvtxError` is raised only when the file cannot be opened or is not an evtx file.
"""
import heapq
import mmap
import struct
from datetime import datetime, timedelta, timezone

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
REC_MAGIC = b"\x2a\x2a\x00\x00"
HEADER_SIZE = 0x1000
CHUNK_SIZE = 0x10000
FIRST_REC = 0x200
MAX_DEPTH = 32
MAX_RECORDS = 2000000
MAX_DATA = 10
MAX_STEPS = 100000      # per-record work budget (tokens, elements, attributes, substitutions)
MAX_DATA_LEN = 300
LEVEL_NAMES = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_INT_FMT = {3: "<b", 4: "<B", 5: "<h", 6: "<H", 7: "<i", 8: "<I", 9: "<q", 10: "<Q", 11: "<f", 12: "<d"}
_ELEM_SIZE = {3: 1, 4: 1, 5: 2, 6: 2, 7: 4, 8: 4, 9: 8, 10: 8, 11: 4, 12: 8, 13: 4, 0x0f: 16, 0x11: 8,
              0x12: 16, 0x14: 4, 0x15: 8}


class EvtxError(Exception):
    pass


class _BinXmlError(Exception):
    pass


def _filetime(v):
    try:
        return (_EPOCH + timedelta(seconds=v // 10000000 - 11644473600)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return ""


class _El:
    __slots__ = ("name", "attrs", "kids")

    def __init__(self, name):
        self.name, self.attrs, self.kids = name, {}, []


def _text(el):
    return "".join(k if isinstance(k, str) else _text(k) for k in el.kids)


def _hex(b):
    return b.hex().upper()


def _scalar(vt, b):
    """Text of one non-array value of base type vt."""
    n = len(b)
    if vt == 1:
        return b.decode("utf-16-le", "replace").rstrip("\x00")
    if vt == 2:
        return b.decode("cp1252", "replace").rstrip("\x00")
    if vt in _INT_FMT:
        f = _INT_FMT[vt]
        if n != struct.calcsize(f):
            return _hex(b)
        v = struct.unpack(f, b)[0]
        return repr(v) if isinstance(v, float) else str(v)
    if vt == 0x0d:
        return "true" if n >= 1 and any(b) else "false"
    if vt == 0x0e:
        return _hex(b)
    if vt == 0x0f and n == 16:
        d1, d2, d3 = struct.unpack("<IHH", b[:8])
        return "{%08X-%04X-%04X-%s-%s}" % (d1, d2, d3, _hex(b[8:10]), _hex(b[10:]))
    if vt == 0x10 and n in (4, 8):
        return "0x%x" % int.from_bytes(b, "little")
    if vt == 0x11 and n == 8:
        v = struct.unpack("<Q", b)[0]
        t = _filetime(v)
        return t[:-1] + ".%07dZ" % (v % 10000000) if t else ""
    if vt == 0x12 and n == 16:
        y, mo, _dow, d, h, mi, s, ms = struct.unpack("<8H", b)
        return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (y, mo, d, h, mi, s, ms)
    if vt == 0x13 and n >= 8:
        sub = b[1]
        auth = int.from_bytes(b[2:8], "big")
        parts = [str(x) for x in struct.unpack_from("<%dI" % sub, b, 8)] if n >= 8 + 4 * sub else []
        return "S-%d-%d%s" % (b[0], auth, "".join("-" + p for p in parts))
    if vt in (0x14, 0x15):
        return "0x%x" % int.from_bytes(b, "little")
    return _hex(b)


def _value_text(vt, b):
    if not b or vt == 0:
        return ""
    if vt & 0x80:
        base = vt & 0x7f
        if base in (1, 2):
            if base == 1:
                parts = b.decode("utf-16-le", "replace").split("\x00")
            else:
                parts = b.decode("cp1252", "replace").split("\x00")
            return ", ".join(p for p in parts if p)
        es = _ELEM_SIZE.get(base)
        if not es:
            return _hex(b)
        return ", ".join(_scalar(base, b[i:i + es]) for i in range(0, len(b) - es + 1, es))
    return _scalar(vt, b)


class _Chunk:
    """Parser state for one 64 KiB chunk (offsets in BinXml are relative to the chunk start)."""

    def __init__(self, buf):
        self.buf = buf
        self.names = {}
        self.defs = {}
        self.steps = 0

    def tick(self, n=1):
        self.steps += n
        if self.steps > MAX_STEPS:
            raise _BinXmlError("record exceeds the work budget (%d steps)" % MAX_STEPS)

    # -- names
    def _name(self, ref, pos):
        """Return (name, new_pos). The name structure is inline when ref == pos."""
        buf = self.buf
        inline = ref == pos
        if ref + 8 > len(buf):
            raise _BinXmlError("name offset 0x%x outside chunk" % ref)
        n = struct.unpack_from("<H", buf, ref + 6)[0]
        end = ref + 8 + 2 * n + 2
        if end > len(buf):
            raise _BinXmlError("name outside chunk")
        name = self.names.get(ref)
        if name is None:
            name = buf[ref + 8:ref + 8 + 2 * n].decode("utf-16-le", "replace")
            self.names[ref] = name
        return name, (end if inline else pos)

    # -- parsing into a node tree: ("t", str) ("s", idx, optional) ("e", name, attrs, kids) ("i", defnodes, values)
    def parse_stream(self, pos, end, depth):
        nodes, _ = self._nodes(pos, end, depth, False)
        return nodes

    def _nodes(self, pos, end, depth, until_end):
        if depth > MAX_DEPTH:
            raise _BinXmlError("BinXml nesting too deep")
        buf = self.buf
        end = min(end, len(buf))
        nodes = []
        while pos < end:
            self.tick()
            tok = buf[pos]
            base = tok & 0xbf
            if tok == 0x00:
                if until_end:
                    raise _BinXmlError("unexpected end of stream inside element")
                return nodes, pos + 1
            if tok == 0x04:
                if not until_end:
                    raise _BinXmlError("stray EndElement")
                return nodes, pos + 1
            if tok == 0x0f:
                pos += 4
            elif base == 0x01:
                el, pos = self._element(pos, tok, depth)
                nodes.append(el)
            elif base == 0x05:
                s, pos = self._literal(pos + 1)
                nodes.append(("t", s))
            elif tok in (0x0d, 0x0e):
                if pos + 4 > end:
                    raise _BinXmlError("truncated substitution")
                nodes.append(("s", struct.unpack_from("<H", buf, pos + 1)[0], tok == 0x0e))
                pos += 4
            elif tok == 0x0c:
                inst, pos = self._template(pos, depth)
                nodes.append(inst)
            else:
                raise _BinXmlError("unsupported BinXml token 0x%02x" % tok)
        if until_end:
            raise _BinXmlError("stream ended inside element")
        return nodes, pos

    def _literal(self, pos):
        """Value text token body at pos (the value type byte); returns (text, new_pos)."""
        buf = self.buf
        vt = buf[pos]
        pos += 1
        if vt == 1:
            n = struct.unpack_from("<H", buf, pos)[0]
            pos += 2
            if pos + 2 * n > len(buf):
                raise _BinXmlError("string outside chunk")
            return buf[pos:pos + 2 * n].decode("utf-16-le", "replace"), pos + 2 * n
        sz = _ELEM_SIZE.get(vt)
        if not sz:
            raise _BinXmlError("unsupported literal value type 0x%02x" % vt)
        return _scalar(vt, bytes(buf[pos:pos + sz])), pos + sz

    def _element(self, pos, tok, depth):
        buf = self.buf
        ref = struct.unpack_from("<I", buf, pos + 7)[0]
        pos += 11
        name, pos = self._name(ref, pos)
        attrs = []
        if tok & 0x40:
            pos += 4
            while pos < len(buf) and (buf[pos] & 0xbf) == 0x06:
                self.tick()
                aref = struct.unpack_from("<I", buf, pos + 1)[0]
                aname, pos = self._name(aref, pos + 5)
                vt = buf[pos]
                if (vt & 0xbf) == 0x05:
                    s, pos = self._literal(pos + 1)
                    val = [("t", s)]
                elif vt in (0x0d, 0x0e):
                    val = [("s", struct.unpack_from("<H", buf, pos + 1)[0], vt == 0x0e)]
                    pos += 4
                else:
                    raise _BinXmlError("unsupported attribute value token 0x%02x" % vt)
                attrs.append((aname, val))
        t = buf[pos]
        if t == 0x03:
            return ("e", name, attrs, []), pos + 1
        if t != 0x02:
            raise _BinXmlError("expected CloseStartElement, got 0x%02x" % t)
        kids, pos = self._nodes(pos + 1, len(buf), depth + 1, True)
        return ("e", name, attrs, kids), pos

    def _template(self, pos, depth):
        buf = self.buf
        def_off = struct.unpack_from("<I", buf, pos + 6)[0]
        pos += 10
        if def_off == pos:
            size = struct.unpack_from("<I", buf, def_off + 20)[0]
            nxt = def_off + 24 + size
        else:
            if def_off + 24 > len(buf):
                raise _BinXmlError("template definition outside chunk")
            size = struct.unpack_from("<I", buf, def_off + 20)[0]
            nxt = pos
        defn = self.defs.get(def_off)
        if defn is None:
            defn = self.parse_stream(def_off + 24, def_off + 24 + size, depth + 1)
            self.defs[def_off] = defn
        pos = nxt
        cnt = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        if cnt > 4096 or pos + 4 * cnt > len(buf):
            raise _BinXmlError("bad substitution count %d" % cnt)
        descs = [struct.unpack_from("<HB", buf, pos + 4 * i) for i in range(cnt)]
        pos += 4 * cnt
        vals = []
        for size, vt in descs:
            vals.append((vt, pos, size))
            pos += size
        if pos > len(buf):
            raise _BinXmlError("substitution values outside chunk")
        return ("i", defn, vals), pos

    # -- resolving substitutions into elements
    def resolve(self, nodes, subs, depth, out):
        if depth > MAX_DEPTH:
            raise _BinXmlError("BinXml nesting too deep")
        for n in nodes:
            self.tick()
            k = n[0]
            if k == "t":
                out.append(n[1])
            elif k == "e":
                el = _El(n[1])
                for an, av in n[2]:
                    tmp = []
                    self.resolve(av, subs, depth + 1, tmp)
                    el.attrs[an] = "".join(x for x in tmp if isinstance(x, str))
                self.resolve(n[3], subs, depth + 1, el.kids)
                out.append(el)
            elif k == "s":
                if subs is None or n[1] >= len(subs):
                    continue
                vt, off, size = subs[n[1]]
                if vt == 0x21:
                    self.tick(max(1, size // 8))
                    self.resolve(self.parse_stream(off, off + size, depth + 1), None, depth + 1, out)
                elif vt != 0 and size:
                    out.append(_value_text(vt, bytes(self.buf[off:off + size])))
            else:
                self.resolve(n[1], n[2], depth + 1, out)


def _collect(el, out):
    for k in el.kids:
        if isinstance(k, str) or len(out) >= MAX_DATA:
            continue
        if any(not isinstance(x, str) for x in k.kids):
            _collect(k, out)
        elif k.name != "Binary":
            t = _text(k).strip()
            if t:
                out.append(t[:MAX_DATA_LEN])


def _event_from(tree, record_id, ft):
    root = next((x for x in tree if not isinstance(x, str) and x.name == "Event"), None)
    if root is None:
        raise _BinXmlError("no Event element")
    ev = {"record_id": record_id, "time": _filetime(ft), "provider": "", "event_id": 0, "level": 0,
          "channel": "", "computer": "", "data": []}
    for k in root.kids:
        if isinstance(k, str):
            continue
        if k.name == "System":
            for s in k.kids:
                if isinstance(s, str):
                    continue
                if s.name == "EventRecordID":
                    try:
                        ev["record_id"] = int(_text(s).strip())
                    except ValueError:
                        pass
                elif s.name == "Provider":
                    ev["provider"] = s.attrs.get("Name", "")
                elif s.name in ("EventID", "Level"):
                    try:
                        ev["event_id" if s.name == "EventID" else "level"] = int(_text(s).strip() or 0)
                    except ValueError:
                        pass
                elif s.name == "Channel":
                    ev["channel"] = _text(s).strip()
                elif s.name == "Computer":
                    ev["computer"] = _text(s).strip()
        elif k.name in ("EventData", "UserData"):
            _collect(k, ev["data"])
    return ev


class _Keep:
    """Keeps only the best `limit` events (largest record ids when newest_first) while reading."""

    def __init__(self, limit, newest_first):
        self.limit, self.sign, self.heap, self.seq, self.matched = limit, (1 if newest_first else -1), [], 0, 0

    def append(self, ev):
        self.matched += 1
        if self.limit is None:
            self.heap.append((0, 0, ev))
            return
        if self.limit <= 0:
            return
        self.seq += 1
        item = (self.sign * ev["record_id"], self.seq, ev)
        if len(self.heap) < self.limit:
            heapq.heappush(self.heap, item)
        elif item[:2] > self.heap[0][:2]:
            heapq.heapreplace(self.heap, item)

    def events(self):
        return [x[2] for x in self.heap]


def read_events(path, levels=(1, 2, 3), limit=200, newest_first=True):
    """Return (events, stats). Level filtering happens before the limit."""
    path = str(path)
    stats = {"records_seen": 0, "records_matched": 0, "chunks": 0, "chunks_bad": 0, "errors": [], "dirty": False}

    def err(msg):
        if len(stats["errors"]) < 10:
            stats["errors"].append(msg)

    try:
        f = open(path, "rb")
    except OSError as e:
        raise EvtxError("cannot open %s: %s" % (path, e))
    with f:
        try:
            m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError) as e:
            raise EvtxError("cannot map %s: %s" % (path, e))
        try:
            if len(m) < 0x80 or m[0:8] != FILE_MAGIC:
                raise EvtxError("%s is not an event log file (no ElfFile signature)" % path)
            stats["dirty"] = bool(struct.unpack_from("<I", m, 0x78)[0] & 1)
            hdr_chunks = struct.unpack_from("<H", m, 0x2A)[0]
            levels = set(levels)
            found = _Keep(limit, newest_first)
            pos, idx = HEADER_SIZE, 0
            while pos < len(m) and stats["records_seen"] < MAX_RECORDS:
                buf = m[pos:pos + CHUNK_SIZE]
                pos += CHUNK_SIZE
                idx += 1
                if buf[:8] != CHUNK_MAGIC:
                    if idx > hdr_chunks and not any(buf[:512]):
                        continue
                    stats["chunks"] += 1
                    stats["chunks_bad"] += 1
                    err("chunk %d: no ElfChnk signature" % (idx - 1))
                    continue
                stats["chunks"] += 1
                try:
                    bad = _read_chunk(buf, idx - 1, levels, found, stats, err)
                except Exception as e:
                    bad = True
                    err("chunk %d: %s: %s" % (idx - 1, type(e).__name__, e))
                if bad or len(buf) < CHUNK_SIZE:
                    stats["chunks_bad"] += 1
        finally:
            m.close()
    events = found.events()
    events.sort(key=lambda e: e["record_id"], reverse=newest_first)
    stats["records_matched"] = found.matched
    return events, stats


def _read_chunk(buf, idx, levels, found, stats, err):
    """Parse the records of one chunk. Returns True when something in it was damaged."""
    bad = False
    chunk = _Chunk(buf)
    free = struct.unpack_from("<I", buf, 0x30)[0] if len(buf) >= 0x34 else 0
    if free < FIRST_REC or free > len(buf):
        free = len(buf)
        bad = bad or len(buf) >= CHUNK_SIZE
    off = FIRST_REC
    while off + 28 <= free and stats["records_seen"] < MAX_RECORDS:
        if buf[off:off + 4] != REC_MAGIC:
            nxt = buf.find(REC_MAGIC, off + 1, free)
            bad = True
            err("chunk %d: bad record signature at 0x%x" % (idx, off))
            if nxt < 0:
                break
            off = nxt
            continue
        size, rid, ft = struct.unpack_from("<IQQ", buf, off + 4)
        if size < 28 or off + size > len(buf):
            bad = True
            err("chunk %d: bad record size %d at 0x%x" % (idx, size, off))
            off += 4
            continue
        stats["records_seen"] += 1
        try:
            chunk.steps = 0
            nodes = chunk.parse_stream(off + 24, off + size - 4, 0)
            tree = []
            chunk.resolve(nodes, None, 0, tree)
            ev = _event_from(tree, rid, ft)
            if ev["level"] in levels:
                found.append(ev)
        except Exception as e:
            bad = True
            err("chunk %d record %d: %s: %s" % (idx, rid, type(e).__name__, e))
        off += size
    return bad


def format_text(events):
    out = []
    for i, ev in enumerate(events):
        lvl = ev.get("level", 0)
        out.append("Event[%d]: %s  Level %d (%s)  ID %d  %s  [%s]" % (
            i, ev.get("time", ""), lvl, LEVEL_NAMES.get(lvl, "Level %d" % lvl), ev.get("event_id", 0),
            ev.get("provider", ""), ev.get("channel", "")))
        if ev.get("computer"):
            out.append("  Computer: %s" % ev["computer"])
        for j, d in enumerate(ev.get("data", [])):
            out.append("  Data[%d]: %s" % (j, " ".join(d.split())))
        out.append("")
    text = "\n".join(out)
    return text.encode("ascii", "replace").decode("ascii")
