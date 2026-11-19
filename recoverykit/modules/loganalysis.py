"""Log analysis: reads the COPIES of the target logs in the case folder and extracts the lines a technician
needs first (Startup Repair root cause, CBS/DISM errors, setup errors, device install failures, notable
events, BCD problems). Read-only; never touches the target.

Findings go to inventory/log-findings.json and to the section data (facts for the assistant).
"""
import codecs
import os
import re
from collections import Counter

from ..core.log import LOG

MAX_BYTES = 8 * 2 ** 20
MAX_HEADLINES = 12
BCD_GUID = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"

# (normalised source, event id) -> (category, plain label). Source is lower case without "microsoft-windows-".
NOTABLE = {}


def _add(source, ids, category, label):
    for i in ids:
        NOTABLE[(source, i)] = (category, label)


_add("kernel-power", (41,), "shutdown", "unexpected shutdown (Kernel-Power 41)")
_add("eventlog", (6008,), "shutdown", "unexpected shutdown (EventLog 6008)")
_add("bugcheck", (1001,), "crash", "bug check")
_add("wer-systemerrorreporting", (1001,), "crash", "bug check")
_add("disk", (7,), "storage", "disk bad block")
_add("disk", (11,), "storage", "disk controller error")
_add("disk", (51,), "storage", "disk paging error")
_add("disk", (153,), "storage", "disk I/O retried")
_add("ntfs", (55,), "storage", "NTFS file system corruption")
_add("ntfs", (98,), "storage", "NTFS volume check")
_add("ntfs", (137,), "storage", "NTFS transaction log problem")
_add("volmgr", (161,), "storage", "volume manager: dump file creation failed")
_add("whea-logger", (1, 17, 18, 19, 47), "hardware", "WHEA hardware error")
_add("service control manager", (7000, 7001, 7023, 7026, 7031, 7034), "service", "service failed to start or stopped")
_add("kernel-boot", (16, 29), "boot", "boot-time event (Kernel-Boot)")
_add("windowsupdateclient", (20,), "update", "Windows Update installation failure")
_add("application error", (1000,), "app", "application crash")
_add("volsnap", (25, 36), "storage", "shadow copy (volsnap) problem")

_HRESULT = re.compile(r"0x8[0-9a-fA-F]{7}")
_DATE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")


# ------------------------------------------------------------------ reading
def _read_tail(path):
    """Last MAX_BYTES of a file decoded tolerantly. Returns (text, {"size", "truncated"})."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(4)
        bom, enc = 0, "utf-8"
        if head.startswith(codecs.BOM_UTF8):
            bom, enc = 3, "utf-8"
        elif head[:2] == codecs.BOM_UTF16_LE:
            bom, enc = 2, "utf-16-le"
        elif head[:2] == codecs.BOM_UTF16_BE:
            bom, enc = 2, "utf-16-be"
        elif len(head) == 4 and head[0] and head[1] == 0 and head[2] and head[3] == 0:
            enc = "utf-16-le"
        truncated = size - bom > MAX_BYTES
        start = max(size - MAX_BYTES, bom) if truncated else bom
        if enc.startswith("utf-16") and (start - bom) % 2:
            start += 1
        f.seek(start)
        data = f.read()
    if enc.startswith("utf-16") and len(data) % 2:
        data = data[:-1]
    text = data.decode(enc, errors="replace")
    if truncated:
        nl = text.find("\n")
        text = text[nl + 1:] if nl >= 0 else ""
    return text, {"size": size, "truncated": truncated}


def _lines(text):
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _last_distinct(lines, n):
    seen, out = set(), []
    for ln in reversed(lines):
        if ln not in seen:
            seen.add(ln)
            out.append(ln)
            if len(out) >= n:
                break
    out.reverse()
    return out


def _hresults(lines):
    c = Counter(m.lower() for ln in lines for m in _HRESULT.findall(ln))
    return dict(c.most_common(15))


def _clip(s, n=300):
    s = s.strip()
    return s if len(s) <= n else s[:n] + "..."


# ------------------------------------------------------------------ analysers
def analyse_srttrail(path):
    text, info = _read_tail(path)
    attempts_hdr = text.count("Startup Repair diagnosis and repair log")
    nums = [int(x) for x in re.findall(r"Number of repair attempts:\s*(\d+)", text)]
    chunk = text.split("Startup Repair diagnosis and repair log")[-1] if attempts_hdr else text
    lines = _lines(chunk)
    causes, i = [], 0
    while i < len(lines):
        if lines[i].strip().lower().startswith("root cause found"):
            i += 1
            para = []
            while i < len(lines) and not lines[i].strip():
                i += 1
            while i < len(lines) and re.match(r"^-{3,}\s*$", lines[i].strip()):
                i += 1
            while i < len(lines) and lines[i].strip() and not re.match(r"^-{3,}\s*$", lines[i].strip()):
                para.append(lines[i].strip())
                i += 1
            if para:
                causes.append(" ".join(para))
            continue
        i += 1
    action = result = None
    for idx, ln in enumerate(lines):
        m = re.match(r"^\s*Repair action:\s*(.*)$", ln)
        if m:
            action, result = m.group(1).strip(), None
            for nxt in lines[idx + 1:idx + 6]:
                m2 = re.match(r"^\s*Result:\s*(.*)$", nxt)
                if m2:
                    result = re.sub(r"\s+", " ", m2.group(1)).strip()
                    break
    codes = re.findall(r"Error code\s*=\s*(0x[0-9a-fA-F]+)", chunk)
    nonzero = [c for c in codes if int(c, 16) != 0]
    failed, name = [], None
    for ln in lines:
        m = re.match(r"^\s*Name:\s*(.+?)\s*$", ln)
        if m:
            name = m.group(1)
            continue
        m = re.match(r"^\s*Result:\s*(.*)$", ln)
        if m and name:
            norm = re.sub(r"\s+", " ", m.group(1)).strip().lower()
            if norm != "completed successfully. error code = 0x0":
                failed.append(name)
            name = None
    return {"root_cause": " ; ".join(causes) or None, "repair_action": action, "result": result,
            "error_code": (nonzero or codes or [None])[0],
            "boot_status_ok": "Boot status indicates that the OS booted successfully" in text,
            "tests_failed": failed, "attempts": attempts_hdr or (max(nums) if nums else None), **info}


def _corrupt_names(lines):
    names = {}
    for ln in lines:
        m = re.search(r"Cannot repair member file \[l:\d+\]'([^']+)'", ln)
        if m:
            names.setdefault(m.group(1), 1)
        elif "CSI Payload Corrupt" in ln:
            fields = [x.strip() for x in ln.split("\t") if x.strip()]
            if len(fields) >= 3 and fields[0] == "(p)":
                names.setdefault(fields[-1], 1)
            elif len(fields) >= 2 and "CSI Payload Corrupt" not in fields[-1]:
                names.setdefault(fields[-1], 1)
    return list(names)


def analyse_cbs(path):
    text, info = _read_tail(path)
    lines = _lines(text)
    err = [ln.rstrip() for ln in lines if ", Error " in ln]
    corrupt = _corrupt_names(lines)
    last_time = None
    for ln in reversed(lines):
        m = _DATE.match(ln)
        if m:
            last_time = m.group(1)
            break
    return {"errors": [_clip(x) for x in _last_distinct(err, 20)], "error_count": len(err),
            "hresults": _hresults(err), "corrupt_files": corrupt[:30], "corrupt_count": len(corrupt),
            "last_line_time": last_time, **info}


def analyse_dism(path):
    text, info = _read_tail(path)
    lines = _lines(text)
    err = [ln.rstrip() for ln in lines if ", Error " in ln]
    last_op = None
    for ln in reversed(lines):
        k = ln.find("Executing command line:")
        if k >= 0:
            last_op = _clip(ln[k + len("Executing command line:"):])
            break
    return {"errors": [_clip(x) for x in _last_distinct(err, 20)], "error_count": len(err),
            "hresults": _hresults(err), "last_operation": last_op, **info}


def analyse_setup(path):
    text, info = _read_tail(path)
    lines = _lines(text)
    err = [ln.rstrip() for ln in lines if ", Error " in ln or "FatalError" in ln]
    phase = None
    for ln in reversed(lines):
        if "SETUPPHASE" in ln or "Setup phase" in ln:
            m = (re.search(r"(?:SETUPPHASE|Setup phase)\s*[:=]\s*(\S.*?)\s*$", ln)
                 or re.search(r"SETUPPHASE_?(\w+)", ln))
            if m:
                phase = _clip(m.group(1), 80)
                break
    return {"errors": [_clip(x) for x in _last_distinct(err, 20)], "error_count": len(err),
            "hresults": _hresults(err), "phase": phase, **info}


def analyse_setupapi(path):
    text, info = _read_tail(path)
    installs, pending, fails = [], None, []
    for ln in _lines(text):
        m = re.match(r"^>>>\s+\[((?:Setup online )?Device Install.*)\]\s*$", ln)
        if m:
            pending = {"header": _clip(m.group(1), 200), "start": None}
            installs.append(pending)
            continue
        m = re.match(r"^>>>\s+Section start\s+(.+?)\s*$", ln)
        if m and pending is not None and pending["start"] is None:
            pending["start"] = m.group(1)
        elif ln.startswith("!!!"):
            fails.append(_clip(ln))
    return {"last_installs": installs[-10:], "failures": fails[-10:], **info}


def _norm_source(src):
    s = src.strip().lower()
    return s[len("microsoft-windows-"):] if s.startswith("microsoft-windows-") else s


_SHORT = re.compile(r"^Event\[\d+\]:\s*(\S+)\s+Level\s+\d+\s*(?:\([^)]*\))?\s+ID\s+(\d+)\s+(.+?)(?:\s+\[(.*)\])?\s*$")


def parse_events(text):
    """Both formats. Returns [{"source", "id", "date", "text"}]."""
    events, cur = [], None

    def fin():
        if cur and cur.get("source") and cur.get("id") is not None:
            events.append(cur)

    for ln in _lines(text):
        if ln.startswith("Event["):
            fin()
            cur = {"source": None, "id": None, "date": None, "text": []}
            m = _SHORT.match(ln.rstrip())
            if m:
                cur.update(date=m.group(1), id=int(m.group(2)), source=m.group(3).strip())
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+(Source|Event ID|Date):\s*(.*?)\s*$", ln)
        if m and cur["source"] is None and m.group(1) == "Source":
            cur["source"] = m.group(2)
        elif m and m.group(1) == "Event ID" and cur["id"] is None and m.group(2).isdigit():
            cur["id"] = int(m.group(2))
        elif m and m.group(1) == "Date" and cur["date"] is None:
            cur["date"] = m.group(2)
        elif len(cur["text"]) < 40:
            cur["text"].append(ln.strip())
    fin()
    return events


def analyse_events(path):
    text, info = _read_tail(path)
    events = parse_events(text)
    by = Counter("%s %d" % (e["source"], e["id"]) for e in events)
    notable, summary = [], {}
    for e in events:
        hit = NOTABLE.get((_norm_source(e["source"]), e["id"]))
        if not hit:
            continue
        cat, label = hit
        code = None
        if e["source"].lower() == "bugcheck" or e["id"] == 1001:
            m = re.search(r"0x[0-9a-fA-F]{4,8}", " ".join(e["text"]))
            code = m.group(0) if m else None
        notable.append({"source": e["source"], "id": e["id"], "label": label, "category": cat,
                        "date": e["date"], "code": code})
        s = summary.setdefault((e["source"], e["id"]), {"source": e["source"], "id": e["id"], "label": label,
                                                         "category": cat, "count": 0, "codes": []})
        s["count"] += 1
        if code and code not in s["codes"]:
            s["codes"].append(code)
    return {"count": len(events), "by_source_id": dict(by.most_common(10)), "notable": notable[-50:],
            "notable_summary": sorted(summary.values(), key=lambda s: -s["count"]), **info}


def _parse_bcd(text):
    blocks, cur, prev = [], None, ""
    for ln in _lines(text):
        if re.match(r"^-{3,}\s*$", ln) and prev.strip():
            cur = {"title": prev.strip(), "el": {}}
            blocks.append(cur)
        elif cur is not None and ln and not ln[0].isspace():
            m = re.match(r"^(\S+)\s{2,}(\S.*?)\s*$", ln)
            if m:
                cur["el"].setdefault(m.group(1).lower(), m.group(2))
        prev = ln
    return blocks


def analyse_bcd(path):
    text, info = _read_tail(path)
    blocks = _parse_bcd(text)
    withid = [b for b in blocks if "identifier" in b["el"]]
    res = {"entries": len(withid), "has_bootmgr": False, "default": None, "os_loaders": [], "problems": [], **info}
    if not withid:
        res["problems"] = []
        res["unrecognised"] = True
        return res
    mgr = [b for b in withid if b["el"]["identifier"].lower() == BCD_GUID or b["title"].lower() == "windows boot manager"]
    loaders = [b for b in withid if b not in mgr and (b["title"].lower() == "windows boot loader" or "osdevice" in b["el"])]
    res["has_bootmgr"] = bool(mgr)
    if mgr:
        res["default"] = mgr[0]["el"].get("default")
    for b in loaders:
        e = b["el"]
        res["os_loaders"].append({k: e.get(k) for k in ("identifier", "device", "path", "description", "osdevice", "recoveryenabled")})
    p = res["problems"]
    if not mgr:
        p.append("no boot manager entry in the listing")
    if not loaders:
        p.append("no OS loader entry in the listing")
    for o in res["os_loaders"]:
        for k in ("device", "osdevice"):
            if o.get(k) and "unknown" in o[k].lower():
                p.append("OS loader %s has %s = unknown (typical sign of a broken BCD)" % (o.get("identifier"), k))
    d = res["default"]
    if mgr and d and d.lower() not in ("{default}", "{current}") \
            and d.lower() not in [(o.get("identifier") or "").lower() for o in res["os_loaders"]]:
        p.append("boot manager default %s is not among the OS loaders" % d)
    return res


# ------------------------------------------------------------------ collect
def _registered(ctx):
    """dest -> absolute path of files in the case folder that were copied OK (never the target)."""
    base = os.path.realpath(ctx.case.dir)
    out = {}

    def add(dest):
        p = os.path.realpath(os.path.join(base, *str(dest).replace("\\", "/").split("/")))
        if os.path.commonpath([base, p]) == base and os.path.isfile(p):
            out[str(dest).replace("\\", "/")] = p
    for e in ctx.case.data.get("files") or []:
        if isinstance(e, dict) and e.get("status") == "ok" and e.get("dest"):
            add(e["dest"])
    try:  # text exports written with write_text are not in files[]
        for n in os.listdir(os.path.join(base, "logs")):
            if re.match(r"^target-(events|bcd)-.*\.txt$", n):
                add("logs/" + n)
    except OSError as ex:
        LOG.info("LOGAN | cannot list logs/: %s", ex)
    return out


def _find(files, suffix):
    for dest in sorted(files):
        if os.path.basename(dest).lower().endswith(suffix):
            return files[dest]
    return None


def _run(sec, name, path, fn, missing_why):
    """Run one analyser; records one item. Returns the result dict or None."""
    if not path:
        sec.item(name, "missing", missing_why)
        return None
    try:
        res = fn(path)
    except Exception as ex:  # noqa: BLE001 - one broken log must not stop the others
        LOG.error("LOGAN | %s failed: %s", name, ex)
        sec.item(name, "error", "%s: %s" % (type(ex).__name__, ex))
        return None
    note = ""
    if res.get("truncated"):
        note = "truncated: only the last 8 MB of %.1f MB analysed" % (res["size"] / 2 ** 20)
    if res.get("unrecognised"):
        sec.item(name, "error", "listing not in English or empty" + ("; " + note if note else ""))
        return res
    sec.item(name, "ok", note, size=res.get("size"))
    return res


def _ascii(s):
    return str(s).encode("ascii", "replace").decode("ascii")


def _top(h, n=3):
    return ", ".join("%s x%d" % (k, v) for k, v in list(h.items())[:n])


def _headline(f):
    out = []
    s = f.get("srttrail")
    if s:
        if s.get("root_cause"):
            out.append("Startup Repair log root cause: %s" % s["root_cause"])
        if s.get("repair_action") or s.get("result"):
            out.append("Startup Repair log repair action: %s; result: %s%s." % (
                s.get("repair_action") or "not stated", s.get("result") or "not stated",
                " (error code %s)" % s["error_code"] if s.get("error_code") else ""))
        if s.get("boot_status_ok"):
            out.append("Startup Repair log states the boot status indicates the OS booted successfully.")
    for name, b in f.get("bcd", {}).items():
        for p in b.get("problems", []):
            out.append("BCD listing %s: %s." % (name, p))
    agg = {}
    for name, ev in f.get("events", {}).items():
        for x in ev.get("notable_summary", []):
            a = agg.setdefault((x["category"], x["source"], x["id"]), dict(x, count=0, codes=[], logs=[]))
            a["count"] += x["count"]
            a["codes"] += [c for c in x.get("codes", []) if c not in a["codes"]]
            a["logs"].append(name)
    for cat in ("storage", "hardware", "shutdown", "crash"):
        for (c, src, eid), x in agg.items():
            if c != cat:
                continue
            code = " (code %s)" % ", ".join(x["codes"]) if x["codes"] else ""
            if cat in ("storage", "hardware"):
                out.append("Event log %s: %s event %s %s, %s, %d time(s)." % (
                    ", ".join(x["logs"]), cat, src, eid, x["label"], x["count"]))
            else:
                out.append("Event log %s: %s, %d time(s)%s." % (", ".join(x["logs"]), x["label"], x["count"], code))
    for key, label in (("cbs", "CBS.log"), ("dism", "dism.log")):
        d = f.get(key)
        if d and d.get("hresults"):
            out.append("%s errors: %d; most frequent HRESULTs: %s." % (label, d["error_count"], _top(d["hresults"])))
        elif d and d.get("error_count"):
            out.append("%s has %d error line(s)." % (label, d["error_count"]))
    cbs = f.get("cbs")
    if cbs and cbs.get("corrupt_count"):
        out.append("CBS.log names %d corrupt or unrepairable component file(s)." % cbs["corrupt_count"])
    for k, d in (f.get("setup") or {}).items():
        if d.get("error_count"):
            out.append("Panther %s has %d error line(s)%s." % (k, d["error_count"],
                                                              "; last phase %s" % d["phase"] if d.get("phase") else ""))
    sa = f.get("setupapi")
    if sa and sa.get("failures"):
        out.append("setupapi.dev.log has %d recent device install failure line(s) starting with !!!." % len(sa["failures"]))
    if s and s.get("tests_failed"):
        out.append("Startup Repair tests not completed successfully: %s." % ", ".join(s["tests_failed"][:5]))
    if s and s.get("attempts") and s["attempts"] > 1:
        out.append("Startup Repair log shows %d repair attempts." % s["attempts"])
    return [_ascii(x) for x in out][:MAX_HEADLINES]


def _compact(f):
    c = {}
    for k, v in f.items():
        if k in ("events", "bcd"):
            c[k] = {n: {kk: vv for kk, vv in d.items() if kk != "notable"} for n, d in v.items()}
        elif k == "headline":
            c[k] = v
        elif k == "setup":
            c[k] = {n: dict(d, errors=d["errors"][-5:]) for n, d in v.items()}
        elif isinstance(v, dict) and "errors" in v:
            c[k] = dict(v, errors=v["errors"][-5:])
        else:
            c[k] = v
    return c


def collect(ctx):
    with ctx.case.section("log_findings", "Findings in the collected logs") as sec:
        files = _registered(ctx)
        f = {"srttrail": None, "cbs": None, "dism": None, "setup": {}, "setupapi": None, "events": {}, "bcd": {}}
        not_col = "log was not collected"
        f["srttrail"] = _run(sec, "SrtTrail.txt", _find(files, "srttrail.txt"), analyse_srttrail, not_col)
        f["cbs"] = _run(sec, "CBS.log", _find(files, "cbs.log"), analyse_cbs, not_col)
        f["dism"] = _run(sec, "dism.log", _find(files, "dism.log"), analyse_dism, not_col)
        for nm, suf in (("setuperr", "panther_setuperr.log"), ("setupact", "panther_setupact.log")):
            r = _run(sec, nm + ".log", _find(files, suf), analyse_setup, not_col)
            if r:
                f["setup"][nm] = r
        f["setupapi"] = _run(sec, "setupapi.dev.log", _find(files, "setupapi.dev.log"), analyse_setupapi, not_col)
        for kind, fn, pre in (("events", analyse_events, "target-events-"), ("bcd", analyse_bcd, "target-bcd-")):
            found = [d for d in sorted(files) if os.path.basename(d).startswith(pre) and d.endswith(".txt")]
            if not found:
                sec.item(kind, "missing", "no %s export was collected" % ("event" if kind == "events" else "BCD listing"))
            for d in found:
                n = os.path.basename(d)[len(pre):-4]
                r = _run(sec, "%s-%s" % (kind, n), files[d], fn, not_col)
                if r:
                    f[kind][n] = r
        f["headline"] = _headline(f)
        ctx.case.write_json("inventory/log-findings.json", f)
        sec.data = _compact(f)
        for line in f["headline"]:
            ctx.ui.say("  * " + line)
        LOG.info("LOGAN | %d headline(s)", len(f["headline"]))
    return None
