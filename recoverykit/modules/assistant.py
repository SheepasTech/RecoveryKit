"""Phase 3 troubleshooting assistant: proposes ordered next steps from the scan results.

It only PROPOSES. Nothing here runs a command. The decision logic lives in
config/assistant.toml (rules); this module flattens case data into facts, evaluates
the rules with a tiny safe condition evaluator (no eval) and prints the result.

Condition grammar (all conditions of a rule must hold):
    <fact> == <value>      <fact> != <value>
    <fact> > <value>       <fact> < <value>      <fact> >= <value>     <fact> <= <value>
    <fact> in [a, b]       <fact> contains <value>
    exists <fact>          missing <fact>        <fact> is true|false
A comparison on an absent fact is False, except `missing` and `!=` which are True.
"""
import os
import re
import tomllib

from ..core.log import LOG

GB = 2 ** 30
BRANCHES = ("A", "B", "C", "D", "E", "X")
BRANCH_TITLES = {
    "A": "A. Preserve data and establish the exact boot failure",
    "B": "B. DISM repair with a matching source",
    "C": "C. Recovery environment options, one at a time",
    "D": "D. Boot configuration: inspect, do not rewrite",
    "E": "E. Storage and hardware",
    "X": "Notices and guardrails",
}
_NOT_EXECUTED = ("declined", "dry-run", "dry_run", "dryrun")
_RUN_DIR = re.compile(r"^(\d{8})-(\d{4})(?:-(\d+))?$")


# ---------------------------------------------------------------- facts

def _g(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return default
        d = d[p]
    return d


def facts(case_data):
    """Flatten case.json data into dotted facts. Anything missing is simply absent."""
    f = {}
    cd = case_data or {}
    sections = cd.get("sections") or {}

    for k, v in (cd.get("operator_answers") or {}).items():
        f["operator." + k] = v

    target = cd.get("target") or {}
    f["target.present"] = bool(target)
    if target:
        info = target.get("info") or {}
        for key, val in (("online", target.get("online")), ("edition", info.get("edition")),
                         ("build", info.get("build")), ("ubr", info.get("ubr")),
                         ("language", info.get("language")),
                         ("disk_offline", _g(target, "disk", "offline"))):
            if val is not None:
                f["target." + key] = val

    for name, sec in sections.items():
        if name == "assistant":  # never feed our own output back in
            continue
        if isinstance(sec, dict) and sec.get("status") is not None:
            f["section.%s.status" % name] = sec["status"]

    low = _g(sections, "free_space", "data", "low")
    if low is not None:
        f["free_space.low"] = bool(low)
    pend = _g(sections, "pending", "data", "any_pending")
    if pend is not None:
        f["pending.any"] = bool(pend)
    if "bitlocker" in sections:
        f["bitlocker.unreadable"] = bool(_g(sections, "bitlocker", "data", "unreadable_volumes"))
    efi = _g(sections, "boot_structure", "data", "efi_partitions")
    if isinstance(efi, list):
        f["boot.efi_count"] = len(efi)
        f["boot.efi_on_target_disk"] = sum(1 for e in efi if e.get("on_target_disk"))

    f["bcd.captured"] = any(
        str(e.get("dest", "")).startswith("exports/bcd-") and e.get("status") == "ok"
        for e in (cd.get("files") or []) if isinstance(e, dict))

    for it in _g(sections, "logs_target", "items", default=[]) or []:
        if "SrtTrail.txt" in str(it.get("name", "")):
            f["log.srttrail"] = it.get("status")

    last = {}
    for r in cd.get("repair_log") or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        if str(r.get("kind", "")).lower() in _NOT_EXECUTED:
            continue
        last[r["id"]] = r
    for rid, r in last.items():
        f["repair.%s.done" % rid] = True
        if r.get("finding") is not None:
            f["repair.%s.finding" % rid] = r["finding"]
        if r.get("error_code"):
            f["repair.%s.error_code" % rid] = str(r["error_code"]).lower()
        if r.get("rc") is not None:
            f["repair.%s.rc" % rid] = r["rc"]

    sc = cd.get("source_check")
    f["source.checked"] = bool(sc)
    if isinstance(sc, dict):
        if sc.get("ok") is not None:
            f["source.ok"] = bool(sc["ok"])
        mm = sc.get("mismatch_fields")
        if mm is None and isinstance(sc.get("mismatches"), list):
            mm = [m.get("field") if isinstance(m, dict) else m for m in sc["mismatches"]]
        if mm is not None:
            f["source.mismatch_fields"] = list(mm)

    recent = _g(sections, "drivers", "data", "recent")
    if isinstance(recent, list):
        f["drivers.recent_count"] = len(recent)
        f["drivers.recent"] = ", ".join(str(x) for x in recent[:8])
    notable = _g(sections, "registry", "data", "notable")
    if isinstance(notable, list):
        f["registry.notable_count"] = len(notable)
    changes = _g(sections, "registry", "data", "changes")
    if isinstance(changes, list):
        f["registry.changes_count"] = len(changes)
    flagged = 0
    seen = False
    for name in ("autoruns", "services", "tasks"):
        fl = _g(sections, name, "data", "flagged")
        if isinstance(fl, list):
            seen = True
            flagged += len(fl)
    if seen:
        f["startup.flagged_count"] = flagged

    lf = _g(sections, "log_findings", "data")
    if isinstance(lf, dict) and lf:
        srt = lf.get("srttrail") or {}
        if srt.get("root_cause"):
            f["logs.srt_root_cause"] = str(srt["root_cause"])
        if srt:
            f["logs.srt_boot_ok"] = bool(srt.get("boot_status_ok"))
        f["logs.bcd_problem_count"] = sum(len(b.get("problems") or []) for b in (lf.get("bcd") or {}).values())

        def ev_count(*cats):
            return sum(x.get("count", 0) for e in (lf.get("events") or {}).values()
                       for x in e.get("notable_summary") or [] if x.get("category") in cats)
        f["logs.storage_event_count"] = ev_count("storage")
        f["logs.hardware_event_count"] = ev_count("hardware")
        f["logs.unexpected_shutdowns"] = ev_count("shutdown")
        f["logs.cbs_corrupt_count"] = int((lf.get("cbs") or {}).get("corrupt_count") or 0)
        f["logs.headline_count"] = len(lf.get("headline") or [])

    if cd.get("booted_after_repair") is not None:
        f["booted"] = cd["booted_after_repair"]
    return f


# ------------------------------------------------------- condition evaluator

_NAME = r"[A-Za-z_][\w.\-]*"
_RE_EXISTS = re.compile(r"^(exists|missing)\s+(%s)$" % _NAME)
_RE_IS = re.compile(r"^(%s)\s+is\s+(true|false)$" % _NAME)
_RE_IN = re.compile(r"^(%s)\s+in\s+\[(.*)\]$" % _NAME)
_RE_CONTAINS = re.compile(r"^(%s)\s+contains\s+(.+)$" % _NAME)
_RE_CMP = re.compile(r"^(%s)\s*(==|!=|>=|<=|>|<)\s*(.+)$" % _NAME)


def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _split_list(s):
    parts, cur, q = [], "", None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            cur += ch
        elif ch == ",":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if q:
        raise ValueError("unterminated quote in list")
    parts.append(cur)
    return [_unquote(p) for p in parts if p.strip()]


def _num(x):
    if isinstance(x, bool):
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _eq(fv, lit):
    if isinstance(fv, (list, tuple, dict)):
        return False
    if isinstance(fv, bool):
        return str(fv).lower() == lit.lower()
    if isinstance(fv, (int, float)):
        n = _num(lit)
        return n is not None and n == fv
    return str(fv).lower() == lit.lower()


def compile_condition(text):
    """Return a function facts -> bool. Raises ValueError for anything outside the grammar."""
    t = str(text).strip()
    m = _RE_EXISTS.match(t)
    if m:
        want, name = m.group(1) == "exists", m.group(2)
        return lambda f: (name in f) == want
    m = _RE_IS.match(t)
    if m:
        name, want = m.group(1), m.group(2)
        return lambda f: name in f and _eq(f[name], want)
    m = _RE_IN.match(t)
    if m:
        name, items = m.group(1), _split_list(m.group(2))
        return lambda f: name in f and any(_eq(f[name], i) for i in items)
    m = _RE_CONTAINS.match(t)
    if m:
        name, lit = m.group(1), _unquote(m.group(2))

        def contains(f):
            v = f.get(name)
            if isinstance(v, (list, tuple)):
                return any(_eq(i, lit) for i in v)
            if isinstance(v, str):
                return lit.lower() in v.lower()
            return False
        return contains
    m = _RE_CMP.match(t)
    if m:
        name, op, lit = m.group(1), m.group(2), _unquote(m.group(3))
        if op == "==":
            return lambda f: name in f and _eq(f[name], lit)
        if op == "!=":
            return lambda f: name not in f or not _eq(f[name], lit)
        n = _num(lit)
        if n is None:
            raise ValueError("operator %s needs a number, got %r" % (op, lit))
        cmp = {">": lambda a: a > n, "<": lambda a: a < n,
               ">=": lambda a: a >= n, "<=": lambda a: a <= n}[op]
        return lambda f: _num(f.get(name)) is not None and cmp(_num(f[name]))
    raise ValueError("cannot parse condition %r" % t)


# ------------------------------------------------------------------- rules

def validate_rule(rule):
    """Raise ValueError if the rule table is malformed; return the compiled conditions."""
    if not isinstance(rule, dict):
        raise ValueError("rule is not a table")
    for k in ("id", "title", "text"):
        if not isinstance(rule.get(k), str) or not rule[k].strip():
            raise ValueError("%s missing or not a string" % k)
    if rule.get("branch") not in BRANCHES:
        raise ValueError("branch must be one of %s" % ", ".join(BRANCHES))
    if isinstance(rule.get("order"), bool) or not isinstance(rule.get("order"), int):
        raise ValueError("order must be an integer")
    for k in ("when", "evidence", "symptoms"):
        v = rule.get(k, [])
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ValueError("%s must be a list of strings" % k)
    return [compile_condition(c) for c in rule.get("when", [])]


def load_rules(kit_root):
    """Read config/assistant.toml. Returns (rules, errors); a bad rule is skipped and reported."""
    path = os.path.join(kit_root, "config", "assistant.toml")
    try:
        with open(path, "rb") as fh:
            doc = tomllib.load(fh)
    except FileNotFoundError:
        return [], ["%s not found: no suggestions available" % path]
    except (OSError, tomllib.TOMLDecodeError) as e:
        return [], ["%s unreadable: %s" % (path, e)]
    return check_rules(doc.get("rule") or [])


def check_rules(raw_rules):
    """Split raw rule tables into (valid rules, error strings)."""
    rules, errors, seen = [], [], set()
    for i, r in enumerate(raw_rules):
        rid = r.get("id", "#%d" % (i + 1)) if isinstance(r, dict) else "#%d" % (i + 1)
        try:
            validate_rule(r)
            if r["id"] in seen:
                raise ValueError("duplicate id")
        except ValueError as e:
            errors.append("rule %s skipped: %s" % (rid, e))
            continue
        seen.add(r["id"])
        rules.append(r)
    return rules, errors


def _fmt(v):
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return str(v)


def suggest(case_data, rules):
    """Evaluate rules against the case. Returns [{id, branch, title, text, evidence}] sorted by order."""
    f = facts(case_data)
    out = []
    for r in sorted(rules, key=lambda r: (r["order"], r["id"])):
        conds = validate_rule(r)
        syms = r.get("symptoms")
        if syms and f.get("operator.symptom") not in syms:
            continue
        if not all(c(f) for c in conds):
            continue
        text = re.sub(r"\{(%s)\}" % _NAME,
                      lambda m: _fmt(f[m.group(1)]) if m.group(1) in f else m.group(0), r["text"])
        out.append({"id": r["id"], "branch": r["branch"], "title": r["title"], "text": text,
                    "evidence": {n: f.get(n) for n in r.get("evidence", [])}})
    return out


# ------------------------------------------------------------ what changed

def _run_key(name):
    m = _RUN_DIR.match(name)
    return (m.group(1) + m.group(2), int(m.group(3) or 1)) if m else None


def previous_run(case_dir):
    """Path of the latest sibling run folder sorting before case_dir, or None."""
    case_dir = os.path.abspath(case_dir)
    cur = _run_key(os.path.basename(case_dir))
    parent = os.path.dirname(case_dir)
    if cur is None or not os.path.isdir(parent):
        return None
    best = None
    for n in os.listdir(parent):
        k = _run_key(n)
        if k and k < cur and os.path.isdir(os.path.join(parent, n)) and (best is None or k > best[0]):
            best = (k, n)
    return os.path.join(parent, best[1]) if best else None


def what_changed(case_dir, case_data):
    """Differences against the previous run of the same case ([] when there is none)."""
    import json
    prev_dir = previous_run(case_dir)
    if not prev_dir:
        return []
    try:
        with open(os.path.join(prev_dir, "case.json"), encoding="utf-8") as fh:
            old = json.load(fh)
    except (OSError, ValueError) as e:
        return ["previous run %s has no readable case.json (%s): no comparison" % (os.path.basename(prev_dir), e)]
    new = case_data or {}
    fo, fn = facts(old), facts(new)
    out = []

    def diff(label, a, b):
        if a != b:
            out.append("%s: %s -> %s" % (label, "absent" if a is None else _fmt(a),
                                         "absent" if b is None else _fmt(b)))

    for k in sorted(set(fo) | set(fn)):
        if k.startswith("section.") and k.endswith(".status"):
            diff("section %s status" % k[8:-7], fo.get(k), fn.get(k))
    diff("target build", fo.get("target.build"), fn.get("target.build"))
    diff("target ubr", fo.get("target.ubr"), fn.get("target.ubr"))
    a, b = _g(old, "sections", "free_space", "data", "free"), _g(new, "sections", "free_space", "data", "free")
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and abs(a - b) > GB:
        out.append("free space on target: %.1f GB -> %.1f GB" % (a / GB, b / GB))
    diff("pending servicing", fo.get("pending.any"), fn.get("pending.any"))

    def events(d):
        return {i.get("name"): i.get("events") for i in _g(d, "sections", "event_logs", "items", default=[]) or []
                if isinstance(i, dict)}
    eo, en = events(old), events(new)
    for n in sorted(set(eo) | set(en), key=str):
        diff("event log %s events" % n, eo.get(n), en.get(n))
    diff("disk count", _g(old, "sections", "disks", "data", "disk_count"),
         _g(new, "sections", "disks", "data", "disk_count"))
    for k in sorted(set(fo) | set(fn)):
        if k.startswith("operator."):
            diff("operator answer %s" % k[9:], fo.get(k), fn.get(k))
    return out


# ------------------------------------------------------------ module entry

def collect(ctx):
    with ctx.case.section("assistant", "Suggested next steps") as sec:
        rules, errors = load_rules(ctx.kit_root)
        for e in errors:
            sec.item("rules", "error", e)
        sugg = suggest(ctx.case.data, rules)
        changed = what_changed(ctx.case.dir, ctx.case.data)
        sec.data = {"suggestions": sugg, "what_changed": changed, "rule_errors": errors}
        LOG.info("ASSIST| %d suggestion(s), %d change(s), %d rule error(s)", len(sugg), len(changed), len(errors))


def _ascii(s):
    return str(s).encode("ascii", "replace").decode("ascii")


def show(ctx):
    sec = (ctx.case.data.get("sections") or {}).get("assistant") or {}
    data = sec.get("data") or {}
    say = ctx.ui.say
    say("")
    say("=== Suggested next steps (proposals only; nothing is run) ===")
    for e in data.get("rule_errors", []):
        say("WARNING: " + _ascii(e))
    branch, n = None, 0
    for s in data.get("suggestions", []):
        n += 1
        if s["branch"] != branch:
            branch = s["branch"]
            say("")
            say(BRANCH_TITLES.get(branch, branch))
        say("%2d. %s" % (n, _ascii(s["title"])))
        say("    " + _ascii(s["text"]))
        ev = "; ".join("%s = %s" % (k, "absent" if v is None else _fmt(v)) for k, v in s["evidence"].items())
        if ev:
            say("    Because: " + _ascii(ev))
    if not n:
        say("No suggestions.")
    ch = data.get("what_changed") or []
    if ch:
        say("")
        say("What changed since the previous run:")
        for c in ch:
            say("  - " + _ascii(c))
