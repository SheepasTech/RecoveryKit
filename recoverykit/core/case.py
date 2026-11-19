"""Case folder, section status and case.json.

A run starts in cases/_pending/<stamp>/ and is moved to cases/<case-id>/<stamp>/
once the target is known (the case ID is derived from the target, never from the
machine running the kit).
"""
import hashlib
import json
import os
import re
import time
import traceback
from contextlib import contextmanager

from . import log
from .log import LOG

SCHEMA = 1
STATUSES = ("ok", "missing", "error", "skipped")


class Section:
    def __init__(self, name, title):
        self.name, self.title = name, title
        self.status, self.reason = None, ""
        self.data = {}
        self.items = []  # per-source results: {name, status, reason, ...}

    def set(self, status, reason=""):
        assert status in STATUSES, status
        self.status, self.reason = status, reason

    def item(self, name, status, reason="", **extra):
        assert status in STATUSES, status
        e = {"name": name, "status": status, "reason": reason}
        e.update(extra)
        self.items.append(e)
        LOG.info("ITEM  | %s/%s: %s %s", self.name, name, status, reason)
        return e

    def as_dict(self):
        return {"title": self.title, "status": self.status, "reason": self.reason,
                "items": self.items, "data": self.data}


class Case:
    def __init__(self, out_root, kit_version="0"):
        self.out_root = os.path.abspath(out_root)
        self.stamp = time.strftime("%Y%m%d-%H%M")
        base = os.path.join(self.out_root, "_pending", self.stamp)
        n, self.dir = 1, base
        while os.path.exists(self.dir):
            n += 1
            self.dir = "%s-%d" % (base, n)
        for sub in ("inventory", "logs", "exports", "audit"):
            os.makedirs(os.path.join(self.dir, sub))
        self._handler = log.add_file(os.path.join(self.dir, "debug.log"))
        self.data = {
            "schema": SCHEMA, "kit_version": kit_version, "case_id": None, "ticket": None,
            "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "finished": None,
            "environment": {}, "target": {}, "operator_answers": {},
            "sections": {}, "files": [], "source_check": None,
            "booted_after_repair": None,  # set only by the operator, never inferred
        }
        LOG.info("CASE  | run folder %s", self.dir)
        self.save()

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def assign(self, case_id, ticket=None):
        """Move the run folder under its case ID."""
        case_id = re.sub(r"[^A-Za-z0-9_-]", "", case_id) or "unknown"
        dest_parent = os.path.join(self.out_root, case_id)
        os.makedirs(dest_parent, exist_ok=True)
        dest = os.path.join(dest_parent, os.path.basename(self.dir))
        n = 1
        while os.path.exists(dest):
            n += 1
            dest = os.path.join(dest_parent, "%s-%d" % (self.stamp, n))
        log.remove(self._handler)
        self._handler = None
        try:
            os.rename(self.dir, dest)
            self.dir = dest
        finally:
            self._handler = log.add_file(os.path.join(self.dir, "debug.log"))
        self.data["case_id"], self.data["ticket"] = case_id, ticket
        LOG.info("CASE  | assigned %s, folder %s", case_id, self.dir)
        self.save()

    @contextmanager
    def section(self, name, title):
        """Run one report section. An exception marks it error and never aborts the others."""
        sec = Section(name, title)
        LOG.info("SECTION| start %s (%s)", name, title)
        try:
            yield sec
            if sec.status is None:
                bad = [i for i in sec.items if i["status"] == "error"]
                note = "%d item(s) had errors, see items" % len(bad) if bad else ""
                sec.set("ok", "; ".join(x for x in (sec.reason, note) if x))
        except Exception as e:  # noqa: BLE001 - spec: a failed section never aborts the others
            sec.set("error", "%s: %s" % (type(e).__name__, e))
            LOG.error("SECTION| %s failed\n%s", name, traceback.format_exc())
        finally:
            self.data["sections"][name] = sec.as_dict()
            LOG.info("SECTION| end %s: %s %s", name, sec.status, sec.reason)
            self.save()

    def write_json(self, rel, obj):
        p = self.path(*rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False, default=str)
        return p

    def write_text(self, rel, text):
        p = self.path(*rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", errors="replace") as f:
            f.write(text)
        return p

    def collect_file(self, src, rel_dest, source="target", max_bytes=None):
        """Copy one file into the case, read-only on the source.

        Returns {src, dest, source, status, reason, size, mtime, sha256}. Status is
        ok, missing, error, or skipped (larger than max_bytes: metadata only).
        """
        e = {"src": src, "dest": rel_dest, "source": source, "status": "ok", "reason": "",
             "size": None, "mtime": None, "sha256": None}
        try:
            st = os.stat(src)
            e["size"], e["mtime"] = st.st_size, time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(st.st_mtime))
            e["_mtime_ns"] = st.st_mtime_ns
            if max_bytes is not None and st.st_size > max_bytes:
                e["status"], e["reason"] = "skipped", "larger than %d MB, metadata only" % (max_bytes // 2**20)
            else:
                dest = self.path(*rel_dest.split("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                h = hashlib.sha256()
                with open(src, "rb") as fi, open(dest, "wb") as fo:
                    while True:
                        chunk = fi.read(1 << 20)
                        if not chunk:
                            break
                        h.update(chunk)
                        fo.write(chunk)
                e["sha256"] = h.hexdigest()
        except FileNotFoundError:
            e["status"], e["reason"] = "missing", "not found"
        except OSError as ex:
            e["status"], e["reason"] = "error", "%s: %s" % (type(ex).__name__, ex.strerror or ex)
        LOG.info("FILE  | %s -> %s: %s %s", src, rel_dest, e["status"], e["reason"])
        self.data["files"].append(e)
        return e

    def verify_sources(self):
        """Re-stat every collected source. Returns the entries whose size or mtime changed."""
        changed = []
        for e in self.data["files"]:
            if e["status"] not in ("ok", "skipped") or "_mtime_ns" not in e:
                continue
            try:
                st = os.stat(e["src"])
                if st.st_size != e["size"] or st.st_mtime_ns != e["_mtime_ns"]:
                    changed.append(e["src"])
            except OSError:
                changed.append(e["src"])
        return changed

    def save(self):
        tmp = self.path("case.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, self.path("case.json"))

    def close(self):
        self.data["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.save()
        LOG.info("CASE  | closed %s", self.dir)
        log.remove(self._handler)
        self._handler = None
