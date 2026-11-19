"""The engine: every operation of the kit, with no UI of its own (ADR 0010).

Front ends are thin clients of this class: the text menu, the headless CLI and
the HTTP agent API (route() below, used for loopback and for relayed calls).
One lock serializes operations: never two operations on a target at once.
"""
import hashlib
import json
import os
import threading
import time
import tomllib
import traceback
import zipfile

from . import __version__
from .core import env as envmod
from .core.case import Case
from .core.context import Ctx
from .core.log import LOG
from .core.runner import Refused, Runner

API = "/api/v1"


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


class Engine:
    def __init__(self, kit_root, out_root, ui, options=None, dry_run=False):
        self.kit_root = kit_root
        self.lock = threading.RLock()
        self.busy = ""                    # name of the running operation, for /status
        self.allow_repairs = False        # API clients on loopback may run repair steps (--allow-repairs)
        self.allow_remote_repairs = False  # relayed clients may run repair steps (--allow-remote-repairs)
        self.scanned = False
        self.last_bundle = None
        self._steps = {}
        try:
            with open(os.path.join(kit_root, "config", "kit.toml"), "rb") as f:
                cfg = tomllib.load(f)
            self.cfg_error = ""
        except (OSError, tomllib.TOMLDecodeError) as e:
            cfg, self.cfg_error = {}, "config/kit.toml not usable (%s); built-in defaults are used" % e
        case = Case(out_root, __version__)
        runner = Runner(case, ui, kit_root, dry_run=dry_run)
        self.ctx = Ctx(kit_root, cfg, envmod.detect(), case, ui, runner, options=dict(options or {}))
        case.data["tools_manifest"] = runner.verify_tools()

    # ------------------------------------------------------------ helpers
    def module(self, name, func, *args):
        """Call recoverykit.modules.<name>.<func>(ctx, ...). A broken module becomes an error section."""
        ctx = self.ctx
        try:
            mod = __import__("recoverykit.modules." + name, fromlist=[func])
            return getattr(mod, func)(ctx, *args)
        except Exception as e:  # noqa: BLE001 - one module must never take the run down
            LOG.error("MODULE| %s.%s failed\n%s", name, func, traceback.format_exc())
            with ctx.case.section("module_" + name, "Module %s" % name) as sec:
                sec.set("error", "%s.%s failed: %s: %s" % (name, func, type(e).__name__, e))
            ctx.ui.say("Module %s failed: %s (details in debug.log)" % (name, e))
            return None

    def _op(self, name):
        eng = self

        class _Op:
            def __enter__(self):
                eng.lock.acquire()
                eng.busy = name
                LOG.info("ENGINE| start %s", name)

            def __exit__(self, *a):
                LOG.info("ENGINE| end %s", name)
                eng.busy = ""
                eng.lock.release()
        return _Op()

    # ------------------------------------------------------------ operations
    def scan(self, **opts):
        """Phase 1: discovery, log collection, plugins, read-only check, assistant, report."""
        from . import plugins
        from .modules import discovery
        ctx, ui = self.ctx, self.ctx.ui
        with self._op("scan"):
            for k in ("ticket", "target", "target_path", "chkdsk", "answers"):
                if opts.get(k) is not None:
                    ctx.options[k] = opts[k]
            if ctx.target and ctx.target.reg:
                ctx.target.reg.close()
            ui.header("Discovery")
            discovery.collect(ctx)
            ui.say("Target: %s" % (discovery.describe(ctx.target) if ctx.target else "none"))
            ui.header("Collecting logs (read-only)")
            self.module("logs", "collect")
            plugins.run_all(ctx)
            self.read_only_check()
            self.module("assistant", "collect")
            self.scanned = True
            self.report()
            return self.sections()

    def read_only_check(self):
        """Re-stat every collected source file and record whether any changed during the run."""
        ctx = self.ctx
        changed = ctx.case.verify_sources()
        n = sum(1 for f in ctx.case.data["files"] if f.get("status") in ("ok", "skipped"))
        if not changed:
            summary = "%d collected source files re-checked after the run: size and modification time unchanged." % n
        elif ctx.target and ctx.target.online:
            summary = ("%d of %d source files changed during the run. Expected: the target is the running Windows, "
                       "which keeps writing its own logs." % (len(changed), n))
        else:
            summary = "WARNING: %d of %d source files changed during the run: %s" % (len(changed), n, ", ".join(changed[:10]))
        ctx.case.data["read_only_check"] = {"checked": n, "changed": changed, "summary": summary}
        LOG.info("VERIFY| %s", summary)

    def report(self):
        from .modules import report
        with self._op("report"):
            return report.generate(self.ctx.case)

    def sections(self):
        return {n: {"title": s["title"], "status": s["status"], "reason": s["reason"],
                    "items": [i for i in s["items"] if i["status"] != "ok"]}
                for n, s in self.ctx.case.data["sections"].items()}

    def status(self):
        ctx, t = self.ctx, self.ctx.target
        from .modules import discovery
        return {"version": __version__, "environment": ctx.env["kind"], "admin": ctx.env["admin"],
                "firmware": ctx.env["firmware"], "busy": self.busy, "scanned": self.scanned,
                "case_id": ctx.case.data["case_id"], "case_dir": ctx.case.dir, "dry_run": ctx.runner.dry_run,
                "allow_repairs": self.allow_repairs, "allow_remote_repairs": self.allow_remote_repairs,
                "target": discovery.describe(t) if t else None, "target_online": bool(t and t.online),
                "booted_after_repair": ctx.case.data.get("booted_after_repair")}

    def suggestions(self, refresh=False):
        with self._op("assistant"):
            if refresh or "assistant" not in self.ctx.case.data["sections"]:
                self.module("assistant", "collect")
            return (self.ctx.case.data["sections"].get("assistant") or {}).get("data") or {}

    def set_answers(self, answers):
        from .modules import discovery
        valid = {k: [o[0] for o in opts] for k, _, opts in discovery.QUESTIONS}
        for k, v in answers.items():
            if k in valid and v not in valid[k]:
                raise ApiError(400, "answer %s must be one of %s" % (k, ", ".join(valid[k])))
            if k not in valid and k not in ("stop_code", "symptom_text"):
                raise ApiError(400, "unknown question %s" % k)
        with self._op("answers"):
            cur = dict(self.ctx.case.data.get("operator_answers") or {})
            cur.update({k: str(v) for k, v in answers.items()})
            with self.ctx.case.section("operator", "Not yet established (asked from the operator)") as sec:
                sec.data = cur
                self.ctx.case.data["operator_answers"] = cur
            self.module("assistant", "collect")
            self.report()
            return cur

    def set_boot_result(self, booted, note=""):
        if booted not in (True, False, None):
            raise ApiError(400, "booted must be true, false or null")
        with self._op("boot-result"):
            self.ctx.case.data["booted_after_repair"] = booted
            self.ctx.case.data["boot_note"] = str(note)
            self.module("assistant", "collect")
            self.report()
            return {"booted_after_repair": booted}

    def bundle(self):
        """Zip the run folder next to it. Returns the zip path."""
        case = self.ctx.case
        with self._op("bundle"):
            self.report()
            dest = case.dir.rstrip("\\/") + ".zip"
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
                for root, dirs, files in os.walk(case.dir):
                    dirs[:] = [d for d in dirs if d != "scratch"]
                    for name in files:
                        full = os.path.join(root, name)
                        try:
                            z.write(full, os.path.relpath(full, os.path.dirname(case.dir)))
                        except OSError as e:
                            LOG.error("BUNDLE| could not add %s: %s", full, e)
            LOG.info("BUNDLE| %s (%d bytes)", dest, os.path.getsize(dest))
            self.last_bundle = dest
            return dest

    def files(self):
        out = []
        base = self.ctx.case.dir
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d != "scratch"]
            for name in files:
                full = os.path.join(root, name)
                try:
                    out.append({"path": os.path.relpath(full, base).replace("\\", "/"), "size": os.path.getsize(full)})
                except OSError:
                    continue
        return out

    def file_path(self, rel):
        """Absolute path of a file inside the run folder; refuses anything outside it."""
        base = os.path.abspath(self.ctx.case.dir)
        full = os.path.abspath(os.path.join(base, *[p for p in rel.replace("\\", "/").split("/") if p]))
        if os.path.commonpath([base, full]) != base or not os.path.isfile(full):
            raise ApiError(404, "no such file in the run folder")
        return full

    def audit(self, since=0):
        out = []
        try:
            with open(self.ctx.case.path("audit.log"), encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if e.get("seq", 0) > since:
                        out.append(e)
        except OSError:
            pass
        return out

    def log_tail(self, offset=0, limit=200000):
        p = self.ctx.case.path("debug.log")
        try:
            size = os.path.getsize(p)
            with open(p, "rb") as f:
                f.seek(max(0, min(offset, size)))
                data = f.read(limit)
        except OSError as e:
            raise ApiError(500, "debug.log not readable: %s" % e)
        return {"offset": offset, "next": offset + len(data), "size": size, "text": data.decode("utf-8", "replace")}

    # ------------------------------------------------------------ repairs
    def check_source(self, path, index=None):
        with self._op("source-check"):
            res = self.module("repair", "check_source", path, index)
            self.report()
            return res

    def repair_steps(self):
        """Proposed steps with the exact command and a token bound to that command (ADR 0012)."""
        from .modules import repair
        ctx = self.ctx
        with self._op("repair-steps"):
            steps = list(repair.online_disk_steps(ctx))
            blockers = []
            if ctx.target is None:
                blockers.append("no target selected: run the scan first")
            elif ctx.target.online:
                blockers.append("the target is the running Windows; target repairs are refused")
            else:
                steps += repair.repair_steps(ctx) + repair.bcd_steps(ctx)
                blockers += ["BCD repair not offered: " + b for b in repair.bcd_blockers(ctx)]
            self._steps = {}
            out = []
            for i, s in enumerate(steps):
                cmd = "diskpart: " + " / ".join(s.diskpart) if s.diskpart is not None else " ".join(
                    '"%s"' % a if " " in str(a) else str(a) for a in s.argv)
                key = s.id if s.id not in self._steps else "%s-%d" % (s.id, i)
                token = hashlib.sha256(cmd.encode("utf-8")).hexdigest()[:12]
                self._steps[key] = (s, token)
                out.append({"id": key, "title": s.title, "command": cmd, "effect": s.effect, "risk": s.risk,
                            "evidence": s.evidence, "touches_target": s.touches_target, "token": token})
            return {"steps": out, "blockers": blockers, "dry_run": ctx.runner.dry_run}

    def run_step(self, step_id, token, confirm, operator="api", remote=False):
        """Run one proposed step after an explicit confirm bound to the shown command."""
        from .modules import repair
        ctx = self.ctx
        allowed = self.allow_remote_repairs if remote else self.allow_repairs
        if not allowed:
            raise ApiError(403, "repairs are not enabled for this session on the target (start it with %s)" % (
                "--allow-remote-repairs" if remote else "--allow-repairs"))
        if step_id not in self._steps:
            raise ApiError(404, "unknown step id; list the steps first")
        step, want = self._steps[step_id]
        if confirm != "yes" or token != want:
            raise ApiError(409, "not confirmed: send confirm=\"yes\" and the token shown for this exact command")
        with self._op("repair " + step_id):
            ui = ctx.ui
            LOG.info("REPAIR| API confirmation by operator %r for step %s (%s)", operator, step_id,
                     "relayed" if remote else "loopback")
            original = ui.confirm_yes
            ui.confirm_yes = lambda question: True
            ctx.runner.repairs_enabled = True
            try:
                res = ctx.runner.repair(step)
            except Refused as e:
                raise ApiError(409, "refused: %s" % e)
            finally:
                ctx.runner.repairs_enabled = False
                ui.confirm_yes = original
            entry = repair.record(ctx, step, res, note="confirmed through the API by %s" % operator)
            if step.id == "assign_letter" and res is not None and res.ok:
                repair.refresh_letter(ctx)
            self.module("assistant", "collect")
            self.report()
            return {"result": entry, "output": (res.out if res is not None else "")[-20000:],
                    "next": "Test boot before the next step, then record the result."}

    def close(self):
        ctx = self.ctx
        try:
            from .modules import report
            report.generate(ctx.case)
        except Exception:  # noqa: BLE001
            LOG.error("REPORT| final report failed\n%s", traceback.format_exc())
        for t in ctx.inventory.get("installs", []) + ([ctx.target] if ctx.target else []):
            if t.reg:
                t.reg.close()
        ctx.case.close()


# ---------------------------------------------------------------- the agent API
REMOTE_POST = {"/scan", "/bundle", "/answers", "/boot-result", "/repair/source", "/repair/run"}


def route(engine, method, path, query=None, body=None, remote=False, operator="api"):
    """Dispatch one agent-API call. Returns (status, payload); payload is a JSON-able object or
    (bytes, content_type). Used unchanged for loopback HTTP and for jobs relayed by the server."""
    query, body = query or {}, body or {}
    t0 = time.monotonic()
    try:
        if not path.startswith(API + "/"):
            raise ApiError(404, "unknown path; the API lives under %s" % API)
        p = path[len(API):].rstrip("/")
        if method not in ("GET", "POST"):
            raise ApiError(405, "only GET and POST are used")
        if method == "POST" and remote and p not in REMOTE_POST:
            raise ApiError(403, "not available to relayed sessions")
        result = _dispatch(engine, method, p, query, body, remote, operator)
        status = 200
    except ApiError as e:
        status, result = e.status, {"error": e.message}
    except Exception as e:  # noqa: BLE001 - an API call must never take the agent down
        LOG.error("API   | %s %s failed\n%s", method, path, traceback.format_exc())
        status, result = 500, {"error": "%s: %s" % (type(e).__name__, e)}
    LOG.info("API   | %s %s %s by %s -> %s in %.1fs", "relayed" if remote else "loopback", method, path, operator,
             status, time.monotonic() - t0)
    return status, result


def _dispatch(e, method, p, q, b, remote, operator):
    if method == "GET":
        if p == "/status":
            return e.status()
        if p == "/case":
            return e.ctx.case.data
        if p == "/sections":
            return e.sections()
        if p == "/report":
            with open(e.report(), "rb") as f:
                return f.read(), "text/markdown; charset=utf-8"
        if p == "/suggestions":
            return e.suggestions(refresh=q.get("refresh") == "1")
        if p == "/files":
            return e.files()
        if p.startswith("/files/"):
            with open(e.file_path(p[len("/files/"):]), "rb") as f:
                return f.read(), "application/octet-stream"
        if p == "/audit":
            return e.audit(int(q.get("since", 0)))
        if p == "/log":
            return e.log_tail(int(q.get("offset", 0)))
        if p == "/repair/steps":
            return e.repair_steps()
        if p == "/bundle/download":
            if not e.last_bundle or not os.path.isfile(e.last_bundle):
                raise ApiError(404, "no bundle yet: POST %s/bundle first" % API)
            with open(e.last_bundle, "rb") as f:
                return f.read(), "application/zip"
        raise ApiError(404, "unknown GET route %s" % p)
    if p == "/scan":
        if not isinstance(b.get("answers", {}), dict):
            raise ApiError(400, "answers must be an object")
        return e.scan(ticket=b.get("ticket"), target=b.get("target"), target_path=b.get("target_path"),
                      chkdsk=b.get("chkdsk"), answers=b.get("answers"))
    if p == "/answers":
        return e.set_answers(b)
    if p == "/boot-result":
        return e.set_boot_result(b.get("booted"), b.get("note", ""))
    if p == "/bundle":
        path = e.bundle()
        return {"path": path, "size": os.path.getsize(path), "download": API + "/bundle/download"}
    if p == "/repair/source":
        if not b.get("path"):
            raise ApiError(400, "path is required")
        return e.check_source(str(b["path"]), b.get("index"))
    if p == "/repair/run":
        return e.run_step(str(b.get("id", "")), str(b.get("token", "")), b.get("confirm"),
                          operator=str(b.get("operator") or operator), remote=remote)
    raise ApiError(404, "unknown POST route %s" % p)
