"""RecoveryKit entry point: `run.cmd` -> `python -m recoverykit`."""
import argparse
import os
import shutil
import sys
import time
import tomllib
import traceback
import zipfile

from . import __version__
from .core import env as envmod
from .core import log
from .core.case import Case
from .core.context import Ctx
from .core.log import LOG
from .core.runner import Runner
from .core.ui import UI

KIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_args(argv):
    p = argparse.ArgumentParser(prog="run.cmd", description="RecoveryKit: diagnose, collect evidence from and "
                                "(only with confirmation) repair unbootable Windows installations.")
    p.add_argument("--scan", action="store_true", help="discovery + log collection + report, then exit (no menu)")
    p.add_argument("--auto", action="store_true", help="never wait for input; defaults are used and no repair is ever confirmed")
    p.add_argument("--target", metavar="LETTER", help="drive letter of the target Windows volume (still verified by contents)")
    p.add_argument("--target-path", metavar="DIR", help="folder that contains \Windows (mounted image or mapped "
                   "folder), for a target that is not a volume root")
    p.add_argument("--ticket", metavar="NR", help="ticket number for the case ID")
    p.add_argument("--out", metavar="DIR", help="where to write cases (default: cases\\ next to run.cmd)")
    p.add_argument("--chkdsk", action="store_true", help="also run a read-only chkdsk on the target (slow)")
    p.add_argument("--dry-run", action="store_true", help="repair steps are shown and logged but never executed")
    p.add_argument("--bundle", action="store_true", help="zip the run folder when done")
    p.add_argument("--wipe-case", metavar="CASE_ID", help="delete a case folder from the output location and exit")
    p.add_argument("--answer", action="append", default=[], metavar="KEY=VALUE",
                   help="pre-answer an operator question, e.g. symptom=repair_loop (repeatable)")
    p.add_argument("--version", action="store_true", help="print the version and exit")
    return p.parse_args(argv)


def writable_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".rk-write-test")
        with open(probe, "w") as f:
            f.write("x")
        os.remove(probe)
        return True
    except OSError:
        return False


def pick_out_root(args, ui):
    """cases/ on the USB; if it is read-only or full, ask for another location. Never the target disk
    by default: the operator has to type the location."""
    first = os.path.abspath(args.out) if args.out else os.path.join(KIT_ROOT, "cases")
    if writable_dir(first) and shutil.disk_usage(first).free > 50 * 2**20:
        return first
    ui.say("Cannot write cases to %s (read-only, missing or less than 50 MB free)." % first)
    while not ui.auto:
        alt = ui.ask("Type another writable folder for the case output (NOT on the target disk), or Enter to quit", "")
        if not alt:
            break
        if writable_dir(alt):
            return os.path.abspath(alt)
        ui.say("Cannot write to %s." % alt)
    tmp = os.path.join(os.environ.get("TEMP") or os.environ.get("TMP") or ".", "RecoveryKit", "cases")
    if ui.auto and writable_dir(tmp):
        ui.say("Using %s instead (lost on reboot in WinRE)." % tmp)
        return tmp
    return None


def bundle(case, ui):
    """Zip the run folder next to it. Returns the zip path."""
    dest = case.dir.rstrip("\\/") + ".zip"
    case.save()
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
    ui.say("Bundle: %s" % dest)
    return dest


def wipe_case(out_root, case_id, ui):
    target = os.path.abspath(os.path.join(out_root, case_id))
    if os.path.dirname(target) != os.path.abspath(out_root) or not case_id.strip(". "):
        ui.say("Not a case ID: %r" % case_id)
        return 2
    if not os.path.isdir(target):
        ui.say("No such case folder: %s" % target)
        return 1
    n = sum(len(f) for _, _, f in os.walk(target))
    if not ui.confirm_yes("Delete case folder %s (%d files) and its bundles permanently?" % (target, n)):
        ui.say("Not deleted.")
        return 1
    shutil.rmtree(target)
    ui.say("Deleted %s. Note: deleted files on a USB stick can still be recoverable with forensic tools." % target)
    return 0


def read_only_check(ctx):
    """Re-stat every source file that was collected and record whether any changed during the run."""
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


def scan(ctx):
    """Phase 1: discovery, log collection, plugins, assistant, report."""
    from .modules import discovery, report
    ui = ctx.ui
    ui.header("Discovery")
    discovery.collect(ctx)
    ui.say("Target: %s" % (discovery.describe(ctx.target) if ctx.target else "none"))
    ui.header("Collecting logs (read-only)")
    _module(ctx, "logs", "collect")
    from . import plugins
    plugins.run_all(ctx)
    read_only_check(ctx)
    _module(ctx, "assistant", "collect")
    path = report.generate(ctx.case)
    summary(ctx)
    ui.say("Report:  %s" % path)
    ui.say("Folder:  %s" % ctx.case.dir)
    ctx.options["scanned"] = True


def _module(ctx, name, func):
    """Call recoverykit.modules.<name>.<func>(ctx). A broken module becomes an error section."""
    try:
        mod = __import__("recoverykit.modules." + name, fromlist=[func])
        return getattr(mod, func)(ctx)
    except Exception as e:  # noqa: BLE001 - one module must never take the run down
        LOG.error("MODULE| %s.%s failed\n%s", name, func, traceback.format_exc())
        with ctx.case.section("module_" + name, "Module %s" % name) as sec:
            sec.set("error", "%s.%s failed: %s: %s" % (name, func, type(e).__name__, e))
        ctx.ui.say("Module %s failed: %s (details in debug.log)" % (name, e))


def summary(ctx):
    ui = ctx.ui
    ui.header("Section status")
    for name, s in ctx.case.data["sections"].items():
        ui.say("  %-8s %-34s %s" % (s["status"], (s["title"] or name)[:34], (s["reason"] or "")[:110]))
        for i in s["items"]:
            if i["status"] != "ok":
                ui.say("             - %s: %s %s" % (i["name"], i["status"], (i["reason"] or "")[:100]))


def menu(ctx):
    from .modules import report
    ui = ctx.ui
    while True:
        choice = ui.choose("RecoveryKit menu", [
            ("scan", "Scan: find the target, collect logs, write the report (read-only)"),
            ("assistant", "Troubleshooting assistant: suggested next steps"),
            ("repair", "Repair and backup helpers (every step is shown and confirmed)"),
            ("answers", "Answer / update the boot-failure questions"),
            ("bundle", "Bundle this run into a zip"),
            ("quit", "Quit"),
        ], "quit" if ctx.options.get("scanned") else "scan")
        if choice == "scan":
            scan(ctx)
        elif choice in ("assistant", "repair", "answers", "bundle") and not ctx.options.get("scanned"):
            ui.say("Run the scan first: nothing is known about the target yet.")
        elif choice == "assistant":
            _module(ctx, "assistant", "collect")
            _module(ctx, "assistant", "show")
            report.generate(ctx.case)
        elif choice == "repair":
            _module(ctx, "repair", "run_menu")
            _module(ctx, "assistant", "collect")
            report.generate(ctx.case)
        elif choice == "answers":
            from .modules import discovery
            ctx.options.pop("answers", None)
            with ctx.case.section("operator", "Not yet established (asked from the operator)") as sec:
                sec.data = discovery.ask_operator(ctx)
                ctx.case.data["operator_answers"] = sec.data
            _module(ctx, "assistant", "collect")
            report.generate(ctx.case)
        elif choice == "bundle":
            bundle(ctx.case, ui)
        else:
            return


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.version:
        print("RecoveryKit %s (Python %s, %s)" % (__version__, sys.version.split()[0], sys.executable))
        return 0
    auto = args.auto
    ui = UI(auto=auto)
    stamp = log.stamp()
    env = envmod.detect()
    mirror = log.add_temp_mirror(stamp) if env["kind"] == "windows" else None
    LOG.info("START | RecoveryKit %s argv=%r kit_root=%s", __version__, sys.argv[1:] if argv is None else argv, KIT_ROOT)

    if sys.maxsize <= 2**32:
        ui.say("RecoveryKit needs 64-bit Python (WinRE has no 32-bit support).")
        return 2
    out_root = pick_out_root(args, ui)
    if not out_root:
        ui.say("No writable location for case output. Nothing was done.")
        return 2
    if args.wipe_case:
        return wipe_case(out_root, args.wipe_case, ui)

    try:
        with open(os.path.join(KIT_ROOT, "config", "kit.toml"), "rb") as f:
            cfg = tomllib.load(f)
        cfg_error = ""
    except (OSError, tomllib.TOMLDecodeError) as e:
        cfg, cfg_error = {}, "config/kit.toml not usable (%s); built-in defaults are used" % e

    case = Case(out_root, __version__)
    runner = Runner(case, ui, KIT_ROOT, dry_run=args.dry_run)
    answers = {}
    for kv in args.answer:
        k, _, v = kv.partition("=")
        answers[k.strip()] = v.strip()
    ctx = Ctx(KIT_ROOT, cfg, env, case, ui, runner,
              options={"chkdsk": args.chkdsk, "ticket": args.ticket if args.ticket is not None else ("" if auto else None),
                       "target": args.target, "target_path": args.target_path, "answers": answers})
    rc = 0
    try:
        ui.say("RecoveryKit %s  -  %s, %s firmware, administrator: %s" % (
            __version__, env["kind"], env["firmware"], "yes" if env["admin"] else "NO"))
        ui.say("Scanning and collecting are read-only. Repairs are separate and each one asks first.")
        ui.say("Everything is logged to %s" % case.dir + (" and %s" % mirror if mirror else ""))
        if cfg_error:
            ui.say("WARNING: " + cfg_error)
        if args.dry_run:
            ui.say("DRY RUN: repair commands will be shown and logged, never executed.")
        if not env["admin"]:
            ui.say("NOT running as administrator: BCD, BitLocker and several logs will be reported as unreadable.")
        tools = runner.verify_tools()
        for name, st in tools.items():
            if st != "ok":
                ui.say("WARNING: tools/%s: %s" % (name, st))
        case.data["tools_manifest"] = tools
        if args.scan or auto:
            scan(ctx)
            _module(ctx, "assistant", "show")
        else:
            menu(ctx)
        if args.bundle:
            bundle(case, ui)
    except KeyboardInterrupt:
        ui.say("Interrupted by the operator.")
        rc = 130
    except Exception as e:  # noqa: BLE001
        LOG.critical("FATAL |\n%s", traceback.format_exc())
        ui.say("Unexpected error: %s: %s. Details are in debug.log in %s" % (type(e).__name__, e, case.dir))
        rc = 1
    finally:
        try:
            from .modules import report
            report.generate(case)
        except Exception:  # noqa: BLE001
            LOG.error("REPORT| final report failed\n%s", traceback.format_exc())
        if ctx.target and ctx.target.reg:
            ctx.target.reg.close()
        for t in ctx.inventory.get("installs", []):
            t.reg.close()
        LOG.info("END   | exit code %s after %.0fs", rc, time.monotonic() - _T0)
        case.close()
    return rc


_T0 = time.monotonic()

if __name__ == "__main__":
    sys.exit(main())
