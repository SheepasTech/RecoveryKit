"""RecoveryKit entry point: `run.cmd` -> `python -m recoverykit`.

Front ends over the engine (ADR 0010): text menu (default), headless scan
(--scan / --auto), agent API on loopback (--serve), outbound remote session
(--connect), control server (--server) and its operator client (--ctl).
"""
import argparse
import os
import shutil
import sys
import time
import traceback

from . import __version__
from .core import env as envmod
from .core import log
from .core.log import LOG
from .core.ui import UI

KIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_args(argv):
    p = argparse.ArgumentParser(prog="run.cmd", description="RecoveryKit: diagnose, collect evidence from and "
                                "(only with confirmation) repair unbootable Windows installations.",
                                allow_abbrev=False)
    g = p.add_argument_group("scan")
    g.add_argument("--scan", action="store_true", help="discovery + log collection + report, then exit (no menu)")
    g.add_argument("--auto", action="store_true", help="never wait for input; defaults are used and no repair is ever confirmed")
    g.add_argument("--target", metavar="LETTER", help="drive letter of the target Windows volume (still verified by contents)")
    g.add_argument("--target-path", metavar="DIR", help="folder that contains the Windows directory (mounted image or "
                   "mapped folder), for a target that is not a volume root")
    g.add_argument("--ticket", metavar="NR", help="ticket number for the case ID")
    g.add_argument("--out", metavar="DIR", help="where to write cases (default: the cases folder next to run.cmd)")
    g.add_argument("--chkdsk", action="store_true", help="also run a read-only chkdsk on the target (slow)")
    g.add_argument("--answer", action="append", default=[], metavar="KEY=VALUE",
                   help="pre-answer an operator question, e.g. symptom=repair_loop (repeatable)")
    g.add_argument("--bundle", action="store_true", help="zip the run folder when done")
    g.add_argument("--dry-run", action="store_true", help="repair steps are shown and logged but never executed")
    g = p.add_argument_group("headless agent API (this machine only)")
    g.add_argument("--serve", action="store_true", help="serve the agent API on 127.0.0.1 and wait")
    g.add_argument("--port", type=int, default=None, help="port for --serve (default 8766) or --server (default 8765)")
    g.add_argument("--allow-repairs", action="store_true", help="let loopback API clients run confirmed repair steps")
    g = p.add_argument_group("remote session (agent connects out; no port is opened on the target)")
    g.add_argument("--connect", metavar="URL", help="control server URL, e.g. http://192.168.1.10:8765")
    g.add_argument("--token", metavar="T", help="agent token of the server (from its config/token-server.json)")
    g.add_argument("--pin", metavar="SHA256", help="expected SHA-256 fingerprint of the server's TLS certificate")
    g.add_argument("--session-minutes", type=int, default=60, help="remote session length (default 60)")
    g.add_argument("--allow-remote-repairs", action="store_true",
                   help="let the remote operator run confirmed repair steps in this session (default: read-only)")
    g = p.add_argument_group("control server (on the main machine)")
    g.add_argument("--server", action="store_true", help="run the control server")
    g.add_argument("--bind", metavar="IP", default="127.0.0.1", help="interface to bind (default 127.0.0.1; give the LAN address)")
    g.add_argument("--store", metavar="DIR", help="where received bundles are stored (default: cases/_server)")
    g.add_argument("--intake", metavar="DIR", help="also copy bundles to <DIR>/ITW <ticket>/ (vault intake)")
    g.add_argument("--ctl", nargs=argparse.REMAINDER, metavar="...", help="operator client: agents | pair ID CODE | "
                   "get ID PATH | post ID PATH [JSON] | fetch-bundle ID | bundles | revoke ID")
    g = p.add_argument_group("other")
    g.add_argument("--decode-id", metavar="DEVICE_ID", help="show which components a device ID stands for and exit")
    g.add_argument("--wipe-case", metavar="CASE_ID", help="delete a case folder from the output location and exit")
    g.add_argument("--version", action="store_true", help="print the version and exit")
    return p.parse_args(argv)


def start_line(args):
    """The START log line, built from the PARSED arguments with secrets masked (never from raw argv)."""
    shown = {}
    for k, v in sorted(vars(args).items()):
        if k in ("token", "pin") and v:
            v = "<%s>" % k
        elif k == "ctl" and v:         # the remainder is passed to the ctl client unparsed
            v = ["<secret>" if i and v[i - 1] in ("--token", "--pin") else a for i, a in enumerate(v)]
        shown[k] = v
    return "START | RecoveryKit %s args=%r kit_root=%s" % (__version__, shown, KIT_ROOT)


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


def wipe_case(out_root, case_id, ui):
    target = os.path.abspath(os.path.join(out_root, case_id))
    if os.path.dirname(target) != os.path.abspath(out_root) or not case_id.strip(". "):
        ui.say("Not a case ID: %r" % case_id)
        return 2
    if case_id.startswith("_"):
        ui.say("Refused: %r is not a case folder (names starting with _ are kit internals such as _pending or "
               "_server). Also note that --wipe-case never removes devices\\<ID> or the %%TEMP%% mirror of the log." % case_id)
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
    ui.say("Not removed: devices\\<ID> (the device record on the stick) and the copy of the log in %TEMP%.")
    return 0


def summary(engine):
    ui = engine.ctx.ui
    ui.header("Section status")
    for name, s in engine.ctx.case.data["sections"].items():
        ui.say("  %-8s %-34s %s" % (s["status"], (s["title"] or name)[:34], (s["reason"] or "")[:110]))
        for i in s["items"]:
            if i["status"] != "ok":
                ui.say("             - %s: %s %s" % (i["name"], i["status"], (i["reason"] or "")[:100]))
    ui.say("Report:  %s" % engine.ctx.case.path("report.md"))
    ui.say("Folder:  %s" % engine.ctx.case.dir)


def menu(engine):
    ui, ctx = engine.ctx.ui, engine.ctx
    while True:
        choice = ui.choose("RecoveryKit menu", [
            ("scan", "Scan: find the target, collect logs, write the report (read-only)"),
            ("assistant", "Troubleshooting assistant: suggested next steps"),
            ("repair", "Repair and backup helpers (every step is shown and confirmed)"),
            ("drivers", "Third-party drivers: newest first, propose removing one"),
            ("answers", "Answer / update the boot-failure questions"),
            ("device", "Device settings saved on this stick (notes, ticket)"),
            ("bundle", "Bundle this run into a zip"),
            ("quit", "Quit"),
        ], "quit" if engine.scanned else "scan")
        if choice == "scan":
            engine.scan()
            summary(engine)
        elif choice == "repair":
            # available before a scan too: an offline disk or a locked volume has to be dealt with first
            if not engine.scanned:
                ui.say("No scan yet: only disk online, BitLocker unlock and source check make sense now.")
                with ctx.case.section("disks", "Disks, partitions and volumes"):
                    from .core import winapi
                    ctx.inventory.update(disks=winapi.disks(), volumes=winapi.volumes())
            engine.module("repair", "run_menu")
            engine.module("assistant", "collect")
            engine.report()
        elif choice in ("assistant", "answers", "bundle", "drivers", "device") and not engine.scanned:
            ui.say("Run the scan first: nothing is known about the target yet.")
        elif choice == "assistant":
            engine.suggestions(refresh=True)
            engine.module("assistant", "show")
            engine.report()
        elif choice == "device":
            engine.module("device", "edit_settings")
        elif choice == "drivers":
            engine.module("drivers", "run_menu")
            engine.report()
        elif choice == "answers":
            from .modules import discovery
            ctx.options.pop("answers", None)
            with ctx.case.section("operator", "Not yet established (asked from the operator)") as sec:
                sec.data = discovery.ask_operator(ctx)
                ctx.case.data["operator_answers"] = sec.data
            engine.suggestions(refresh=True)
            engine.report()
        elif choice == "bundle":
            ui.say("Bundle: %s" % engine.bundle())
        else:
            return


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    args = parse_args(argv)
    if args.version:
        print("RecoveryKit %s (Python %s, %s)" % (__version__, sys.version.split()[0], sys.executable))
        return 0
    if args.decode_id:
        from .modules import device
        ddir = os.path.join(os.path.dirname(os.path.abspath(args.out)) if args.out else KIT_ROOT, "devices")
        for seg in device.decode(ddir, args.decode_id):
            print("%-4s %s  %s" % (seg["segment"], seg["code"], seg["detail"] or seg["value"] or
                                   ("not readable" if seg["code"] == device.UNKNOWN else "code not in components.json")))
        return 0
    if args.ctl is not None:
        from . import net
        return net.ctl(KIT_ROOT, args.ctl, pin=args.pin)
    if args.server:
        from . import net
        store = os.path.abspath(args.store) if args.store else os.path.join(KIT_ROOT, "cases", "_server")
        return net.run_server(KIT_ROOT, args.bind, args.port or 8765, store, args.intake)

    headless = args.auto or args.serve or bool(args.connect)
    ui = UI(auto=headless)
    stamp = log.stamp()
    mirror = log.add_temp_mirror(stamp) if envmod.kind() == "windows" else None
    LOG.info("%s", start_line(args))
    if sys.maxsize <= 2**32:
        ui.say("RecoveryKit needs 64-bit Python (WinRE has no 32-bit support).")
        return 2
    if args.connect and not args.token:
        ui.say("--connect needs --token <agent token of the server>.")
        return 2
    out_root = pick_out_root(args, ui)
    if not out_root:
        ui.say("No writable location for case output. Nothing was done.")
        return 2
    if args.wipe_case:
        return wipe_case(out_root, args.wipe_case, UI(auto=args.auto))

    from .engine import Engine
    answers = {}
    for kv in args.answer:
        k, _, v = kv.partition("=")
        answers[k.strip()] = v.strip()
    engine = Engine(KIT_ROOT, out_root, ui, dry_run=args.dry_run, options={
        "chkdsk": args.chkdsk, "ticket": args.ticket if args.ticket is not None else ("" if headless else None),
        "target": args.target, "target_path": args.target_path, "answers": answers})
    engine.allow_repairs = args.allow_repairs
    engine.allow_remote_repairs = args.allow_remote_repairs
    env, case = engine.ctx.env, engine.ctx.case
    rc = 0
    try:
        ui.say("RecoveryKit %s  -  %s, %s firmware, administrator: %s" % (
            __version__, env["kind"], env["firmware"], "yes" if env["admin"] else "NO"))
        ui.say("Scanning and collecting are read-only. Repairs are separate and each one asks first.")
        ui.say("Everything is logged to %s" % case.dir + (" and %s" % mirror if mirror else ""))
        if engine.cfg_error:
            ui.say("WARNING: " + engine.cfg_error)
        if args.dry_run:
            ui.say("DRY RUN: repair commands will be shown and logged, never executed.")
        if not env["admin"]:
            ui.say("NOT running as administrator: BCD, BitLocker and several logs will be reported as unreadable.")
        for name, st in case.data["tools_manifest"].items():
            if st != "ok":
                ui.say("WARNING: tools/%s: %s" % (name, st))
        if args.scan or args.auto:
            engine.scan()
            summary(engine)
            engine.module("assistant", "show")
        if args.serve:
            from . import net
            net.serve_local(engine, args.port or 8766)
        elif args.connect:
            from . import net
            net.connect(engine, args.connect, args.token, pin=args.pin, minutes=args.session_minutes)
        elif not (args.scan or args.auto):
            menu(engine)
        if args.bundle:
            ui.say("Bundle: %s" % engine.bundle())
    except KeyboardInterrupt:
        ui.say("Interrupted by the operator.")
        rc = 130
    except Exception as e:  # noqa: BLE001
        LOG.critical("FATAL |\n%s", traceback.format_exc())
        ui.say("Unexpected error: %s: %s. Details are in debug.log in %s" % (type(e).__name__, e, case.dir))
        rc = 1
    finally:
        LOG.info("END   | exit code %s after %.0fs", rc, time.monotonic() - _T0)
        engine.close()
    return rc


_T0 = time.monotonic()

if __name__ == "__main__":
    sys.exit(main())
