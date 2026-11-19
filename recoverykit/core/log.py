"""Debug logging. Always on, cannot be switched off.

Everything the kit does goes to the `rk` logger: screen lines, prompts, answers,
commands, exceptions. Files are attached with add_file(); the case attaches
debug.log in its folder, and on a normal Windows a mirror goes to
%TEMP%\\Debug\\RecoveryKit\\<run>\\ like the other ITwork tools.
"""
import logging
import os
import time

LOG = logging.getLogger("rk")
LOG.setLevel(logging.DEBUG)
LOG.propagate = False
_FMT = logging.Formatter("%(asctime)s.%(msecs)03d %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")


def add_file(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    h = logging.FileHandler(path, encoding="utf-8")
    h.setFormatter(_FMT)
    LOG.addHandler(h)
    return h


def remove(handler):
    if handler:
        LOG.removeHandler(handler)
        handler.close()


def add_temp_mirror(stamp):
    """Mirror to %TEMP%\\Debug\\RecoveryKit\\<stamp>\\debug.log. Returns the path or None."""
    tmp = os.environ.get("TEMP") or os.environ.get("TMP")
    if not tmp:
        return None
    path = os.path.join(tmp, "Debug", "RecoveryKit", stamp, "debug.log")
    try:
        add_file(path)
        return path
    except OSError:
        return None


def stamp(fmt="%Y%m%d-%H%M%S"):
    return time.strftime(fmt)
