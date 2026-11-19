"""Shared objects handed to every module: Ctx, Target and RegView."""
import os
import struct
import winreg
from dataclasses import dataclass, field

from . import regf

LCID = {"0409": "en-US", "0809": "en-GB", "0427": "lt-LT", "0419": "ru-RU", "0415": "pl-PL", "0407": "de-DE",
        "040c": "fr-FR", "0426": "lv-LV", "0425": "et-EE", "0410": "it-IT", "0c0a": "es-ES", "0422": "uk-UA"}


_HIVE_ERRORS = (regf.HiveError, struct.error, MemoryError, ValueError, OverflowError, RecursionError,
                IndexError)


TRUNCATED_NOTE = "more than %d entries: only the first %d were read"


class ChildList(list):
    """Result of RegView.children(); `truncated` is True when the cap cut the enumeration short."""
    truncated = False


class RegView:
    """Read-only view of a Windows install's SOFTWARE and SYSTEM hives.

    Offline install: parses the hive files directly (never reg load).
    Running Windows: reads HKLM through winreg with KEY_READ.
    """

    def __init__(self, windir, online):
        self.windir, self.online = windir, online
        self._hives = {}
        self.errors = {}   # hive name -> reason it could not be opened
        self.dirty = {}    # hive name -> True if the file was not cleanly flushed
        self.notes = {}    # hive name -> [reason a read was truncated or cut short]

    def _hive(self, name):
        if name not in self._hives:
            path = os.path.join(self.windir, "System32", "config", name)
            try:
                h = regf.Hive(path)
                self.dirty[name] = h.dirty
                self._hives[name] = h
            except (OSError, *_HIVE_ERRORS) as e:
                self.errors[name] = "%s: %s" % (type(e).__name__, e)
                self._hives[name] = None
        return self._hives[name]

    def _note(self, hive, e):
        self.errors.setdefault(hive, "%s: %s" % (type(e).__name__, e))

    def get(self, hive, path, name, default=None):
        if self.online:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive + "\\" + path, 0, winreg.KEY_READ) as k:
                    return winreg.QueryValueEx(k, name)[0]
            except OSError:
                return default
        h = self._hive(hive)
        try:
            return h.get(path, name, default) if h else default
        except _HIVE_ERRORS as e:
            self._note(hive, e)
            return default

    def subkeys(self, hive, path):
        if self.online:
            out = []
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive + "\\" + path, 0, winreg.KEY_READ) as k:
                    i = 0
                    while True:
                        try:
                            out.append(winreg.EnumKey(k, i))
                        except OSError:
                            break
                        i += 1
            except OSError:
                pass
            return out
        h = self._hive(hive)
        try:
            k = h.open(path) if h else None
            return k.subkey_names() if k else []
        except _HIVE_ERRORS as e:
            self._note(hive, e)
            return []

    def values(self, hive, path):
        """All values of a key as {name: value}; {} if the key is absent or unreadable."""
        if self.online:
            out = {}
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive + chr(92) + path, 0, winreg.KEY_READ) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        out[name] = val
                        i += 1
            except OSError:
                pass
            return out
        h = self._hive(hive)
        try:
            k = h.open(path) if h else None
            vals = k.values() if k else {}
            if h:
                self._sync_notes(hive, h)
            return vals
        except _HIVE_ERRORS as e:
            self._note(hive, e)
            return {}

    def _sync_notes(self, hive, h):
        lst = self.notes.setdefault(hive, [])
        for n in h.notes:
            if n not in lst and len(lst) < 20:
                lst.append(n)

    def children(self, hive, path, max_children=5000):
        """[(child name, {value name: value})] of the subkeys of a key, in one pass.

        Offline: the subkey list is walked once and each child is read by offset. Online: winreg
        EnumKey plus the values of each child. At most `max_children` are returned; when there are
        more, the list's `truncated` is True and TRUNCATED_NOTE is added to self.notes[hive]."""
        out = ChildList()
        if self.online:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive + "\\" + path, 0, winreg.KEY_READ) as k:
                    i = 0
                    while True:
                        try:
                            name = winreg.EnumKey(k, i)
                        except OSError:
                            break
                        if len(out) >= max_children:
                            out.truncated = True
                            break
                        out.append((name, self.values(hive, path + "\\" + name)))
                        i += 1
            except OSError:
                pass
        else:
            h = self._hive(hive)
            try:
                key = h.open(path) if h else None
                if key:
                    for k in key.children():
                        if len(out) >= max_children:
                            out.truncated = True
                            break
                        try:
                            vals = k.values()
                        except regf.HiveError:
                            vals = {}
                        out.append((k.name, vals))
            except _HIVE_ERRORS as e:
                self._note(hive, e)
            if h:
                self._sync_notes(hive, h)
        if out.truncated:
            note = TRUNCATED_NOTE % (max_children, max_children)
            if note not in self.notes.setdefault(hive, []):
                self.notes[hive].append(note)
        return out

    def exists(self, hive, path):
        if self.online:
            try:
                winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive + "\\" + path, 0, winreg.KEY_READ))
                return True
            except OSError:
                return False
        h = self._hive(hive)
        try:
            return bool(h and h.open(path))
        except _HIVE_ERRORS as e:
            self._note(hive, e)
            return False

    def control_set(self):
        """Name of the control set key under SYSTEM to read (offline hives have no CurrentControlSet)."""
        if self.online:
            return "CurrentControlSet"
        cur = self.get("SYSTEM", "Select", "Current")
        return "ControlSet%03d" % cur if isinstance(cur, int) else "ControlSet001"

    def close(self):
        for h in self._hives.values():
            if h:
                h.close()
        self._hives = {}


@dataclass
class Target:
    root: str                 # volume root: "W:\\" or "\\\\?\\Volume{guid}\\" when it has no letter
    windir: str               # root + "Windows"
    online: bool              # True if this is the running Windows
    letter: object            # "W" or None
    volume: dict              # winapi.volumes() entry
    disk: dict                # winapi.disk() entry, or None if unknown
    partition: dict           # partition entry on that disk, or None
    info: dict = field(default_factory=dict)   # see modules/discovery.install_info()
    reg: RegView = None


@dataclass
class Ctx:
    kit_root: str
    cfg: dict
    env: dict
    case: object              # core.case.Case
    ui: object                # core.ui.UI
    runner: object            # core.runner.Runner
    options: dict = field(default_factory=dict)   # CLI switches: chkdsk, ticket, target, ...
    inventory: dict = field(default_factory=dict)  # {"disks": [...], "volumes": [...], "installs": [...]}
    target: Target = None
