"""Detect the environment the kit is running in (the host, not the target)."""
import os
import platform
import shutil
import sys
import winreg

from . import winapi

TOOLS = ["dism", "bcdedit", "bcdboot", "bootrec", "reg", "diskpart", "chkdsk", "sfc", "wevtutil",
         "manage-bde", "robocopy", "wmic", "wpeutil", "drvload", "reagentc", "powershell", "pwsh", "ipconfig"]


def _reg(path, name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _key_exists(path):
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ))
        return True
    except OSError:
        return False


def kind():
    """windows, winre, setup or winpe."""
    if not _key_exists(r"SYSTEM\CurrentControlSet\Control\MiniNT"):
        return "windows"
    sysdrive = os.environ.get("SystemDrive", "X:")
    if os.path.exists(sysdrive + r"\sources\recovery\RecEnv.exe"):
        return "winre"
    if os.path.exists(sysdrive + r"\setup.exe") or os.path.exists(sysdrive + r"\sources\setup.exe"):
        return "setup"
    return "winpe"


def detect():
    cv = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    tools = {t: shutil.which(t) for t in TOOLS}
    return {
        "kind": kind(),
        "admin": winapi.is_admin(),
        "firmware": winapi.firmware_type(),
        "system_drive": os.environ.get("SystemDrive", ""),
        "windir": os.environ.get("SystemRoot", ""),
        "arch": platform.machine(),
        "os": {"product": _reg(cv, "ProductName"), "display_version": _reg(cv, "DisplayVersion"),
               "build": _reg(cv, "CurrentBuild"), "ubr": _reg(cv, "UBR"), "edition": _reg(cv, "EditionID")},
        "python": {"version": platform.python_version(), "executable": sys.executable,
                   "bits": 64 if sys.maxsize > 2**32 else 32},
        "powershell": tools.get("powershell") or tools.get("pwsh"),
        "tools": tools,
    }
