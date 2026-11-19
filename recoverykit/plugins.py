"""Plugin loader (phase 5). A plugin is a .py file in <kit>/plugins/ with collect(ctx).

Plugins get the same Ctx as built-in modules, so external programs only run
through ctx.runner (allowlist, forbidden list, audit). Before loading, the source
is scanned and refused if it imports process-starting or native-call modules.
This is a guard against mistakes, not a sandbox: only install plugins you trust.
"""
import ast
import importlib.util
import os

from .core.log import LOG

BANNED_MODULES = {"subprocess", "ctypes", "_ctypes", "multiprocessing", "socket", "winreg", "_winapi", "msvcrt",
                  "importlib", "runpy", "pty", "asyncio"}
BANNED_CALLS = {("os", "system"), ("os", "popen"), ("os", "startfile"), ("os", "remove"), ("os", "unlink"),
                ("os", "rmdir"), ("os", "rename"), ("os", "replace"), ("shutil", "rmtree"), ("shutil", "move")}
BANNED_NAMES = {"eval", "exec", "__import__", "compile"}


def check_source(text, filename="<plugin>"):
    """Return a list of reasons the plugin source is refused (empty = acceptable)."""
    try:
        tree = ast.parse(text, filename)
    except SyntaxError as e:
        return ["syntax error: %s" % e]
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in BANNED_MODULES:
                    bad.append("line %d: import %s is not allowed" % (node.lineno, a.name))
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in BANNED_MODULES:
                bad.append("line %d: from %s import is not allowed" % (node.lineno, node.module))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if (node.value.id, node.attr) in BANNED_CALLS:
                bad.append("line %d: %s.%s is not allowed" % (node.lineno, node.value.id, node.attr))
        elif isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            bad.append("line %d: %s is not allowed" % (node.lineno, node.id))
    return bad


def run_all(ctx):
    """Load and run every plugin. Each runs in its own section; failures are recorded, never raised."""
    pdir = os.path.join(ctx.kit_root, "plugins")
    if not os.path.isdir(pdir):
        return
    for name in sorted(os.listdir(pdir)):
        if not name.endswith(".py") or name.startswith("_"):
            continue
        path = os.path.join(pdir, name)
        sec_name = "plugin_" + name[:-3]
        with ctx.case.section(sec_name, "Plugin %s" % name) as sec:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            bad = check_source(text, name)
            if bad:
                sec.set("error", "plugin refused: " + "; ".join(bad))
                continue
            spec = importlib.util.spec_from_file_location("rk_plugin_" + name[:-3], path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if not hasattr(mod, "collect"):
                sec.set("error", "plugin has no collect(ctx)")
                continue
            LOG.info("PLUGIN| running %s", name)
            result = mod.collect(ctx)
            if isinstance(result, dict):
                sec.data = result
