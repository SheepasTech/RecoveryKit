"""Plugin loader (phase 5). A plugin is a .py file in <kit>/plugins/ with collect(ctx).

A plugin is loaded ONLY when plugins/manifest.sha256 lists it with a matching SHA-256 (same line
format as tools/manifest.sha256: "<64 hex>  <file name>", "#" comments). No manifest, not listed or
a changed file: the plugin's section is an error with the reason and the file is never imported.
The bytes that were hashed are the bytes that are compiled (no second read).

Plugins get the same Ctx as built-in modules, so external programs should only run through
ctx.runner (allowlist, forbidden list, audit). check_source additionally refuses obvious
process-starting, native-call, reflection and ctx-tampering constructs.

This is a guard against mistakes plus an integrity check, NOT a sandbox: a plugin that is listed
in the manifest is trusted code and runs with the kit's rights.
"""
import ast
import hashlib
import os
import types

from .core.log import LOG

BANNED_MODULES = {"subprocess", "ctypes", "_ctypes", "multiprocessing", "socket", "winreg", "_winapi", "msvcrt",
                  "importlib", "runpy", "pty", "asyncio", "builtins"}
BANNED_CALLS = {("os", "system"), ("os", "popen"), ("os", "startfile"), ("os", "remove"), ("os", "unlink"),
                ("os", "rmdir"), ("os", "rename"), ("os", "replace"), ("shutil", "rmtree"), ("shutil", "move")}
BANNED_NAMES = {"eval", "exec", "__import__", "compile", "getattr", "setattr", "delattr", "globals", "locals",
                "vars", "builtins"}
CALL_MODULES = {m for m, _ in BANNED_CALLS} | {"builtins"}
PROTECTED_ATTRS = {"repairs_enabled", "confirm_yes", "dry_run", "target_online"}
READ_MODES = ("r", "rb")


def _root_name(node):
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.value if not isinstance(node, ast.Call) else node.func
    return node.id if isinstance(node, ast.Name) else None


def _attr_targets(node):
    """Attribute nodes that are assigned or deleted by this statement."""
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
        targets = [node.target]
    elif isinstance(node, ast.Delete):
        targets = list(node.targets)
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        targets = [node.target]
    elif isinstance(node, ast.withitem):
        targets = [node.optional_vars] if node.optional_vars is not None else []
    else:
        return []
    out = []
    stack = targets
    while stack:
        t = stack.pop()
        if isinstance(t, (ast.Tuple, ast.List)):
            stack.extend(t.elts)
        elif isinstance(t, ast.Starred):
            stack.append(t.value)
        elif isinstance(t, ast.Attribute):
            out.append(t)
    return out


def _open_ok(call):
    """open() is allowed with one positional argument or a literal read mode."""
    if any(k.arg is None or k.arg == "opener" for k in call.keywords) or not call.args and not call.keywords:
        return False
    mode = None
    if len(call.args) >= 2:
        mode = call.args[1]
    for k in call.keywords:
        if k.arg == "mode":
            mode = k.value
    if len(call.args) > 3 or any(isinstance(a, ast.Starred) for a in call.args):
        return False
    if mode is None:
        return True
    return isinstance(mode, ast.Constant) and mode.value in READ_MODES


def check_source(text, filename="<plugin>"):
    """Return a list of reasons the plugin source is refused (empty = acceptable)."""
    try:
        tree = ast.parse(text, filename)
    except (SyntaxError, ValueError) as e:
        return ["syntax error: %s" % e]
    bad = []
    aliases = {}   # local name -> real module, for modules whose calls are banned
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if top in BANNED_MODULES:
                    bad.append("line %d: import %s is not allowed" % (node.lineno, a.name))
                elif top in CALL_MODULES:
                    aliases[a.asname or top] = top
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if top in BANNED_MODULES:
                bad.append("line %d: from %s import is not allowed" % (node.lineno, node.module))
            elif top in CALL_MODULES:
                for a in node.names:
                    if a.name == "*" or (top, a.name) in BANNED_CALLS:
                        bad.append("line %d: from %s import %s is not allowed" % (node.lineno, node.module, a.name))
            elif node.level and not node.module:
                bad.append("line %d: relative import is not allowed" % node.lineno)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                real = aliases.get(node.value.id, node.value.id)
                if (real, node.attr) in BANNED_CALLS:
                    bad.append("line %d: %s.%s is not allowed" % (node.lineno, node.value.id, node.attr))
            if node.attr.startswith("_"):
                bad.append("line %d: access to attribute %s is not allowed" % (node.lineno, node.attr))
        elif isinstance(node, ast.Name):
            if node.id in BANNED_NAMES:
                bad.append("line %d: %s is not allowed" % (node.lineno, node.id))
            elif node.id in aliases and aliases[node.id] == "builtins":
                bad.append("line %d: builtins is not allowed" % node.lineno)
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id == "open" and not _open_ok(node):
                bad.append("line %d: open() is allowed only for reading (one argument, or mode 'r'/'rb')"
                           % node.lineno)
        for t in _attr_targets(node):
            if _root_name(t) == "ctx" or t.attr in PROTECTED_ATTRS:
                bad.append("line %d: assigning to attribute %s of ctx or its parts is not allowed"
                           % (t.lineno, t.attr))
    # open used as a value (open = ..., f = open, map(open, ...)) instead of being called directly
    called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "open" and id(node) not in called:
            bad.append("line %d: open may only be called directly" % node.lineno)
    return bad


def load_manifest(pdir):
    """{file name: sha256 hex} from plugins/manifest.sha256, or None when there is no manifest.
    Raises OSError when it exists but cannot be read."""
    path = os.path.join(pdir, "manifest.sha256")
    if not os.path.isfile(path):
        return None
    out = {}
    from .core.runner import read_manifest_lines
    for line in read_manifest_lines(path):
        parts = line.split()
        if len(parts) < 2 or line.lstrip().startswith("#"):
            continue
        if len(parts[0]) != 64 or any(c not in "0123456789abcdefABCDEF" for c in parts[0]):
            continue                                   # not a SHA-256: the file stays unlisted
        out[" ".join(parts[1:]).lstrip("*")] = parts[0].lower()
    return out


def run_all(ctx):
    """Load and run every listed plugin. Each runs in its own section; failures are recorded, never raised."""
    pdir = os.path.join(ctx.kit_root, "plugins")
    if not os.path.isdir(pdir):
        return
    try:
        manifest, manifest_err = load_manifest(pdir), None
    except OSError as e:
        manifest, manifest_err = None, "plugins/manifest.sha256 cannot be read: %s" % e
    for name in sorted(os.listdir(pdir)):
        if not name.endswith(".py") or name.startswith("_"):
            continue
        path = os.path.join(pdir, name)
        sec_name = "plugin_" + name[:-3]
        with ctx.case.section(sec_name, "Plugin %s" % name) as sec:
            if manifest_err:
                sec.set("error", "plugin refused: " + manifest_err)
                continue
            if manifest is None:
                sec.set("error", "plugin refused: no plugins/manifest.sha256 (plugins load only when listed "
                                 "with their SHA-256)")
                continue
            if name not in manifest:
                sec.set("error", "plugin refused: not listed in plugins/manifest.sha256")
                continue
            with open(path, "rb") as f:
                data = f.read()
            if hashlib.sha256(data).hexdigest() != manifest[name]:
                sec.set("error", "plugin refused: checksum mismatch")
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as e:
                sec.set("error", "plugin refused: not UTF-8 text (%s)" % e)
                continue
            bad = check_source(text, name)
            if bad:
                sec.set("error", "plugin refused: " + "; ".join(bad))
                continue
            mod = types.ModuleType("rk_plugin_" + name[:-3])
            mod.__file__ = path
            exec(compile(text, path, "exec"), mod.__dict__)
            if not hasattr(mod, "collect"):
                sec.set("error", "plugin has no collect(ctx)")
                continue
            LOG.info("PLUGIN| running %s", name)
            result = mod.collect(ctx)
            if isinstance(result, dict):
                sec.data = result
