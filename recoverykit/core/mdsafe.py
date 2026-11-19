"""Escaping for text that ends up in Markdown (report.md, devices/index.md).

Everything read from the inspected disk, the operator, a remote client or a log
is attacker-controlled; Obsidian renders HTML, links, embeds and code blocks.
"""
import re

_CTL = re.compile("[" + chr(0) + "-" + chr(31) + chr(127) + chr(0x85) + chr(0x2028) + chr(0x2029) + "]")
_SPACES = re.compile(" {2,}")
_SPECIAL = re.compile(r"([\\`*_\[\]<>|#!~$=^{}])")
_LEAD = re.compile(r"^(?:[-+](?=\s|$)|>|\d+[.)](?=\s|$))")


def _fold(value, limit):
    s = _CTL.sub(" ", str(value))
    s = _SPACES.sub(" ", s).strip()
    if limit and len(s) > limit:
        s = s[:max(limit - 3, 0)].rstrip() + "..."
    return s


def text(value, limit=300, empty=""):
    """Prose / table cell text: one line, Markdown-significant characters backslash-escaped."""
    if value is None:
        return empty
    s = _fold(value, limit)
    if not s:
        return empty
    s = _SPECIAL.sub(lambda m: "\\" + m.group(1), s).replace("://", ":\\//")
    if _LEAD.match(s):
        s = "\\" + s
    return s


def code(value, limit=300, empty=""):
    """Inline code span, safe inside a table: no backtick or pipe can end the span or the cell."""
    if value is None:
        return empty
    s = _fold(value, limit).replace("`", "'").replace("|", "/")
    if not s:
        return empty
    return "`%s`" % s
