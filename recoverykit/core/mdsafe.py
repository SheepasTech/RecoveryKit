"""Escaping for text that ends up in Markdown (report.md, devices/index.md).

Everything read from the inspected disk, the operator, a remote client or a log
is attacker-controlled; Obsidian renders HTML, links, embeds and code blocks.
"""
import re
import unicodedata

_CTL = re.compile("[" + chr(0) + "-" + chr(31) + chr(127) + chr(0x85) + chr(0x2028) + chr(0x2029) + "]")
_SPACES = re.compile(" {2,}")
_SPECIAL = re.compile(r"([\\`*_\[\]<>|#!~$=^{}%])")
_LEAD = re.compile(r"^(?:[-+](?=\s|$)|>|\d+[.)](?=\s|$))")


def _clean_chars(s):
    """Drop format characters (bidi overrides, zero-width, BOM: category Cf) and private-use ones (Co);
    a lone surrogate (Cs) becomes U+FFFD."""
    if s.isascii():
        return s
    out = []
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Co"):
            continue
        out.append(chr(0xFFFD) if cat == "Cs" else ch)
    return "".join(out)


def _fold(value, limit):
    s = _CTL.sub(" ", _clean_chars(str(value)))
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
    if _LEAD.match(s) or s.startswith("---"):      # list item, quote, numbered item, horizontal rule
        s = "\\" + s
    return s


def code(value, limit=300, empty="", table=False):
    """Inline code span, safe inside a table: no backtick can end the span.

    table=True (a span placed in a table cell): `|` is written as a backslash and a pipe (the cell parser removes the backslash
    before the inline text is read, so the command shows with its pipe). table=False leaves `|` alone.
    A value starting with `=` or `$=` would be a Dataview inline query: it gets a leading `'` (visible, so
    the text is still readable). `<%` (Templater) is written `< %`.
    """
    if value is None:
        return empty
    s = _fold(value, limit).replace("`", "'").replace("<%", "< %")
    if table:
        s = s.replace("|", "\\|")
    if not s:
        return empty
    if s.startswith("=") or s.startswith("$="):
        s = "'" + s
    return "`%s`" % s
