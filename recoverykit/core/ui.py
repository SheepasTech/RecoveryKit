"""Plain-text console UI. Works in WinRE's bare console (no ANSI, ASCII only).

Every line shown and every answer typed is logged. Secret answers are logged
as <hidden>.
"""
import sys

from .log import LOG


class UI:
    def __init__(self, auto=False):
        # auto: never wait for input; ask() returns the default, confirm_yes() is always False.
        self.auto = auto
        for s in (sys.stdout, sys.stderr):
            try:
                s.reconfigure(errors="replace")
            except Exception:
                pass

    def say(self, text=""):
        for line in str(text).splitlines() or [""]:
            LOG.info("SCREEN| %s", line)
            print(line, flush=True)

    def raw(self, line):
        """A line of live tool output."""
        LOG.info("TOOL  | %s", line)
        print(line, flush=True)

    def header(self, text):
        self.say()
        self.say("=== %s ===" % text)

    def ask(self, prompt, default="", secret=False):
        LOG.info("PROMPT| %s [default=%r]", prompt, default)
        if self.auto:
            LOG.info("ANSWER| (auto) %r", default)
            return default
        try:
            ans = input("%s%s: " % (prompt, " [%s]" % default if default else "")).strip()
        except EOFError:
            LOG.info("ANSWER| (end of input) %r", default)
            self.auto = True
            return default
        LOG.info("ANSWER| %s", "<hidden>" if secret and ans else repr(ans))
        return ans or default

    def choose(self, title, options, default=None):
        """options: list of (key, label). Returns the chosen key."""
        self.say()
        self.say(title)
        for i, (_, label) in enumerate(options, 1):
            self.say("  %d. %s" % (i, label))
        keys = [k for k, _ in options]
        dflt = str(keys.index(default) + 1) if default in keys else ""
        while True:
            ans = self.ask("Choose 1-%d" % len(options), dflt)
            if ans.isdigit() and 1 <= int(ans) <= len(options):
                return keys[int(ans) - 1]
            if self.auto:
                return default
            self.say("Type a number from the list.")

    def confirm_yes(self, question):
        """True only if the operator types the whole word yes. Never true in auto mode."""
        LOG.info("CONFIRM| %s", question)
        if self.auto:
            LOG.info("ANSWER| (auto) no")
            return False
        try:
            ans = input("%s Type yes to proceed: " % question).strip().lower()
        except EOFError:
            ans = ""
        LOG.info("ANSWER| %r", ans)
        return ans == "yes"
