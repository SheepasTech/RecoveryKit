"""The browser front end: static checks on the page and that the server serves it without a token."""
import os
import re
import tempfile
import unittest

from recoverykit import net

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "recoverykit", "web", "index.html")

FORBIDDEN = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
             "http://", "https://", "localStorage"]
SERVER_PATHS = {"/status", "/agents", "/cases"}
SERVER_AGENT_VERBS = {"pair", "revoke", "fetch-bundle"}
AGENT_PATHS = {"status", "scan", "report", "suggestions", "repair/steps", "audit", "files", "case"}


def read_page():
    with open(PAGE, "rb") as f:
        return f.read()


class PageStatic(unittest.TestCase):
    def test_forbidden_strings_and_ascii(self):
        raw = read_page()
        raw.decode("ascii")                                   # raises if any non-ASCII byte
        text = raw.decode("ascii")
        for bad in FORBIDDEN:
            self.assertNotIn(bad, text, bad)

    def test_size_script_and_no_external_resources(self):
        raw = read_page()
        text = raw.decode("ascii")
        self.assertLess(len(raw), 120 * 1024)
        self.assertEqual(len(re.findall(r"<script\b", text, re.I)), 1)
        self.assertNotRegex(text, r"(?i)\bsrc\s*=")

    def test_api_paths_exist(self):
        script = re.search(r"<script>(.*)</script>", read_page().decode("ascii"), re.S).group(1)
        srv = set(re.findall(r'\bsrv\(\s*"([^"]+)"', script))
        verbs = set(re.findall(r'\bsrvAgent\(\s*[^,()]+,\s*"([^"]+)"', script))
        agent = {p.rstrip("/") for p in re.findall(r'\bagent\(\s*[^,()]+,\s*"([^"]+)"', script)}
        self.assertEqual(srv, SERVER_PATHS)
        self.assertEqual(verbs, SERVER_AGENT_VERBS)
        self.assertEqual(agent, AGENT_PATHS)

    def test_no_data_driven_href_or_src(self):
        script = re.search(r"<script>(.*)</script>", read_page().decode("ascii"), re.S).group(1)
        self.assertNotRegex(script, r"""setAttribute\(\s*["'](href|src|style|on\w+)["']""")
        for m in re.finditer(r"\.(href|src)\s*=(?!=)\s*([^;\n]*)", script):
            self.assertRegex(m.group(2).strip(), r'^"[^"]*"$', m.group(0))

    def test_every_input_has_label(self):
        text = read_page().decode("ascii")
        for tag in re.findall(r"<input\b[^>]*>", text):
            m = re.search(r'\bid="([^"]+)"', tag)
            self.assertIsNotNone(m, tag)
            self.assertRegex(text, r'<label[^>]*\bfor="%s"' % re.escape(m.group(1)))
        for tag in re.findall(r"<select\b[^>]*>", text):
            m = re.search(r'\bid="([^"]+)"', tag)
            self.assertRegex(text, r'<label[^>]*\bfor="%s"' % re.escape(m.group(1)))

    def test_status_line_is_live_region(self):
        self.assertRegex(read_page().decode("ascii"), r'<div id="statusline"[^>]*aria-live="polite"')


class PageServed(unittest.TestCase):
    def test_served_without_token_api_still_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            kit = os.path.join(tmp, "kit")
            os.makedirs(os.path.join(kit, "config"))
            server = net.Server(kit, os.path.join(tmp, "store"), os.path.join(tmp, "intake"), say=lambda m: None)
            url = server.start("127.0.0.1", 0)
            self.addCleanup(server.stop)
            status, headers, body = net._request(url + "/")
            self.assertEqual(status, 200)
            self.assertTrue(headers.get("Content-Type", "").startswith("text/html"))
            csp = headers.get("Content-Security-Policy", "")
            self.assertIn("default-src 'self'", csp)
            self.assertIn("connect-src 'self'", csp)
            self.assertEqual(body, read_page())
            self.assertEqual(net._request(url + net.API + "/agents")[0], 401)


if __name__ == "__main__":
    unittest.main()
