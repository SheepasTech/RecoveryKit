"""TLS with the control host as certificate authority (ADR 0020).

Every test uses TEMP folders as the CA folder: the real %LOCALAPPDATA%\\ITwork\\CA is never touched.
Needs PowerShell (Windows PowerShell 5.1 and/or PowerShell 7); the whole module is skipped without it.
"""
import contextlib
import datetime
import hashlib
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from recoverykit import net, tlsca
from recoverykit.engine import API
from tests import test_net

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "New-ItworkCertificates.ps1")
PS5 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
PS5 = PS5 if os.path.isfile(PS5) else None
PS7 = shutil.which("pwsh")
PS = PS5 or PS7

_tmp = None
F = {}          # shared fixture paths, built once


def issue(ps, ca_dir, out_dir=None, *extra):
    args = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", SCRIPT, "-CaDir", ca_dir]
    args += ["-OutDir", out_dir] if out_dir else ["-CaOnly"]
    r = subprocess.run(args + list(extra), capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
    return r


def issue_ok(ps, ca_dir, out_dir=None, *extra):
    r = issue(ps, ca_dir, out_dir, *extra)
    assert r.returncode == 0, "exit %s\n%s\n%s" % (r.returncode, r.stdout, r.stderr)
    return r


def sha(path):
    return tlsca.cert_info(path)["sha256"]


def setUpModule():
    global _tmp
    if not PS:
        raise unittest.SkipTest("no PowerShell (powershell.exe or pwsh) found: the certificate script cannot run")
    _tmp = tempfile.mkdtemp(prefix="rk-tls-test-")
    F["ca"] = os.path.join(_tmp, "ca")
    F["out"] = os.path.join(_tmp, "out-localhost")
    issue_ok(PS, F["ca"], F["out"], "-DnsName", "localhost", "-IpAddress", "127.0.0.1")
    F["ca_cert"] = os.path.join(F["ca"], "ca-cert.pem")
    F["cert"], F["key"] = os.path.join(F["out"], "server-cert.pem"), os.path.join(F["out"], "server-key.pem")
    # a certificate for the name localhost only (the IP in it is a dummy): 127.0.0.1 must not verify against it
    F["out_name"] = os.path.join(_tmp, "out-name-only")
    issue_ok(PS, F["ca"], F["out_name"], "-DnsName", "localhost", "-IpAddress", "10.255.255.1")
    # a second, unrelated CA
    F["ca2"] = os.path.join(_tmp, "ca2")
    issue_ok(PS, F["ca2"])
    F["ca2_cert"] = os.path.join(F["ca2"], "ca-cert.pem")


def tearDownModule():
    if _tmp:
        shutil.rmtree(_tmp, ignore_errors=True)


class Script(unittest.TestCase):
    def test_files_and_pem(self):
        for f in ("ca-cert.pem", "ca-key.pem", "README.txt", "issued.log"):
            self.assertTrue(os.path.isfile(os.path.join(F["ca"], f)), f)
        with open(os.path.join(F["ca"], "ca-key.pem")) as f:
            self.assertTrue(f.read().startswith("-----BEGIN PRIVATE KEY-----"))
        with open(F["cert"]) as f:
            self.assertEqual(f.read().count("-----BEGIN CERTIFICATE-----"), 2)          # leaf + CA
        ssl.create_default_context(cafile=F["ca_cert"])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(F["cert"], F["key"])
        info = tlsca.cert_info(F["cert"])
        self.assertEqual((info["dns"], info["ip"]), (["localhost"], ["127.0.0.1"]))
        self.assertGreater(info["not_after"], datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=300))
        with open(os.path.join(F["ca"], "README.txt")) as f:
            self.assertIn("NEVER copy it to a USB stick", f.read())

    def test_second_run_reuses_the_ca_and_force_never_recreates_it(self):
        out = os.path.join(_tmp, "out-reuse")
        ca_before = sha(F["ca_cert"])
        issue_ok(PS, F["ca"], out, "-DnsName", "localhost", "-IpAddress", "127.0.0.1")
        first = tlsca.cert_info(os.path.join(out, "server-cert.pem"))
        c1 = open(os.path.join(out, "server-cert.pem")).read()
        r = issue_ok(PS, F["ca"], out, "-DnsName", "localhost", "-IpAddress", "127.0.0.1")        # no -Force
        self.assertIn("already exists", r.stdout)
        self.assertEqual(open(os.path.join(out, "server-cert.pem")).read(), c1)
        r = issue_ok(PS, F["ca"], out, "-DnsName", "localhost", "-IpAddress", "127.0.0.1", "-Force")
        self.assertIn("CA reused", r.stdout)
        self.assertNotEqual(open(os.path.join(out, "server-cert.pem")).read(), c1)               # a new leaf
        self.assertEqual(sha(F["ca_cert"]), ca_before)
        self.assertIn(ca_before, r.stdout)
        self.assertEqual(tlsca.cert_info(os.path.join(out, "server-cert.pem"))["sha256"] == first["sha256"], False)
        with open(os.path.join(F["ca"], "issued.log")) as f:
            self.assertGreaterEqual(len(f.read().strip().splitlines()), 3)

    def test_half_a_ca_is_refused(self):
        d = os.path.join(_tmp, "half-ca")
        os.makedirs(d)
        shutil.copy(F["ca_cert"], d)
        r = issue(PS, d, os.path.join(_tmp, "out-half"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Half a CA", r.stderr)

    def test_bad_names_are_refused(self):
        r = issue(PS, F["ca"], os.path.join(_tmp, "out-bad"), "-DnsName", "bad name;calc", "-IpAddress", "127.0.0.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Not a valid DNS name", r.stderr)

    @unittest.skipUnless(PS5 and PS7, "needs both powershell.exe and pwsh")
    def test_ca_from_one_runtime_is_usable_by_the_other(self):
        for first, second in ((PS5, PS7), (PS7, PS5)):
            ca = os.path.join(_tmp, "cross-ca-%s" % os.path.basename(first))
            issue_ok(first, ca)
            out = os.path.join(_tmp, "cross-out-%s" % os.path.basename(second))
            r = issue_ok(second, ca, out, "-DnsName", "localhost", "-IpAddress", "127.0.0.1")
            self.assertIn("CA reused", r.stdout)
            self._handshake(os.path.join(ca, "ca-cert.pem"), os.path.join(out, "server-cert.pem"),
                            os.path.join(out, "server-key.pem"))

    def test_rsa_fallback_works(self):
        ca, out = os.path.join(_tmp, "rsa-ca"), os.path.join(_tmp, "rsa-out")
        issue_ok(PS, ca, out, "-DnsName", "localhost", "-IpAddress", "127.0.0.1", "-Algorithm", "RSA")
        self._handshake(os.path.join(ca, "ca-cert.pem"), os.path.join(out, "server-cert.pem"),
                        os.path.join(out, "server-key.pem"))

    def _handshake(self, ca, cert, key):
        srv = net.Server(os.path.join(_tmp, "hskit"), os.path.join(_tmp, "hsstore"), None, say=lambda m: None)
        url = srv.start("127.0.0.1", 0, cert, key, tls=True)
        try:
            self.assertEqual(net._request(url + "/", ca_file=ca)[0], 200)
        finally:
            srv.stop()


class Tlsca(unittest.TestCase):
    def test_host_names_and_ips(self):
        names, ips = tlsca.host_names_and_ips("127.0.0.1")
        self.assertIn("localhost", names)
        self.assertIn("127.0.0.1", ips)
        self.assertTrue(all(tlsca.NAME_RE.match(n) for n in names))

    def test_needs_issue(self):
        self.assertEqual(tlsca.needs_issue(F["cert"], F["key"], ["localhost"], ["127.0.0.1"]), (False, ""))
        self.assertEqual(tlsca.needs_issue(F["cert"], F["key"], ["localhost"], ["127.0.0.1"], ca_cert_path=F["ca_cert"]),
                         (False, ""))
        need, why = tlsca.needs_issue(F["cert"], F["key"], ["localhost", "otherhost"], ["127.0.0.1"])
        self.assertTrue(need)
        self.assertIn("otherhost", why)
        need, why = tlsca.needs_issue(F["cert"], F["key"], ["localhost"], ["127.0.0.1", "10.9.9.9"])
        self.assertTrue(need)
        self.assertIn("10.9.9.9", why)
        self.assertTrue(tlsca.needs_issue(F["cert"], F["key"], ["localhost"], ["127.0.0.1"], min_days=400)[0])
        self.assertTrue(tlsca.needs_issue(F["cert"], F["key"] + ".missing", ["localhost"], ["127.0.0.1"])[0])
        # issued by another CA than the one given
        need, why = tlsca.needs_issue(F["cert"], F["key"], ["localhost"], ["127.0.0.1"], ca_cert_path=F["ca2_cert"])
        self.assertTrue(need)
        self.assertIn("CA", why)

    def test_cert_expiring_soon_needs_issue(self):
        out = os.path.join(_tmp, "out-1day")
        issue_ok(PS, F["ca"], out, "-DnsName", "localhost", "-IpAddress", "127.0.0.1", "-Days", "1")
        need, why = tlsca.needs_issue(os.path.join(out, "server-cert.pem"), os.path.join(out, "server-key.pem"),
                                      ["localhost"], ["127.0.0.1"])
        self.assertTrue(need)
        self.assertIn("expires", why)

    def test_ensure_server_cert_issues_once(self):
        kit = os.path.join(_tmp, "kit-ensure")
        os.makedirs(kit)
        shutil.copy(SCRIPT, kit)
        ca = os.path.join(_tmp, "ca-ensure")
        cert, key, ca_cert, msg = tlsca.ensure_server_cert(kit, ca, bind_ip="127.0.0.1")
        self.assertTrue(msg.startswith("Issued"), msg)
        self.assertEqual(os.path.dirname(cert), os.path.join(kit, "config"))
        self.assertEqual(ca_cert, os.path.join(os.path.abspath(ca), "ca-cert.pem"))
        info = tlsca.cert_info(cert)
        self.assertIn("127.0.0.1", info["ip"])
        self.assertIn("localhost", info["dns"])
        first = open(cert).read()
        self.assertTrue(tlsca.ensure_server_cert(kit, ca, bind_ip="127.0.0.1")[3].endswith("is current."))
        self.assertEqual(open(cert).read(), first)

    def test_ensure_server_cert_without_script_raises_and_server_refuses(self):
        kit = os.path.join(_tmp, "kit-noscript")
        os.makedirs(kit)
        with self.assertRaises(tlsca.TlsError):
            tlsca.ensure_server_cert(kit, os.path.join(_tmp, "ca-noscript"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = net.run_server(kit, "127.0.0.1", 0, os.path.join(_tmp, "store-noscript"), None,
                                ca_dir=os.path.join(_tmp, "ca-noscript"))
        self.assertEqual(rc, 2)
        self.assertIn("--no-tls", out.getvalue())
        self.assertFalse(os.path.exists(os.path.join(kit, "config", "token-server.json")))     # nothing was started


class Https(test_net.Base):
    def setUp(self):
        super().setUp()
        self.msgs = []
        self.kit = os.path.join(self.tmp, "serverkit")
        os.makedirs(os.path.join(self.kit, "config"))
        self.server = net.Server(self.kit, os.path.join(self.tmp, "store"), None, say=self.msgs.append)
        self.url = self.server.start("127.0.0.1", 0, F["cert"], F["key"], tls=True)
        self.addCleanup(self.server.stop)
        self.port = self.server.httpd.server_address[1]
        self.op = {"Authorization": "Bearer " + self.server.tokens["operator_token"], "X-RK-Operator": "alice",
                   "Content-Type": "application/json"}

    def api(self, method, path, body=None, url=None, ca=None):
        data = json.dumps(body).encode() if body is not None else b""
        status, headers, out = net._request((url or self.url) + API + path, method, data,
                                            dict(self.op, **{"Content-Length": str(len(data))}), 60,
                                            ca_file=ca or F["ca_cert"])
        return status, (json.loads(out) if headers.get("Content-Type", "").startswith("application/json") else out)

    def start_agent(self, url=None, **kw):
        got, stop, result = {}, threading.Event(), {}

        def run():
            try:
                result["reason"] = net.connect(self.engine, url or self.url, self.server.tokens["agent_token"],
                                               minutes=5, stop=stop, on_code=lambda a, c: got.update(id=a, code=c), **kw)
            except Exception as e:  # noqa: BLE001
                result["error"] = e
        t = threading.Thread(target=run)
        t.start()
        for _ in range(100):
            if got or result:
                break
            time.sleep(0.05)
        self.addCleanup(lambda: (stop.set(), t.join(15)))
        return got, result, t

    def test_server_reports_https_and_chain_verifies(self):
        self.assertTrue(self.url.startswith("https://127.0.0.1:"))
        self.assertTrue(self.server.tls)
        ctx = ssl.create_default_context(cafile=F["ca_cert"])
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname="127.0.0.1") as t:
                self.assertEqual(hashlib.sha256(t.getpeercert(True)).hexdigest(), sha(F["cert"]))
                self.assertEqual(t.version()[:3], "TLS")

    def test_full_agent_session_over_https_with_the_ca_file(self):
        got, result, t = self.start_agent(ca_file=F["ca_cert"])
        self.assertNotIn("error", result)
        aid = got["id"]
        self.assertEqual(self.api("POST", "/agents/%s/pair" % aid, {"code": got["code"]}), (200, {"paired": True}))
        status, st = self.api("GET", "/agents/%s/api/status" % aid)
        self.assertEqual((status, st["scanned"]), (200, False))
        self.assertEqual(self.api("POST", "/agents/%s/revoke" % aid), (200, {"revoked": True}))
        t.join(20)
        self.assertEqual(result.get("reason"), "revoked by the server")

    def test_default_ca_file_is_config_ca_cert_pem_of_the_kit(self):
        self.assertEqual(self.engine.kit_root, test_net.ROOT)
        # the real kit's config/ca-cert.pem is not touched: a fake engine root is used instead
        fake = os.path.join(self.tmp, "stickkit")
        os.makedirs(os.path.join(fake, "config"))
        shutil.copy(F["ca_cert"], os.path.join(fake, "config", "ca-cert.pem"))
        self.engine.kit_root = fake
        got, result, t = self.start_agent()
        self.assertNotIn("error", result)
        self.assertTrue(got)

    def test_wrong_ca_fails_with_a_clear_message_and_sends_nothing(self):
        got, result, t = self.start_agent(ca_file=F["ca2_cert"])
        t.join(10)
        err = result.get("error")
        self.assertIsInstance(err, net.TlsError)
        msg = str(err)
        self.assertNotIn("\n", msg)
        for word in ("different CA", "not in the server certificate", "clock", time.strftime("%Y-%m-%d")):
            self.assertIn(word, msg)
        self.assertEqual(self.api("GET", "/agents"), (200, []))                    # no hello ever reached the server

    def test_https_without_ca_or_pin_is_refused(self):
        fake = os.path.join(self.tmp, "emptykit")
        os.makedirs(fake)
        self.engine.kit_root = fake
        got, result, t = self.start_agent()
        t.join(10)
        self.assertIsInstance(result.get("error"), net.TlsError)
        self.assertIn("no CA certificate on this stick", str(result["error"]))
        self.assertEqual(self.api("GET", "/agents"), (200, []))
        with self.assertRaises(net.TlsError):
            net._request(self.url + "/")

    def test_names_and_addresses(self):
        port = self.port
        self.assertEqual(self.api("GET", "/status", url="https://localhost:%d" % port)[0], 200)
        self.assertEqual(self.api("GET", "/status", url="https://127.0.0.1:%d" % port)[0], 200)
        # a certificate that lists localhost only (no 127.0.0.1): connecting by address must fail verification
        srv = net.Server(os.path.join(self.tmp, "kit2"), os.path.join(self.tmp, "store2"), None, say=lambda m: None)
        srv.start("127.0.0.1", 0, os.path.join(F["out_name"], "server-cert.pem"),
                  os.path.join(F["out_name"], "server-key.pem"), tls=True)
        self.addCleanup(srv.stop)
        p2 = srv.httpd.server_address[1]
        self.assertEqual(net._request("https://localhost:%d/" % p2, ca_file=F["ca_cert"])[0], 200)
        with self.assertRaises(net.TlsError) as cm:
            net._request("https://127.0.0.1:%d/" % p2, ca_file=F["ca_cert"])
        self.assertIn("not in the server certificate", str(cm.exception))

    def test_pin_still_works_without_a_ca_file(self):
        fp = sha(F["cert"])
        self.assertEqual(net._request(self.url + "/", pin=fp)[0], 200)
        self.assertEqual(net._request(self.url + "/", pin=fp.upper())[0], 200)
        with self.assertRaises(ConnectionError):
            net._request(self.url + "/", pin="00" * 32)
        got, result, t = self.start_agent(pin=fp)
        self.assertNotIn("error", result)
        self.assertTrue(got)

    def test_ctl_uses_the_ca_dir_and_ca_flag(self):
        out = []
        rc = net.ctl(self.kit, ["--url", self.url, "--token", self.server.tokens["operator_token"], "agents"], out.append,
                     ca_dir=F["ca"])
        self.assertEqual(rc, 0, out)
        out = []
        rc = net.ctl(self.kit, ["--url", self.url, "--token", self.server.tokens["operator_token"], "--ca", F["ca2_cert"],
                                "agents"], out.append)
        self.assertEqual(rc, 1)
        self.assertIn("cannot trust the server", out[0])
        out = []
        rc = net.ctl(self.kit, ["--url", self.url, "--token", self.server.tokens["operator_token"], "agents"], out.append,
                     ca_dir=os.path.join(self.tmp, "no-such-ca"))        # no CA anywhere: refused, not unverified
        self.assertEqual(rc, 1)
        self.assertIn("no CA certificate", out[0])

    def test_failed_handshake_is_one_log_line_and_does_not_disturb_others(self):
        with self.assertLogs("rk", level="INFO") as cm:
            for junk in (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"\x16\x03\x01\x00\x05garbage", b""):
                with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
                    if junk:
                        s.sendall(junk)
                    s.settimeout(5)
                    with contextlib.suppress(OSError):
                        s.recv(100)
            self.assertEqual(self.api("GET", "/status")[0], 200)          # a good client right after
            time.sleep(0.3)
        lines = [m for m in cm.output if "failed" in m and "HTTP" in m]
        self.assertGreaterEqual(len(lines), 2)
        self.assertTrue(all("\n" not in m for m in lines))
        self.assertTrue(any("TLS handshake" in m for m in lines))

    def test_200_tls_connections_in_sequence_leave_no_threads_or_sockets_behind(self):
        self.assertEqual(self.api("GET", "/status")[0], 200)
        time.sleep(0.3)
        baseline = threading.active_count()
        for i in range(200):
            status = net._request(self.url + "/", ca_file=F["ca_cert"])[0]
            self.assertEqual(status, 200, i)
        for _ in range(100):                                          # handler threads end when the client has closed
            if threading.active_count() <= baseline:
                break
            time.sleep(0.1)
        self.assertLessEqual(threading.active_count(), baseline)
        self.assertEqual(self.api("GET", "/status")[0], 200)          # and the server still answers
        # a failed handshake closes its socket too: junk, then a good request
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(b"GET / HTTP/1.1\r\n\r\n")
            s.settimeout(5)
            with contextlib.suppress(OSError):
                s.recv(100)
        self.assertEqual(self.api("GET", "/status")[0], 200)
        for _ in range(100):
            if threading.active_count() <= baseline:
                break
            time.sleep(0.1)
        self.assertLessEqual(threading.active_count(), baseline)


class InstallToUsb(unittest.TestCase):
    def test_only_the_ca_certificate_reaches_the_stick(self):
        dest = os.path.join(_tmp, "stick", "ITWORK", "RecoveryKit")
        r = subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", os.path.join(ROOT, "Install-ToUsb.ps1"),
                            "-Destination", dest, "-CaDir", F["ca"]],
                           capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:] + r.stderr[-1500:])
        got = os.path.join(dest, "config", "ca-cert.pem")
        self.assertTrue(os.path.isfile(got))
        with open(got, "rb") as a, open(F["ca_cert"], "rb") as b:
            self.assertEqual(a.read(), b.read())
        self.assertIn("CA certificate copied", r.stdout)
        found = []
        for root, _, files in os.walk(dest):
            found += [f for f in files if f in ("ca-key.pem", "server-key.pem", "server-cert.pem", "token-server.json")
                      or f.startswith("token")]
        self.assertEqual(found, [])

    def _install(self, dest):
        return subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", os.path.join(ROOT, "Install-ToUsb.ps1"),
                               "-Destination", dest, "-CaDir", F["ca"]],
                              capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)

    def test_no_purge_into_a_folder_that_is_not_a_kit_but_purge_into_a_kit(self):
        dest = os.path.join(_tmp, "stick2", "ITWORK", "RecoveryKit")
        keep = os.path.join(dest, "python", "keep.txt")
        os.makedirs(os.path.dirname(keep))
        with open(keep, "w") as f:
            f.write("not ours")
        r = self._install(dest)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:] + r.stderr[-1500:])
        self.assertTrue(os.path.isfile(keep), "an unrelated python/keep.txt must survive a copy into a non-kit folder")
        self.assertIn("without /PURGE", r.stdout)
        self.assertIn("not a RecoveryKit", r.stdout)
        self.assertIn("Interpreter: Python", r.stdout)
        self.assertTrue(os.path.isfile(os.path.join(dest, "run.cmd")))
        self.assertTrue(os.path.isfile(os.path.join(dest, "kit-version.txt")))
        # now it is a kit (run.cmd and kit-version.txt): the second run purges files the source does not have
        r = self._install(dest)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:] + r.stderr[-1500:])
        self.assertNotIn("without /PURGE", r.stdout)
        self.assertFalse(os.path.exists(keep))


if __name__ == "__main__":
    unittest.main()
