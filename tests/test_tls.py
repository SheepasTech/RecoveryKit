"""TLS with the control host as certificate authority (ADR 0020).

Every test uses TEMP folders as the CA folder: the real %LOCALAPPDATA%\\ITwork\\CA is never touched.
Needs PowerShell (Windows PowerShell 5.1 and/or PowerShell 7); the whole module is skipped without it.
"""
import contextlib
import datetime
import getpass
import hashlib
import io
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

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


# ------------------------------------------------------------------ round 3
def handshake(ca, cert, key):
    srv = net.Server(os.path.join(_tmp, "hskit3"), os.path.join(_tmp, "hsstore3"), None, say=lambda m: None)
    url = srv.start("127.0.0.1", 0, cert, key, tls=True)
    try:
        return net._request(url + "/", ca_file=ca)[0]
    finally:
        srv.stop()


def runtimes():
    return [p for p in (PS5, PS7) if p]


class ScriptRound3(unittest.TestCase):
    def test_six_parallel_first_runs_make_one_ca_and_every_certificate_verifies_against_it(self):
        for ps in runtimes():
            with self.subTest(runtime=os.path.basename(ps)):
                base = tempfile.mkdtemp(prefix="par-", dir=_tmp)
                ca = os.path.join(base, "ca")                      # does not exist yet: all six start from nothing
                procs = []
                for i in range(6):
                    out = os.path.join(base, "out%d" % i)
                    procs.append(subprocess.Popen(
                        [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", SCRIPT, "-CaDir", ca, "-OutDir", out,
                         "-DnsName", "localhost", "-IpAddress", "127.0.0.1"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL))
                results = [p.communicate(timeout=300) + (p.returncode,) for p in procs]
                for o, e, rc in results:
                    self.assertEqual(rc, 0, o + e)
                self.assertEqual(sum("CA created" in o for o, _, _ in results), 1, [o for o, _, _ in results])
                self.assertTrue(all("CA created" in o or "CA reused" in o or "using it" in o for o, _, _ in results))
                fps = {re.search(r"CA SHA-256:\s+(\w+)", o).group(1) for o, _, _ in results}
                self.assertEqual(fps, {sha(os.path.join(ca, "ca-cert.pem"))})          # all six saw the CA on disk
                for i in range(6):
                    out = os.path.join(base, "out%d" % i)
                    self.assertEqual(handshake(os.path.join(ca, "ca-cert.pem"), os.path.join(out, "server-cert.pem"),
                                               os.path.join(out, "server-key.pem")), 200, i)
                left = [f for _, _, fs in os.walk(base) for f in fs if f.endswith(".tmp")]
                self.assertEqual(left, [])
                with open(os.path.join(ca, "issued.log")) as f:
                    self.assertEqual(len(f.read().strip().splitlines()), 6)

    def test_key_files_are_for_the_current_user_only_and_inheritance_is_off(self):
        for key in (os.path.join(F["ca"], "ca-key.pem"), F["key"]):
            r = subprocess.run(["icacls.exe", key], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(r.stdout.count(":("), 1, r.stdout)           # exactly one access entry ...
            self.assertNotIn("(I)", r.stdout)                              # ... not inherited ...
            self.assertIn(getpass.getuser().lower(), r.stdout.lower())     # ... and it is this user

    def test_reissue_over_a_key_file_with_extra_access_entries_still_ends_owner_only(self):
        # Found in a live run: replacing an existing server-key.pem carried over that file's explicit access
        # entries (the kit's config folder gives SYSTEM and Administrators explicit rights), and removing only
        # the inherited entries left them there, so the server could not start with TLS in the real project.
        for ps in runtimes():
            with self.subTest(runtime=os.path.basename(ps)):
                base = tempfile.mkdtemp(prefix="acl-", dir=_tmp)
                ca, out = os.path.join(base, "ca"), os.path.join(base, "out")
                args = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", SCRIPT, "-CaDir", ca, "-OutDir", out,
                        "-DnsName", "localhost", "-IpAddress", "127.0.0.1"]
                r = subprocess.run(args, capture_output=True, text=True, stdin=subprocess.DEVNULL)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                key = os.path.join(out, "server-key.pem")
                for who in ("*S-1-5-18", "*S-1-5-32-545"):                 # SYSTEM and Users, as explicit entries
                    g = subprocess.run(["icacls.exe", key, "/grant", who + ":(R)"], capture_output=True, text=True,
                                       stdin=subprocess.DEVNULL)
                    self.assertEqual(g.returncode, 0, g.stdout + g.stderr)
                r = subprocess.run(args + ["-Force"], capture_output=True, text=True, stdin=subprocess.DEVNULL)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                a = subprocess.run(["icacls.exe", key], capture_output=True, text=True, stdin=subprocess.DEVNULL)
                self.assertEqual(a.stdout.count(":("), 1, a.stdout)
                self.assertNotIn("(I)", a.stdout)
                self.assertIn(getpass.getuser().lower(), a.stdout.lower())

    def test_certificates_start_a_day_before_issue(self):
        decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
        if decode is None:
            self.skipTest("this Python cannot decode a certificate")
        for path in (F["cert"], F["ca_cert"]):
            nb = ssl.cert_time_to_seconds(decode(path)["notBefore"])
            self.assertGreater(time.time() - nb, 23 * 3600, path)
            self.assertLess(time.time() - nb, 26 * 3600, path)

    def test_ip_addresses_must_be_written_the_usual_way(self):
        for bad in ("10", "192.168.1", "010.0.0.1", "1.2.3", "300.1.1.1", "1.2.3.4.5"):
            r = issue(PS, F["ca"], os.path.join(_tmp, "out-badip"), "-DnsName", "localhost", "-IpAddress", bad)
            self.assertNotEqual(r.returncode, 0, bad)
            self.assertIn("Not an IP address", r.stderr, bad)
        out = os.path.join(_tmp, "out-goodip")
        issue_ok(PS, F["ca"], out, "-DnsName", "localhost", "-IpAddress", "127.0.0.1,192.168.1.10")
        self.assertEqual(tlsca.cert_info(os.path.join(out, "server-cert.pem"))["ip"], ["127.0.0.1", "192.168.1.10"])

    def test_half_a_ca_message_says_which_file_to_delete(self):
        d = os.path.join(_tmp, "half-ca-cert-only")
        os.makedirs(d)
        shutil.copy(F["ca_cert"], d)
        r = issue(PS, d, os.path.join(_tmp, "out-half3"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Half a CA", r.stderr)
        self.assertIn("delete ca-cert.pem", r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(d, "ca-cert.pem")))      # nothing was touched
        self.assertFalse(os.path.exists(os.path.join(d, "ca-key.pem")))

    def test_a_lone_key_file_is_waited_for_30_seconds_then_named(self):
        d = os.path.join(_tmp, "half-ca-key-only")
        os.makedirs(d)
        with open(os.path.join(d, "ca-key.pem"), "w") as f:
            f.write("")
        t0 = time.monotonic()
        r = issue(PS, d, os.path.join(_tmp, "out-half4"))
        self.assertNotEqual(r.returncode, 0)
        self.assertGreater(time.monotonic() - t0, 25)
        self.assertIn("Half a CA", r.stderr)
        self.assertIn("delete ca-key.pem", r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(d, "ca-key.pem")))

    def test_a_ca_folder_on_a_network_share_is_refused_unless_allowed(self):
        r = issue(PS, r"\\rk-no-such-host\share\ca")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("network share", r.stderr)
        self.assertIn("-AllowInsecureCaDir", r.stderr)


class TlscaRound3(unittest.TestCase):
    def kit(self, name, script=True):
        kit = os.path.join(_tmp, name)
        os.makedirs(os.path.join(kit, "config"), exist_ok=True)
        if script:
            shutil.copy(SCRIPT, kit)
        return kit

    def test_a_key_that_does_not_match_the_certificate_is_detected_and_reissued(self):
        self.assertTrue(tlsca.pair_matches(F["cert"], F["key"]))
        other_key = os.path.join(F["out_name"], "server-key.pem")
        self.assertFalse(tlsca.pair_matches(F["cert"], other_key))
        need, why = tlsca.needs_issue(F["cert"], other_key, ["localhost"], ["127.0.0.1"])
        self.assertTrue(need)
        self.assertIn("do not belong together", why)
        kit = self.kit("kit-mismatch")
        shutil.copy(F["cert"], os.path.join(kit, "config", "server-cert.pem"))
        shutil.copy(other_key, os.path.join(kit, "config", "server-key.pem"))
        cert, key, ca_cert, msg = tlsca.ensure_server_cert(kit, os.path.join(_tmp, "ca-mismatch"), bind_ip="127.0.0.1")
        self.assertTrue(msg.startswith("Issued"), msg)
        self.assertIn("do not belong together", msg)
        self.assertTrue(tlsca.pair_matches(cert, key))

    def test_failure_message_is_the_scripts_own_last_error_line(self):
        kit = self.kit("kit-fake-fail", script=False)
        with open(os.path.join(kit, SCRIPT_NAME), "w") as f:
            f.write('param([string]$CaDir,[string]$OutDir,[string]$DnsName,[string]$IpAddress,[switch]$Force)\n'
                    'Write-Host "Runtime: fake"\n'
                    '[Console]::Error.WriteLine("WARNING: something minor")\n'
                    '[Console]::Error.WriteLine("ERROR: disk on fire")\n'
                    'exit 1\n')
        with self.assertRaises(tlsca.TlsError) as cm:
            tlsca.ensure_server_cert(kit, os.path.join(_tmp, "ca-fake-fail"), bind_ip="127.0.0.1")
        msg = str(cm.exception)
        self.assertIn("ERROR: disk on fire", msg)
        self.assertNotIn("Runtime: fake", msg)
        self.assertNotIn("something minor", msg)

    def test_a_warning_from_the_script_is_surfaced_even_on_success(self):
        src = os.path.join(_tmp, "fake-src")
        os.makedirs(src, exist_ok=True)
        shutil.copy(F["ca_cert"], os.path.join(src, "ca-cert.pem"))
        shutil.copy(F["cert"], os.path.join(src, "server-cert.pem"))
        shutil.copy(F["key"], os.path.join(src, "server-key.pem"))
        kit = self.kit("kit-fake-warn", script=False)
        with open(os.path.join(kit, SCRIPT_NAME), "w") as f:
            f.write('param([string]$CaDir,[string]$OutDir,[string]$DnsName,[string]$IpAddress,[switch]$Force)\n'
                    'New-Item -ItemType Directory -Force -Path $CaDir | Out-Null\n'
                    'Copy-Item -LiteralPath (Join-Path $env:RK_FAKE_SRC "ca-cert.pem") -Destination $CaDir -Force\n'
                    'Copy-Item -LiteralPath (Join-Path $env:RK_FAKE_SRC "server-cert.pem") -Destination $OutDir -Force\n'
                    'Copy-Item -LiteralPath (Join-Path $env:RK_FAKE_SRC "server-key.pem") -Destination $OutDir -Force\n'
                    '[Console]::Error.WriteLine("WARNING: could not restrict the permissions of x: icacls exit 5")\n'
                    'exit 0\n')
        with mock.patch.dict(os.environ, {"RK_FAKE_SRC": src}):
            cert, key, ca_cert, msg = tlsca.ensure_server_cert(kit, os.path.join(_tmp, "ca-fake-warn"), bind_ip="127.0.0.1")
        self.assertTrue(msg.startswith("Issued"), msg)
        self.assertIn("WARNING: could not restrict the permissions", msg)

    def test_a_non_ascii_ca_folder_works(self):
        kit = self.kit("kit-nonascii")
        ca = os.path.join(_tmp, "ca-\u00e9\u00e8\u00fc-\u00df")
        cert, key, ca_cert, msg = tlsca.ensure_server_cert(kit, ca, bind_ip="127.0.0.1")
        self.assertTrue(msg.startswith("Issued"), msg)
        self.assertTrue(os.path.isfile(ca_cert))

    def run_server_lines(self, kit, port, **kw):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = net.run_server(kit, "127.0.0.1", port, os.path.join(_tmp, "store-rs"), None, **kw)
        return rc, out.getvalue().strip().splitlines()

    def test_a_port_that_is_in_use_is_one_clear_line_and_exit_2(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        self.addCleanup(s.close)
        rc, lines = self.run_server_lines(self.kit("kit-port", script=False), s.getsockname()[1], no_tls=True)
        self.assertEqual(rc, 2)
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("Cannot start the server", lines[0])
        self.assertIn("127.0.0.1:%d" % s.getsockname()[1], lines[0])

    def test_an_unusable_certificate_is_one_clear_line_and_exit_2(self):
        kit = self.kit("kit-badcert", script=False)
        bad_key = os.path.join(kit, "config", "server-key.pem")
        with open(bad_key, "w") as f:
            f.write("this is not a key\n")
        with mock.patch.object(tlsca, "ensure_server_cert", lambda *a, **k: (F["cert"], bad_key, F["ca_cert"], "fake")):
            rc, lines = self.run_server_lines(kit, 0)
        self.assertEqual(rc, 2)
        self.assertEqual(lines[0], "fake")
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("Cannot start the server", lines[1])
        self.assertIn("server-cert.pem", lines[1])


class HttpsRound3(test_net.Base):
    def setUp(self):
        super().setUp()
        self.kit = os.path.join(self.tmp, "serverkit")
        os.makedirs(os.path.join(self.kit, "config"))

    def start(self, tls=True, **kw):
        srv = net.Server(self.kit, os.path.join(self.tmp, "store"), None, say=lambda m: None)
        url = srv.start("127.0.0.1", 0, F["cert"] if tls else None, F["key"] if tls else None, tls=tls, **kw)
        self.addCleanup(srv.stop)
        return srv, url

    def test_renegotiation_is_off(self):
        if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
            self.skipTest("this Python has no OP_NO_RENEGOTIATION")
        srv, url = self.start()
        self.assertTrue(srv.httpd.tls_ctx.options & ssl.OP_NO_RENEGOTIATION)

    def test_a_refused_tls_connection_is_closed_without_a_handshake_and_without_a_plain_answer(self):
        srv, url = self.start(max_conn=1, reserve=0)
        port = srv.httpd.server_address[1]
        hold = socket.create_connection(("127.0.0.1", port), timeout=5)       # takes the only slot (no handshake)
        self.addCleanup(hold.close)
        time.sleep(0.3)
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.addCleanup(s.close)
        s.settimeout(5)
        try:
            data = s.recv(100)
        except OSError:
            data = b""
        self.assertEqual(data, b"")                                           # closed; nothing a TLS client cannot read

    def test_ctl_scheme_in_upper_case_and_no_scheme(self):
        srv, url = self.start()
        tok = srv.tokens["operator_token"]
        out = []
        rc = net.ctl(self.kit, ["--url", url.replace("https://", "HTTPS://"), "--token", tok, "--ca", F["ca_cert"], "agents"],
                     out.append)
        self.assertEqual(rc, 0, out)
        out = []
        rc = net.ctl(self.kit, ["--url", url.replace("https://", ""), "--token", tok, "--ca", F["ca_cert"], "agents"], out.append)
        self.assertEqual(rc, 2)
        self.assertEqual(len(out), 1)
        self.assertIn("http://", out[0])

    def test_https_against_a_plain_http_server_adds_the_no_tls_hint(self):
        srv, url = self.start(tls=False)
        out = []
        rc = net.ctl(self.kit, ["--url", url.replace("http://", "https://"), "--token", srv.tokens["operator_token"],
                                "--ca", F["ca_cert"], "agents"], out.append)
        self.assertEqual(rc, 2)
        self.assertEqual(len(out), 1)
        self.assertIn("cannot reach the server at https://", out[0])
        self.assertIn("the server may be running with --no-tls: pass --url http://", out[0])


SCRIPT_NAME = "New-ItworkCertificates.ps1"
KEY_BLOCK = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n"
TOKENS = '{"agent_token": "abc", "operator_token": "def"}'


def make_zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in members.items():
            z.writestr(k, v)
    return buf.getvalue()


class InstallerSecretCheck(unittest.TestCase):
    """Install-ToUsb.ps1 -CheckOnly <folder>: only the final secret check, exit 0 (clean) or 1 (names the files)."""

    def check(self, ps, folder):
        return subprocess.run([ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", os.path.join(ROOT, "Install-ToUsb.ps1"),
                               "-CheckOnly", folder], capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)

    def folder_with(self, name, content):
        d = tempfile.mkdtemp(prefix="chk-", dir=_tmp)
        path = os.path.join(d, "config", name)
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode("utf-8"))
        return d

    def test_every_name_from_the_review_fails_and_is_named(self):
        cases = {name: KEY_BLOCK for name in ("ca-key - Copy.pem", "CA-KEY.PEM.bak", "ca-key.pem.txt", "key.pem",
                                              "server-key (1).pem", "server-key.pem.old", "ca-key.pem.bak", "ca-key.pem",
                                              "server-key.pem")}
        cases.update({name: TOKENS for name in ("my-token-server.json", "token-server.json.bak", "token-server.json")})
        cases["backup.zip"] = make_zip_bytes({"config/token-server.json": TOKENS})
        cases["notes.zip"] = make_zip_bytes({"readme.txt": "see " + KEY_BLOCK})
        cases["ca-cert.pem"] = open(F["ca_cert"]).read() + KEY_BLOCK        # a certificate file that also holds a key
        cases["utf16.txt"] = TOKENS.encode("utf-16")
        for ps in runtimes():
            for name, content in cases.items():
                d = self.folder_with(name, content)
                r = self.check(ps, d)
                self.assertEqual(r.returncode, 1, (os.path.basename(ps), name, r.stdout, r.stderr))
                self.assertIn(name, r.stdout, (os.path.basename(ps), name))

    def test_a_clean_stick_passes(self):
        d = tempfile.mkdtemp(prefix="chk-clean-", dir=_tmp)
        os.makedirs(os.path.join(d, "config"))
        shutil.copy(F["ca_cert"], os.path.join(d, "config", "ca-cert.pem"))
        for name, text in (("config/kit.toml", "[kit]\nname = 'x'\n"), ("run.cmd", "@echo off\n"),
                           ("recoverykit/mod.py", "x = 1\n")):
            os.makedirs(os.path.dirname(os.path.join(d, name)), exist_ok=True)
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        # outside the check: customer data, device records, the interpreter, and anything of 64 KB or more
        for name, text in (("cases/c1/notes.txt", KEY_BLOCK), ("devices/D1/device.json", TOKENS), ("python/x.txt", KEY_BLOCK),
                           ("docs/big.txt", KEY_BLOCK + "x" * 70000)):
            os.makedirs(os.path.dirname(os.path.join(d, name)), exist_ok=True)
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        for ps in runtimes():
            r = self.check(ps, d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("No secret files found", r.stdout)

    def test_a_missing_folder_is_not_a_pass(self):
        r = self.check(PS, os.path.join(_tmp, "no-such-folder"))
        self.assertNotEqual(r.returncode, 0)

    def test_the_stick_gets_only_the_allowlisted_config_files_and_a_key_in_ca_cert_is_refused(self):
        dest = os.path.join(_tmp, "stick-allow", "ITWORK", "RecoveryKit")
        r = subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", os.path.join(ROOT, "Install-ToUsb.ps1"),
                            "-Destination", dest, "-CaDir", F["ca"]], capture_output=True, text=True, timeout=600,
                           stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:] + r.stderr[-1500:])
        self.assertEqual(sorted(os.listdir(os.path.join(dest, "config"))), ["assistant.toml", "ca-cert.pem", "kit.toml"])
        # a CA folder whose ca-cert.pem also holds a key is refused
        badca = os.path.join(_tmp, "ca-with-key-in-cert")
        os.makedirs(badca)
        with open(os.path.join(badca, "ca-cert.pem"), "w") as f:
            f.write(open(F["ca_cert"]).read() + KEY_BLOCK)
        dest2 = os.path.join(_tmp, "stick-badca", "ITWORK", "RecoveryKit")
        r = subprocess.run([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", os.path.join(ROOT, "Install-ToUsb.ps1"),
                            "-Destination", dest2, "-CaDir", badca], capture_output=True, text=True, timeout=600,
                           stdin=subprocess.DEVNULL)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("PRIVATE KEY", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(os.path.join(dest2, "config", "ca-cert.pem")))


if __name__ == "__main__":
    unittest.main()
