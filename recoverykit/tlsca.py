"""TLS certificates for the control server (ADR 0020). Stdlib only.

The control host PC is the certificate authority. This module only decides WHEN a server certificate has to
be (re)issued and runs New-ItworkCertificates.ps1 to do it. It runs on the control host, never on a target, and
is the one place besides core/runner.py that starts a process: a fixed argument list, no shell, and every
subject alternative name is validated before it is passed on.
"""
import datetime
import hashlib
import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess

SCRIPT = "New-ItworkCertificates.ps1"
NAME_RE = re.compile(r"^[A-Za-z0-9.\-]+$")
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
ISSUE_TIMEOUT = 180


class TlsError(RuntimeError):
    """The certificate could not be made or is unusable; the message says why."""


def default_ca_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    return os.path.join(base, "ITwork", "CA")


def host_names_and_ips(bind_ip=None):
    """(names, ips) this host should be reachable by: computer name, localhost, 127.0.0.1, local IPv4 addresses."""
    names, ips = [], ["127.0.0.1"]
    for n in (socket.gethostname(), "localhost"):
        if n and NAME_RE.match(n) and n.lower() not in [x.lower() for x in names]:
            names.append(n)
    try:
        found = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
    except OSError:
        found = []
    if bind_ip and bind_ip not in ("0.0.0.0", ""):
        found.append(bind_ip)
    for a in found:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_unspecified and str(ip) not in ips:
            ips.append(str(ip))
    return names, ips


def _pem_blocks(path):
    with open(path, encoding="ascii", errors="replace") as f:
        return PEM_RE.findall(f.read())


def pem_sha256(pem_text):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem_text)).hexdigest()


def cert_info(pem_path):
    """{"not_after": datetime (UTC) or None, "dns": [...], "ip": [...], "sha256": hex} for the FIRST certificate in
    the file. Without ssl._ssl._test_decode_cert only "sha256" is known (the other fields are None / empty)."""
    blocks = _pem_blocks(pem_path)
    if not blocks:
        raise TlsError("no certificate in %s" % pem_path)
    info = {"not_after": None, "dns": [], "ip": [], "sha256": pem_sha256(blocks[0])}
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decode is not None:
        try:
            d = decode(pem_path)
            info["not_after"] = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(d["notAfter"]),
                                                                datetime.timezone.utc)
            for kind, val in d.get("subjectAltName", ()):
                if kind == "DNS":
                    info["dns"].append(val)
                elif kind == "IP Address":
                    info["ip"].append(str(ipaddress.ip_address(val)))
        except (OSError, ValueError, KeyError, ssl.SSLError):
            pass
    return info


def needs_issue(cert_path, key_path, names, ips, min_days=30, ca_cert_path=None):
    """(True, reason) when the server certificate must be issued again, else (False, "")."""
    if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
        return True, "no server certificate yet"
    try:
        info = cert_info(cert_path)
    except (OSError, TlsError, ValueError, ssl.SSLError) as e:
        return True, "the server certificate is unreadable (%s)" % e
    if info["not_after"] is None:
        return True, "cannot read the certificate's expiry on this Python"
    left = info["not_after"] - datetime.datetime.now(datetime.timezone.utc)
    if left < datetime.timedelta(days=min_days):
        return True, "the server certificate expires in %d days" % max(left.days, 0)
    have = {n.lower() for n in info["dns"]}
    missing = [n for n in names if n.lower() not in have] + [i for i in ips if i not in info["ip"]]
    if missing:
        return True, "the host's names or addresses are not all in the certificate (%s)" % ", ".join(missing)
    if ca_cert_path:
        try:
            if not os.path.isfile(ca_cert_path):
                return True, "no CA yet"
            blocks = _pem_blocks(cert_path)
            if len(blocks) < 2 or pem_sha256(blocks[-1]) != pem_sha256(_pem_blocks(ca_cert_path)[0]):
                return True, "the server certificate was not issued by the current CA"
        except (OSError, ValueError, IndexError, ssl.SSLError):
            return True, "the CA certificate cannot be compared"
    return False, ""


def _powershell():
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    exe = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    if os.path.isfile(exe):
        return exe
    return shutil.which("pwsh")


def ca_fingerprint(ca_dir):
    p = os.path.join(ca_dir, "ca-cert.pem")
    return cert_info(p)["sha256"] if os.path.isfile(p) else None


def ensure_server_cert(kit_root, ca_dir=None, bind_ip=None):
    """Issue config/server-cert.pem + server-key.pem from the CA when needs_issue says so (creating the CA when
    there is none). Returns (cert_path, key_path, ca_cert_path, message); raises TlsError when it cannot."""
    ca_dir = os.path.abspath(ca_dir or default_ca_dir())
    out_dir = os.path.join(kit_root, "config")
    cert, key = os.path.join(out_dir, "server-cert.pem"), os.path.join(out_dir, "server-key.pem")
    ca_cert = os.path.join(ca_dir, "ca-cert.pem")
    names, ips = host_names_and_ips(bind_ip)
    need, reason = needs_issue(cert, key, names, ips, ca_cert_path=ca_cert)
    if not need:
        return cert, key, ca_cert, "Server certificate in %s is current." % out_dir
    script = os.path.join(kit_root, SCRIPT)
    if not os.path.isfile(script):
        raise TlsError("%s is not next to the kit (%s): cannot issue a certificate (%s)" % (SCRIPT, script, reason))
    ps = _powershell()
    if not ps:
        raise TlsError("PowerShell was not found: cannot issue a certificate (%s)" % reason)
    for n in names:
        if not NAME_RE.match(n):
            raise TlsError("not a valid DNS name: %r" % n)
    ips = [str(ipaddress.ip_address(i)) for i in ips]
    os.makedirs(out_dir, exist_ok=True)
    cmd = [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
           "-CaDir", ca_dir, "-OutDir", out_dir, "-DnsName", ",".join(names), "-IpAddress", ",".join(ips), "-Force"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=ISSUE_TIMEOUT, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as e:
        raise TlsError("could not run PowerShell (%s): %s" % (ps, e))
    if r.returncode != 0:
        raise TlsError("%s failed (exit %d): %s" % (SCRIPT, r.returncode, (r.stderr or r.stdout).strip()[:500]))
    if not (os.path.isfile(cert) and os.path.isfile(key) and os.path.isfile(ca_cert)):
        raise TlsError("%s finished but did not write the expected files" % SCRIPT)
    return cert, key, ca_cert, "Issued a new server certificate (%s)." % reason
