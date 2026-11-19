"""Network front ends (ADR 0010, 0011). Stdlib only.

- serve_local(engine):   agent API on 127.0.0.1, bearer token          (run.cmd --serve)
- Server:                control server on the main machine             (run.cmd --server)
- connect(engine, url):  the agent dials OUT to the server and executes relayed
                         agent-API calls; the target opens no LAN port  (run.cmd --connect URL)
- ctl():                 small operator client for the server API       (run.cmd --ctl ...)

Agent <-> server messages: metadata as base64 JSON in the X-RK-Meta header, raw
body, and X-RK-Sig = HMAC-SHA256(agent_token, meta_b64 + "." + sha256(body)).
Requests carry a fresh nonce and a rising counter; the response signature covers
the request nonce, so neither side accepts a replay or a peer without the token.
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import queue
import secrets
import shutil
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .core.log import LOG
from .engine import API, route

MAX_BODY = 64 * 2**20          # request bodies accepted by either HTTP server
POLL_WAIT = 20                 # seconds an agent poll is held open
JOB_TIMEOUT = 1800             # a relayed call may take this long (a scan with chkdsk is slow)


# ---------------------------------------------------------------- shared helpers
def _sig(token, meta_b64, body):
    msg = meta_b64.encode("ascii") + b"." + hashlib.sha256(body).hexdigest().encode("ascii")
    return hmac.new(token.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _pack(meta):
    return base64.b64encode(json.dumps(meta).encode("utf-8")).decode("ascii")


def _unpack(meta_b64):
    return json.loads(base64.b64decode(meta_b64.encode("ascii")).decode("utf-8"))


def _payload(result):
    """(bytes, content_type) for a route() payload."""
    if isinstance(result, tuple):
        return result[0], result[1]
    return json.dumps(result, ensure_ascii=False, default=str).encode("utf-8"), "application/json; charset=utf-8"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RecoveryKit/" + __version__

    def log_message(self, fmt, *args):
        LOG.debug("HTTP  | %s %s", self.address_string(), fmt % args)

    def _go(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send(413, {}, b'{"error": "body too large"}')
            body = self.rfile.read(n) if n else b""
            u = urllib.parse.urlsplit(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            status, headers, data = self.server.app(self.command, u.path, q, self.headers, body)
        except Exception as e:  # noqa: BLE001 - a bad request must not kill the server thread
            LOG.exception("HTTP  | handler failed")
            status, headers, data = 500, {}, json.dumps({"error": "%s: %s" % (type(e).__name__, e)}).encode()
        self._send(status, headers, data)

    def _send(self, status, headers, data):
        self.send_response(status)
        headers = dict(headers or {})
        headers.setdefault("Content-Type", "application/json; charset=utf-8")
        headers["Content-Length"] = str(len(data))
        headers["Cache-Control"] = "no-store"
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _go


def _http_server(app, host, port, certfile=None, keyfile=None):
    srv = ThreadingHTTPServer((host, port), _Handler)
    srv.daemon_threads = True
    srv.app = app
    if certfile and keyfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def _request(url, method="GET", body=b"", headers=None, timeout=60, pin=None):
    """One HTTP(S) request. pin: expected SHA-256 hex of the server certificate (self-signed is fine then).
    Returns (status, headers, body)."""
    u = urllib.parse.urlsplit(url)
    path = u.path + ("?" + u.query if u.query else "")
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        if pin:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
        conn.connect()
        if pin:
            got = hashlib.sha256(conn.sock.getpeercert(True)).hexdigest()
            if not hmac.compare_digest(got, pin.lower().replace(":", "")):
                conn.close()
                raise ConnectionError("server certificate does not match the pinned fingerprint (got %s)" % got)
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.request(method, path, body=body or None, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.headers, r.read()
    finally:
        conn.close()


# ---------------------------------------------------------------- agent API on loopback
def local_app(engine, token):
    def app(method, path, q, headers, body):
        auth = headers.get("Authorization") or ""
        if not hmac.compare_digest(auth.encode(), ("Bearer " + token).encode()):
            LOG.info("API   | loopback %s %s rejected: bad or missing token", method, path)
            return 401, {"WWW-Authenticate": "Bearer"}, b'{"error": "missing or wrong bearer token"}'
        try:
            b = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(b, dict):
                raise ValueError("body must be a JSON object")
        except ValueError as e:
            return 400, {}, json.dumps({"error": "bad JSON body: %s" % e}).encode()
        status, result = route(engine, method, path, q, b, remote=False,
                               operator=headers.get("X-RK-Operator") or "loopback")
        data, ctype = _payload(result)
        return status, {"Content-Type": ctype}, data
    return app


def serve_local(engine, port=8766, ready=None, stop=None):
    """Headless agent: the agent API on 127.0.0.1 only. Blocks until stop is set or Ctrl+C."""
    token = secrets.token_urlsafe(24)
    srv = _http_server(local_app(engine, token), "127.0.0.1", port)
    port = srv.server_address[1]
    token_file = os.path.join(engine.ctx.case.out_root, "_api-token.txt")
    try:
        with open(token_file, "w") as f:
            f.write("http://127.0.0.1:%d%s\n%s\n" % (port, API, token))
    except OSError as e:
        token_file = "(could not be written: %s)" % e
    ui = engine.ctx.ui
    ui.say("Agent API listening on http://127.0.0.1:%d%s (this machine only)." % (port, API))
    ui.say("Bearer token: %s" % token)
    ui.say("Also written to %s. Repairs through the API: %s. Ctrl+C stops." % (
        token_file, "ENABLED (--allow-repairs)" if engine.allow_repairs else "disabled"))
    LOG.info("API   | bearer token issued (not logged)")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    if ready is not None:
        ready(port, token)
    try:
        while not (stop is not None and stop.is_set()):
            time.sleep(0.2)
    except KeyboardInterrupt:
        ui.say("Stopping.")
    finally:
        srv.shutdown()
        srv.server_close()
        try:
            os.remove(token_file)
        except OSError:
            pass


# ---------------------------------------------------------------- control server
class Server:
    def __init__(self, kit_root, store, intake=None, say=print):
        self.kit_root, self.store, self.intake, self.say = kit_root, os.path.abspath(store), intake, say
        os.makedirs(self.store, exist_ok=True)
        self.agents = {}
        self.lock = threading.Lock()
        self.token_file = os.path.join(kit_root, "config", "token-server.json")
        self.tokens = self._tokens()

    def _tokens(self):
        try:
            with open(self.token_file, encoding="utf-8") as f:
                t = json.load(f)
            if t.get("agent_token") and t.get("operator_token"):
                return t
        except (OSError, ValueError):
            pass
        t = {"agent_token": secrets.token_urlsafe(24), "operator_token": secrets.token_urlsafe(24),
             "created": time.strftime("%Y-%m-%d %H:%M")}
        os.makedirs(os.path.dirname(self.token_file), exist_ok=True)
        with open(self.token_file, "w", encoding="utf-8") as f:
            json.dump(t, f, indent=2)
        return t

    # ---- agent side
    def _agent_call(self, path, headers, body):
        meta_b64 = headers.get("X-RK-Meta") or ""
        sig = headers.get("X-RK-Sig") or ""
        if not meta_b64 or not hmac.compare_digest(sig, _sig(self.tokens["agent_token"], meta_b64, body)):
            LOG.info("SERVER| agent call %s rejected: bad signature", path)
            return 401, {}, b'{"error": "bad signature"}'
        try:
            meta = _unpack(meta_b64)
            aid, n, nonce = str(meta["agent_id"]), int(meta["n"]), str(meta["nonce"])
        except (ValueError, KeyError, TypeError):
            return 400, {}, b'{"error": "bad metadata"}'
        with self.lock:
            a = self.agents.get(aid)
            if path == "/agent/v1/hello":
                if a is None:
                    a = self.agents[aid] = {"id": aid, "paired": False, "revoked": False, "n": 0, "jobs": queue.Queue(),
                                            "results": {}, "pair_failures": 0, "first_seen": time.time()}
                a.update(name=str(meta.get("name", ""))[:60], version=str(meta.get("version", "")),
                         code_hash=str(meta.get("code_hash", "")), repairs=bool(meta.get("allow_remote_repairs")))
            if a is None:
                return self._agent_reply(404, {"error": "unknown agent: say hello first"}, nonce)
            if n <= a["n"]:
                LOG.info("SERVER| agent %s replayed or reordered message (n=%s, last=%s)", aid, n, a["n"])
                return 409, {}, b'{"error": "stale counter"}'
            a["n"], a["last_seen"] = n, time.time()
        if path == "/agent/v1/hello":
            LOG.info("SERVER| agent %s (%s) said hello", aid, a["name"])
            self.say("Agent %s (%s) connected. Pair it with the code shown on its screen:  ctl pair %s <code>" % (
                aid, a["name"], aid))
            return self._agent_reply(200, {"paired": a["paired"]}, nonce)
        if path == "/agent/v1/poll":
            if a["revoked"]:
                return self._agent_reply(200, {"revoked": True}, nonce)
            if not a["paired"]:
                time.sleep(min(float(meta.get("wait", 2)), 2))
                return self._agent_reply(200, {"paired": False}, nonce)
            try:
                job = a["jobs"].get(timeout=min(float(meta.get("wait", POLL_WAIT)), POLL_WAIT))
            except queue.Empty:
                return self._agent_reply(200, {"paired": True}, nonce)
            return self._agent_reply(200, {"paired": True, "job": job}, nonce)
        if path == "/agent/v1/result":
            slot = a["results"].get(str(meta.get("job_id")))
            if slot is None:
                return self._agent_reply(404, {"error": "unknown job"}, nonce)
            slot.update(status=int(meta.get("status", 500)), ctype=str(meta.get("ctype", "application/json")), body=body)
            slot["done"].set()
            return self._agent_reply(200, {"ok": True}, nonce)
        return 404, {}, b'{"error": "unknown agent route"}'

    def _agent_reply(self, status, obj, nonce):
        body = json.dumps(obj).encode("utf-8")
        meta_b64 = _pack({"nonce": nonce})
        return status, {"X-RK-Meta": meta_b64, "X-RK-Sig": _sig(self.tokens["agent_token"], meta_b64, body)}, body

    # ---- operator side
    def relay(self, aid, method, path, q, body_obj, operator, timeout=JOB_TIMEOUT):
        a = self.agents.get(aid)
        if a is None:
            return 404, "application/json", b'{"error": "unknown agent"}'
        if not a["paired"] or a["revoked"]:
            return 409, "application/json", b'{"error": "agent is not paired (or was revoked)"}'
        job_id = secrets.token_hex(8)
        slot = a["results"][job_id] = {"done": threading.Event()}
        a["jobs"].put({"id": job_id, "method": method, "path": path, "query": q, "body": body_obj, "operator": operator})
        LOG.info("SERVER| job %s for agent %s by %s: %s %s", job_id, aid, operator, method, path)
        if not slot["done"].wait(timeout):
            a["results"].pop(job_id, None)
            return 504, "application/json", b'{"error": "the agent did not answer in time"}'
        a["results"].pop(job_id, None)
        return slot["status"], slot["ctype"], slot["body"]

    def _operator_call(self, method, path, q, headers, body):
        auth = headers.get("Authorization") or ""
        if not hmac.compare_digest(auth.encode(), ("Bearer " + self.tokens["operator_token"]).encode()):
            return 401, {"WWW-Authenticate": "Bearer"}, b'{"error": "missing or wrong bearer token"}'
        operator = (headers.get("X-RK-Operator") or "operator")[:40]
        try:
            b = json.loads(body.decode("utf-8")) if body else {}
        except ValueError as e:
            return 400, {}, json.dumps({"error": "bad JSON body: %s" % e}).encode()

        def js(status, obj):
            return status, {}, json.dumps(obj, default=str).encode("utf-8")
        p = path[len(API):]
        if p == "/status" and method == "GET":
            return js(200, {"version": __version__, "role": "server", "agents": len(self.agents), "store": self.store,
                            "intake": self.intake})
        if p == "/agents" and method == "GET":
            now = time.time()
            return js(200, [{"id": a["id"], "name": a.get("name"), "version": a.get("version"), "paired": a["paired"],
                             "revoked": a["revoked"], "repairs_enabled_on_target": a.get("repairs"),
                             "seconds_since_seen": round(now - a.get("last_seen", now))} for a in self.agents.values()])
        if p == "/bundles" and method == "GET":
            out = []
            for root, _, files in os.walk(self.store):
                out += [{"path": os.path.relpath(os.path.join(root, f), self.store).replace("\\", "/"),
                         "size": os.path.getsize(os.path.join(root, f))} for f in files if f.endswith(".zip")]
            return js(200, out)
        parts = p.strip("/").split("/", 3)
        if len(parts) >= 3 and parts[0] == "agents":
            aid, verb = parts[1], parts[2]
            a = self.agents.get(aid)
            if a is None:
                return js(404, {"error": "unknown agent"})
            if verb == "pair" and method == "POST":
                if a["pair_failures"] >= 5:
                    return js(429, {"error": "too many wrong codes; restart the session on the target"})
                want = hashlib.sha256(("%s|%s" % (str(b.get("code", "")).strip(), aid)).encode()).hexdigest()
                if not hmac.compare_digest(want, a.get("code_hash", "")):
                    a["pair_failures"] += 1
                    LOG.info("SERVER| wrong pairing code for agent %s by %s", aid, operator)
                    return js(403, {"error": "wrong pairing code"})
                a["paired"] = True
                LOG.info("SERVER| agent %s paired by %s", aid, operator)
                return js(200, {"paired": True})
            if verb == "revoke" and method == "POST":
                a["revoked"], a["paired"] = True, False
                LOG.info("SERVER| agent %s revoked by %s", aid, operator)
                return js(200, {"revoked": True})
            if verb == "fetch-bundle" and method == "POST":
                return js(*self.fetch_bundle(aid, operator))
            if verb == "api" and len(parts) == 4:
                status, ctype, data = self.relay(aid, method, API + "/" + parts[3], q, b, operator)
                return status, {"Content-Type": ctype}, data
        return js(404, {"error": "unknown route"})

    def fetch_bundle(self, aid, operator):
        """Ask the agent to bundle its run, pull the zip, store it, and copy it to the intake folder."""
        status, _, data = self.relay(aid, "POST", API + "/bundle", {}, {}, operator)
        if status != 200:
            return status, {"error": "bundle failed on the agent", "detail": data.decode("utf-8", "replace")[:500]}
        s2, _, st = self.relay(aid, "GET", API + "/status", {}, {}, operator)
        info = json.loads(st.decode("utf-8")) if s2 == 200 else {}
        s3, _, cs = self.relay(aid, "GET", API + "/case", {}, {}, operator)
        ticket = (json.loads(cs.decode("utf-8")).get("ticket") if s3 == 200 else None)
        status, _, blob = self.relay(aid, "GET", API + "/bundle/download", {}, {}, operator)
        if status != 200:
            return status, {"error": "bundle download failed"}
        case_id = "".join(c for c in str(info.get("case_id") or "unknown") if c.isalnum() or c in "-_") or "unknown"
        name = os.path.basename(json.loads(data.decode("utf-8")).get("path", "bundle.zip").replace("\\", "/"))
        name = "".join(c for c in name if c.isalnum() or c in "-_.") or "bundle.zip"
        dest_dir = os.path.join(self.store, case_id)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, name)
        with open(dest, "wb") as f:
            f.write(blob)
        out = {"stored": dest, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest(), "intake": None}
        if self.intake and ticket:
            idir = os.path.join(self.intake, "ITW %s" % "".join(c for c in str(ticket) if c.isalnum()))
            try:
                os.makedirs(idir, exist_ok=True)
                shutil.copyfile(dest, os.path.join(idir, name))
                out["intake"] = os.path.join(idir, name)
            except OSError as e:
                out["intake_error"] = str(e)
        elif self.intake:
            out["intake_error"] = "no ticket number on the case: not copied to the intake"
        LOG.info("SERVER| bundle from %s stored: %s", aid, out)
        return 200, out

    def app(self, method, path, q, headers, body):
        if path.startswith("/agent/v1/") and method == "POST":
            return self._agent_call(path, headers, body)
        if path.startswith(API + "/"):
            return self._operator_call(method, path, q, headers, body)
        return 404, {}, b'{"error": "unknown path"}'

    def start(self, host="127.0.0.1", port=8765):
        cert = os.path.join(self.kit_root, "config", "server-cert.pem")
        key = os.path.join(self.kit_root, "config", "server-key.pem")
        tls = os.path.isfile(cert) and os.path.isfile(key)
        self.httpd = _http_server(self.app, host, port, cert if tls else None, key if tls else None)
        self.url = "%s://%s:%d" % ("https" if tls else "http", host, self.httpd.server_address[1])
        self.tls = tls
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self.url

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def run_server(kit_root, host, port, store, intake):
    from .core import log
    log.add_file(os.path.join(store, "_server-logs", "server-%s.log" % log.stamp()))
    srv = Server(kit_root, store, intake)
    url = srv.start(host, port)
    print("RecoveryKit control server %s on %s  (%s)" % (__version__, url,
          "TLS" if srv.tls else "NO TLS: traffic is authenticated but not encrypted, use on a trusted LAN only"))
    print("Tokens: %s (keep it out of git; the agent needs agent_token, the operator needs operator_token)" % srv.token_file)
    print("Bundles are stored in %s%s" % (srv.store, "; intake: %s" % intake if intake else ""))
    print("On the target:  run.cmd --connect %s --token <agent_token>" % url)
    print("Ctrl+C stops.")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopping.")
    finally:
        srv.stop()
    return 0


# ---------------------------------------------------------------- agent: connect out
def _key_pressed():
    try:
        import msvcrt
        if msvcrt.kbhit():
            msvcrt.getwch()
            return True
    except (ImportError, OSError):
        pass
    return False


def connect(engine, url, token, pin=None, minutes=60, name="", stop=None, on_code=None):
    """Dial out to the control server and serve relayed agent-API calls until a key is pressed on the
    target, the session times out, or the server revokes it. Returns the reason it ended."""
    ui = engine.ctx.ui
    url = url.rstrip("/")
    agent_id = secrets.token_hex(4)
    code = "%06d" % secrets.randbelow(10 ** 6)
    counter = [0]

    def call(path, meta, body=b"", timeout=POLL_WAIT + 15):
        counter[0] += 1
        nonce = secrets.token_hex(12)
        meta = dict(meta, agent_id=agent_id, n=counter[0], nonce=nonce)
        meta_b64 = _pack(meta)
        status, headers, data = _request(url + path, "POST", body, {
            "X-RK-Meta": meta_b64, "X-RK-Sig": _sig(token, meta_b64, body),
            "Content-Type": "application/octet-stream", "Content-Length": str(len(body))}, timeout, pin)
        rmeta = headers.get("X-RK-Meta") or ""
        if not rmeta or not hmac.compare_digest(headers.get("X-RK-Sig") or "", _sig(token, rmeta, data)) \
                or _unpack(rmeta).get("nonce") != nonce:
            raise ConnectionError("the server's answer is not signed with the shared token (HTTP %s): wrong token, "
                                  "or this is not the RecoveryKit server" % status)
        return status, json.loads(data.decode("utf-8"))

    if url.startswith("http://"):
        ui.say("WARNING: no TLS. Traffic is authenticated but NOT encrypted. Use on a trusted LAN only.")
    code_hash = hashlib.sha256(("%s|%s" % (code, agent_id)).encode()).hexdigest()
    call("/agent/v1/hello", {"name": name or (engine.ctx.case.data.get("case_id") or "unpaired"),
                             "version": __version__, "code_hash": code_hash,
                             "allow_remote_repairs": engine.allow_remote_repairs})
    ui.say("Connected to %s as agent %s." % (url, agent_id))
    ui.say("PAIRING CODE: %s   (tell it to the operator at the server; nothing is relayed before pairing)" % code)
    ui.say("Session: %s; ends after %d minutes or when a key is pressed here." % (
        "read-only + REPAIRS ENABLED (--allow-remote-repairs)" if engine.allow_remote_repairs else "read-only", minutes))
    if on_code:
        on_code(agent_id, code)
    deadline = time.monotonic() + minutes * 60
    failures, reason, paired = 0, "", False
    while not reason:
        if stop is not None and stop.is_set():
            reason = "stopped"
        elif _key_pressed():
            reason = "key pressed on the target"
        elif time.monotonic() > deadline:
            reason = "session timed out"
        if reason:
            break
        try:
            _, r = call("/agent/v1/poll", {"wait": 3 if stop is not None else POLL_WAIT})
            failures = 0
        except (OSError, ValueError, http.client.HTTPException) as e:
            failures += 1
            LOG.info("AGENT | poll failed (%d): %s", failures, e)
            if failures >= 5:
                reason = "server unreachable: %s" % e
            time.sleep(min(2 * failures, 10))
            continue
        if r.get("revoked"):
            reason = "revoked by the server"
            break
        if r.get("paired") and not paired:
            paired = True
            ui.say("Paired. The operator can now use this session.")
        job = r.get("job")
        if not job:
            continue
        operator = "%s@server" % (job.get("operator") or "operator")
        ui.say("Remote request by %s: %s %s" % (operator, job.get("method"), job.get("path")))
        status, result = route(engine, str(job.get("method")), str(job.get("path")), job.get("query") or {},
                               job.get("body") or {}, remote=True, operator=operator)
        data, ctype = _payload(result)
        try:
            call("/agent/v1/result", {"job_id": job.get("id"), "status": status, "ctype": ctype}, data, timeout=300)
        except (OSError, ValueError, http.client.HTTPException) as e:
            LOG.error("AGENT | could not deliver the result of job %s: %s", job.get("id"), e)
    ui.say("Remote session ended: %s." % reason)
    LOG.info("AGENT | session ended: %s", reason)
    return reason


# ---------------------------------------------------------------- operator client
def ctl(kit_root, argv, out=print):
    """run.cmd --ctl [--url URL] [--token T] agents | pair ID CODE | revoke ID | fetch-bundle ID | bundles |
    get ID PATH | post ID PATH [JSON]      (PATH is an agent API path such as /status or /repair/steps)"""
    url, token = "http://127.0.0.1:8765", None
    args = list(argv)
    while args and args[0] in ("--url", "--token", "--pin"):
        flag, val = args.pop(0), args.pop(0)
        if flag == "--url":
            url = val.rstrip("/")
        elif flag == "--token":
            token = val
    if token is None:
        try:
            with open(os.path.join(kit_root, "config", "token-server.json"), encoding="utf-8") as f:
                token = json.load(f)["operator_token"]
        except (OSError, ValueError, KeyError):
            out("No operator token: pass --token or run on the machine that holds config/token-server.json.")
            return 2
    if not args:
        out(ctl.__doc__)
        return 2
    verb, rest = args[0], args[1:]
    method, path, body = "GET", None, b""
    if verb == "agents":
        path = "/agents"
    elif verb == "bundles":
        path = "/bundles"
    elif verb == "pair" and len(rest) == 2:
        method, path, body = "POST", "/agents/%s/pair" % rest[0], json.dumps({"code": rest[1]}).encode()
    elif verb in ("revoke", "fetch-bundle") and len(rest) == 1:
        method, path = "POST", "/agents/%s/%s" % (rest[0], verb)
    elif verb == "get" and len(rest) == 2:
        path = "/agents/%s/api/%s" % (rest[0], rest[1].lstrip("/"))
    elif verb == "post" and len(rest) in (2, 3):
        method, path = "POST", "/agents/%s/api/%s" % (rest[0], rest[1].lstrip("/"))
        body = (rest[2] if len(rest) == 3 else "{}").encode("utf-8")
    else:
        out(ctl.__doc__)
        return 2
    status, headers, data = _request(url + API + path, method, body, {
        "Authorization": "Bearer " + token, "Content-Type": "application/json", "Content-Length": str(len(body)),
        "X-RK-Operator": os.environ.get("USERNAME", "operator")}, timeout=JOB_TIMEOUT + 30)
    ctype = headers.get("Content-Type", "")
    if ctype.startswith("application/json"):
        try:
            out(json.dumps(json.loads(data.decode("utf-8")), indent=2, ensure_ascii=False))
        except ValueError:
            out(data.decode("utf-8", "replace"))
    elif ctype.startswith("text/"):
        out(data.decode("utf-8", "replace"))
    else:
        out("(%d bytes of %s)" % (len(data), ctype))
    return 0 if status < 400 else 1
