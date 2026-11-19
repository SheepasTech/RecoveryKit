"""Network front ends (ADR 0010, 0011). Stdlib only.

- serve_local(engine):   agent API on 127.0.0.1, bearer token          (run.cmd --serve)
- Server:                control server on the main machine             (run.cmd --server)
- connect(engine, url):  the agent dials OUT to the server and executes relayed
                         agent-API calls; the target opens no LAN port  (run.cmd --connect URL)
- ctl():                 small operator client for the server API       (run.cmd --ctl ...)

Agent <-> server messages: metadata as base64 JSON in the X-RK-Meta header, raw
body, and X-RK-Sig = HMAC-SHA256(agent_token, path + "\\n" + meta_b64 + "." + sha256(body)).
The path is the request path; the response is signed over the same request path.
Requests carry a fresh nonce and a rising counter; the response signature covers
the request nonce, so neither side accepts a replay or a peer without the token.
"""
import base64
import hashlib
import hmac
import http.client
import io
import json
import os
import queue
import re
import secrets
import shutil
import ssl
import sys
import threading
import time
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .core.log import LOG
from .engine import API, route

MAX_BODY = 64 * 2**20          # request bodies accepted by either HTTP server
MAX_RESULT = 2**30             # the agent's result route only: a bundle can be big
POLL_WAIT = 20                 # seconds an agent poll is held open
JOB_TIMEOUT = 1800             # a relayed call may take this long (a scan with chkdsk is slow)
MAX_AGENTS = 64
STALE_UNPAIRED = 600           # an unpaired agent entry silent this long may be replaced by a new hello
MAX_N_JUMP = 1_000_000
MAX_CASE_JSON = 20 * 2**20     # largest case.json /cases will read out of a stored bundle
RESULT_CTYPES = ("application/json", "application/zip", "application/octet-stream", "text/markdown")
RESULT_PATH = "/agent/v1/result"


class _TooLarge(Exception):
    """The server refused an upload with 413."""


# ---------------------------------------------------------------- shared helpers
def _sig(token, path, meta_b64, body):
    msg = (path.encode("utf-8") + b"\n" + meta_b64.encode("ascii") + b"." +
           hashlib.sha256(body).hexdigest().encode("ascii"))
    return hmac.new(token.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _json_dict(data):
    """Agent-provided bytes -> dict, or None when they are not a JSON object."""
    try:
        d = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return d if isinstance(d, dict) else None


def _say_secret(text):
    """Show a secret on the console only: never through the logger (debug.log is bundled and served)."""
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except (OSError, ValueError, AttributeError):
        pass


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
    timeout = 30                     # per socket operation: a stalled client cannot hold a thread forever

    def setup(self):
        ctx = getattr(self.server, "tls_ctx", None)
        if ctx is not None:              # TLS handshake here, in the handler thread, not in the accept loop
            self.request.settimeout(self.timeout)
            self.request = ctx.wrap_socket(self.request, server_side=True)
        super().setup()

    def log_message(self, fmt, *args):
        LOG.debug("HTTP  | %s %s", self.address_string(), fmt % args)

    def _refuse(self, status, message):
        self.close_connection = True
        return self._send(status, {"Connection": "close"}, json.dumps({"error": message}).encode())

    def _go(self):
        try:
            u = urllib.parse.urlsplit(self.path)
            limit = MAX_RESULT if u.path == RESULT_PATH else MAX_BODY
            if self.headers.get("Transfer-Encoding"):
                return self._refuse(400, "chunked bodies are not accepted")
            cl = self.headers.get("Content-Length")
            if cl is None:
                if self.command == "POST":
                    return self._refuse(400, "Content-Length is required")
                n = 0
            else:
                cl = cl.strip()
                if not (cl.isascii() and cl.isdigit()) or len(cl) > 15:
                    return self._refuse(400, "bad Content-Length")
                n = int(cl)
                if n > limit:
                    return self._refuse(413, "body too large")
            try:
                body = self.rfile.read(n) if n else b""
            except OSError as e:          # stalled or reset client (socket timeout)
                LOG.info("HTTP  | body not received from %s: %s", self.address_string(), e)
                self.close_connection = True
                return
            if len(body) != n:
                self.close_connection = True
                return
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


class _Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # failed TLS handshakes, resets and timeouts are routine on a LAN: one log line, no traceback on the console
        LOG.info("HTTP  | connection from %s failed: %s", client_address[0], sys.exc_info()[1])


def _http_server(app, host, port, certfile=None, keyfile=None):
    srv = _Server((host, port), _Handler)
    srv.daemon_threads = True
    srv.app = app
    srv.tls_ctx = None
    if certfile and keyfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        srv.tls_ctx = ctx                # each accepted socket is wrapped in its handler thread
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
    _say_secret("Bearer token: %s" % token)
    ui.say("Also written to %s. Repairs through the API: %s. Ctrl+C stops." % (
        token_file, "ENABLED (--allow-repairs)" if engine.allow_repairs else "disabled"))
    LOG.info("API   | bearer token shown on the console (not logged)")
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
        self.cancelled = {}               # job id -> time it timed out; the poll handler never delivers these
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
        if not meta_b64 or not hmac.compare_digest(sig, _sig(self.tokens["agent_token"], path, meta_b64, body)):
            LOG.info("SERVER| agent call %s rejected: bad signature", path)
            return 401, {}, b'{"error": "bad signature"}'
        try:
            meta = _unpack(meta_b64)
            aid, n, nonce = str(meta["agent_id"]), meta["n"], str(meta["nonce"])
        except (ValueError, KeyError, TypeError, AttributeError):
            return 400, {}, b'{"error": "bad metadata"}'
        if not isinstance(meta, dict) or isinstance(n, bool) or not isinstance(n, int) or not 0 < n < 2**53:
            return 400, {}, b'{"error": "bad metadata: n"}'
        now = time.time()
        with self.lock:
            a = self.agents.get(aid)
            if path == "/agent/v1/hello":
                if a is not None:
                    silent = now - a.get("last_seen", a["first_seen"])
                    if a["paired"] or silent < STALE_UNPAIRED:
                        LOG.info("SERVER| hello for existing agent id %s refused", aid)
                        return self._agent_reply(409, {"error": "agent id already in use"}, nonce, path)
                    a["jobs"].put(None)
                    del self.agents[aid]
                if len(self.agents) >= MAX_AGENTS:
                    old = [x for x in self.agents.values() if not x["paired"]]
                    if not old:
                        LOG.info("SERVER| hello refused: %d agents, all paired", len(self.agents))
                        return self._agent_reply(429, {"error": "too many agents"}, nonce, path)
                    victim = min(old, key=lambda x: x.get("last_seen", x["first_seen"]))
                    victim["jobs"].put(None)
                    del self.agents[victim["id"]]
                a = self.agents[aid] = {"id": aid, "paired": False, "revoked": False, "n": 0, "jobs": queue.Queue(),
                                        "results": {}, "pair_failures": 0, "first_seen": now}
                a.update(name=str(meta.get("name", ""))[:60], version=str(meta.get("version", ""))[:40],
                         code_hash=str(meta.get("code_hash", ""))[:128], repairs=bool(meta.get("allow_remote_repairs")))
            if a is None:
                return self._agent_reply(404, {"error": "unknown agent: say hello first"}, nonce, path)
            if n <= a["n"] or n - a["n"] > MAX_N_JUMP:
                LOG.info("SERVER| agent %s replayed, reordered or jumping message (n=%s, last=%s)", aid, n, a["n"])
                return 409, {}, b'{"error": "stale or implausible counter"}'
            a["n"], a["last_seen"] = n, now
        if path == "/agent/v1/hello":
            LOG.info("SERVER| agent %s (%s) said hello", aid, a["name"])
            self.say("Agent %s (%s) connected. Pair it with the code shown on its screen:  ctl pair %s <code>" % (
                aid, a["name"], aid))
            return self._agent_reply(200, {"paired": a["paired"]}, nonce, path)
        if path == "/agent/v1/poll":
            if a["revoked"]:
                return self._agent_reply(200, {"revoked": True}, nonce, path)
            try:
                wait = float(meta.get("wait", POLL_WAIT))
            except (TypeError, ValueError):
                wait = POLL_WAIT
            if not a["paired"]:
                time.sleep(max(0.0, min(wait, 2)))
                return self._agent_reply(200, {"paired": False}, nonce, path)
            end = time.monotonic() + max(0.0, min(wait, POLL_WAIT))
            while True:
                try:
                    job = a["jobs"].get(timeout=max(0.0, end - time.monotonic()))
                except queue.Empty:
                    return self._agent_reply(200, {"paired": True}, nonce, path)
                if job is None or a["revoked"]:      # woken up by a revoke
                    return self._agent_reply(200, {"revoked": True}, nonce, path)
                left = job["expires"] - time.time()
                if left <= 0 or job["id"] in self.cancelled:
                    continue                          # the operator already got its 504: never run it
                return self._agent_reply(200, {"paired": True, "job": dict(job, ttl=left)}, nonce, path)
        if path == RESULT_PATH:
            return self._result(a, meta, body, nonce, path)
        return 404, {}, b'{"error": "unknown agent route"}'

    def _result(self, a, meta, body, nonce, path):
        job_id, status, ctype = meta.get("job_id"), meta.get("status", 500), meta.get("ctype", "application/json")
        if not isinstance(job_id, str) or isinstance(status, bool) or not isinstance(status, int) \
                or not isinstance(ctype, str):
            return self._agent_reply(400, {"error": "bad result metadata"}, nonce, path)
        with self.lock:
            slot = a["results"].get(job_id)
        if slot is None:
            return self._agent_reply(404, {"error": "unknown job"}, nonce, path)
        base, _, rest = ctype.partition(";")
        base, rest = base.strip().lower(), rest.strip().lower()
        if base in RESULT_CTYPES and rest in ("", "charset=utf-8"):
            ctype = base + ("; charset=utf-8" if rest else "")
        else:
            ctype = "application/octet-stream"
        slot.update(status=status if 200 <= status <= 599 else 502, ctype=ctype, body=body)
        slot["done"].set()
        return self._agent_reply(200, {"ok": True}, nonce, path)

    def _agent_reply(self, status, obj, nonce, path):
        body = json.dumps(obj).encode("utf-8")
        meta_b64 = _pack({"nonce": nonce})
        return status, {"X-RK-Meta": meta_b64, "X-RK-Sig": _sig(self.tokens["agent_token"], path, meta_b64, body)}, body

    # ---- operator side
    def _cancel(self, a, job_id):
        with self.lock:
            a["results"].pop(job_id, None)
            now = time.time()
            self.cancelled[job_id] = now
            if len(self.cancelled) > 1000 or len(self.cancelled) % 50 == 0:
                for k in [k for k, t in self.cancelled.items() if now - t > 2 * JOB_TIMEOUT]:
                    del self.cancelled[k]

    def relay(self, aid, method, path, q, body_obj, operator, timeout=JOB_TIMEOUT):
        a = self.agents.get(aid)
        if a is None:
            return 404, "application/json", b'{"error": "unknown agent"}'
        if not a["paired"] or a["revoked"]:
            return 409, "application/json", b'{"error": "agent is not paired (or was revoked)"}'
        job_id = secrets.token_hex(8)
        slot = {"done": threading.Event()}
        with self.lock:
            a["results"][job_id] = slot
        a["jobs"].put({"id": job_id, "method": method, "path": path, "query": q, "body": body_obj, "operator": operator,
                       "expires": time.time() + timeout})
        LOG.info("SERVER| job %s for agent %s by %s: %s %s", job_id, aid, operator, method, path)
        if not slot["done"].wait(timeout):
            self._cancel(a, job_id)
            return 504, "application/json", b'{"error": "the agent did not answer in time"}'
        with self.lock:
            a["results"].pop(job_id, None)
        return slot["status"], slot["ctype"], slot["body"]

    def _operator_call(self, method, path, q, headers, body):
        auth = headers.get("Authorization") or ""
        if not hmac.compare_digest(auth.encode(), ("Bearer " + self.tokens["operator_token"]).encode()):
            return 401, {"WWW-Authenticate": "Bearer"}, b'{"error": "missing or wrong bearer token"}'
        operator = "".join(c for c in (headers.get("X-RK-Operator") or "") if c.isprintable())[:40] or "operator"
        try:
            b = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(b, dict):
                raise ValueError("body must be a JSON object")
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
                             "seconds_since_seen": round(now - a.get("last_seen", now))} for a in list(self.agents.values())])
        if p == "/bundles" and method == "GET":
            out = []
            for root, _, files in os.walk(self.store):
                out += [{"path": os.path.relpath(os.path.join(root, f), self.store).replace("\\", "/"),
                         "size": os.path.getsize(os.path.join(root, f))} for f in files if f.endswith(".zip")]
            return js(200, out)
        if p == "/cases" and method == "GET":
            return js(200, self.cases())
        parts = p.strip("/").split("/", 3)
        if len(parts) >= 3 and parts[0] == "agents":
            aid, verb = parts[1], parts[2]
            a = self.agents.get(aid)
            if a is None:
                return js(404, {"error": "unknown agent"})
            if verb == "pair" and method == "POST":
                want = hashlib.sha256(("%s|%s" % (str(b.get("code", "")).strip(), aid)).encode()).hexdigest()
                with self.lock:                  # check and increment as one step
                    if a["pair_failures"] >= 5:
                        return js(429, {"error": "too many wrong codes; restart the session on the target"})
                    if not hmac.compare_digest(want, a.get("code_hash", "")):
                        a["pair_failures"] += 1
                        LOG.info("SERVER| wrong pairing code for agent %s by %s", aid, operator)
                        return js(403, {"error": "wrong pairing code"})
                a["paired"] = True
                LOG.info("SERVER| agent %s paired by %s", aid, operator)
                return js(200, {"paired": True})
            if verb == "revoke" and method == "POST":
                a["revoked"], a["paired"] = True, False
                a["jobs"].put(None)              # wake a held poll so the agent learns it at once
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
        info = (_json_dict(st) if s2 == 200 else {})
        s3, _, cs = self.relay(aid, "GET", API + "/case", {}, {}, operator)
        case = (_json_dict(cs) if s3 == 200 else {})
        if info is None or case is None:
            return 502, {"error": "the agent sent an answer that is not a JSON object"}
        ticket = "".join(c for c in str(case.get("ticket") or "") if c.isascii() and c.isalnum())[:20]
        status, _, blob = self.relay(aid, "GET", API + "/bundle/download", {}, {}, operator)
        if status != 200:
            return status, {"error": "bundle download failed"}
        try:
            if not blob[:2] == b"PK":
                raise ValueError("does not start with PK")
            bad = zipfile.ZipFile(io.BytesIO(blob)).testzip()
            if bad is not None:
                raise ValueError("corrupt member %s" % bad[:80])
        except Exception as e:  # noqa: BLE001 - anything unreadable is refused
            LOG.info("SERVER| bundle from %s refused: %s", aid, e)
            return 502, {"error": "the agent's bundle is not a readable zip file: %s" % str(e)[:100]}
        case_id = "".join(c for c in str(info.get("case_id") or "") if c.isascii() and (c.isalnum() or c in "-_"))[:64]
        if not case_id or case_id.startswith("_"):
            case_id = "unknown"
        dest_dir = os.path.join(self.store, case_id)
        os.makedirs(dest_dir, exist_ok=True)
        base = "%s-%s" % (case_id, time.strftime("%Y%m%d-%H%M%S"))
        name, k = base + ".zip", 1
        while True:                       # the server names the file and never overwrites one
            dest = os.path.join(dest_dir, name)
            try:
                with open(dest, "xb") as f:
                    f.write(blob)
                break
            except FileExistsError:
                k += 1
                name = "%s-%d.zip" % (base, k)
        out = {"stored": dest, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest(), "intake": None}
        if self.intake and ticket:
            idir = os.path.join(self.intake, "ITW %s" % ticket)
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

    def cases(self):
        """Fleet view: every stored case with its runs, read from the case.json inside each stored bundle."""
        import zipfile
        out = []
        for case_id in sorted(os.listdir(self.store)):
            cdir = os.path.join(self.store, case_id)
            if not os.path.isdir(cdir) or case_id.startswith("_"):
                continue
            runs = []
            for name in sorted(os.listdir(cdir)):
                if not name.endswith(".zip"):
                    continue
                run = {"bundle": "%s/%s" % (case_id, name), "size": os.path.getsize(os.path.join(cdir, name))}
                try:
                    with zipfile.ZipFile(os.path.join(cdir, name)) as z:
                        member = next(n for n in z.namelist() if n.endswith("/case.json") or n == "case.json")
                        if z.getinfo(member).file_size > MAX_CASE_JSON:
                            raise ValueError("case.json is larger than %d MB" % (MAX_CASE_JSON >> 20))
                        d = json.loads(z.read(member).decode("utf-8"))
                    if not isinstance(d, dict):
                        raise ValueError("case.json is not a JSON object")

                    def sub(x, k):
                        v = x.get(k) if isinstance(x, dict) else None
                        return v if isinstance(v, dict) else {}
                    info, disk = sub(sub(d, "target"), "info"), sub(sub(d, "target"), "disk")
                    secs = sub(d, "sections")
                    log = d.get("repair_log")
                    run.update(device_id=sub(d, "device").get("id"), started=d.get("started"), ticket=d.get("ticket"),
                               kit_version=d.get("kit_version"), environment=sub(d, "environment").get("kind"),
                               target="%s %s %s" % (info.get("product") or "?", info.get("build_full") or "",
                                                    info.get("language") or ""),
                               disk=disk.get("model"), booted_after_repair=d.get("booted_after_repair"),
                               sections={n: (s.get("status") if isinstance(s, dict) else None) for n, s in secs.items()},
                               repairs=[r.get("id") for r in (log if isinstance(log, list) else [])
                                        if isinstance(r, dict) and r.get("kind") != "declined"])
                except Exception as e:  # noqa: BLE001 - one bad bundle must not break the fleet view
                    run["error"] = "bundle not readable: %s: %s" % (type(e).__name__, str(e)[:200])
                runs.append(run)
            if runs:
                out.append({"case_id": case_id, "ticket": next((r.get("ticket") for r in runs if r.get("ticket")), None),
                            "runs": runs})
        return out

    def _static(self, path):
        """The browser front end (one self-contained page). No token needed to load it; every API call needs one."""
        web = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
        name = {"/": "index.html", "/index.html": "index.html"}.get(path)
        if name is None:
            return 404, {}, b'{"error": "unknown path"}'
        try:
            with open(os.path.join(web, name), "rb") as f:
                data = f.read()
        except OSError:
            return 404, {}, b'{"error": "the web page is not installed"}'
        return 200, {"Content-Type": "text/html; charset=utf-8", "X-Content-Type-Options": "nosniff",
                     "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                                                "connect-src 'self'; img-src data:; frame-ancestors 'none'"}, data

    def app(self, method, path, q, headers, body):
        if method == "GET" and path in ("/", "/index.html"):
            return self._static(path)
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
            "X-RK-Meta": meta_b64, "X-RK-Sig": _sig(token, path, meta_b64, body),
            "Content-Type": "application/octet-stream", "Content-Length": str(len(body))}, timeout, pin)
        if status == 413:
            raise _TooLarge()
        rmeta = headers.get("X-RK-Meta") or ""
        if not rmeta or not hmac.compare_digest(headers.get("X-RK-Sig") or "", _sig(token, path, rmeta, data)) \
                or _unpack(rmeta).get("nonce") != nonce:
            raise ConnectionError("the server's answer is not signed with the shared token (HTTP %s): wrong token, "
                                  "or this is not the RecoveryKit server" % status)
        obj = _json_dict(data)
        if obj is None:
            raise ConnectionError("the server's answer is not a JSON object")
        return status, obj

    if url.startswith("http://"):
        ui.say("WARNING: no TLS. Traffic is authenticated but NOT encrypted. Use on a trusted LAN only.")
        if pin:
            ui.say("WARNING: --pin is ignored with an http:// URL (there is no certificate to pin). Use https://.")
    code_hash = hashlib.sha256(("%s|%s" % (code, agent_id)).encode()).hexdigest()
    st, hello = call("/agent/v1/hello", {"name": name or (engine.ctx.case.data.get("case_id") or "unpaired"),
                                         "version": __version__, "code_hash": code_hash,
                                         "allow_remote_repairs": engine.allow_remote_repairs})
    if st != 200:
        raise ConnectionError("the server refused this session (HTTP %s): %s" % (st, hello.get("error", "")))
    ui.say("Connected to %s as agent %s." % (url, agent_id))
    _say_secret("PAIRING CODE: %s   (tell it to the operator at the server; nothing is relayed before pairing)" % code)
    LOG.info("AGENT | pairing code shown on the console (not logged)")
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
        received = time.monotonic()
        operator = "%s@server" % "".join(c for c in str(job.get("operator") or "operator") if c.isprintable())[:40]
        ttl = job.get("ttl")
        query, jbody = job.get("query"), job.get("body")
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0:
            LOG.info("AGENT | job %s expired before it reached this agent: not executed", job.get("id"))
            status, data, ctype = 410, b'{"error": "the job had expired; it was not executed"}', "application/json"
        elif not (isinstance(job.get("method"), str) and isinstance(job.get("path"), str)
                  and isinstance(query, (dict, type(None))) and isinstance(jbody, (dict, type(None)))):
            status, data, ctype = 400, b'{"error": "malformed job"}', "application/json"
        elif time.monotonic() - received >= ttl:
            status, data, ctype = 410, b'{"error": "the job had expired; it was not executed"}', "application/json"
        else:
            ui.say("Remote request by %s: %s %s" % (operator, job.get("method"), job.get("path")))
            status, result = route(engine, job["method"], job["path"], query or {}, jbody or {},
                                   remote=True, operator=operator)
            data, ctype = _payload(result)
        meta = {"job_id": job.get("id"), "status": status, "ctype": ctype}
        try:
            if len(data) > MAX_RESULT:
                raise _TooLarge()
            call(RESULT_PATH, meta, data, timeout=300)
        except _TooLarge:
            LOG.error("AGENT | result of job %s is too large for the server (%d bytes)", job.get("id"), len(data))
            err = json.dumps({"error": "the result (%d bytes) is larger than the server accepts" % len(data)}).encode()
            try:
                call(RESULT_PATH, dict(meta, status=413, ctype="application/json"), err, timeout=60)
            except (OSError, ValueError, http.client.HTTPException, _TooLarge) as e:
                LOG.error("AGENT | could not deliver the error result of job %s: %s", job.get("id"), e)
        except (OSError, ValueError, http.client.HTTPException) as e:
            LOG.error("AGENT | could not deliver the result of job %s: %s", job.get("id"), e)
    ui.say("Remote session ended: %s." % reason)
    LOG.info("AGENT | session ended: %s", reason)
    return reason


# ---------------------------------------------------------------- operator client
def ctl(kit_root, argv, out=print, pin=None):
    """run.cmd --ctl [--url URL] [--token T] [--pin SHA256] agents | pair ID CODE | revoke ID | fetch-bundle ID |
    bundles | get ID PATH | post ID PATH [JSON]      (PATH is an agent API path such as /status or /repair/steps)"""
    url, token = "http://127.0.0.1:8765", None
    args = list(argv)
    while len(args) >= 2 and args[0] in ("--url", "--token", "--pin"):
        flag, val = args.pop(0), args.pop(0)
        if flag == "--url":
            url = val.rstrip("/")
        elif flag == "--token":
            token = val
        else:
            pin = val
    if pin and url.startswith("http://"):
        out("WARNING: --pin is ignored with an http:// URL (there is no certificate to pin). Use https://.")
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
    if any(ch.isspace() or ord(ch) < 33 or ch in (":", chr(92)) for ch in path):
        out("Not a valid API path: %r (use for example /status or /repair/steps)" % path)
        return 2
    try:
        status, headers, data = _request(url + API + path, method, body, {
            "Authorization": "Bearer " + token, "Content-Type": "application/json", "Content-Length": str(len(body)),
            "X-RK-Operator": os.environ.get("USERNAME", "operator")}, timeout=JOB_TIMEOUT + 30,
            pin=pin)
    except (OSError, http.client.HTTPException) as e:
        out("Cannot reach the server at %s: %s: %s" % (url, type(e).__name__, e))
        return 1
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
