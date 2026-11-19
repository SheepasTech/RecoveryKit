"""Network and engine hardening (security review 2026-11-19: C6-C13, C15). Each test is a concrete attack.

Servers bind 127.0.0.1 port 0 only. Engines are dry-run; no repair command is ever executed.
"""
import contextlib
import hashlib
import io
import json
import os
import re
import secrets
import socket
import tempfile
import threading
import time
import types
import unittest
import zipfile
from unittest import mock

from recoverykit import __main__ as main_mod
from recoverykit import net
from recoverykit.engine import API, route
from tests.test_net import Base, QuietUI

HELLO = "/agent/v1/hello"
POLL = "/agent/v1/poll"
RESULT = "/agent/v1/result"


def raw_http(port, data, wait=5.0):
    """Send raw bytes, read until the server closes. Returns (status or None, closed_by_server)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=wait)
    try:
        s.sendall(data)
        buf = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    return (int(buf.split(b" ", 2)[1]) if buf else None), True
                buf += chunk
        except socket.timeout:
            return (int(buf.split(b" ", 2)[1]) if buf else None), False
    finally:
        s.close()


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmpdir.cleanup)
        self.tmp = self.tmpdir.name
        self.kit = os.path.join(self.tmp, "kit")
        os.makedirs(os.path.join(self.kit, "config"))
        self.store = os.path.join(self.tmp, "store")
        self.intake = os.path.join(self.tmp, "intake")
        self.server = net.Server(self.kit, self.store, self.intake, say=lambda m: None)
        self.url = self.server.start("127.0.0.1", 0)
        self.port = self.server.httpd.server_address[1]
        self.addCleanup(self.server.stop)
        self.token = self.server.tokens["agent_token"]
        self.op = {"Authorization": "Bearer " + self.server.tokens["operator_token"], "X-RK-Operator": "alice",
                   "Content-Type": "application/json"}

    # signed agent message by hand
    def post(self, path, meta, body=b"", sign_path=None, tok=None):
        m = net._pack(meta)
        return net._request(self.url + path, "POST", body, net._signed_headers(tok or self.token, sign_path or path, m, body))

    def api(self, method, path, body=None, timeout=60):
        data = json.dumps(body).encode() if body is not None else b""
        status, headers, out = net._request(self.url + API + path, method, data,
                                            dict(self.op, **{"Content-Length": str(len(data))}), timeout)
        if headers.get("Content-Type", "").startswith("application/json"):
            return status, json.loads(out)
        return status, out


class FakeAgent:
    """An agent speaking the wire protocol by hand; answers relayed jobs from a table path -> (status, ctype, bytes)."""

    code = "K7QF4-M2XWP"

    def __init__(self, t, answers=None, aid=None):
        self.t, self.answers, self.aid, self.n = t, answers or {}, aid or secrets.token_hex(4), 0
        self.key = t.token                       # the agent token until the server says "switch"
        self.jobs, self.stop = [], threading.Event()
        self.thread = None

    def call(self, path, meta, body=b""):
        self.n += 1
        status, headers, data = self.t.post(path, dict(meta, agent_id=self.aid, n=self.n, nonce=secrets.token_hex(6)), body,
                                            tok=self.key)
        obj = json.loads(data)
        if obj.get("switch") and self.key == self.t.token:
            self.key = net._session_key(self.t.token, self.aid, self.code)
        return status, obj

    def hello(self):
        return self.call(HELLO, {"name": "fake", "code_hash": hashlib.sha256(
            ("%s|%s" % (self.code.replace("-", ""), self.aid)).encode()).hexdigest()})

    def pair(self):
        """hello, the operator's pairing, and the first poll that tells this agent to switch to the session key."""
        self.hello()
        status, out = self.t.api("POST", "/agents/%s/pair" % self.aid, {"code": self.code})
        assert status == 200, out
        status, r = self.call(POLL, {"wait": 0})
        assert (status, r) == (200, {"paired": True, "switch": True}), (status, r)
        assert self.key != self.t.token

    def result(self, job_id, status=200, ctype="application/json", body=b"{}"):
        return self.call(RESULT, {"job_id": job_id, "status": status, "ctype": ctype}, body)

    def serve(self):
        def loop():
            while not self.stop.is_set():
                _, r = self.call(POLL, {"wait": 0.3})
                job = r.get("job")
                if job:
                    self.jobs.append(job)
                    status, ctype, body = self.answers.get(job["path"][len(API):], (404, "application/json", b"{}"))
                    self.result(job["id"], status, ctype, body)
        self.thread = threading.Thread(target=loop)
        self.thread.start()
        self.t.addCleanup(lambda: (self.stop.set(), self.thread.join(10)))


def make_zip(members=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in (members or {"run/case.json": b"{}"}).items():
            z.writestr(k, v)
    return buf.getvalue()


def js(obj):
    return json.dumps(obj).encode()


# ------------------------------------------------------------------ C10
class HttpFraming(ServerCase):
    def test_negative_content_length_is_rejected_and_closed(self):
        status, closed = raw_http(self.port, b"POST /api/v1/agents HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n")
        self.assertEqual((status, closed), (400, True))

    def test_garbage_and_missing_content_length(self):
        for hdr in (b"Content-Length: abc\r\n", b"Content-Length: 1e3\r\n", b"Content-Length: \xc2\xb2\r\n", b""):
            status, closed = raw_http(self.port, b"POST /api/v1/agents HTTP/1.1\r\nHost: x\r\n" + hdr + b"\r\n")
            self.assertEqual((status, closed), (400, True), hdr)
        status, closed = raw_http(self.port, b"POST /api/v1/agents HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
        self.assertEqual((status, closed), (400, True))

    def test_oversized_body_is_refused_before_it_is_read(self):
        head = b"POST /api/v1/agents HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % (net.MAX_BODY + 1)
        self.assertEqual(raw_http(self.port, head), (413, True))
        # only the agent's result route may exceed MAX_BODY (up to MAX_RESULT)
        head = b"POST /agent/v1/result HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % (net.MAX_RESULT + 1)
        self.assertEqual(raw_http(self.port, head), (413, True))

    def test_a_stalled_client_is_dropped(self):
        self.assertEqual(net._Handler.timeout, 30)
        with mock.patch.object(net._Handler, "timeout", 0.5):
            s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            try:
                s.sendall(b"POST /api/v1/agents HTTP/1.1\r\nAuthorization: Bearer " +
                          self.server.tokens["operator_token"].encode() + b"\r\nContent-Length: 100\r\n\r\nabc")   # then silence
                t0 = time.monotonic()
                self.assertEqual(s.recv(100), b"")                  # the server closed it
                self.assertLess(time.monotonic() - t0, 8)
            finally:
                s.close()

    def test_plain_http_still_works(self):
        self.assertEqual(self.api("GET", "/status")[0], 200)


# ------------------------------------------------------------------ C9
class AgentProtocol(ServerCase):
    def test_hello_hijack_with_huge_counter_is_rejected_and_state_kept(self):
        victim = FakeAgent(self)
        victim.pair()
        before = dict(self.server.agents[victim.aid])
        meta = {"agent_id": victim.aid, "nonce": "z", "name": "evil", "code_hash": "evil"}
        # a message with a valid signature but a bad counter (the key is the victim's own)
        for n, want in ((10**18, 400), (2**53, 400), (-5, 400), ("7", 400), (True, 400)):
            self.assertEqual(self.post(HELLO, dict(meta, n=n), tok=victim.key)[0], want, n)
        status, headers, data = self.post(HELLO, dict(meta, n=50), tok=victim.key)
        self.assertEqual(status, 409)
        self.assertEqual(headers["X-RK-Sig"], net._sig(victim.key, HELLO, headers["X-RK-Meta"], data, "resp"))   # signed reply
        a = self.server.agents[victim.aid]
        self.assertTrue(a["paired"])
        self.assertEqual((a["n"], a["name"]), (before["n"], "fake"))
        self.assertEqual(a["code_hash"], before["code_hash"])
        self.assertEqual(victim.call(POLL, {"wait": 0})[0], 200)       # the real agent carries on

    def test_one_message_cannot_burn_the_counter(self):
        victim = FakeAgent(self)
        victim.pair()
        n = self.server.agents[victim.aid]["n"]
        self.assertEqual(self.post(POLL, {"agent_id": victim.aid, "n": n + 1_000_001, "nonce": "z", "wait": 0},
                                   tok=victim.key)[0], 409)
        self.assertEqual(victim.call(POLL, {"wait": 0})[0], 200)

    def test_old_unpaired_entry_can_be_replaced_a_paired_one_never(self):
        a = FakeAgent(self, aid="aaaa0001")
        a.hello()
        self.server.agents["aaaa0001"]["last_seen"] -= 700
        self.assertEqual(self.post(HELLO, {"agent_id": "aaaa0001", "n": 1, "nonce": "q", "name": "new"})[0], 200)
        self.assertEqual(self.server.agents["aaaa0001"]["name"], "new")
        self.server.agents["aaaa0001"]["paired"] = True
        self.server.agents["aaaa0001"]["last_seen"] -= 700
        self.assertEqual(self.post(HELLO, {"agent_id": "aaaa0001", "n": 1, "nonce": "q2", "name": "again"})[0], 409)

    def test_poll_body_replayed_to_hello_fails_the_signature(self):
        a = FakeAgent(self)
        a.hello()
        m = net._pack({"agent_id": a.aid, "n": 2, "nonce": "p1", "wait": 0})
        hdr = net._signed_headers(self.token, POLL, m, b"")
        status, _, _ = net._request(self.url + POLL, "POST", b"", hdr)
        self.assertEqual(status, 200)
        status, _, _ = net._request(self.url + HELLO, "POST", b"", hdr)
        self.assertEqual(status, 401)

    def test_pair_failures_are_counted_under_the_lock(self):
        a = FakeAgent(self)
        a.hello()
        results = []

        def guess():
            results.append(self.api("POST", "/agents/%s/pair" % a.aid, {"code": "999999"})[0])
        ts = [threading.Thread(target=guess) for _ in range(12)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(self.server.agents[a.aid]["pair_failures"], 5)
        self.assertEqual(sorted(results).count(403), 5)


# ------------------------------------------------------------------ A2 session key
class SessionKey(ServerCase):
    def queue_job(self, a, job_id="j1"):
        ag = self.server.agents[a.aid]
        ag["results"][job_id] = {"done": threading.Event()}
        ag["jobs"].put({"id": job_id, "method": "GET", "path": API + "/status", "query": {}, "body": {}, "operator": "x",
                        "expires": time.time() + 100})
        return ag

    def snapshot(self, ag):
        return (ag["n"], ag["last_seen"], ag["jobs"].qsize(), sorted(ag["results"]))

    def test_session_key_is_bound_to_token_agent_and_code(self):
        k = net._session_key(self.token, "aabbccdd", "123456")
        self.assertNotEqual(k, self.token)
        self.assertEqual(len(k), 64)
        self.assertNotEqual(k, net._session_key(self.token, "aabbccdd", "123457"))
        self.assertNotEqual(k, net._session_key(self.token, "aabbccde", "123456"))
        self.assertNotEqual(k, net._session_key("other-token", "aabbccdd", "123456"))

    def test_token_holder_cannot_poll_post_results_or_hello_for_a_paired_agent(self):
        victim = FakeAgent(self)
        victim.pair()
        victim.call(POLL, {"wait": 0})                      # a message signed with the session key: window closed
        ag = self.queue_job(victim)
        before = self.snapshot(ag)
        n = ag["n"]
        for path, extra in ((POLL, {"wait": 0}), (RESULT, {"job_id": "j1", "status": 200, "ctype": "application/json"}),
                            (HELLO, {"name": "evil", "code_hash": "x"})):
            status, headers, data = self.post(path, dict(extra, agent_id=victim.aid, n=n + 1, nonce="z"), b"{}")
            self.assertEqual(status, 401, path)
            self.assertNotIn("X-RK-Sig", headers)
            self.assertEqual(self.snapshot(ag), before, path)          # nothing changed: not n, last_seen, queue
        # a guess at the session key with a wrong code does not work either
        bad = net._session_key(self.token, victim.aid, "000000")
        self.assertEqual(self.post(POLL, {"agent_id": victim.aid, "n": n + 1, "nonce": "z", "wait": 0}, tok=bad)[0], 401)
        self.assertEqual(self.snapshot(ag), before)
        status, r = victim.call(POLL, {"wait": 1})                      # the real agent still gets its job
        self.assertEqual((status, r["job"]["id"]), (200, "j1"))
        self.assertEqual(self.server.agents[victim.aid]["name"], "fake")

    def test_before_the_first_session_message_a_token_poll_only_gets_a_stateless_switch_answer(self):
        victim = FakeAgent(self)
        victim.hello()
        self.assertEqual(self.api("POST", "/agents/%s/pair" % victim.aid, {"code": victim.code})[0], 200)
        ag = self.queue_job(victim)
        before = self.snapshot(ag)
        status, headers, data = self.post(POLL, {"agent_id": victim.aid, "n": 99999, "nonce": "z", "wait": 0})
        self.assertEqual((status, json.loads(data)), (200, {"paired": True, "switch": True}))   # no job, signed with the token
        self.assertEqual(headers["X-RK-Sig"], net._sig(self.token, POLL, headers["X-RK-Meta"], data, "resp"))
        self.assertEqual(self.snapshot(ag), before)
        self.assertEqual(self.post(RESULT, {"agent_id": victim.aid, "n": 99999, "nonce": "z", "job_id": "j1"}, b"{}")[0], 401)
        self.assertEqual(self.post(HELLO, {"agent_id": victim.aid, "n": 99999, "nonce": "z"})[0], 401)
        self.assertEqual(self.snapshot(ag), before)
        status, r = victim.call(POLL, {"wait": 0})          # the real agent: switch, then the job comes with the new key
        self.assertTrue(r["switch"])
        status, r = victim.call(POLL, {"wait": 1})
        self.assertEqual(r["job"]["id"], "j1")
        self.assertEqual(self.post(POLL, {"agent_id": victim.aid, "n": 99999, "nonce": "z", "wait": 0})[0], 401)   # closed now

    def test_nothing_is_relayed_before_pairing(self):
        a = FakeAgent(self)
        a.hello()
        self.assertEqual(self.api("GET", "/agents/%s/api/status" % a.aid)[0], 409)
        self.assertEqual(a.call(POLL, {"wait": 0}), (200, {"paired": False}))

    def test_connect_switches_keys_and_the_whole_session_runs_on_the_session_key(self):
        seen = []
        orig = net._sig

        def spy(key, *a):
            seen.append(key)
            return orig(key, *a)
        eng = types.SimpleNamespace(ctx=types.SimpleNamespace(ui=QuietUI(), case=types.SimpleNamespace(data={})),
                                    allow_remote_repairs=False)
        got, stop = {}, threading.Event()
        with mock.patch.object(net, "_sig", spy), mock.patch.object(net, "route", lambda *a, **k: (200, {"ok": 1})):
            t = threading.Thread(target=net.connect, args=(eng, self.url, self.token),
                                 kwargs={"minutes": 1, "stop": stop, "on_code": lambda i, c: got.update(id=i, code=c)})
            t.start()
            self.addCleanup(lambda: (stop.set(), t.join(15)))
            for _ in range(100):
                if got:
                    break
                time.sleep(0.05)
            self.assertEqual(self.api("POST", "/agents/%s/pair" % got["id"], {"code": got["code"]})[0], 200)
            self.assertEqual(self.api("GET", "/agents/%s/api/status" % got["id"]), (200, {"ok": 1}))
            time.sleep(0.5)
        sk = net._session_key(self.token, got["id"], got["code"])
        self.assertIn(self.token, seen)
        self.assertIn(sk, seen)
        self.assertEqual(seen[-5:].count(sk), 5)            # the end of the session uses the session key only


# ------------------------------------------------------------------ A3 agent table
class AgentTable(ServerCase):
    def test_fresh_table_refuses_new_hello_with_a_signed_429_and_a_stale_entry_makes_room(self):
        ids = []
        for i in range(net.MAX_AGENTS):
            a = FakeAgent(self, aid="%08x" % (0xa0000000 + i))
            self.assertEqual(a.hello()[0], 200)
            ids.append(a.aid)
        extra = FakeAgent(self, aid="eeeeeeee")
        status, headers, data = self.post(HELLO, {"agent_id": "eeeeeeee", "n": 1, "nonce": "q", "name": "x"})
        self.assertEqual(status, 429)
        self.assertEqual(headers["X-RK-Sig"], net._sig(self.token, HELLO, headers["X-RK-Meta"], data, "resp"))
        self.assertEqual(len(self.server.agents), 64)
        self.assertIn(ids[0], self.server.agents)                      # nobody was evicted
        self.server.agents[ids[5]]["last_seen"] -= net.STALE_UNPAIRED + 1
        self.server.agents[ids[6]]["last_seen"] -= net.STALE_UNPAIRED + 50     # the longest silent one goes
        self.assertEqual(extra.hello()[0], 200)
        self.assertNotIn(ids[6], self.server.agents)
        self.assertIn(ids[5], self.server.agents)
        self.assertEqual(len(self.server.agents), 64)
        for a in self.server.agents.values():
            a["paired"] = True
        self.assertEqual(FakeAgent(self, aid="1a7e1a7e").hello()[0], 429)
        self.assertEqual(len(self.server.agents), 64)

    def test_silent_paired_entries_are_pruned_on_hello_and_on_the_agent_list(self):
        for i in range(3):
            a = FakeAgent(self, aid="%08x" % (0xb0000000 + i))
            a.hello()
            self.server.agents[a.aid]["paired"] = True
        for aid in ("b0000000", "b0000001"):
            self.server.agents[aid]["last_seen"] -= net.PAIRED_IDLE + 60
        self.assertEqual(FakeAgent(self, aid="c0000000").hello()[0], 200)
        self.assertEqual(sorted(self.server.agents), ["b0000002", "c0000000"])
        self.server.agents["b0000002"]["last_seen"] -= net.PAIRED_IDLE + 60
        status, listing = self.api("GET", "/agents")
        self.assertEqual([x["id"] for x in listing], ["c0000000"])
        self.assertNotIn("b0000002", self.server.agents)

    def _run_connect(self, on_code=None):
        eng = types.SimpleNamespace(ctx=types.SimpleNamespace(ui=QuietUI(), case=types.SimpleNamespace(data={})),
                                    allow_remote_repairs=False)
        polls = []
        orig_call = self.server._agent_call

        def counting(path, headers, body):
            if path == POLL:
                polls.append(1)
            return orig_call(path, headers, body)
        out = {}
        stop = threading.Event()
        with mock.patch.object(net, "BACKOFF_STEP", 0.01), mock.patch.object(net, "BACKOFF_MAX", 0.02), \
                mock.patch.object(self.server, "_agent_call", counting):
            t0 = time.monotonic()
            out["reason"] = net.connect(eng, self.url, self.token, minutes=1, stop=stop,
                                        on_code=(lambda i, c: on_code(i)) if on_code else None)
            out["seconds"] = time.monotonic() - t0
        out["polls"] = len(polls)
        return out

    def test_connect_treats_a_signed_404_as_a_failure_with_backoff_and_ends_after_five(self):
        out = self._run_connect(lambda aid: self.server.agents.pop(aid))     # the entry was evicted: signed 404s
        self.assertEqual(out["polls"], 5)
        self.assertIn("server unreachable", out["reason"])
        self.assertIn("404", out["reason"])
        self.assertLess(out["seconds"], 10)

    def test_connect_treats_409_and_429_the_same_way(self):
        for status in (409, 429):
            orig = self.server._agent_reply

            def reply(st, obj, nonce, path, key, _s=status, _o=orig):
                if path == POLL:
                    return _o(_s, {"error": "no"}, nonce, path, key)
                return _o(st, obj, nonce, path, key)
            with mock.patch.object(self.server, "_agent_reply", reply):
                out = self._run_connect()
            self.assertEqual(out["polls"], 5, status)
            self.assertIn(str(status), out["reason"])


# ------------------------------------------------------------------ A4 head MAC, limits
class HeadAuth(ServerCase):
    def head_request(self, path, meta, body_len, head_key=None, cl=None):
        """Request headers only (the body is NOT sent), as bytes. head_key None = no X-RK-Head."""
        m = net._pack(meta)
        lines = ["POST %s HTTP/1.1" % path, "Host: x", "X-RK-Meta: %s" % m, "X-RK-Sig: %s" % ("0" * 64),
                 "Content-Length: %d" % (body_len if cl is None else cl)]
        if head_key:
            lines.append("X-RK-Head: %s" % net._head_sig(head_key, path, m, body_len))
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def test_huge_content_length_with_a_bad_head_mac_is_refused_without_reading_the_body(self):
        meta = {"agent_id": "aabbccdd", "n": 1, "nonce": "z", "job_id": "nope"}
        for head_key in (None, "wrong-key"):
            t0 = time.monotonic()
            res = raw_http(self.port, self.head_request(RESULT, meta, 2**30, head_key), wait=10)
            self.assertEqual(res, (401, True), head_key)
            self.assertLess(time.monotonic() - t0, 3)              # answered at once, nothing was waited for

    def test_head_mac_covers_path_and_content_length(self):
        meta = {"agent_id": "aabbccdd", "n": 1, "nonce": "z"}
        # MAC made for 5 bytes but the request says 6: refused before the body
        req = self.head_request(POLL, meta, 5, self.token, cl=6)
        self.assertEqual(raw_http(self.port, req, wait=5), (401, True))
        # MAC made for the poll path used on the hello path
        req = self.head_request(POLL, meta, 5, self.token).replace(b"POST " + POLL.encode(), b"POST " + HELLO.encode())
        self.assertEqual(raw_http(self.port, req, wait=5), (401, True))

    def test_result_limit_is_64_mib_unless_the_job_is_pending_for_that_agent(self):
        a = FakeAgent(self)
        a.pair()
        size = net.MAX_BODY + 1
        meta = {"agent_id": a.aid, "n": 99, "nonce": "z", "job_id": "unknown"}
        req = self.head_request(RESULT, meta, size, a.key)
        self.assertEqual(raw_http(self.port, req, wait=5), (413, True))
        self.server.agents[a.aid]["results"]["j9"] = {"done": threading.Event()}
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            s.sendall(self.head_request(RESULT, dict(meta, job_id="j9"), size, a.key))
            s.settimeout(1)
            with self.assertRaises(socket.timeout):               # accepted: the server now waits for the body
                s.recv(100)
        finally:
            s.close()
        other = FakeAgent(self)
        other.pair()
        req = self.head_request(RESULT, dict(meta, agent_id=other.aid, job_id="j9"), size, other.key)
        self.assertEqual(raw_http(self.port, req, wait=5), (413, True))            # another agent's job id

    def test_slow_drip_body_is_cut_off_at_the_total_deadline(self):
        srv = net.Server(self.kit, os.path.join(self.tmp, "store2"), None, say=lambda m: None)
        srv.start("127.0.0.1", 0, deadline=1.5)
        self.addCleanup(srv.stop)
        port = srv.httpd.server_address[1]
        m = net._pack({"agent_id": "aabbccdd", "n": 1, "nonce": "z", "name": "x"})
        hdr = net._signed_headers(srv.tokens["agent_token"], HELLO, m, b"x" * 200)
        req = ("POST %s HTTP/1.1\r\nHost: x\r\n" % HELLO + "".join("%s: %s\r\n" % kv for kv in hdr.items()) + "\r\n").encode()
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        t0 = time.monotonic()
        sent, closed = 0, False
        try:
            s.sendall(req)
            while time.monotonic() - t0 < 10 and not closed:
                try:
                    s.sendall(b"x")
                    sent += 1
                except OSError:
                    closed = True
                    break
                time.sleep(0.2)                                    # well inside the 30 s socket timeout
                s.setblocking(False)
                try:
                    closed = s.recv(10) == b""
                except BlockingIOError:
                    pass
                except OSError:
                    closed = True
                s.setblocking(True)
            self.assertTrue(closed)
            self.assertLess(time.monotonic() - t0, 4)
            self.assertLess(sent, 100)
        finally:
            s.close()

    def test_connection_cap_gives_503_at_once_and_frees_up(self):
        srv = net.Server(self.kit, os.path.join(self.tmp, "store3"), None, say=lambda m: None)
        url = srv.start("127.0.0.1", 0, max_conn=3, reserve=0)
        self.addCleanup(srv.stop)
        port = srv.httpd.server_address[1]
        idle = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(3)]
        try:
            time.sleep(0.3)
            t0 = time.monotonic()
            self.assertEqual(raw_http(port, b"", wait=5), (503, True))   # the 4th connection of a cap of 3
            self.assertLess(time.monotonic() - t0, 2)
            idle.pop().close()                                     # one slot comes back
            for _ in range(50):
                try:
                    if net._request(url + "/", timeout=5)[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                self.fail("the freed slot was never usable")
        finally:
            for s in idle:
                s.close()
        self.assertEqual(net.MAX_CONNECTIONS, 64)


# ------------------------------------------------------------------ B14 agent id and text
class AgentIdAndText(ServerCase):
    def test_bad_agent_ids_are_400_and_create_no_state(self):
        for bad in ("__proto__", "AABBCCDD", "aabbccd", "aabbccdd0", "aabb ccd", "aabbccd\n", "../x", "", "constructor"):
            status = self.post(HELLO, {"agent_id": bad, "n": 1, "nonce": "z", "name": "x"})[0]
            self.assertEqual(status, 400, repr(bad))
        self.assertEqual(self.server.agents, {})
        self.assertEqual(self.post(HELLO, {"agent_id": "0a1b2c3d", "n": 1, "nonce": "z", "name": "x"})[0], 200)

    def test_name_and_version_are_printable_ascii_and_clipped(self):
        meta = {"agent_id": "0a1b2c3d", "n": 1, "nonce": "z", "name": "ev\nil\x1b[31m‮ nameé" + "x" * 100,
                "version": "1.\r\n2" + "9" * 50}
        self.assertEqual(self.post(HELLO, meta)[0], 200)
        a = self.server.agents["0a1b2c3d"]
        self.assertEqual(len(a["name"]), 60)
        self.assertTrue(a["name"].startswith("evil[31m name"))
        self.assertEqual(a["version"], ("1.2" + "9" * 50)[:20])
        for c in a["name"] + a["version"]:
            self.assertTrue(" " <= c <= "~")


# ------------------------------------------------------------------ C8
class JobExpiry(ServerCase):
    def test_timed_out_job_is_never_delivered(self):
        a = FakeAgent(self)
        a.pair()
        t0 = time.time()
        status, _, _ = self.server.relay(a.aid, "POST", API + "/repair/run", {}, {"id": "x"}, "alice", timeout=0.3)
        self.assertEqual(status, 504)
        self.assertEqual(self.server.agents[a.aid]["results"], {})
        self.assertEqual(len(self.server.cancelled), 1)
        _, r = a.call(POLL, {"wait": 0.2})                         # the stale job is skipped, not handed out
        self.assertEqual(r, {"paired": True})
        self.assertLess(time.time() - t0, 5)

    def test_expired_job_in_the_queue_is_skipped_but_a_fresh_one_is_delivered(self):
        a = FakeAgent(self)
        a.pair()
        q = self.server.agents[a.aid]["jobs"]
        q.put({"id": "old", "method": "GET", "path": API + "/status", "query": {}, "body": {}, "operator": "x",
               "expires": time.time() - 1})
        q.put({"id": "new", "method": "GET", "path": API + "/status", "query": {}, "body": {}, "operator": "x",
               "expires": time.time() + 100})
        _, r = a.call(POLL, {"wait": 0.5})
        self.assertEqual(r["job"]["id"], "new")
        self.assertTrue(0 < r["job"]["ttl"] <= 100)

    def test_agent_refuses_a_job_whose_ttl_ran_out_and_answers_410(self):
        calls = []
        orig = self.server._agent_reply

        def zero_ttl(status, obj, *rest):
            if "job" in obj:
                obj = dict(obj, job=dict(obj["job"], ttl=0))
            return orig(status, obj, *rest)
        self.server._agent_reply = zero_ttl
        eng = types.SimpleNamespace(ctx=types.SimpleNamespace(ui=QuietUI(), case=types.SimpleNamespace(data={})),
                                    allow_remote_repairs=False)
        got, stop = {}, threading.Event()
        with mock.patch.object(net, "route", lambda *a, **k: calls.append(a) or (200, {"ok": 1})):
            t = threading.Thread(target=net.connect, args=(eng, self.url, self.token),
                                 kwargs={"minutes": 1, "stop": stop, "on_code": lambda i, c: got.update(id=i, code=c)})
            t.start()
            self.addCleanup(lambda: (stop.set(), t.join(15)))
            for _ in range(100):
                if got:
                    break
                time.sleep(0.05)
            self.assertEqual(self.api("POST", "/agents/%s/pair" % got["id"], {"code": got["code"]})[0], 200)
            status, out = self.api("POST", "/agents/%s/api/scan" % got["id"], {})
        self.assertEqual(status, 410)
        self.assertEqual(calls, [])                                # nothing ran

    def test_a_live_job_runs_once(self):
        calls = []
        eng = types.SimpleNamespace(ctx=types.SimpleNamespace(ui=QuietUI(), case=types.SimpleNamespace(data={})),
                                    allow_remote_repairs=False)
        got, stop = {}, threading.Event()
        with mock.patch.object(net, "route", lambda *a, **k: calls.append(a) or (200, {"ok": 1})):
            t = threading.Thread(target=net.connect, args=(eng, self.url, self.token),
                                 kwargs={"minutes": 1, "stop": stop, "on_code": lambda i, c: got.update(id=i, code=c)})
            t.start()
            self.addCleanup(lambda: (stop.set(), t.join(15)))
            for _ in range(100):
                if got:
                    break
                time.sleep(0.05)
            self.api("POST", "/agents/%s/pair" % got["id"], {"code": got["code"]})
            self.assertEqual(self.api("GET", "/agents/%s/api/status" % got["id"]), (200, {"ok": 1}))
        self.assertEqual(len(calls), 1)

    def test_oversized_result_is_answered_with_a_small_error(self):
        eng = types.SimpleNamespace(ctx=types.SimpleNamespace(ui=QuietUI(), case=types.SimpleNamespace(data={})),
                                    allow_remote_repairs=False)
        got, stop = {}, threading.Event()
        with mock.patch.object(net, "MAX_RESULT", 2000), \
                mock.patch.object(net, "route", lambda *a, **k: (200, (b"x" * 5000, "application/zip"))):
            t = threading.Thread(target=net.connect, args=(eng, self.url, self.token),
                                 kwargs={"minutes": 1, "stop": stop, "on_code": lambda i, c: got.update(id=i, code=c)})
            t.start()
            self.addCleanup(lambda: (stop.set(), t.join(15)))
            for _ in range(100):
                if got:
                    break
                time.sleep(0.05)
            self.api("POST", "/agents/%s/pair" % got["id"], {"code": got["code"]})
            status, out = self.api("GET", "/agents/%s/api/bundle/download" % got["id"])
            self.assertEqual(status, 413)
            self.assertIn("larger than the server accepts", out["error"])
            head = b"POST /agent/v1/result HTTP/1.1\r\nHost: x\r\nContent-Length: 2001\r\n\r\n"
            self.assertEqual(raw_http(self.port, head), (413, True))


# ------------------------------------------------------------------ C11
class AgentControlledData(ServerCase):
    def relay_http(self, a, status=200, ctype="application/json", body=b"{}", meta_extra=None):
        out = {}

        def op():
            out["r"] = net._request(self.url + API + "/agents/%s/api/status" % a.aid, "GET", b"",
                                    dict(self.op, **{"Content-Length": "0"}), 30)
        t = threading.Thread(target=op)
        t.start()
        job = None
        for _ in range(50):
            _, r = a.call(POLL, {"wait": 0.3})
            if r.get("job"):
                job = r["job"]
                break
        self.assertIsNotNone(job)
        meta = {"job_id": job["id"], "status": status, "ctype": ctype}
        meta.update(meta_extra or {})
        res = a.call(RESULT, meta, body)
        t.join(30)
        return res, out["r"]

    def test_ctype_with_crlf_cannot_inject_a_header(self):
        a = FakeAgent(self)
        a.pair()
        _, (status, headers, data) = self.relay_http(a, ctype="text/html\r\nX-Injected: 1")
        self.assertIsNone(headers.get("X-Injected"))
        self.assertEqual(headers["Content-Type"], "application/octet-stream")

    def test_ctype_whitelist_and_status_clamp(self):
        a = FakeAgent(self)
        a.pair()
        for sent, want in (("application/json; charset=utf-8", "application/json; charset=utf-8"),
                           ("text/markdown; charset=utf-8", "text/markdown; charset=utf-8"),
                           ("application/zip", "application/zip"),
                           ("text/html", "application/octet-stream"),
                           ("application/json; charset=evil", "application/octet-stream")):
            _, (status, headers, _) = self.relay_http(a, ctype=sent)
            self.assertEqual(headers["Content-Type"], want, sent)
        for bad in (99999, 0, 199, 600, -1):
            _, (status, _, _) = self.relay_http(a, status=bad)
            self.assertEqual(status, 502, bad)
        self.assertEqual(self.relay_http(a, status=404)[1][0], 404)

    def test_wrong_metadata_types_are_rejected(self):
        a = FakeAgent(self)
        a.pair()
        out = {}
        t = threading.Thread(target=lambda: out.update(r=self.server.relay(a.aid, "GET", API + "/status", {}, {}, "x", 20)))
        t.start()
        job = None
        for _ in range(50):
            job = a.call(POLL, {"wait": 0.3})[1].get("job")
            if job:
                break
        self.assertIsNotNone(job)
        good = {"job_id": job["id"], "status": 200, "ctype": "application/json"}
        for extra in ({"status": "200"}, {"status": True}, {"ctype": 5}, {"status": [1]}, {"job_id": 7}):
            self.assertEqual(a.call(RESULT, dict(good, **extra))[0], 400, extra)
        self.assertFalse("r" in out)                               # none of them completed the job
        self.assertEqual(a.call(RESULT, good, b"{}")[0], 200)
        t.join(10)
        self.assertEqual(out["r"][0], 200)


class BundleFetch(ServerCase):
    def fetch(self, status_obj=None, case_obj=None, blob=None, bundle_status=200):
        a = FakeAgent(self, {
            "/bundle": (200, "application/json", js({"path": "C:\\x\\..\\notes.md", "size": 1})),
            "/status": (200, "application/json", js(status_obj if status_obj is not None else {"case_id": "ITW-1-A"})
                        if not isinstance(status_obj, bytes) else status_obj),
            "/case": (200, "application/json", js(case_obj if case_obj is not None else {"ticket": "4242"})),
            "/bundle/download": (bundle_status, "application/zip", blob if blob is not None else make_zip())})
        a.pair()
        a.serve()
        return self.api("POST", "/agents/%s/fetch-bundle" % a.aid)

    def stored_files(self):
        return sorted(os.path.relpath(os.path.join(r, f), self.store).replace("\\", "/")
                      for r, _, fs in os.walk(self.store) for f in fs)

    def test_server_generates_the_name_and_never_overwrites(self):
        s1, o1 = self.fetch()
        s2, o2 = self.fetch()
        self.assertEqual((s1, s2), (200, 200), (o1, o2))
        self.assertNotEqual(o1["stored"], o2["stored"])
        for o in (o1, o2):
            self.assertRegex(os.path.basename(o["stored"]), r"^ITW-1-A-\d{8}-\d{6}(-\d+)?\.zip$")
            self.assertEqual(os.path.dirname(o["stored"]), os.path.join(self.store, "ITW-1-A"))
        self.assertEqual(len([f for f in self.stored_files() if f.endswith(".zip")]), 2)
        self.assertEqual(os.path.basename(o1["intake"]), os.path.basename(o1["stored"]))

    def test_hostile_case_ids_stay_inside_their_folder(self):
        for hostile, folder in (("../x.zip", "xzip"), ("..\\..\\evil", "evil"), ("_server-logs", "unknown"),
                                ("_pending", "unknown"), ("", "unknown"), ("???", "unknown"), ("a" * 200, "a" * 64)):
            status, out = self.fetch(status_obj={"case_id": hostile})
            self.assertEqual(status, 200, (hostile, out))
            rel = os.path.relpath(out["stored"], self.store).replace("\\", "/")
            self.assertEqual(rel.split("/")[0], folder, hostile)
            self.assertEqual(len(rel.split("/")), 2)
            self.assertFalse(os.path.exists(os.path.join(self.store, "_server-logs")))
            self.assertFalse(os.path.exists(os.path.join(self.store, "x.zip")))
        self.assertFalse(any(f.endswith("notes.md") for f in self.stored_files()))

    def test_hostile_ticket_is_sanitised_for_the_intake(self):
        status, out = self.fetch(case_obj={"ticket": "../../outside"})
        self.assertEqual(status, 200)
        self.assertEqual(os.path.basename(os.path.dirname(out["intake"])), "ITW outside")
        status, out = self.fetch(case_obj={"ticket": "9" * 40})
        self.assertEqual(os.path.basename(os.path.dirname(out["intake"])), "ITW " + "9" * 20)
        self.assertEqual(os.listdir(self.tmp).count("outside"), 0)

    def test_a_blob_that_is_not_a_zip_is_refused_and_nothing_is_stored(self):
        for blob in (b"<html>hi</html>", b"PK\x03\x04 but not really a zip", b""):
            status, out = self.fetch(blob=blob)
            self.assertEqual(status, 502, blob)
        self.assertEqual([f for f in self.stored_files() if f.endswith(".zip")], [])
        self.assertFalse(os.path.exists(self.intake) and os.listdir(self.intake))

    def test_corrupt_zip_member_is_refused(self):
        good = bytearray(make_zip({"run/case.json": b"x" * 500}))
        good[40] ^= 0xFF                                   # flip a byte inside the stored data
        status, _ = self.fetch(blob=bytes(good))
        self.assertEqual(status, 502)

    def test_zip_bombs_and_huge_directories_are_refused_before_testzip(self):
        def refused(blob):
            with mock.patch.object(zipfile.ZipFile, "testzip", side_effect=AssertionError("testzip must not run")):
                status, out = self.fetch(blob=blob)
            self.assertEqual(status, 502, out)
            self.assertEqual([f for f in self.stored_files() if f.endswith(".zip")], [])
        zeros = {"run/case.json": b"{}", "run/big.bin": b"\x00" * (2 * 2**20)}      # ~2 KiB compressed
        with mock.patch.object(net, "ZIP_RATIO_MIN_SIZE", 2**20):
            refused(make_zip(zeros))                                              # ratio above 1000 and above the size floor
        with mock.patch.object(net, "MAX_ZIP_TOTAL", 2**20):
            refused(make_zip(zeros))                                              # declared total too large
        with mock.patch.object(net, "MAX_ZIP_MEMBERS", 3):
            refused(make_zip({"run/f%d" % i: b"x" for i in range(5)}))            # too many members
        # the real limits accept a normal bundle, and a big but honest member is not a bomb
        self.assertEqual(self.fetch(blob=make_zip({"run/case.json": b"{}", "run/x.bin": os.urandom(100000)}))[0], 200)

    def test_declared_huge_member_is_refused_with_the_real_limits(self):
        blob = make_zip({"run/case.json": b"{}", "run/zeros.bin": b"\x00" * (300 * 2**20)})   # ~300 KiB, 300 MiB declared
        with mock.patch.object(zipfile.ZipFile, "testzip", side_effect=AssertionError("testzip must not run")):
            status, out = self.fetch(blob=blob)
        self.assertEqual(status, 502, out)
        self.assertIn("compression ratio", out["error"])
        self.assertEqual([f for f in self.stored_files() if f.endswith(".zip")], [])

    def test_agent_json_that_is_not_an_object_gives_502(self):
        self.assertEqual(self.fetch(status_obj=[1, 2])[0], 502)
        self.assertEqual(self.fetch(case_obj="text")[0], 502)


# ------------------------------------------------------------------ C12
class CasesView(ServerCase):
    def put(self, case, name, members):
        d = os.path.join(self.store, case)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "wb") as f:
            f.write(make_zip(members))

    def test_bad_bundles_do_not_break_the_fleet_view(self):
        self.put("c1", "list.zip", {"run/case.json": b"[]"})
        self.put("c1", "big.zip", {"run/case.json": b"0" * (30 * 2**20)})
        self.put("c1", "shape.zip", {"run/case.json": js({"sections": {"a": "x"}, "target": [], "repair_log": "no",
                                                            "device": 5, "environment": None})})
        self.put("c1", "list-of-things.zip", {"run/case.json": js({"repair_log": [1, None, {"id": "r", "kind": "ok"}]})})
        self.put("c1", "empty.zip", {"run/other.txt": b"x"})
        with open(os.path.join(self.store, "c1", "garbage.zip"), "wb") as f:
            f.write(b"not a zip")
        status, cases = self.api("GET", "/cases")
        self.assertEqual(status, 200)
        runs = {r["bundle"].split("/")[1]: r for r in cases[0]["runs"]}
        self.assertIn("not a JSON object", runs["list.zip"]["error"])
        self.assertIn("larger than 20 MB", runs["big.zip"]["error"])
        self.assertNotIn("error", runs["shape.zip"])
        self.assertEqual(runs["list-of-things.zip"]["repairs"], ["r"])
        self.assertIn("error", runs["empty.zip"])
        self.assertIn("error", runs["garbage.zip"])


# ------------------------------------------------------------------ C6/C7/C15 engine
class EngineHardening(Base):
    def call(self, method, path, body=None, query=None, remote=False, operator="tester"):
        return route(self.engine, method, API + path, query, body, remote=remote, operator=operator)

    def lettered(self):
        self.call("POST", "/scan", {})
        t = self.engine.ctx.target
        t.letter, t.disk, t.partition = "W", {"number": 9, "style": "GPT", "partitions": []}, {"number": 4}
        return t

    def test_token_is_bound_to_the_listing_and_dies_with_a_rescan(self):
        self.lettered()
        first = self.call("GET", "/repair/steps")[1]["steps"][0]
        second = self.call("GET", "/repair/steps")[1]["steps"][0]
        self.assertEqual(first["command"], second["command"])
        self.assertNotEqual(first["token"], second["token"])               # random per listing
        self.engine.allow_repairs = True
        self.call("POST", "/scan", {})                                     # rescan
        self.lettered()
        status, res = self.call("POST", "/repair/run", {"id": second["id"], "token": second["token"], "confirm": "yes"})
        self.assertEqual(status, 404)
        self.assertIn("list the steps", res["error"])

    def test_repeated_run_is_404_and_the_old_argv_cannot_follow_a_target_change(self):
        from recoverykit.modules import repair
        t = self.lettered()
        self.engine.allow_repairs = True
        step = self.call("GET", "/repair/steps")[1]["steps"][0]
        body = {"id": step["id"], "token": step["token"], "confirm": "yes"}
        with mock.patch.object(repair, "target_check", lambda ctx: (True, "test")):
            self.assertEqual(self.call("POST", "/repair/run", body)[0], 200)
            self.assertEqual(self.call("POST", "/repair/run", body)[0], 404)
            step = self.call("GET", "/repair/steps")[1]["steps"][0]
            t.volume = dict(t.volume or {}, guid_path="\\\\?\\Volume{other}\\")   # another volume is now the target
            status, res = self.call("POST", "/repair/run", {"id": step["id"], "token": step["token"], "confirm": "yes"})
            self.assertEqual(status, 409)
            self.assertIn("target changed", res["error"])

    def test_relayed_body_cannot_spoof_the_operator(self):
        from recoverykit.modules import repair
        self.lettered()
        self.engine.allow_remote_repairs = True
        step = self.call("GET", "/repair/steps")[1]["steps"][0]
        with mock.patch.object(repair, "target_check", lambda ctx: (True, "test")):
            status, _ = self.call("POST", "/repair/run", {"id": step["id"], "token": step["token"], "confirm": "yes",
                                                          "operator": "the-boss"}, remote=True, operator="alice@server")
        self.assertEqual(status, 200)
        note = self.engine.ctx.case.data["repair_log"][-1]["note"]
        self.assertIn("alice@server", note)
        self.assertNotIn("the-boss", note)

    def test_scan_body_types(self):
        for bad in ({"target": 5}, {"target": "CD"}, {"target": "1"}, {"target": ["C"]}, {"ticket": ["x"]},
                    {"ticket": "9" * 21}, {"ticket": True}, {"chkdsk": "yes"}, {"target_path": 5}, {"answers": []},
                    {"answers": {"symptom": 1}}, {"answers": {1: "x"}}):
            self.assertEqual(self.call("POST", "/scan", bad)[0], 400, bad)
        self.assertNotEqual(self.engine.ctx.options.get("target"), 5)
        self.assertFalse(self.engine.scanned)
        self.assertEqual(self.call("POST", "/scan", {"ticket": 4242, "answers": {"symptom": "spinning"}})[0], 200)

    def test_relayed_scan_cannot_set_target_path(self):
        before = self.engine.ctx.options.get("target_path")
        status, res = self.call("POST", "/scan", {"target_path": "C:\\Users"}, remote=True)
        self.assertEqual(status, 403)
        self.assertEqual(self.engine.ctx.options.get("target_path"), before)
        self.assertEqual(self.call("POST", "/scan", {"target_path": before}, remote=False)[0], 200)   # loopback may

    def test_scan_resets_the_runner_when_it_knows_how(self):
        calls = []
        self.engine.ctx.runner.reset_for_scan = lambda: calls.append(1)
        self.call("POST", "/scan", {})
        self.assertEqual(calls, [1])


# ------------------------------------------------------------------ C13 / C15 command line
class CommandLine(unittest.TestCase):
    def test_token_and_pin_never_reach_the_start_line(self):
        for argv in (["--connect", "http://h:1", "--token=SECRET1", "--pin=ABCDEF"],
                     ["--connect", "http://h:1", "--token", "SECRET1", "--pin", "ABCDEF"]):
            line = main_mod.start_line(main_mod.parse_args(argv))
            self.assertNotIn("SECRET1", line)
            self.assertNotIn("ABCDEF", line)
            self.assertIn("<token>", line)
        line = main_mod.start_line(main_mod.parse_args(["--ctl", "--token", "SECRET1", "agents"]))
        self.assertNotIn("SECRET1", line)

    def test_abbreviated_options_are_an_argparse_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for argv in (["--tok", "SECRET1"], ["--conn", "http://h"], ["--tok=SECRET1"]):
                with self.assertRaises(SystemExit) as cm:
                    main_mod.parse_args(argv)
                self.assertEqual(cm.exception.code, 2)

    def test_wipe_case_refuses_internal_names(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as out:
            for name in ("_pending", "_server"):
                os.makedirs(os.path.join(out, name))
                ui = QuietUI()
                self.assertEqual(main_mod.wipe_case(out, name, ui), 2)
                self.assertTrue(os.path.isdir(os.path.join(out, name)))
                self.assertTrue(any("devices" in l and "TEMP" in l for l in ui.lines))
            for evil in ("./_server", ".\\_pending", "x/../_server", "_server/", "sub/ITW-1-A", "sub\\ITW-1-A",
                         "..\\" + os.path.basename(out), "./ITW-1-A"):
                ui = QuietUI()
                ui.confirm_yes = lambda question: self.fail("must not even ask: %r" % evil)
                self.assertEqual(main_mod.wipe_case(out, evil, ui), 2, evil)
                self.assertTrue(os.path.isdir(os.path.join(out, "_server")), evil)
            os.makedirs(os.path.join(out, "ITW-1-A"))
            ui = QuietUI()
            ui.confirm_yes = lambda question: True
            self.assertEqual(main_mod.wipe_case(out, "ITW-1-A", ui), 0)
            self.assertTrue(any("devices" in l and "TEMP" in l for l in ui.lines))

    def test_ctl_strips_control_characters_from_what_the_server_sends(self):
        evil = "ok \x1b[2J\x1b]0;pwned\x07 a\rb\x7f\x9b end\nsecond line"
        for ctype, data in (("text/markdown", evil.encode()), ("application/json", json.dumps({"k": evil}).encode()),
                            ("application/json", b'{"bad": "' + evil.encode() + b'"}'), ("application/octet-stream", b"x")):
            out = []
            with mock.patch.object(net, "_request", lambda *a, **k: (200, {"Content-Type": ctype}, data)):
                net.ctl(tempfile.gettempdir(), ["--url", "http://127.0.0.1:1", "--token", "t", "get", "abc12345", "/report"],
                        out.append)
            text = "\n".join(out)
            for ch in "\x1b\x07\r\x7f\x9b":
                self.assertNotIn(ch, text, (ctype, repr(ch)))
            if ctype == "text/markdown":
                self.assertIn("end\nsecond line", text)

    def test_pin_with_http_warns_in_ctl(self):
        out = []
        net.ctl(tempfile.gettempdir(), ["--url", "http://127.0.0.1:1", "--token", "t", "--pin", "AB", "agents"], out.append)
        self.assertTrue(any("--pin is ignored" in l for l in out))
        out = []
        net.ctl(tempfile.gettempdir(), ["--url", "http://127.0.0.1:1", "--token", "t", "agents"], out.append, pin="AB")
        self.assertTrue(any("--pin is ignored" in l for l in out))


class SecretsStayOutOfLogs(Base):
    def test_pairing_code_is_on_the_console_not_in_the_log(self):
        kit = os.path.join(self.tmp, "serverkit")
        os.makedirs(os.path.join(kit, "config"))
        server = net.Server(kit, os.path.join(self.tmp, "store"), None, say=lambda m: None)
        url = server.start("127.0.0.1", 0)
        self.addCleanup(server.stop)
        got, stop = {}, threading.Event()
        console = io.StringIO()
        with contextlib.redirect_stdout(console):
            t = threading.Thread(target=net.connect, args=(self.engine, url, server.tokens["agent_token"]),
                                 kwargs={"minutes": 1, "stop": stop, "pin": "AB",
                                         "on_code": lambda a, c: got.update(id=a, code=c)})
            t.start()
            for _ in range(100):
                if got:
                    break
                time.sleep(0.05)
            stop.set()
            t.join(15)
        self.assertIn("PAIRING CODE: %s" % got["code"], console.getvalue())
        with open(self.engine.ctx.case.path("debug.log"), encoding="utf-8") as f:
            log = f.read()
        self.assertNotIn("PAIRING CODE: %s" % got["code"], log)
        self.assertNotIn(server.tokens["agent_token"], log)
        self.assertIn("pairing code shown on the console", log)
        self.assertTrue(any("--pin is ignored" in l for l in self.engine.ctx.ui.lines))


# ------------------------------------------------------------------ round 3: pairing code, MAC labels, operator API, results
def agent_engine():
    return types.SimpleNamespace(ctx=types.SimpleNamespace(ui=QuietUI(), case=types.SimpleNamespace(data={})),
                                 allow_remote_repairs=False)


def start_connect(t, eng, **kw):
    """net.connect in a thread; returns (got, stop, thread, result)."""
    got, stop, result = {}, threading.Event(), {}

    def run():
        try:
            result["reason"] = net.connect(eng, t.url, t.token, minutes=1, stop=stop,
                                           on_code=lambda i, c: got.update(id=i, code=c), **kw)
        except Exception as e:  # noqa: BLE001
            result["error"] = e
    th = threading.Thread(target=run)
    th.start()
    t.addCleanup(lambda: (stop.set(), th.join(15)))
    for _ in range(100):
        if got or result:
            break
        time.sleep(0.05)
    return got, stop, th, result


class PairingCode(ServerCase):
    ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    def test_generated_codes_use_the_unambiguous_alphabet(self):
        self.assertEqual(net.PAIR_ALPHABET, self.ALPHABET)
        for ch in "IO01":
            self.assertNotIn(ch, net.PAIR_ALPHABET)
        seen = set()
        for _ in range(300):
            c = net._new_code()
            self.assertRegex(c, r"^[A-HJ-NP-Z2-9]{10}$")
            self.assertRegex(net._show_code(c), r"^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$")
            seen.add(c)
        self.assertGreater(len(seen), 290)                       # random, not a counter or a constant

    def test_connect_shows_the_grouped_code_and_it_pairs(self):
        got, stop, th, result = start_connect(self, agent_engine())
        self.assertRegex(got["code"], r"^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$")
        self.assertEqual(self.api("POST", "/agents/%s/pair" % got["id"], {"code": got["code"]})[0], 200)

    def test_every_spelling_of_the_code_pairs_and_nothing_else_is_mapped(self):
        for typed in ("k7qf4-m2xwp", "K7QF4M2XWP", " k7qf4 m2xwp ", "K7QF4-M2XWP", "k7Qf4 - m2xWp"):
            a = FakeAgent(self)
            a.hello()
            self.assertEqual(self.api("POST", "/agents/%s/pair" % a.aid, {"code": typed})[0], 200, typed)
        a = FakeAgent(self)
        a.hello()
        for wrong in ("K7QF4-M2XWO", "K7QF4-M2XW0", "K7QF4-M2XWP1", "K7QF4", ""):   # O/0 are not mapped to anything
            self.assertEqual(self.api("POST", "/agents/%s/pair" % a.aid, {"code": wrong})[0], 403, wrong)

    def test_key_derivations_use_the_normalised_ten_characters(self):
        k = net._session_key(self.token, "aabbccdd", "K7QF4M2XWP")
        for typed in ("k7qf4-m2xwp", "K7QF4-M2XWP", " k7qf4 m2xwp"):
            self.assertEqual(net._session_key(self.token, "aabbccdd", typed), k)
            self.assertEqual(net._code_hash(typed, "aabbccdd"), net._code_hash("K7QF4M2XWP", "aabbccdd"))
        self.assertEqual(net._code_hash("K7QF4M2XWP", "aabbccdd"),
                         hashlib.sha256(b"K7QF4M2XWP|aabbccdd").hexdigest())
        self.assertNotEqual(net._session_key(self.token, "aabbccdd", "K7QF4M2XWQ"), k)

    def test_ctl_pair_normalises_the_code(self):
        sent = []

        def fake(url, method="GET", body=b"", headers=None, **kw):
            sent.append(json.loads(body))
            return 200, {"Content-Type": "application/json"}, b'{"paired": true}'
        with mock.patch.object(net, "_request", fake):
            net.ctl(self.tmp, ["--url", "http://127.0.0.1:1", "--token", "t", "pair", "aabbccdd", "k7qf4-m2xwp"], lambda m: None)
        self.assertEqual(sent, [{"code": "K7QF4M2XWP"}])


class BadMacRevocation(ServerCase):
    def bad(self, aid, n, kind):
        """One message for agent id `aid` with a wrong MAC. kind: head (wrong X-RK-Head) or sig (right head, wrong sig)."""
        meta = {"agent_id": aid, "n": n, "nonce": "z", "wait": 0}
        m = net._pack(meta)
        hdr = net._signed_headers("not-the-key", POLL, m, b"")
        if kind == "sig":                                     # valid head needs the token while unpaired
            hdr["X-RK-Head"] = net._head_sig(self.token, POLL, m, 0)
        return net._request(self.url + POLL, "POST", b"", hdr)[0]

    def test_twenty_bad_macs_revoke_an_existing_agent_with_a_reason(self):
        a = FakeAgent(self)
        a.pair()
        for i in range(19):
            self.assertEqual(self.bad(a.aid, 100 + i, "head" if i % 2 else "sig"), 401)
        entry = self.server.agents[a.aid]
        self.assertFalse(entry["revoked"])
        self.assertTrue(entry["paired"])
        self.assertEqual(a.call(POLL, {"wait": 0})[0], 200)       # the real agent is still served at 19
        self.assertEqual(self.bad(a.aid, 200, "head"), 401)       # a counted bad MAC again: 20
        listing = {x["id"]: x for x in self.api("GET", "/agents")[1]}[a.aid]
        self.assertTrue(listing["revoked"])
        self.assertEqual(listing["revoked_reason"], "too many invalid signatures")
        self.assertFalse(listing["paired"])
        self.assertEqual(a.call(POLL, {"wait": 0}), (200, {"revoked": True}))     # the agent is told, signed
        self.assertEqual(self.api("GET", "/agents/%s/api/status" % a.aid)[0], 409)

    def test_ids_that_do_not_exist_are_not_counted_and_create_nothing(self):
        for i in range(60):
            self.assertEqual(self.bad("deadbeef", 1 + i, "head"), 401)
        self.assertEqual(self.server.agents, {})
        a = FakeAgent(self)
        a.hello()
        self.assertEqual(self.server.agents[a.aid].get("bad_macs", 0), 0)

    def test_good_traffic_never_counts_and_other_agents_are_not_affected(self):
        a, b = FakeAgent(self), FakeAgent(self)
        a.pair()
        b.pair()
        for i in range(30):
            self.assertEqual(a.call(POLL, {"wait": 0})[0], 200)
        for i in range(19):
            self.bad(b.aid, 100 + i, "head")
        self.assertFalse(self.server.agents[a.aid]["revoked"])
        self.assertFalse(self.server.agents[b.aid]["revoked"])

    def test_the_agent_is_told_to_start_a_new_session(self):
        eng = agent_engine()
        got, stop, th, result = start_connect(self, eng)
        self.assertEqual(self.api("POST", "/agents/%s/pair" % got["id"], {"code": got["code"]})[0], 200)
        for i in range(20):
            self.bad(got["id"], 5000 + i, "head")
        th.join(20)
        self.assertEqual(result.get("reason"), "revoked by the server")
        self.assertTrue(any("start a new session" in l for l in eng.ctx.ui.lines), eng.ctx.ui.lines)


class DirectionLabels(ServerCase):
    def test_request_and_response_macs_differ_by_label(self):
        k, m = "key", net._pack({"nonce": "x"})
        self.assertNotEqual(net._sig(k, POLL, m, b"b"), net._sig(k, POLL, m, b"b", "resp"))
        self.assertEqual(net._sig(k, POLL, m, b"b"), net._sig(k, POLL, m, b"b", "req"))

    def test_a_reflected_request_is_not_accepted_as_a_response(self):
        key, nonce = self.token, "n-reflect"
        meta = net._pack({"agent_id": "aabbccdd", "n": 1, "nonce": nonce})
        req = net._signed_headers(key, POLL, meta, b"{}")
        # an attacker answers with the request's own meta, signature and body
        self.assertFalse(net._reply_ok(key, POLL, req, b"{}", nonce))
        # a real answer from the server is accepted
        a = FakeAgent(self)
        a.hello()
        m = net._pack({"agent_id": a.aid, "n": 9, "nonce": "n2", "wait": 0})
        status, headers, data = net._request(self.url + POLL, "POST", b"", net._signed_headers(self.token, POLL, m, b""))
        self.assertEqual(status, 200)
        self.assertTrue(net._reply_ok(self.token, POLL, headers, data, "n2"))
        self.assertFalse(net._reply_ok(self.token, POLL, headers, data, "other-nonce"))
        self.assertFalse(net._reply_ok("wrong", POLL, headers, data, "n2"))
        self.assertFalse(net._reply_ok(self.token, HELLO, headers, data, "n2"))            # nor on another path
        self.assertEqual(headers["X-RK-Sig"], net._sig(self.token, POLL, headers["X-RK-Meta"], data, "resp"))
        self.assertNotEqual(headers["X-RK-Sig"], net._sig(self.token, POLL, headers["X-RK-Meta"], data, "req"))

    def test_a_server_that_reflects_the_agents_request_is_refused_by_connect(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class Reflect(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                self.send_response(200)
                for h in ("X-RK-Meta", "X-RK-Sig"):
                    self.send_header(h, self.headers[h])
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        httpd = HTTPServer(("127.0.0.1", 0), Reflect)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        eng = agent_engine()
        with self.assertRaises(net.ProtocolError) as cm:
            net.connect(eng, "http://127.0.0.1:%d" % httpd.server_address[1], self.token, minutes=1, stop=threading.Event())
        self.assertIn("not signed", str(cm.exception))


class OperatorApiBeforeBody(ServerCase):
    def head(self, path, cl, token=None, method="POST"):
        lines = ["%s %s HTTP/1.1" % (method, path), "Host: x", "Content-Length: %d" % cl]
        if token:
            lines.append("Authorization: Bearer " + token)
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def test_unauthenticated_posts_announcing_64_mib_get_401_without_a_body_byte(self):
        import tracemalloc
        tracemalloc.start()
        socks = []
        try:
            for i in range(8):
                s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
                s.sendall(self.head("/api/v1/agents/aabbccdd/pair", net.MAX_BODY, "wrong-token" if i % 2 else None))
                socks.append(s)                                      # the body is never sent
            t0 = time.monotonic()
            for s in socks:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = s.recv(4096)
                    self.assertTrue(chunk, "closed without an answer")
                    buf += chunk
                self.assertTrue(buf.startswith(b"HTTP/1.1 401"), buf[:40])
            self.assertLess(time.monotonic() - t0, 3)
            grown = tracemalloc.get_traced_memory()[1]
            self.assertLess(grown, 50 * 2**20)
        finally:
            tracemalloc.stop()
            for s in socks:
                s.close()

    def test_a_valid_token_is_waited_for_and_the_route_still_works(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            s.sendall(self.head("/api/v1/agents/aabbccdd/pair", 100, self.server.tokens["operator_token"]))
            s.settimeout(1)
            with self.assertRaises(socket.timeout):               # accepted: the server now waits for the body
                s.recv(100)
        finally:
            s.close()
        self.assertEqual(self.api("GET", "/status")[0], 200)

    def test_a_get_or_head_with_a_body_is_refused_400(self):
        tok = self.server.tokens["operator_token"]
        req = self.head("/api/v1/status", 5, tok, "GET") + b"hello"
        self.assertEqual(raw_http(self.port, req), (400, True))
        req = self.head("/", 5, None, "GET") + b"hello"
        self.assertEqual(raw_http(self.port, req), (400, True))
        req = self.head("/api/v1/status", 5, tok, "HEAD") + b"hello"
        self.assertIn(raw_http(self.port, req)[0], (400, 501))   # HEAD is not served at all: never read as a body
        self.assertEqual(self.api("GET", "/status")[0], 200)

    def test_agent_routes_and_operator_routes_both_keep_working(self):
        self.assertEqual(FakeAgent(self).hello()[0], 200)
        self.assertEqual(self.api("GET", "/agents")[0], 200)
        self.assertEqual(net._request(self.url + net.API + "/agents")[0], 401)


class ConnectionLimits(ServerCase):
    def start(self, **kw):
        srv = net.Server(self.kit, os.path.join(self.tmp, "store-%d" % len(kw)), None, say=lambda m: None)
        url = srv.start("127.0.0.1", 0, **kw)
        self.addCleanup(srv.stop)
        return url, srv.httpd.server_address[1]

    def idle(self, port, n):
        socks = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(n)]
        self.addCleanup(lambda: [s.close() for s in socks])
        time.sleep(0.3)
        return socks

    def test_per_address_limit_refuses_the_next_connection_of_the_same_address(self):
        url, port = self.start(per_addr=3, exempt=(), reserve=0)
        socks = self.idle(port, 3)
        self.assertEqual(raw_http(port, b"", wait=5), (503, True))
        socks.pop().close()                                      # one slot comes back
        for _ in range(50):
            try:
                if net._request(url + "/", timeout=5)[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            self.fail("the freed slot was never usable")

    def test_the_default_is_eight_per_address_and_loopback_is_exempt(self):
        self.assertEqual(net.PER_ADDRESS_CONNECTIONS, 8)
        self.assertEqual(net.LOOPBACK_ADDRS[0], "127.0.0.1")
        url, port = self.start(per_addr=2)                       # exempt defaults to loopback: 3 idle ones are fine
        self.idle(port, 3)
        self.assertEqual(net._request(url + "/", timeout=5)[0], 200)

    def test_loopback_has_a_reserve_above_the_global_cap(self):
        url, port = self.start(max_conn=2, reserve=3)
        socks = self.idle(port, 5)                               # 2 + 3 reserved slots
        self.assertEqual(raw_http(port, b"", wait=5), (503, True))
        # without loopback being exempt there is no reserve
        url2, port2 = self.start(max_conn=2, reserve=3, exempt=())
        self.idle(port2, 2)
        self.assertEqual(raw_http(port2, b"", wait=5), (503, True))

    def test_the_503_is_delivered_even_when_the_client_already_sent_a_big_request(self):
        url, port = self.start(max_conn=1, reserve=0)
        self.idle(port, 1)
        req = b"POST /api/v1/agents HTTP/1.1\r\nHost: x\r\nContent-Length: 40000\r\n\r\n" + b"x" * 40000
        self.assertEqual(raw_http(port, req, wait=5), (503, True))

    def test_many_refusals_do_not_leak_threads(self):
        url, port = self.start(max_conn=1, reserve=0)
        self.idle(port, 1)
        base = threading.active_count()
        for _ in range(40):
            self.assertEqual(raw_http(port, b"GET / HTTP/1.1\r\n\r\n", wait=5)[0], 503)
        for _ in range(50):
            if threading.active_count() <= base + 1:
                break
            time.sleep(0.1)
        self.assertLessEqual(threading.active_count(), base + 1)


class ResultDeadline(ServerCase):
    def raw_post(self, port, path, key, meta, size, early, late, pause):
        """Headers with a valid head MAC for `size` bytes, then `early` bytes at once, a pause, the rest. Returns the
        status line's code or None when the server closed without answering."""
        body_early = b"x" * early
        body_late = b"x" * late
        m = net._pack(meta)
        hdr = {"X-RK-Meta": m, "X-RK-Sig": "0" * 64, "X-RK-Head": net._head_sig(key, path, m, size),
               "Content-Length": str(size)}
        req = ("POST %s HTTP/1.1\r\nHost: x\r\n" % path + "".join("%s: %s\r\n" % kv for kv in hdr.items()) + "\r\n").encode()
        s = socket.create_connection(("127.0.0.1", port), timeout=15)
        try:
            s.sendall(req + body_early)
            time.sleep(pause)
            try:
                s.sendall(body_late)
            except OSError:
                pass
            buf = b""
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\r\n\r\n" in buf:
                        break
            except OSError:
                pass
            return int(buf.split(b" ", 2)[1]) if buf else None
        finally:
            s.close()

    def test_the_result_route_gets_one_second_per_mib_other_routes_do_not(self):
        self.assertEqual(net.RESULT_SECONDS_PER_MIB, 1)
        srv = net.Server(self.kit, os.path.join(self.tmp, "store-d"), None, say=lambda m: None)
        srv.start("127.0.0.1", 0, deadline=0.5)                  # tiny base deadline
        self.addCleanup(srv.stop)
        port = srv.httpd.server_address[1]
        size = 4 * 2**20
        meta = {"agent_id": "aabbccdd", "n": 1, "nonce": "z", "job_id": "j1", "status": 200}
        tok = srv.tokens["agent_token"]
        # the last 100 KB arrive 1.2 s late: past the 0.5 s base, well inside 0.5 + 4 s
        late = self.raw_post(port, RESULT, tok, meta, size, size - 100000, 100000, 1.2)
        self.assertIsNotNone(late, "an upload slower than the base deadline was cut on the result route")
        # the same delay on any other route is cut at the base deadline (the connection is closed, no answer)
        cut = self.raw_post(port, HELLO, tok, dict(meta, name="x"), size, size - 100000, 100000, 1.2)
        self.assertIsNone(cut)

    def test_a_result_upload_failure_is_answered_with_a_small_502(self):
        for exc in (ConnectionResetError("connection reset by peer"), socket.timeout("timed out")):
            with self.subTest(exc=type(exc).__name__):
                self._upload_fails(lambda orig, exc=exc: self._raise_on_big(orig, exc))

    def test_a_non_200_answer_to_the_result_is_answered_with_a_small_502(self):
        orig = self.server._result

        def refuse(a, meta, body, nonce, path, key):
            if len(body) > 1000:
                return self.server._agent_reply(500, {"error": "disk full"}, nonce, path, key)
            return orig(a, meta, body, nonce, path, key)
        self._upload_fails(None, patch_result=refuse, expect="HTTP 500")

    def _raise_on_big(self, orig, exc):
        def req(url, method="GET", body=b"", *a, **kw):
            if url.endswith(RESULT) and len(body) > 1000:
                raise exc
            return orig(url, method, body, *a, **kw)
        return req

    def _upload_fails(self, make_request, patch_result=None, expect=None):
        eng = agent_engine()
        patches = [mock.patch.object(net, "route", lambda *a, **k: (200, (b"x" * 5000, "application/zip")))]
        if make_request:
            patches.append(mock.patch.object(net, "_request", make_request(net._request)))
        if patch_result:
            patches.append(mock.patch.object(self.server, "_result", patch_result))
        with contextlib.ExitStack() as st:
            for p in patches:
                st.enter_context(p)
            got, stop, th, result = start_connect(self, eng)
            self.assertEqual(self.api("POST", "/agents/%s/pair" % got["id"], {"code": got["code"]})[0], 200)
            t0 = time.monotonic()
            status, out = self.api("GET", "/agents/%s/api/bundle/download" % got["id"])
            self.assertLess(time.monotonic() - t0, 20)            # at once, not after the 1800 s job timeout
            stop.set()
            th.join(15)
        self.assertEqual(status, 502, out)
        self.assertIn("result upload failed", out["error"])
        if expect:
            self.assertIn(expect, out["error"])


class CommandLineRound3(unittest.TestCase):
    def run_main(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main_mod.main(argv)
        return rc, out.getvalue()

    def free_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_url_normalisation(self):
        self.assertEqual(net.normalize_url("HTTPS://Host:8765/"), "https://Host:8765")
        self.assertEqual(net.normalize_url(" Http://10.0.0.1:1 "), "http://10.0.0.1:1")
        for bad in ("127.0.0.1:9", "ftp://x", "//x", "https://", "http://h:99999", "localhost"):
            with self.assertRaises(net.UrlError, msg=bad):
                net.normalize_url(bad)

    def test_pin_normalisation(self):
        good = "ab" * 32
        self.assertEqual(net.normalize_pin(good.upper()), good)
        self.assertEqual(net.normalize_pin(":".join(good[i:i + 2] for i in range(0, 64, 2))), good)
        for bad in ("zz", "ab" * 31, "ab" * 33, "é" * 64, "g" * 64, ""):
            with self.assertRaises(ValueError, msg=bad):
                net.normalize_pin(bad)

    def test_connect_without_a_scheme_is_refused_with_one_line_and_exit_2(self):
        rc, out = self.run_main(["--connect", "127.0.0.1:9", "--token", "t"])
        self.assertEqual(rc, 2)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertIn("http://", out)

    def test_bad_pin_is_exit_2_not_a_traceback(self):
        for pin in ("zz", "é" * 64):
            rc, out = self.run_main(["--connect", "https://127.0.0.1:9", "--token", "t", "--pin", pin])
            self.assertEqual(rc, 2, pin)
            self.assertIn("64 hex", out)
            self.assertEqual(len(out.strip().splitlines()), 1)

    def test_server_down_is_one_line_exit_2_no_traceback_and_the_start_line_is_in_the_case_log(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            url = "HTTP://127.0.0.1:%d" % self.free_port()
            rc, out = self.run_main(["--connect", url, "--token", "SECRET-TOKEN-1", "--no-tls", "--out", tmp])
            self.assertEqual(rc, 2, out)
            self.assertIn("cannot reach the server at http://127.0.0.1:", out)
            self.assertNotIn("Unexpected error", out)
            self.assertIn("--no-tls only applies to --server", out)
            logs = [os.path.join(r, f) for r, _, fs in os.walk(tmp) for f in fs if f == "debug.log"]
            self.assertTrue(logs)
            text = open(logs[0], encoding="utf-8").read()
            self.assertIn("START | RecoveryKit", text)                # also in the case's own debug.log
            self.assertIn("<token>", text)
            self.assertNotIn("SECRET-TOKEN-1", text)

    def test_pin_with_ca_says_the_pin_is_used(self):
        eng = agent_engine()
        with self.assertRaises(OSError):
            net.connect(eng, "https://127.0.0.1:%d" % self.free_port(), "t", pin="ab" * 32, ca_file="whatever.pem",
                        minutes=1, stop=threading.Event())
        self.assertTrue(any("pin is used" in l and "--ca" in l for l in eng.ctx.ui.lines), eng.ctx.ui.lines)
        out = []
        net.ctl(tempfile.gettempdir(), ["--url", "https://127.0.0.1:%d" % self.free_port(), "--token", "t", "--pin", "ab" * 32,
                                        "--ca", "whatever.pem", "agents"], out.append)
        self.assertTrue(any("pin is used" in l for l in out), out)

    def test_ctl_server_down_and_bad_urls(self):
        out = []
        rc = net.ctl(tempfile.gettempdir(), ["--url", "http://127.0.0.1:%d" % self.free_port(), "--token", "t", "agents"],
                     out.append)
        self.assertEqual(rc, 2)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].startswith("cannot reach the server at http://127.0.0.1:"), out)
        out = []
        self.assertEqual(net.ctl(tempfile.gettempdir(), ["--url", "127.0.0.1:9", "--token", "t", "agents"], out.append), 2)
        self.assertEqual(len(out), 1)
        out = []
        self.assertEqual(net.ctl(tempfile.gettempdir(), ["--url", "https://127.0.0.1:9", "--token", "t", "--pin", "zz",
                                                         "agents"], out.append), 2)
        self.assertIn("64 hex", out[0])

    def test_help_examples_use_https(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            with self.assertRaises(SystemExit):
                main_mod.parse_args(["--help"])
        self.assertIn("https://192.168.1.10:8765", buf.getvalue().replace("\n", " ").replace("  ", ""))
        self.assertNotIn("e.g. http://", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
