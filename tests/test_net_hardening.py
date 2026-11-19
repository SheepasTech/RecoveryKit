"""Network and engine hardening (security review 2026-11-19: C6-C13, C15). Each test is a concrete attack.

Servers bind 127.0.0.1 port 0 only. Engines are dry-run; no repair command is ever executed.
"""
import contextlib
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
        return net._request(self.url + path, "POST", body, {
            "X-RK-Meta": m, "X-RK-Sig": net._sig(tok or self.token, sign_path or path, m, body),
            "Content-Length": str(len(body))})

    def api(self, method, path, body=None, timeout=60):
        data = json.dumps(body).encode() if body is not None else b""
        status, headers, out = net._request(self.url + API + path, method, data,
                                            dict(self.op, **{"Content-Length": str(len(data))}), timeout)
        if headers.get("Content-Type", "").startswith("application/json"):
            return status, json.loads(out)
        return status, out


class FakeAgent:
    """An agent speaking the wire protocol by hand; answers relayed jobs from a table path -> (status, ctype, bytes)."""

    def __init__(self, t, answers=None, aid=None):
        self.t, self.answers, self.aid, self.n = t, answers or {}, aid or secrets.token_hex(4), 0
        self.jobs, self.stop = [], threading.Event()
        self.thread = None

    def call(self, path, meta, body=b""):
        self.n += 1
        status, headers, data = self.t.post(path, dict(meta, agent_id=self.aid, n=self.n, nonce=secrets.token_hex(6)), body)
        return status, json.loads(data)

    def hello(self):
        return self.call(HELLO, {"name": "fake", "code_hash": "x"})

    def pair(self):
        self.hello()
        self.t.server.agents[self.aid]["paired"] = True

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
                s.sendall(b"POST /api/v1/agents HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc")   # then silence
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
        self.assertEqual(self.post(HELLO, dict(meta, n=10**18))[0], 400)
        self.assertEqual(self.post(HELLO, dict(meta, n=2**53))[0], 400)
        self.assertEqual(self.post(HELLO, dict(meta, n=-5))[0], 400)
        self.assertEqual(self.post(HELLO, dict(meta, n="7"))[0], 400)
        self.assertEqual(self.post(HELLO, dict(meta, n=True))[0], 400)
        status, headers, data = self.post(HELLO, dict(meta, n=50))
        self.assertEqual(status, 409)
        self.assertEqual(headers["X-RK-Sig"], net._sig(self.token, HELLO, headers["X-RK-Meta"], data))   # signed reply
        a = self.server.agents[victim.aid]
        self.assertTrue(a["paired"])
        self.assertEqual((a["n"], a["name"], a["code_hash"]), (before["n"], "fake", "x"))
        self.assertEqual(victim.call(POLL, {"wait": 0})[0], 200)       # the real agent carries on

    def test_one_message_cannot_burn_the_counter(self):
        victim = FakeAgent(self)
        victim.pair()
        n = self.server.agents[victim.aid]["n"]
        self.assertEqual(self.post(POLL, {"agent_id": victim.aid, "n": n + 1_000_001, "nonce": "z", "wait": 0})[0], 409)
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
        sig = net._sig(self.token, POLL, m, b"")
        status, _, _ = net._request(self.url + POLL, "POST", b"", {"X-RK-Meta": m, "X-RK-Sig": sig, "Content-Length": "0"})
        self.assertEqual(status, 200)
        status, _, _ = net._request(self.url + HELLO, "POST", b"", {"X-RK-Meta": m, "X-RK-Sig": sig, "Content-Length": "0"})
        self.assertEqual(status, 401)

    def test_agent_cap(self):
        ids = []
        for i in range(net.MAX_AGENTS):
            a = FakeAgent(self, aid="a%03d" % i)
            self.assertEqual(a.hello()[0], 200)
            ids.append(a.aid)
        self.assertEqual(len(self.server.agents), 64)
        extra = FakeAgent(self, aid="extra")
        self.assertEqual(extra.hello()[0], 200)                     # the oldest unpaired entry made room
        self.assertEqual(len(self.server.agents), 64)
        self.assertNotIn(ids[0], self.server.agents)
        for a in self.server.agents.values():
            a["paired"] = True
        self.assertEqual(FakeAgent(self, aid="late").hello()[0], 429)
        self.assertEqual(len(self.server.agents), 64)

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

        def zero_ttl(status, obj, nonce, path):
            if "job" in obj:
                obj = dict(obj, job=dict(obj["job"], ttl=0))
            return orig(status, obj, nonce, path)
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
            os.makedirs(os.path.join(out, "ITW-1-A"))
            ui = QuietUI()
            ui.confirm_yes = lambda question: True
            self.assertEqual(main_mod.wipe_case(out, "ITW-1-A", ui), 0)
            self.assertTrue(any("devices" in l and "TEMP" in l for l in ui.lines))

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


if __name__ == "__main__":
    unittest.main()
