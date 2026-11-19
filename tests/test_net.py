"""Engine API, loopback agent API, control server and the outbound agent session, all on 127.0.0.1.

The target is a fake offline Windows folder (tests/fakewin.py). Repairs run in dry-run only.
"""
import json
import os
import tempfile
import threading
import time
import unittest
import zipfile

from recoverykit import net
from recoverykit.core.ui import UI
from recoverykit.engine import API, Engine, route
from tests import fakewin

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class QuietUI(UI):
    def __init__(self):
        super().__init__(auto=True)
        self.lines = []

    def say(self, text=""):
        self.lines.append(str(text))

    raw = say


def make_engine(tmp, **kw):
    fakewin.make_target(os.path.join(tmp, "target"))
    return Engine(ROOT, os.path.join(tmp, "cases"), QuietUI(), dry_run=True,
                  options={"ticket": "4242", "target_path": os.path.join(tmp, "target"), "answers": {}}, **kw)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.tmp = self.tmpdir.name
        self.engine = make_engine(self.tmp)
        self.addCleanup(self.tmpdir.cleanup)
        self.addCleanup(self.engine.close)


class EngineRoutes(Base):
    def call(self, method, path, body=None, query=None, remote=False):
        return route(self.engine, method, API + path, query, body, remote=remote, operator="tester")

    def test_scan_and_read_routes(self):
        self.assertEqual(self.call("GET", "/status")[1]["scanned"], False)
        status, sections = self.call("POST", "/scan", {"answers": {"symptom": "repair_loop"}})
        self.assertEqual(status, 200)
        self.assertEqual(sections["target"]["status"], "ok")
        st = self.call("GET", "/status")[1]
        self.assertTrue(st["scanned"])
        self.assertTrue(st["case_id"].startswith("ITW-4242-"))
        case = self.call("GET", "/case")[1]
        self.assertEqual(case["target"]["info"]["build_full"], "10.0.26100.8875")
        self.assertEqual(case["target"]["info"]["language"], "en-US")
        self.assertEqual(case["operator_answers"]["symptom"], "repair_loop")
        files = [f["path"] for f in self.call("GET", "/files")[1]]
        self.assertIn("logs/target-Logs_CBS_CBS.log", files)
        self.assertIn("report.md", files)
        data, ctype = self.call("GET", "/files/logs/target-Logs_CBS_CBS.log")[1]
        self.assertTrue(data.startswith(b"cbs line"))
        report, ctype = self.call("GET", "/report")[1]
        self.assertIn(b"## 5. Suggested next steps", report)
        self.assertIn(b"does not claim the target is fixed", report)
        self.assertTrue(self.call("GET", "/suggestions")[1]["suggestions"])
        self.assertTrue(self.call("GET", "/audit")[1])
        self.assertIn("SECTION|", self.call("GET", "/log")[1]["text"])
        self.assertEqual(self.engine.ctx.case.data["read_only_check"]["changed"], [])

    def test_rescan_keeps_the_run_folder(self):
        self.call("POST", "/scan", {})
        d = self.engine.ctx.case.dir
        self.call("POST", "/scan", {})
        self.assertEqual(self.engine.ctx.case.dir, d)

    def test_bad_requests(self):
        self.assertEqual(self.call("GET", "/nope")[0], 404)
        self.assertEqual(route(self.engine, "GET", "/etc/passwd")[0], 404)
        self.assertEqual(route(self.engine, "DELETE", API + "/case")[0], 405)
        self.call("POST", "/scan", {})
        for evil in ("/files/../../../config/kit.toml", "/files/..%5c..%5cx", "/files/C:/Windows/win.ini",
                     "/files/nope.txt"):
            self.assertEqual(self.call("GET", evil)[0], 404, evil)
        self.assertEqual(self.call("POST", "/answers", {"symptom": "explode"})[0], 400)
        self.assertEqual(self.call("POST", "/answers", {"hack": "x"})[0], 400)
        self.assertEqual(self.call("POST", "/answers", {"firmware_sees_disk": "no"})[0], 200)
        self.assertEqual(self.call("POST", "/boot-result", {"booted": "maybe"})[0], 400)
        self.assertEqual(self.call("GET", "/bundle/download")[0], 404)

    def test_repairs_need_enable_token_and_confirm(self):
        from recoverykit.modules import repair
        self.call("POST", "/scan", {})
        t = self.engine.ctx.target                       # make the fake target look like a lettered volume
        t.letter, t.disk, t.partition = "W", {"number": 9, "style": "GPT", "partitions": []}, {"number": 4}
        steps = self.call("GET", "/repair/steps")[1]["steps"]
        ids = [s["id"] for s in steps]
        self.assertEqual(ids, ["scanhealth", "restorehealth", "sfc", "list_packages"])
        scan = steps[0]
        self.assertIn("/ScanHealth", scan["command"])
        body = {"id": "scanhealth", "token": scan["token"], "confirm": "yes"}
        self.assertEqual(self.call("POST", "/repair/run", body)[0], 403)            # not enabled on the target
        self.engine.allow_repairs = True
        self.assertEqual(self.call("POST", "/repair/run", body, remote=True)[0], 403)  # remote needs its own enable
        self.assertEqual(self.call("POST", "/repair/run", dict(body, token="0" * 12))[0], 409)
        self.assertEqual(self.call("POST", "/repair/run", dict(body, confirm="y"))[0], 409)
        self.assertEqual(self.call("POST", "/repair/run", dict(body, id="format"))[0], 404)
        status, res = self.call("POST", "/repair/run", body)                         # real target re-check refuses
        self.assertEqual(status, 409)
        self.assertIn("target re-check failed", res["error"])
        original = repair.target_check
        repair.target_check = lambda ctx: (True, "test")
        try:
            status, res = self.call("POST", "/repair/run", body)
        finally:
            repair.target_check = original
        self.assertEqual(status, 200)
        self.assertEqual(res["result"]["kind"], "dry-run")                           # confirmed, logged, not executed
        self.assertFalse(self.engine.ctx.runner.repairs_enabled)
        kinds = [a["kind"] for a in self.call("GET", "/audit")[1]]
        self.assertEqual(kinds.count("dry-run"), 1)
        self.assertNotIn("repair", kinds)
        self.assertEqual(self.engine.ctx.case.data["repair_log"][-1]["note"], "confirmed through the API by tester")

    def test_remote_sessions_are_read_only(self):
        for p in ("/whatever", "/repair/unknown"):
            self.assertEqual(self.call("POST", p, {}, remote=True)[0], 403)
        self.assertEqual(self.call("GET", "/status", remote=True)[0], 200)


class LoopbackHttp(Base):
    def test_token_required_and_scan_over_http(self):
        got, stop = {}, threading.Event()
        t = threading.Thread(target=net.serve_local, args=(self.engine, 0),
                             kwargs={"ready": lambda port, token: got.update(port=port, token=token), "stop": stop})
        t.start()
        try:
            for _ in range(100):
                if got:
                    break
                time.sleep(0.05)
            base = "http://127.0.0.1:%d%s" % (got["port"], API)
            self.assertEqual(net._request(base + "/status")[0], 401)
            self.assertEqual(net._request(base + "/status", headers={"Authorization": "Bearer wrong"})[0], 401)
            h = {"Authorization": "Bearer " + got["token"], "Content-Type": "application/json"}
            status, _, data = net._request(base + "/status", headers=h)
            self.assertEqual((status, json.loads(data)["scanned"]), (200, False))
            body = json.dumps({"answers": {"symptom": "spinning"}}).encode()
            status, _, data = net._request(base + "/scan", "POST", body, dict(h, **{"Content-Length": str(len(body))}), 120)
            self.assertEqual(status, 200, data[:300])
            status, hdrs, data = net._request(base + "/report", headers=h)
            self.assertEqual(status, 200)
            self.assertTrue(hdrs["Content-Type"].startswith("text/markdown"))
            self.assertEqual(net._request(base + "/scan", "POST", b"not json", dict(h, **{"Content-Length": "8"}))[0], 400)
            self.assertEqual(net._request("http://127.0.0.1:%d/" % got["port"], headers=h)[0], 404)
            self.assertNotIn(got["token"], open(self.engine.ctx.case.path("debug.log"), encoding="utf-8").read())
        finally:
            stop.set()
            t.join(10)


class ServerAndAgent(Base):
    def setUp(self):
        super().setUp()
        self.kit = os.path.join(self.tmp, "serverkit")           # the server keeps its tokens under <kit>/config
        os.makedirs(os.path.join(self.kit, "config"))
        self.intake = os.path.join(self.tmp, "intake")
        self.msgs = []
        self.server = net.Server(self.kit, os.path.join(self.tmp, "store"), self.intake, say=self.msgs.append)
        self.url = self.server.start("127.0.0.1", 0)
        self.addCleanup(self.server.stop)
        self.op = {"Authorization": "Bearer " + self.server.tokens["operator_token"], "X-RK-Operator": "alice",
                   "Content-Type": "application/json"}

    def api(self, method, path, body=None, timeout=120):
        data = json.dumps(body).encode() if body is not None else b""
        status, headers, out = net._request(self.url + API + path, method, data,
                                            dict(self.op, **{"Content-Length": str(len(data))}), timeout)
        if headers.get("Content-Type", "").startswith("application/json"):
            return status, json.loads(out)
        return status, out

    def start_agent(self, token=None):
        got, stop, result = {}, threading.Event(), {}

        def run():
            try:
                result["reason"] = net.connect(self.engine, self.url, token or self.server.tokens["agent_token"],
                                               minutes=5, stop=stop, on_code=lambda a, c: got.update(id=a, code=c))
            except Exception as e:  # noqa: BLE001
                result["error"] = e
        t = threading.Thread(target=run)
        t.start()
        for _ in range(100):
            if got or result:
                break
            time.sleep(0.05)
        self.addCleanup(lambda: (stop.set(), t.join(15)))
        return got, stop, result, t

    def test_tokens_file_and_operator_auth(self):
        self.assertTrue(os.path.isfile(os.path.join(self.kit, "config", "token-server.json")))
        self.assertEqual(net._request(self.url + API + "/agents")[0], 401)
        self.assertEqual(self.api("GET", "/agents"), (200, []))
        self.assertEqual(self.api("GET", "/status")[1]["role"], "server")

    def test_wrong_agent_token_cannot_connect(self):
        got, stop, result, t = self.start_agent(token="not-the-token")
        t.join(10)
        self.assertIsInstance(result.get("error"), ConnectionError)
        self.assertEqual(self.api("GET", "/agents")[1], [])

    def test_full_remote_session(self):
        got, stop, result, t = self.start_agent()
        aid = got["id"]
        agents = self.api("GET", "/agents")[1]
        self.assertEqual([(a["id"], a["paired"]) for a in agents], [(aid, False)])
        self.assertTrue(any(aid in m for m in self.msgs))
        self.assertEqual(self.api("GET", "/agents/%s/api/status" % aid)[0], 409)      # nothing before pairing
        self.assertEqual(self.api("POST", "/agents/%s/pair" % aid, {"code": "000000x"})[0], 403)
        self.assertEqual(self.api("POST", "/agents/%s/pair" % aid, {"code": got["code"]}), (200, {"paired": True}))
        status, st = self.api("GET", "/agents/%s/api/status" % aid)
        self.assertEqual((status, st["scanned"]), (200, False))
        status, sections = self.api("POST", "/agents/%s/api/scan" % aid, {"answers": {"symptom": "repair_loop"}})
        self.assertEqual(status, 200, sections)
        self.assertEqual(sections["target"]["status"], "ok")
        status, report = self.api("GET", "/agents/%s/api/report" % aid)
        self.assertIn(b"# RecoveryKit case ITW-4242-", report)
        # read-only session: no repair, no unknown POST
        status, steps = self.api("GET", "/agents/%s/api/repair/steps" % aid)
        self.assertEqual(status, 200)
        self.assertEqual(self.api("POST", "/agents/%s/api/repair/run" % aid,
                                  {"id": "scanhealth", "token": "x", "confirm": "yes"})[0], 403)
        self.assertEqual(self.api("POST", "/agents/%s/api/whatever" % aid, {})[0], 403)
        # bundle retrieval into the store and the intake folder
        status, b = self.api("POST", "/agents/%s/fetch-bundle" % aid)
        self.assertEqual(status, 200, b)
        self.assertTrue(os.path.isfile(b["stored"]))
        with zipfile.ZipFile(b["stored"]) as z:
            names = z.namelist()
        self.assertTrue(any(n.endswith("/case.json") for n in names))
        self.assertTrue(any(n.endswith("/audit.log") for n in names))
        self.assertTrue(b["intake"] and os.path.isfile(b["intake"]))
        self.assertEqual(os.path.basename(os.path.dirname(b["intake"])), "ITW 4242")
        self.assertEqual(len(self.api("GET", "/bundles")[1]), 1)
        cases = self.api("GET", "/cases")[1]                                           # fleet view from the store
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["ticket"], "4242")
        run = cases[0]["runs"][0]
        self.assertIn("10.0.26100.8875", run["target"])
        self.assertEqual(run["sections"]["target"], "ok")
        self.assertIsNone(run["booted_after_repair"])
        # the relayed calls are in the agent's own log with the operator's name
        with open(self.engine.ctx.case.path("debug.log"), encoding="utf-8") as f:
            log = f.read()
        self.assertIn("relayed POST /api/v1/scan by alice@server", log)
        # revocation ends the session on the agent
        self.assertEqual(self.api("POST", "/agents/%s/revoke" % aid)[0], 200)
        t.join(15)
        self.assertEqual(result.get("reason"), "revoked by the server")
        self.assertEqual(self.api("GET", "/agents/%s/api/status" % aid)[0], 409)

    def test_replayed_and_forged_agent_messages_are_rejected(self):
        token = self.server.tokens["agent_token"]

        def post(path, meta, body=b"", tok=token):
            m = net._pack(meta)
            return net._request(self.url + path, "POST", body, {"X-RK-Meta": m, "X-RK-Sig": net._sig(tok, m, body),
                                                                "Content-Length": str(len(body))})
        hello = {"agent_id": "aaaa1111", "n": 1, "nonce": "n1", "name": "x", "code_hash": "h"}
        self.assertEqual(post("/agent/v1/hello", hello)[0], 200)
        self.assertEqual(post("/agent/v1/hello", hello)[0], 409)                      # replay
        self.assertEqual(post("/agent/v1/poll", {"agent_id": "aaaa1111", "n": 2, "nonce": "n2"}, tok="bad")[0], 401)
        self.assertEqual(post("/agent/v1/poll", {"agent_id": "zzzz", "n": 1, "nonce": "n"})[0], 404)
        status, headers, data = post("/agent/v1/poll", {"agent_id": "aaaa1111", "n": 2, "nonce": "n2", "wait": 0})
        self.assertEqual(status, 200)
        self.assertEqual(net._unpack(headers["X-RK-Meta"])["nonce"], "n2")            # answer bound to our nonce
        self.assertEqual(headers["X-RK-Sig"], net._sig(token, headers["X-RK-Meta"], data))
        for _ in range(5):                                                            # pairing code guessing is capped
            self.assertEqual(self.api("POST", "/agents/aaaa1111/pair", {"code": "123456"})[0], 403)
        self.assertEqual(self.api("POST", "/agents/aaaa1111/pair", {"code": "123456"})[0], 429)

    def test_ctl_client(self):
        got, stop, result, t = self.start_agent()
        out = []
        base = ["--url", self.url, "--token", self.server.tokens["operator_token"]]
        self.assertEqual(net.ctl(self.kit, base + ["pair", got["id"], got["code"]], out.append), 0)
        self.assertEqual(net.ctl(self.kit, base + ["get", got["id"], "/status"], out.append), 0)
        self.assertIn('"scanned": false', out[-1])
        self.assertEqual(net.ctl(self.kit, base + ["agents"], out.append), 0)
        self.assertEqual(net.ctl(self.kit, base + ["nonsense"], out.append), 2)
        self.assertEqual(net.ctl(self.kit, ["--url", self.url, "agents"], out.append), 0)  # token from the kit's file


if __name__ == "__main__":
    unittest.main()
