"""Starts a control server (plain HTTP, 127.0.0.1) plus one connected dry-run agent for the browser smoke test.

Usage: python tests/browser/serve_fixture.py [port]
Prints one JSON line {"url", "operator_token", "agent_id", "pairing_code"}, then waits until stdin closes.
Everything lives in a temp dir; the repo's config/ and cases/ are not touched.
"""
import json
import os
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from recoverykit import net  # noqa: E402
from tests.test_net import make_engine  # noqa: E402


def main():
    out = sys.stdout
    sys.stdout = sys.stderr          # the agent prints its pairing banner; only the JSON line may reach stdout
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    tmp = tmpdir.name
    server = engine = thread = None
    stop = threading.Event()
    try:
        kit = os.path.join(tmp, "serverkit")
        os.makedirs(os.path.join(kit, "config"))
        engine = make_engine(tmp)
        server = net.Server(kit, os.path.join(tmp, "store"), os.path.join(tmp, "intake"), say=lambda m: None)
        url = server.start("127.0.0.1", port, tls=False)
        got = {}
        thread = threading.Thread(target=lambda: net.connect(
            engine, url, server.tokens["agent_token"], minutes=60, stop=stop,
            on_code=lambda a, c: got.update(id=a, code=c)))
        thread.start()
        for _ in range(200):
            if got:
                break
            time.sleep(0.05)
        if not got:
            print("agent did not connect", file=sys.stderr)
            return 1
        print(json.dumps({"url": url, "operator_token": server.tokens["operator_token"],
                          "agent_id": got["id"], "pairing_code": got["code"]}), file=out, flush=True)
        try:
            while sys.stdin.readline():
                pass
        except KeyboardInterrupt:
            pass
    finally:
        stop.set()
        if thread:
            thread.join(15)
        if server:
            server.stop()
        if engine:
            engine.close()
        tmpdir.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
