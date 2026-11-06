"""Boot a throwaway local stack for the .npc e2e proof.

A fresh NPC Verification API (own temp database and TEST keys,
nothing shared with any other local state) plus the dashboard
preview pointed at it, on loopback only:

    API        http://127.0.0.1:8799
    Dashboard  http://127.0.0.1:8790

Usage: NPC_E2E_DIR=/tmp/npc-e2e python3 npc_e2e_stack.py
Prints READY when both servers answer, then serves until killed.
The stack directory is left in place for npc_e2e_validate.py,
which loads the same keys to verify the downloaded .npc file.
"""
import os
import sys
import threading
from http.server import ThreadingHTTPServer

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.dirname(BASE))
sys.path.insert(0, os.path.normpath(os.path.join(BASE, "..", "api")))

from npc_verify.server import create_app, Handler as ApiHandler  # noqa: E402
from npc_verify.seed import seed_all  # noqa: E402
from dashboard.server import make_handler  # noqa: E402

API_PORT = 8799
DASH_PORT = 8790


def main():
    work = os.environ.get("NPC_E2E_DIR") or "/tmp/npc-e2e"
    os.makedirs(work, exist_ok=True)
    db_path = os.path.join(work, "e2e.db")
    keys_dir = os.path.join(work, "keys")
    app = create_app(db_path, keys_dir)
    seeded = seed_all(app.store, app.keys)

    ApiHandler.app = app
    api_server = ThreadingHTTPServer(("127.0.0.1", API_PORT), ApiHandler)
    threading.Thread(target=api_server.serve_forever, daemon=True).start()

    api_url = "http://127.0.0.1:%d" % API_PORT
    handler = make_handler(api_url, seeded["verifier_key"])
    dash_server = ThreadingHTTPServer(("127.0.0.1", DASH_PORT), handler)
    threading.Thread(target=dash_server.serve_forever,
                     daemon=True).start()

    print("READY api=%s dash=http://127.0.0.1:%d dir=%s"
          % (api_url, DASH_PORT, work), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
