"""Cold-start bootstrap for the demo API (api.npclabs.xyz).

Builds the NPC Verification API v1 app on an in-memory SQLite database,
registers the build-time demo signing keys (retiring the random bootstrap
keys), seeds the demo fixtures, installs the demo verifier API key, and
keeps ONLY the read-only demo routes. Write endpoints (attestation
issuance, memory writes) are removed before serving.
"""
import base64
import json
import os
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# Routes kept for the public demo surface (method, sample path).
_KEEP = [
    ("GET", "/v1/health"),
    ("GET", "/v1/keys"),
    ("GET", "/v1/credentials/demo-cred-001"),
    ("POST", "/v1/claims/verify"),
    ("GET", "/v1/products/demo-tag-001"),
    ("GET", "/v1/agents/demo-agent-001/attestation"),
]


def _load_env():
    override = os.environ.get("NPC_DEMO_ENV_JSON")
    if override:
        return json.loads(override)
    with open(os.path.join(HERE, "demo_env.json"), encoding="utf-8") as f:
        return json.load(f)


def build_app():
    from npc_verify.server import App
    from npc_verify import ed25519
    from npc_verify.auth import hash_key
    from npc_verify.models import utcnow_iso
    from seed_demo import seed_demo

    cfg = _load_env()
    keys_dir = tempfile.mkdtemp(prefix="npc-demo-keys-")
    app = App(":memory:", keys_dir)

    # Register the stable demo signing keys; the random bootstrap keys
    # retire into history automatically.
    for purpose in ("api_signing", "issuer"):
        entry = cfg[purpose]
        seed = base64.b64decode(entry["seed_b64"])
        if len(seed) != 32:
            raise RuntimeError(f"bad seed length for {purpose}")
        pub_b64 = base64.b64encode(ed25519.publickey(seed)).decode()
        app.store.register_key(entry["key_id"], purpose, pub_b64,
                               utcnow_iso())
        app.keys._write_seed(entry["key_id"], seed)

    seed_demo(app.store, app.keys)

    # Demo verifier API key (read-only demo fixtures, rate-limited).
    # Plaintext is handed to Bayo for the OpenAI plugin portal auth config.
    app.store.add_api_key(
        hash_key(cfg["demo_verifier_key"]), "demo-verifier", "verifier",
        60, utcnow_iso())

    # Strip everything that is not a read-only demo route.
    app.routes = [
        (method, pattern, fn)
        for (method, pattern, fn) in app.routes
        if any(method == keep_m and pattern.match(keep_p)
               for keep_m, keep_p in _KEEP)
    ]
    return app
