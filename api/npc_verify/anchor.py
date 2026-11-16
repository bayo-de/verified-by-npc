"""Onchain anchoring for the registration registry (Base mainnet).

Registration records are signed by NPC at issuance and live in the
registry store. Anchoring adds a second, independent witness: the
registry periodically batches the registrations it has not yet
anchored, computes one Merkle root over the records' hashes, and
writes that root to Base in a single transaction from the NPC
anchoring wallet. Anyone can later take a record from the public
API, hash it the way this module does, walk its Merkle proof to the
batch root, and find that root inside the anchor transaction on
Basescan. NPC's database is then no longer the only place the
record's existence and shape are attested.

What anchoring is NOT: it is not verification. An anchored record
keeps its registration status exactly ("registered, checks
pending"). The anchor proves the record existed in this exact form
at the block's time; it says nothing about the truth of the record's
contents.

Hash discipline: a record's leaf is the SHA-256 of the canonical
NPC-JCS-v1 bytes of the signed public record (canonicalize() from
npc_verify.canonical), exactly the bytes the record's own signature
discipline uses. The hash input is the public record only: the
registrant email and client IP are server-side store fields, never
part of the signed record, so they can never enter a leaf.

Custody: the OWNER wallet's private key exists only in the Lambda
environment (NPC_ANCHOR_PRIVATE_KEY), the same channel the stack
already uses for its signing seed and detector credentials. It is
read once at App build, held as an integer in memory, and never
written to the store, the logs, or any response. That wallet signs
only anchor transactions and owner rotation notices. The SIGNER
wallet's key is never present at all: Bayo signs batch commitments
in his own MetaMask and only the signature travels.

Calldata layout of an anchor transaction (input bytes):
  bytes 0..12    the ASCII magic "NPC-ANCHOR-V2" (13 bytes)
  bytes 13..45   the 32-byte Merkle root
  bytes 45..110  the signer wallet's 65-byte EIP-191 batch
                 signature (r, s, v)
  bytes 110..    the batch ID, UTF-8 (informational)
A verifier reads the root as input[13:45] of the transaction and
the batch signature as input[45:110].

Fail-closed configuration, in the house pattern: the lane is off
unless NPC_ANCHOR_ENABLED=1. Enabled with a missing key, the lane
reports not_configured and anchors nothing. Enabled with a malformed
key, App build raises: a silent fallback would hide a custody
mistake behind a resting lane.

Crash discipline: a batch row is the source of truth and is
persisted BEFORE anything is broadcast (prepared, with root, record
IDs, leaves, and per-record proofs derivable from them). The signed
raw transaction and its hash are persisted BEFORE broadcast too, so
a crash between broadcast and receipt leaves everything needed to
recover: the next pass reads the chain back (transaction by hash,
receipt, nonce) and finalizes or rebroadcasts the identical raw
transaction. It never signs a second transaction for the same batch
while the first may still land, and never anchors a record twice:
records join exactly one live batch, and a batch whose transaction
failed onchain releases its records back to the unanchored pool.

Authority layer (wallet architecture, Bayo's decision 2026-10-28,
roles as he assigned them): two wallets, two different jobs.

- The OWNER wallet is FRESH, created for this lane and used for
  nothing else. Its key lives server-side (the Lambda environment)
  and it is the submitting and relaying key: every anchor
  transaction is sent from it. It is also the sole rotation
  authority: it alone can authorize, revoke, or rotate the signer.
- The SIGNER wallet is Bayo's main NPC wallet, held in his
  MetaMask since 2017 (the legacy NPC wallet; its authorship
  carries the provenance). It never comes near this service: no
  key, no custody, only its public address, configured as
  NPC_ANCHOR_SIGNER_ADDRESS with Bayo's supplied address as the
  built-in initial value. EVERY batch must carry this wallet's
  EIP-191 signature over the batch commitment (the Merkle root and
  batch ID, in a short statement the wallet owner can read in
  MetaMask before signing). The flow is: the API prepares an
  unsigned batch and returns the commitment statement; Bayo signs
  it in MetaMask; the signed batch comes back; the server checks
  the signature recovers to the currently authorized signer; only
  then does the owner wallet submit the anchor transaction, whose
  calldata carries the root AND the signer's signature, so the
  legacy wallet's authorship is readable from the chain itself.
  An anchor is valid only if its batch signature verifies against
  the signer authorized at the time.

Visible consequence, stated plainly: the onchain transaction
sender is the fresh owner wallet, while the legacy wallet's
authorship rides inside every batch as a verified signature. (If
the sender itself must be the legacy address one day, the
fallback is manual MetaMask submission per batch; that is a
product decision, not built here.)

Rotation: the signer address rotates only by an owner-signed
rotation notice (an EIP-191 statement from the owner wallet,
recorded and inspectable, served publicly at
GET /v1/anchor/authority). A compromised signer is recoverable:
the owner rotates it, and batches it signed stay provable against
the rotation history. A compromised signer cannot install its own
successor, because rotation needs the owner key, which it does
not have. A compromised owner key is bounded by its custody and
by inspection: it cannot forge the signer's signature on batches
already anchored, and every rotation it signs is public the
moment it is recorded.

Approved next layer (design only, NOT built): wallet claiming.
A registrant will be able to claim a record with their own wallet:
the wallet signs a claim statement, and the record gains a
claimed-by attestation naming that wallet. Claiming changes
nothing about the record's registration status or its anchor.
"""
import hashlib
import json
import os
import secrets
import urllib.request

from .canonical import canonicalize
from .ethkeys import (_G, _N, _point_mul, _rfc6979_nonce,
                      address_from_private_key, is_valid_address,
                      keccak256, sign_personal,
                      to_checksum_address, verify_personal_signature)

CHAIN_NAME = "base"
CHAIN_ID = 8453  # Base mainnet
EXPLORER_TX_BASE = "https://basescan.org/tx/"
DEFAULT_RPC_URL = "https://mainnet.base.org"
ANCHOR_MAGIC = b"NPC-ANCHOR-V2"

ENABLED_ENV = "NPC_ANCHOR_ENABLED"
PRIVATE_KEY_ENV = "NPC_ANCHOR_PRIVATE_KEY"
RPC_URL_ENV = "NPC_ANCHOR_RPC_URL"
BATCH_MAX_ENV = "NPC_ANCHOR_BATCH_MAX"
# The authorized batch SIGNER: Bayo's main NPC wallet (MetaMask,
# the legacy NPC wallet). PUBLIC address only; its key never comes
# near this service. Bayo supplied this address on 2026-10-28 as
# the initial authorized signer, so it is the built-in default;
# NPC_ANCHOR_SIGNER_ADDRESS overrides it, and an owner-signed
# rotation notice supersedes both.
SIGNER_ADDRESS_ENV = "NPC_ANCHOR_SIGNER_ADDRESS"
DEFAULT_SIGNER_ADDRESS = to_checksum_address(
    "0xe8afb7c355b68a2a9c616e7877d0ef3352c59d5a")
DEFAULT_BATCH_MAX = 500

# A run waits for the receipt in short polls; Base blocks land about
# every two seconds, so a funded anchor normally confirms inside one
# run. Anything slower is finalized by the next run, not by holding
# the caller open.
_RECEIPT_POLLS = 8
_RECEIPT_POLL_SECONDS = 2.0


class AnchorError(Exception):
    """An anchoring failure a caller can report honestly."""


class AnchorConfigError(AnchorError):
    """The lane is enabled but its configuration is malformed."""


class ChainError(AnchorError):
    """The chain RPC failed or answered nonsense."""


# -- configuration ------------------------------------------------------------

class AnchorConfig:
    def __init__(self, enabled, private_key, rpc_url, batch_max,
                 signer_address=None):
        self.enabled = enabled
        self.private_key = private_key  # int, or None when unset
        self.rpc_url = rpc_url
        self.batch_max = batch_max
        # The authorized batch signer's public address (checksummed).
        # An address, never a key: the signer signs in its own
        # wallet and only signatures travel to this service.
        self.signer_address = signer_address

    @property
    def configured(self):
        return self.enabled and self.private_key is not None

    @property
    def address(self):
        """The OWNER wallet's address: derived from the server-side
        key. This wallet submits every anchor transaction and is
        the sole rotation authority."""
        if self.private_key is None:
            return None
        return address_from_private_key(self.private_key)

    @property
    def configured(self):
        return self.enabled and self.private_key is not None

    @property
    def address(self):
        if self.private_key is None:
            return None
        return address_from_private_key(self.private_key)


def config_from_env(env=None):
    """Anchor configuration from the environment.

    Off unless NPC_ANCHOR_ENABLED=1. A present-but-malformed private
    key raises (see the module docstring); an absent key is the
    honest not_configured state, not an error.
    """
    env = os.environ if env is None else env
    enabled = (env.get(ENABLED_ENV) or "").strip() == "1"
    rpc_url = (env.get(RPC_URL_ENV) or "").strip() or DEFAULT_RPC_URL
    raw_max = (env.get(BATCH_MAX_ENV) or "").strip()
    if raw_max:
        try:
            batch_max = int(raw_max)
        except ValueError:
            raise AnchorConfigError(
                "%s must be an integer" % BATCH_MAX_ENV)
        if batch_max < 1:
            raise AnchorConfigError(
                "%s must be at least 1" % BATCH_MAX_ENV)
    else:
        batch_max = DEFAULT_BATCH_MAX
    private_key = None
    raw_key = (env.get(PRIVATE_KEY_ENV) or "").strip()
    if raw_key:
        hex_part = raw_key[2:] if raw_key.startswith("0x") else raw_key
        try:
            candidate = int(hex_part, 16)
        except ValueError:
            raise AnchorConfigError(
                "%s is not a hex private key" % PRIVATE_KEY_ENV)
        if len(hex_part) != 64 or not (1 <= candidate < _N):
            raise AnchorConfigError(
                "%s is not a valid secp256k1 private key"
                % PRIVATE_KEY_ENV)
        private_key = candidate
    elif enabled:
        # Enabled without a key is a resting lane, loudly visible in
        # the status endpoint, never a crash: funding and key
        # placement are operator steps that may land minutes apart.
        private_key = None
    signer_address = DEFAULT_SIGNER_ADDRESS
    raw_signer = (env.get(SIGNER_ADDRESS_ENV) or "").strip()
    if raw_signer:
        if not is_valid_address(raw_signer):
            raise AnchorConfigError(
                "%s is not a valid Ethereum address"
                % SIGNER_ADDRESS_ENV)
        signer_address = to_checksum_address(raw_signer)
    return AnchorConfig(enabled, private_key, rpc_url, batch_max,
                        signer_address=signer_address)


# -- record leaves and Merkle trees --------------------------------------------

def record_leaf_hash(record) -> str:
    """SHA-256 hex of the record's canonical public bytes.

    The input is the signed public record exactly as the registry
    stores and serves it (the registrant email is a store field,
    never part of the record, so it is never in the input).
    """
    return hashlib.sha256(canonicalize(record)).hexdigest()


def _hash_pair(left_hex, right_hex):
    return hashlib.sha256(
        bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()


def merkle_root(leaves):
    """The Merkle root over an ordered list of leaf hashes (hex).

    Pairwise SHA-256 over adjacent leaves; an odd leaf is promoted
    unchanged. A single leaf is its own root; an empty batch has no
    root and raises.
    """
    if not leaves:
        raise AnchorError("an empty batch has no Merkle root")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_hash_pair(level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def merkle_proof(leaves, index):
    """The proof for leaves[index]: a list of {"position", "hash"}
    steps, leaf level first. "position" says where the SIBLING sits
    relative to the running hash ("left" or "right"). A promoted odd
    leaf contributes no step at that level."""
    if not (0 <= index < len(leaves)):
        raise AnchorError("proof index out of range")
    proof = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if idx % 2:
            proof.append({"position": "left", "hash": level[idx - 1]})
        elif idx + 1 < len(level):
            proof.append({"position": "right", "hash": level[idx + 1]})
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_hash_pair(level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
        idx //= 2
    return proof


def verify_proof(leaf_hex, proof, root_hex) -> bool:
    """Walk a proof from a leaf to a candidate root. The recipe any
    outside verifier runs; the test suite pins it so the public
    instructions and the code cannot drift apart."""
    running = leaf_hex
    for step in proof:
        if step["position"] == "left":
            running = _hash_pair(step["hash"], running)
        elif step["position"] == "right":
            running = _hash_pair(running, step["hash"])
        else:
            return False
    return running == root_hex


def anchor_calldata(root_hex, batch_id, signature_hex) -> bytes:
    """The transaction input carrying a batch root AND the signer
    wallet's batch signature (layout in the module docstring). The
    signature rides onchain so the legacy wallet's authorship of
    the batch is readable from the transaction itself."""
    sig = bytes.fromhex(
        signature_hex[2:] if signature_hex.startswith("0x")
        else signature_hex)
    if len(sig) != 65:
        raise AnchorError("a batch signature is 65 bytes")
    return ANCHOR_MAGIC + bytes.fromhex(root_hex) + sig \
        + batch_id.encode("utf-8")


def root_from_calldata(data: bytes):
    """The Merkle root inside an anchor transaction's input, or
    None when the input is not an anchor payload."""
    if len(data) < len(ANCHOR_MAGIC) + 32:
        return None
    if data[:len(ANCHOR_MAGIC)] != ANCHOR_MAGIC:
        return None
    return data[len(ANCHOR_MAGIC):len(ANCHOR_MAGIC) + 32].hex()


def signer_signature_from_calldata(data: bytes):
    """The signer wallet's batch signature inside an anchor
    transaction's input (0x-prefixed hex), or None when the input
    is not a complete anchor payload."""
    start = len(ANCHOR_MAGIC) + 32
    if len(data) < start + 65:
        return None
    if data[:len(ANCHOR_MAGIC)] != ANCHOR_MAGIC:
        return None
    return "0x" + data[start:start + 65].hex()


def batch_id_from_calldata(data: bytes):
    """The batch ID inside an anchor transaction's input, or None
    when the input is not a complete anchor payload."""
    start = len(ANCHOR_MAGIC) + 32 + 65
    if len(data) <= start:
        return None
    if data[:len(ANCHOR_MAGIC)] != ANCHOR_MAGIC:
        return None
    try:
        return data[start:].decode("utf-8")
    except UnicodeDecodeError:
        return None


# -- the authority layer: batch commitments and signer rotation -----------------

ROTATION_TYPE = "npc.anchor.signer_rotation"


def batch_commitment_message(batch_id, root_hex) -> bytes:
    """The exact statement the SIGNER wallet signs for a batch, as
    EIP-191 message bytes. It is deliberately short and readable:
    this is the text Bayo sees in MetaMask before signing. Every
    value in it is recoverable from the anchor transaction's
    calldata (root, batch ID) plus the chain constant, so a third
    party can rebuild the message from chain data alone and check
    the signature without trusting this service."""
    return (
        "NPC Verify anchor batch\n"
        "Batch: %s\n"
        "Merkle root: %s\n"
        "Chain: Base (%d)" % (batch_id, root_hex, CHAIN_ID)
    ).encode("utf-8")


def verify_batch_commitment(batch_id, root_hex, signature_hex):
    """The address a batch commitment signature recovers to, or
    None. The signature is the signer's EIP-191 personal signature
    over batch_commitment_message; any verifier runs this same
    check against the authorized signer address."""
    if not isinstance(signature_hex, str):
        return None
    try:
        raw = bytes.fromhex(
            signature_hex[2:] if signature_hex.startswith("0x")
            else signature_hex)
    except ValueError:
        return None
    return verify_personal_signature(
        batch_commitment_message(batch_id, root_hex), raw)


def rotation_notice_message(notice) -> bytes:
    """The exact bytes the OWNER wallet signs for a signer rotation
    notice: the canonical (NPC-JCS-v1) form of the notice without
    its signature field. Canonical bytes mean the signature covers
    the notice's meaning, not one JSON serialization of it."""
    body = {k: v for k, v in notice.items() if k != "signature"}
    return canonicalize(body)


def build_signer_rotation(owner_private_key: int, from_signer,
                          to_signer, issued_at, note=None):
    """A complete signer rotation notice, signed by the OWNER
    wallet. The owner key is the server-side key, so this service
    produces the notice itself when an issuer calls the rotation
    endpoint: the signature is what makes the event inspectable
    and binding, whoever operates the endpoint."""
    notice = {
        "type": ROTATION_TYPE,
        "version": 1,
        "from_signer": to_checksum_address(from_signer),
        "to_signer": to_checksum_address(to_signer),
        "issued_at": issued_at,
    }
    if note:
        notice["note"] = note
    notice["signature"] = "0x" + sign_personal(
        owner_private_key, rotation_notice_message(notice)).hex()
    return notice


def verify_signer_rotation(notice, owner_address) -> bool:
    """True when `notice` is a well-formed signer rotation whose
    EIP-191 signature recovers to the OWNER address (the fresh
    server wallet). This is the whole rotation gate: no valid
    owner signature, no rotation. Checks: the type and version,
    both signer fields well-formed, the move is real (from and to
    differ), and the signature is the owner's over the canonical
    notice bytes."""
    if not isinstance(notice, dict) or owner_address is None:
        return False
    if notice.get("type") != ROTATION_TYPE \
            or notice.get("version") != 1:
        return False
    from_signer = notice.get("from_signer")
    to_signer = notice.get("to_signer")
    if not is_valid_address(from_signer or "") \
            or not is_valid_address(to_signer or ""):
        return False
    if to_checksum_address(from_signer) \
            == to_checksum_address(to_signer):
        return False
    signature = notice.get("signature")
    if not isinstance(signature, str):
        return False
    try:
        raw = bytes.fromhex(
            signature[2:] if signature.startswith("0x")
            else signature)
    except ValueError:
        return False
    signer = verify_personal_signature(
        rotation_notice_message(notice), raw)
    return signer is not None and signer == to_checksum_address(
        owner_address)


def rotation_notice_id(notice) -> str:
    """A notice's stable ID: the SHA-256 of its canonical signed
    bytes. Recording the same notice twice is one rotation."""
    return hashlib.sha256(rotation_notice_message(notice)).hexdigest()


def authorized_signer(store, cfg):
    """The signer currently authorized: the newest recorded
    rotation notice's destination when notices exist, otherwise
    the configured signer (Bayo's legacy wallet by default). A
    batch signature carries authority only when it recovers to
    this address."""
    notices = store.list_anchor_rotations()
    if notices:
        return to_checksum_address(notices[-1]["to_signer"])
    return cfg.signer_address


# -- Ethereum transactions (EIP-1559, type 2) -----------------------------------

def _rlp_encode(item) -> bytes:
    if isinstance(item, int):
        if item == 0:
            return _rlp_encode(b"")
        return _rlp_encode(
            item.to_bytes((item.bit_length() + 7) // 8, "big"))
    if isinstance(item, (bytes, bytearray)):
        raw = bytes(item)
        if len(raw) == 1 and raw[0] < 0x80:
            return raw
        if len(raw) <= 55:
            return bytes([0x80 + len(raw)]) + raw
        len_bytes = len(raw).to_bytes(
            (len(raw).bit_length() + 7) // 8, "big")
        return bytes([0xB7 + len(len_bytes)]) + len_bytes + raw
    if isinstance(item, (list, tuple)):
        payload = b"".join(_rlp_encode(x) for x in item)
        if len(payload) <= 55:
            return bytes([0xC0 + len(payload)]) + payload
        len_bytes = len(payload).to_bytes(
            (len(payload).bit_length() + 7) // 8, "big")
        return bytes([0xF7 + len(len_bytes)]) + len_bytes + payload
    raise TypeError("cannot RLP-encode %r" % type(item))


def _sign_digest(private_key: int, digest: bytes):
    """ECDSA over a 32-byte digest with an RFC 6979 nonce and low-s
    normalization (the ethkeys signing discipline). Returns
    (r, s, recid)."""
    z = int.from_bytes(digest, "big")
    k = _rfc6979_nonce(private_key, digest)
    point_r = _point_mul(k, _G)
    r = point_r[0] % _N
    recid = (point_r[1] & 1) | (2 if point_r[0] >= _N else 0)
    s = (pow(k, -1, _N) * (z + r * private_key)) % _N
    if s > _N // 2:
        s = _N - s
        recid ^= 1
    return r, s, recid


def sign_anchor_transaction(private_key: int, *, chain_id, nonce,
                            max_priority_fee, max_fee, gas_limit,
                            to_address, data: bytes):
    """Build and sign a type-2 transaction. Returns (raw_bytes,
    tx_hash_hex). The caller persists both BEFORE broadcasting."""
    to_bytes = bytes.fromhex(to_address[2:])
    fields = [chain_id, nonce, max_priority_fee, max_fee, gas_limit,
              to_bytes, 0, data, []]
    signing_payload = b"\x02" + _rlp_encode(fields)
    digest = keccak256(signing_payload)
    r, s, recid = _sign_digest(private_key, digest)
    signed = b"\x02" + _rlp_encode(fields + [recid, r, s])
    return signed, "0x" + keccak256(signed).hex()


def calldata_gas(data: bytes) -> int:
    """The intrinsic calldata cost of `data`. Base charges the
    higher of two schedules: the post-Istanbul cost (16 gas per
    non-zero byte, 4 per zero byte) and the EIP-7623 floor (10 gas
    per token, with one token per zero byte and four per non-zero
    byte). Budgeting on the Istanbul figure alone underprices the
    floor for data-heavy inputs (this engine's own anchor payload
    is one), and the node rejects such a transaction as
    intrinsically too cheap before it can ever land."""
    standard = sum(4 if b == 0 else 16 for b in data)
    floor = 10 * sum(1 if b == 0 else 4 for b in data)
    return max(standard, floor)


# -- chain access -----------------------------------------------------------------

def _default_rpc_http(url, payload, timeout=15):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "User-Agent": "NPCVerify/1.0 "
                               "(+https://verify.npclabs.xyz)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class BaseChain:
    """A minimal JSON-RPC client for Base. Every call goes through
    one injectable callable taking (method, params) and returning
    the RPC result, so tests run against a fake chain and never
    touch the network."""

    def __init__(self, rpc_url=DEFAULT_RPC_URL, rpc=None):
        self.rpc_url = rpc_url
        self._rpc = rpc if rpc is not None else self._rpc_http

    def _rpc_http(self, method, params):
        body = _default_rpc_http(
            self.rpc_url,
            {"jsonrpc": "2.0", "id": 1, "method": method,
             "params": params})
        if isinstance(body, dict) and body.get("error"):
            raise ChainError("RPC %s answered an error: %s"
                             % (method, body["error"]))
        if not isinstance(body, dict) or "result" not in body:
            raise ChainError("RPC %s answered nonsense" % method)
        return body["result"]

    def call(self, method, params):
        try:
            return self._rpc(method, params)
        except ChainError:
            raise
        except Exception as exc:
            raise ChainError("RPC %s failed: %s" % (method, exc))

    @staticmethod
    def _quantity(value, what):
        try:
            return int(value, 16)
        except (TypeError, ValueError):
            raise ChainError("RPC answered a bad %s" % what)

    def transaction_count(self, address, block="pending"):
        return self._quantity(
            self.call("eth_getTransactionCount", [address, block]),
            "transaction count")

    def balance_wei(self, address):
        return self._quantity(
            self.call("eth_getBalance", [address, "latest"]),
            "balance")

    def max_priority_fee(self):
        return self._quantity(
            self.call("eth_maxPriorityFeePerGas", []), "priority fee")

    def latest_block(self):
        block = self.call("eth_getBlockByNumber", ["latest", False])
        if not isinstance(block, dict):
            raise ChainError("RPC answered a bad block")
        return {
            "number": self._quantity(block.get("number"),
                                     "block number"),
            "base_fee_wei": self._quantity(block.get("baseFeePerGas"),
                                           "base fee"),
            "timestamp": self._quantity(block.get("timestamp"),
                                        "block timestamp"),
        }

    def block_timestamp(self, number):
        block = self.call(
            "eth_getBlockByNumber", [hex(number), False])
        if not isinstance(block, dict):
            raise ChainError("RPC answered a bad block")
        return self._quantity(block.get("timestamp"), "block timestamp")

    def send_raw(self, raw: bytes) -> str:
        result = self.call("eth_sendRawTransaction",
                           ["0x" + raw.hex()])
        if not isinstance(result, str) or not result.startswith("0x"):
            raise ChainError("RPC answered a bad transaction hash")
        return result

    def transaction_by_hash(self, tx_hash):
        tx = self.call("eth_getTransactionByHash", [tx_hash])
        return tx if isinstance(tx, dict) else None

    def receipt(self, tx_hash):
        rec = self.call("eth_getTransactionReceipt", [tx_hash])
        if not isinstance(rec, dict):
            return None
        return {
            "status": self._quantity(rec.get("status"),
                                     "receipt status"),
            "block_number": self._quantity(rec.get("blockNumber"),
                                           "receipt block"),
        }


def chain_from_env(env=None, rpc=None):
    cfg = config_from_env(env)
    return BaseChain(cfg.rpc_url, rpc=rpc)


# -- the public anchor section ------------------------------------------------------

def anchor_section(store, record_id, lane_active, cfg=None):
    """The `anchor` block GET /v1/records/{id} adds to a
    registration record, or None when this deployment carries no
    anchor story for it.

    Byte-identity discipline (the lane precedent): with the lane off
    and no anchor data on record, this returns None and the record
    answers exactly as it always has. Once a record sits in a batch
    (or the lane is on), the section is present and honest about the
    state: not anchored, waiting in a batch, or anchored with the
    full proof anyone can re-walk. The owner wallet's address
    rides along whenever the configuration carries one (see the
    module docstring for the two-wallet authority design).
    """
    owner_wallet = cfg.address if cfg is not None else None
    row = store.get_record_anchor(record_id)
    if row is None:
        if not lane_active:
            return None
        section = {
            "status": "not_anchored",
            "chain": CHAIN_NAME,
            "chain_id": CHAIN_ID,
            "detail": "This record is not anchored onchain yet. "
                      "Anchoring writes the hash of a batch of "
                      "records to Base as a public timestamp. It "
                      "does not change this record's status.",
        }
        if owner_wallet is not None:
            section["owner_wallet"] = owner_wallet
        return section
    batch = store.get_anchor_batch(row["batch_id"])
    if batch is not None and batch.get("status") == "confirmed":
        section = {
            "status": "anchored",
            "chain": CHAIN_NAME,
            "chain_id": CHAIN_ID,
            "batch_id": batch["batch_id"],
            "leaf_hash": row["leaf_hash"],
            "merkle_root": batch["merkle_root"],
            "proof": row["proof"],
            "tx_hash": batch["tx_hash"],
            "block_number": batch["block_number"],
            "block_timestamp": batch["block_timestamp"],
            "explorer_url": EXPLORER_TX_BASE + batch["tx_hash"],
            "detail": "The hash of this record sits in the batch "
                      "anchored in this Base transaction. Anyone can "
                      "hash the record, walk the proof to the batch "
                      "root, and find that root in the transaction. "
                      "Anchoring proves the record existed in this "
                      "exact form at that time. It does not change "
                      "this record's status.",
        }
        if batch.get("batch_sig"):
            # The authority layer, published with the proof: the
            # signer wallet's EIP-191 signature over the batch
            # commitment, and the signer it recovers to. A batch
            # whose signature recovers to a wallet that was not the
            # authorized signer carries no authorship, whatever its
            # root says. The signature also rides in the anchor
            # transaction's calldata, so this can be checked from
            # the chain alone.
            section["batch_signature"] = batch["batch_sig"]
            section["signer_wallet"] = verify_batch_commitment(
                batch["batch_id"], batch["merkle_root"],
                batch["batch_sig"])
        if owner_wallet is not None:
            section["owner_wallet"] = owner_wallet
        return section
    section = {
        "status": "anchor_pending",
        "chain": CHAIN_NAME,
        "chain_id": CHAIN_ID,
        "batch_id": row["batch_id"],
        "leaf_hash": row["leaf_hash"],
        "merkle_root": batch["merkle_root"] if batch else None,
        "detail": "This record is in a batch that has not landed "
                  "onchain yet. Its status is unchanged.",
    }
    if owner_wallet is not None:
        section["owner_wallet"] = owner_wallet
    return section


# -- the engine -----------------------------------------------------------------------

def _iso_from_unix(ts):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _prepare_batch(store, cfg, now_iso):
    """Collect the unanchored registrations into a persisted batch
    (or None when there is nothing to anchor). Proofs are written
    with the batch, before any broadcast: the batch row plus these
    rows are the complete recovery state."""
    records = store.unanchored_registrations(cfg.batch_max)
    if not records:
        return None
    leaves = [record_leaf_hash(r) for r in records]
    root = merkle_root(leaves)
    batch_id = "anchor_" + secrets.token_hex(8)
    batch = {
        "batch_id": batch_id,
        "merkle_root": root,
        # The SIGNER wallet's EIP-191 batch signature. It starts
        # empty: no server key can produce it. The batch waits in
        # this state until the signer signs the commitment in their
        # own wallet and the signature is recorded (see
        # record_batch_signature); only then can it be submitted.
        "batch_sig": None,
        "record_ids": [r["record_id"] for r in records],
        "leaves": leaves,
        "status": "prepared",
        "nonce": None,
        "tx_hash": None,
        "raw_tx": None,
        "block_number": None,
        "block_timestamp": None,
        "error": None,
        "created_at": now_iso,
        "submitted_at": None,
        "confirmed_at": None,
    }
    store.create_anchor_batch(batch)
    for i, record in enumerate(records):
        store.add_record_anchor({
            "record_id": record["record_id"],
            "batch_id": batch["batch_id"],
            "leaf_hash": leaves[i],
            "proof": merkle_proof(leaves, i),
        })
    return batch


def _finalize(store, chain, batch, now_iso, sleep, cfg=None,
              allow_recover=False):
    """Read a submitted batch's receipt back and settle it. A
    missing receipt leaves the batch submitted (a later pass picks
    it up); a failed transaction releases the records and closes
    the batch as failed.

    Recovery (top-level passes only): a batch whose transaction is
    visible nowhere and whose receipt never arrives was dropped
    before landing. It re-enters the submit path, which reads the
    chain state and either rebroadcasts the identical signed
    transaction or, when the nonce was verifiably consumed by a
    replacement, signs fresh for the same root. allow_recover is
    set only by run_anchor_pass, so one pass can delegate at most
    once and never loops."""
    tx_hash = batch["tx_hash"]
    receipt = None
    for attempt in range(_RECEIPT_POLLS):
        receipt = chain.receipt(tx_hash)
        if receipt is not None:
            break
        if attempt + 1 < _RECEIPT_POLLS:
            sleep(_RECEIPT_POLL_SECONDS)
    if receipt is None:
        if allow_recover and cfg is not None \
                and chain.transaction_by_hash(tx_hash) is None:
            return _submit(store, chain, cfg, batch, now_iso, sleep)
        return {"status": "submitted", "batch_id": batch["batch_id"],
                "tx_hash": tx_hash,
                "records": len(batch["record_ids"]),
                "detail": "The anchor transaction is broadcast and "
                          "waiting to land. A later pass finalizes "
                          "it."}
    if receipt["status"] != 1:
        store.release_anchor_batch(batch["batch_id"])
        store.update_anchor_batch(batch["batch_id"], {
            "status": "failed",
            "error": "the anchor transaction failed onchain",
        })
        return {"status": "failed", "batch_id": batch["batch_id"],
                "tx_hash": tx_hash,
                "records": len(batch["record_ids"]),
                "detail": "The anchor transaction failed onchain. "
                          "Its records are back in the unanchored "
                          "pool for the next batch."}
    block_ts = chain.block_timestamp(receipt["block_number"])
    store.update_anchor_batch(batch["batch_id"], {
        "status": "confirmed",
        "block_number": receipt["block_number"],
        "block_timestamp": _iso_from_unix(block_ts),
        "confirmed_at": now_iso,
        "error": None,
    })
    return {"status": "anchored", "batch_id": batch["batch_id"],
            "tx_hash": tx_hash,
            "merkle_root": batch["merkle_root"],
            "block_number": receipt["block_number"],
            "block_timestamp": _iso_from_unix(block_ts),
            "records": len(batch["record_ids"])}


def _submit(store, chain, cfg, batch, now_iso, sleep):
    """Broadcast a prepared batch's transaction, reading the chain
    state back first so a crash anywhere in an earlier attempt can
    neither double-anchor nor lose the batch."""
    address = cfg.address
    if batch.get("tx_hash"):
        seen = chain.transaction_by_hash(batch["tx_hash"])
        if seen is not None:
            if batch["status"] != "submitted":
                store.update_anchor_batch(batch["batch_id"], {
                    "status": "submitted",
                    "submitted_at": batch.get("submitted_at")
                    or now_iso})
                batch = store.get_anchor_batch(batch["batch_id"])
            return _finalize(store, chain, batch, now_iso, sleep)
        mined = chain.transaction_count(address, "latest")
        if mined > (batch.get("nonce") or 0):
            # The nonce was consumed by a transaction the node no
            # longer shows us under our hash: it was replaced or
            # dropped after landing elsewhere. Signing again with a
            # fresh nonce is the honest recovery; the batch (and its
            # root) is unchanged, so nothing can double-anchor a
            # record: the first root write either exists or the
            # record was never anchored.
            store.update_anchor_batch(batch["batch_id"], {
                "tx_hash": None, "raw_tx": None, "nonce": None,
                "status": "prepared", "submitted_at": None})
            batch = store.get_anchor_batch(batch["batch_id"])
        else:
            # Never broadcast, or broadcast and already forgotten by
            # this node with the nonce still free: rebroadcast the
            # IDENTICAL signed transaction (same hash, idempotent).
            rebuilt = False
            try:
                chain.send_raw(bytes.fromhex(batch["raw_tx"]))
            except ChainError as exc:
                text = str(exc).lower()
                if "intrinsic gas too low" in text:
                    # The stored transaction can NEVER be accepted:
                    # its gas limit sits below the chain's intrinsic
                    # floor (for example it was built before the
                    # EIP-7623 floor was priced in). Rebroadcasting
                    # it would fail identically forever, so clear it
                    # exactly like the replaced-transaction case
                    # above and fall through to a fresh build at the
                    # current schedule. The batch, its root and its
                    # signer signature are untouched, so nothing can
                    # double-anchor.
                    store.update_anchor_batch(batch["batch_id"], {
                        "tx_hash": None, "raw_tx": None,
                        "nonce": None, "status": "prepared",
                        "submitted_at": None, "error": None})
                    batch = store.get_anchor_batch(batch["batch_id"])
                    rebuilt = True
                elif "already known" not in text:
                    raise
            if not rebuilt:
                if batch["status"] != "submitted":
                    store.update_anchor_batch(batch["batch_id"], {
                        "status": "submitted",
                        "submitted_at": batch.get("submitted_at")
                        or now_iso})
                    batch = store.get_anchor_batch(batch["batch_id"])
                return _finalize(store, chain, batch, now_iso, sleep)
    if not batch.get("batch_sig"):
        # Engine invariant: a batch is never submitted without the
        # signer wallet's batch signature recorded. run_anchor_pass
        # routes unsigned batches to the awaiting state, so reaching
        # here means a state bug; stop loudly, broadcast nothing.
        raise AnchorError(
            "batch %s has no signer signature recorded; refusing "
            "to submit" % batch["batch_id"])
    data = anchor_calldata(batch["merkle_root"], batch["batch_id"],
                           batch["batch_sig"])
    block = chain.latest_block()
    priority = chain.max_priority_fee()
    max_fee = 2 * block["base_fee_wei"] + priority
    gas_limit = 21000 + calldata_gas(data) + 2000
    balance = chain.balance_wei(address)
    if balance < gas_limit * max_fee:
        return {"status": "unfunded",
                "batch_id": batch["batch_id"],
                "owner_wallet": address,
                "balance_wei": balance,
                "needed_wei": gas_limit * max_fee,
                "records": len(batch["record_ids"]),
                "detail": "The anchoring wallet cannot cover this "
                          "batch's network fee yet. The batch is "
                          "prepared and waits; nothing was "
                          "broadcast."}
    nonce = chain.transaction_count(address, "pending")
    raw, tx_hash = sign_anchor_transaction(
        cfg.private_key, chain_id=CHAIN_ID, nonce=nonce,
        max_priority_fee=priority, max_fee=max_fee,
        gas_limit=gas_limit, to_address=address, data=data)
    # Persist the signed transaction BEFORE broadcasting: from here
    # on, any crash recovers from (batch row, raw_tx, tx_hash).
    store.update_anchor_batch(batch["batch_id"], {
        "nonce": nonce, "tx_hash": tx_hash, "raw_tx": raw.hex(),
        "submitted_at": now_iso})
    try:
        sent = chain.send_raw(raw)
    except ChainError as exc:
        if "already known" in str(exc).lower():
            sent = tx_hash
        else:
            store.update_anchor_batch(batch["batch_id"], {
                "error": "broadcast failed: %s" % exc})
            return {"status": "submit_error",
                    "batch_id": batch["batch_id"],
                    "tx_hash": tx_hash,
                    "detail": "The broadcast failed before the "
                              "transaction reached the chain. The "
                              "signed transaction is on record; the "
                              "next pass rebroadcasts it or reports "
                              "why it cannot."}
    if sent != tx_hash:
        # A node answering a different hash for our bytes would break
        # every recovery assumption; stop loudly instead of guessing.
        raise ChainError(
            "the node answered a different hash for the anchor "
            "transaction than the one computed locally")
    store.update_anchor_batch(batch["batch_id"],
                              {"status": "submitted", "error": None})
    batch = store.get_anchor_batch(batch["batch_id"])
    return _finalize(store, chain, batch, now_iso, sleep)


def _awaiting_summary(store, cfg, batch):
    """The honest state of a prepared batch that has no signer
    signature yet: nothing can be submitted, and the summary
    carries the exact commitment statement the signer signs, so
    the caller (the operator, Bayo) can take it to the wallet."""
    return {
        "status": "awaiting_signature",
        "batch_id": batch["batch_id"],
        "merkle_root": batch["merkle_root"],
        "records": len(batch["record_ids"]),
        "signer_address": authorized_signer(store, cfg),
        "commitment_message": batch_commitment_message(
            batch["batch_id"], batch["merkle_root"]).decode("utf-8"),
        "detail": "The batch is prepared. It can only be anchored "
                  "once the signer wallet signs the commitment "
                  "statement (in MetaMask) and the signature is "
                  "recorded through the sign endpoint. Nothing was "
                  "broadcast.",
    }


def record_batch_signature(store, cfg, batch_id, signature_hex):
    """Record the signer wallet's signature for a prepared batch.

    The signature is accepted only when it recovers to the
    CURRENTLY authorized signer (the configured legacy wallet, or
    the destination of the newest owner rotation). A signature from
    anyone else, or for a different batch, records nothing. While
    the batch is still prepared, re-recording a (valid) signature
    replaces the old one; once the batch is submitted its
    signature is already onchain and locked."""
    batch = store.get_anchor_batch(batch_id)
    if batch is None:
        return {"status": "unknown_batch", "batch_id": batch_id,
                "detail": "No batch with this ID exists. Nothing "
                          "was recorded."}
    if batch["status"] != "prepared":
        return {"status": "batch_locked", "batch_id": batch_id,
                "detail": "This batch has already been submitted; "
                          "its signature is fixed in the anchor "
                          "transaction. Nothing was recorded."}
    authorized = authorized_signer(store, cfg)
    recovered = verify_batch_commitment(
        batch["batch_id"], batch["merkle_root"], signature_hex)
    if recovered is None:
        return {"status": "invalid_signature",
                "batch_id": batch_id,
                "detail": "The signature is malformed or does not "
                          "cover this batch's commitment. Nothing "
                          "was recorded."}
    if authorized is None or recovered != authorized:
        return {"status": "signer_not_authorized",
                "batch_id": batch_id,
                "recovered_signer": recovered,
                "authorized_signer": authorized,
                "detail": "The signature is genuine but comes from "
                          "a wallet that is not the authorized "
                          "signer. Nothing was recorded."}
    normalized = signature_hex.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    store.update_anchor_batch(batch_id, {"batch_sig": normalized})
    return {"status": "signed", "batch_id": batch_id,
            "signer_address": recovered,
            "records": len(batch["record_ids"]),
            "merkle_root": batch["merkle_root"],
            "detail": "The signer signature is recorded and "
                      "verified. The next anchoring pass submits "
                      "the batch from the owner wallet."}


def run_anchor_pass(store, chain, cfg, now_iso, sleep=None):
    """One anchoring pass: finalize an open batch if there is one;
    route a prepared batch to the signer's signature or, once
    signed, to submission; otherwise prepare the next batch (which
    then waits for its signature). Returns a summary dict in every
    state (disabled, not_configured, awaiting_signature, unfunded,
    idle, submitted, anchored, failed, submit_error, chain_error);
    the internal endpoint answers it verbatim."""
    import time as _time
    sleep = sleep if sleep is not None else _time.sleep
    if not cfg.enabled:
        return {"status": "disabled",
                "detail": "Onchain anchoring is not enabled on "
                          "this deployment."}
    if cfg.private_key is None:
        return {"status": "not_configured",
                "detail": "Anchoring is enabled but no anchoring "
                          "key is configured in the server "
                          "environment. Nothing was anchored."}
    try:
        batch = store.open_anchor_batch()
        if batch is not None and batch["status"] == "submitted":
            out = _finalize(store, chain, batch, now_iso, sleep,
                            cfg=cfg, allow_recover=True)
        elif batch is not None and not batch.get("batch_sig"):
            out = _awaiting_summary(store, cfg, batch)
        elif batch is not None:
            out = _submit(store, chain, cfg, batch, now_iso, sleep)
        else:
            batch = _prepare_batch(store, cfg, now_iso)
            if batch is None:
                out = {"status": "idle",
                       "detail": "Every registration is anchored. "
                                 "Nothing to do."}
            else:
                out = _awaiting_summary(store, cfg, batch)
    except ChainError as exc:
        return {"status": "chain_error", "detail": str(exc)}
    out.setdefault("owner_wallet", cfg.address)
    out.setdefault("chain", CHAIN_NAME)
    out.setdefault("chain_id", CHAIN_ID)
    return out


def anchor_status(store, chain, cfg):
    """The status summary the internal endpoint answers: lane state,
    the owner wallet (address and balance when the chain answers),
    batch counts, the open batch if one is waiting (with its
    commitment statement when it awaits the signer's signature),
    and the authority state: the configured signer, the currently
    authorized signer after any owner rotations, and the rotation
    count."""
    out = {
        "enabled": cfg.enabled,
        "configured": cfg.configured,
        "chain": CHAIN_NAME,
        "chain_id": CHAIN_ID,
        "owner_wallet": cfg.address,
        "signer_configured": cfg.signer_address,
        "authorized_signer": authorized_signer(store, cfg),
        "rotations_recorded": len(store.list_anchor_rotations()),
        "batch_max": cfg.batch_max,
        "batches": store.count_anchor_batches(),
        "records_anchored": store.count_anchored_records(),
        "records_waiting": len(store.unanchored_registrations(
            cfg.batch_max)) if cfg.enabled else None,
    }
    open_batch = store.open_anchor_batch()
    if open_batch is not None:
        out["open_batch"] = {
            "batch_id": open_batch["batch_id"],
            "status": open_batch["status"],
            "records": len(open_batch["record_ids"]),
            "merkle_root": open_batch["merkle_root"],
            "tx_hash": open_batch["tx_hash"],
            "created_at": open_batch["created_at"],
            "awaiting_signature": not open_batch.get("batch_sig"),
        }
        if not open_batch.get("batch_sig"):
            out["open_batch"]["commitment_message"] = \
                batch_commitment_message(
                    open_batch["batch_id"],
                    open_batch["merkle_root"]).decode("utf-8")
    if cfg.address is not None:
        try:
            out["wallet_balance_wei"] = chain.balance_wei(cfg.address)
        except ChainError:
            out["wallet_balance_wei"] = None
    return out


def authority_block(store, cfg):
    """The public authority statement behind GET /v1/anchor/
    authority: the owner wallet (which submits every anchor and
    alone can rotate the signer), the currently authorized signer,
    and every recorded rotation notice, so the signer history is
    inspectable by anyone, not just operators."""
    return {
        "chain": CHAIN_NAME,
        "chain_id": CHAIN_ID,
        "owner_wallet": cfg.address,
        "authorized_signer": authorized_signer(store, cfg),
        "signer_rotations": store.list_anchor_rotations(),
        "detail": "The owner wallet submits every anchor "
                  "transaction and is the only wallet that can "
                  "rotate the signer. The signer wallet signs every "
                  "batch commitment. A batch carries authority only "
                  "when its signature recovers to the signer "
                  "authorized at its time; the rotation notices "
                  "above are the complete, owner-signed history of "
                  "who that was.",
    }
