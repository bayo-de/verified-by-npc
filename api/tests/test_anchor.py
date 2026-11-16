"""Onchain anchoring (npc_verify.anchor): Merkle proofs, EIP-1559
signing, the two-wallet authority flow (owner submits, signer
signs), the batch engine's crash discipline, the public record
section, and store parity across both backends.

Wallet roles in these tests (Bayo's 2026-10-28 assignment):
private key 2 is the OWNER wallet (the fresh server wallet: its
address is a public test constant); private key 3 stands in for
the SIGNER (Bayo's legacy MetaMask wallet in production, address
0xe8AFB7C355B68A2A9C616E7877D0ef3352c59D5a by default config);
private key 4 is a rotation destination. Everything runs locally
against a fake chain: no RPC traffic and no funds anywhere.
"""
import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
FAKE_DIR = os.path.join(BASE, "serverless", "lambda_v3", "fake_boto3")
sys.path.insert(0, FAKE_DIR)

from npc_verify import anchor  # noqa: E402
from npc_verify.canonical import canonicalize  # noqa: E402
from npc_verify.ethkeys import (address_from_private_key,  # noqa: E402
                                keccak256, recover_address,
                                sign_personal, verify_personal_signature)
from npc_verify.store import Store  # noqa: E402

NOW = "2026-10-28T12:00:00+00:00"
# The OWNER wallet (server side in production): private key 2.
OWNER_KEY = 2
OWNER_HEX = "0x" + "0" * 63 + "2"
OWNER_ADDRESS = "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"
# The SIGNER stand-in: private key 3.
SIGNER_KEY = 3
SIGNER_ADDRESS = "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69"
# A rotation destination: private key 4.
NEW_SIGNER = address_from_private_key(4)
# Bayo's legacy wallet, the production default signer (supplied by
# Bayo 2026-10-28; the config default must equal it, checksummed).
LEGACY_SIGNER = "0xe8AFB7C355B68A2A9C616E7877D0ef3352c59D5a"


def _record(record_id, registered_at="2026-10-28T10:00:00+00:00",
            **extra):
    rec = {"record_id": record_id, "kind": "content",
           "record_type": "npc.registry.content_registration",
           "title": "Work " + record_id, "content_kind": "image",
           "locator": "https://example.com/" + record_id + ".webp",
           "creator_name": "Maker",
           "status": "registered_checks_pending",
           "registered_at": registered_at,
           "key_id": "npc-test-issuer", "signature": "c2ln"}
    rec.update(extra)
    return rec


def _signer_signature(batch_id, root_hex, key=SIGNER_KEY):
    """What Bayo's MetaMask produces in production: an EIP-191
    personal signature over the batch commitment statement."""
    return "0x" + sign_personal(
        key, anchor.batch_commitment_message(batch_id, root_hex)
    ).hex()


class FakeChain:
    """An in-memory Base. Receipts land immediately unless the
    test holds them back; broadcasts can be dropped from view to
    rehearse the engine's recovery paths."""

    def __init__(self, balance=10 ** 17, base_fee=5_000_000,
                 priority=1_000_000):
        self.balance = balance
        self.base_fee = base_fee
        self.priority = priority
        self.nonce = 0
        self.block_no = 19000000
        self.block_ts = 1760000000
        self.txs = {}
        self.receipts = {}
        self.sent_raws = []
        self.hold_receipts = False
        self.hide_txs = False
        self.fail_next_receipt = False

    def transaction_count(self, address, block="pending"):
        return self.nonce

    def balance_wei(self, address):
        return self.balance

    def max_priority_fee(self):
        return self.priority

    def latest_block(self):
        return {"number": self.block_no, "base_fee_wei": self.base_fee,
                "timestamp": self.block_ts}

    def block_timestamp(self, number):
        return self.block_ts

    def send_raw(self, raw):
        tx_hash = "0x" + keccak256(raw).hex()
        self.sent_raws.append(raw)
        if not self.hide_txs:
            self.txs[tx_hash] = {"hash": tx_hash}
            self.nonce += 1
            if not self.hold_receipts:
                status = 0 if self.fail_next_receipt else 1
                self.fail_next_receipt = False
                self.receipts[tx_hash] = {
                    "status": status, "block_number": self.block_no}
        return tx_hash

    def transaction_by_hash(self, tx_hash):
        return self.txs.get(tx_hash)

    def receipt(self, tx_hash):
        return self.receipts.get(tx_hash)


def _cfg(**kw):
    base = {"enabled": True,
            "private_key": OWNER_KEY,
            "rpc_url": "http://127.0.0.1:0/unused",
            "batch_max": 500,
            "signer_address": SIGNER_ADDRESS}
    base.update(kw)
    return anchor.AnchorConfig(**base)


def _no_sleep(_seconds):
    return None


# -- Merkle + calldata -----------------------------------------------------

class MerkleTest(unittest.TestCase):
    def test_roots_and_proofs_for_many_sizes(self):
        for n in (1, 2, 3, 4, 5, 9, 16):
            leaves = [hashlib.sha256(b"leaf-%d" % i).hexdigest()
                      for i in range(n)]
            root = anchor.merkle_root(leaves)
            for i in range(n):
                proof = anchor.merkle_proof(leaves, i)
                self.assertTrue(
                    anchor.verify_proof(leaves[i], proof, root),
                    (n, i))
                self.assertFalse(
                    anchor.verify_proof(leaves[i], proof, "00" * 32))

    def test_empty_batch_has_no_root(self):
        with self.assertRaises(anchor.AnchorError):
            anchor.merkle_root([])

    def test_leaf_recipe_is_canonical_record_bytes(self):
        rec = _record("reg_leaf")
        expect = hashlib.sha256(canonicalize(rec)).hexdigest()
        self.assertEqual(anchor.record_leaf_hash(rec), expect)
        # The registrant email is a store field, never record data:
        # a record dict carrying one would hash differently, which
        # is exactly why emails are never written into records.
        leaked = dict(rec, creator_email="maker@example.com")
        self.assertNotEqual(anchor.record_leaf_hash(leaked), expect)

    def test_calldata_layout_v2(self):
        root = "ab" * 32
        sig = _signer_signature("anchor_xyz", root)
        data = anchor.anchor_calldata(root, "anchor_xyz", sig)
        self.assertTrue(data.startswith(b"NPC-ANCHOR-V2"))
        self.assertEqual(data[13:45].hex(), root)
        self.assertEqual(anchor.root_from_calldata(data), root)
        self.assertEqual(
            anchor.signer_signature_from_calldata(data), sig)
        self.assertEqual(anchor.batch_id_from_calldata(data),
                         "anchor_xyz")
        self.assertIsNone(anchor.root_from_calldata(b"\x00" * 60))
        self.assertIsNone(
            anchor.signer_signature_from_calldata(b"short"))
        with self.assertRaises(anchor.AnchorError):
            anchor.anchor_calldata(root, "anchor_xyz", "0x1234")


# -- transaction signing ------------------------------------------------------

def _rlp_decode(data, pos=0):
    b0 = data[pos]
    if b0 < 0x80:
        return data[pos:pos + 1], pos + 1
    if b0 < 0xB8:
        ln = b0 - 0x80
        return data[pos + 1:pos + 1 + ln], pos + 1 + ln
    if b0 < 0xC0:
        ll = b0 - 0xB7
        ln = int.from_bytes(data[pos + 1:pos + 1 + ll], "big")
        start = pos + 1 + ll
        return data[start:start + ln], start + ln
    if b0 < 0xF8:
        ln = b0 - 0xC0
        items, p = [], pos + 1
        end = p + ln
        while p < end:
            item, p = _rlp_decode(data, p)
            items.append(item)
        return items, end
    ll = b0 - 0xF7
    ln = int.from_bytes(data[pos + 1:pos + 1 + ll], "big")
    items, p = [], pos + 1 + ll
    end = p + ln
    while p < end:
        item, p = _rlp_decode(data, p)
        items.append(item)
    return items, end


class SigningTest(unittest.TestCase):
    def test_signed_tx_recovers_the_owner_wallet(self):
        root = "cd" * 32
        sig = _signer_signature("anchor_sig", root)
        data = anchor.anchor_calldata(root, "anchor_sig", sig)
        raw, tx_hash = anchor.sign_anchor_transaction(
            OWNER_KEY, chain_id=anchor.CHAIN_ID, nonce=7,
            max_priority_fee=10 ** 6, max_fee=10 ** 8,
            gas_limit=45000, to_address=OWNER_ADDRESS, data=data)
        self.assertEqual(tx_hash, "0x" + keccak256(raw).hex())
        self.assertEqual(raw[0], 2)
        fields, end = _rlp_decode(raw, 1)
        self.assertEqual(end, len(raw))
        self.assertEqual(len(fields), 12)
        chain_id, nonce = int.from_bytes(fields[0], "big"), \
            int.from_bytes(fields[1], "big")
        self.assertEqual((chain_id, nonce), (anchor.CHAIN_ID, 7))
        self.assertEqual(fields[5], bytes.fromhex(OWNER_ADDRESS[2:]))
        self.assertEqual(fields[7], data)
        parity = int.from_bytes(fields[9], "big")
        r = int.from_bytes(fields[10], "big")
        s = int.from_bytes(fields[11], "big")
        sighash = keccak256(b"\x02" + anchor._rlp_encode([
            anchor.CHAIN_ID, 7, 10 ** 6, 10 ** 8, 45000,
            bytes.fromhex(OWNER_ADDRESS[2:]), 0, data, []]))
        # The transaction sender is the OWNER wallet. The signer's
        # authorship rides inside the same transaction's calldata.
        self.assertEqual(recover_address(sighash, r, s, parity),
                         OWNER_ADDRESS)
        self.assertEqual(
            anchor.signer_signature_from_calldata(fields[7]), sig)


# -- configuration ---------------------------------------------------------------

class ConfigTest(unittest.TestCase):
    def test_default_off(self):
        cfg = anchor.config_from_env({})
        self.assertFalse(cfg.enabled)
        self.assertFalse(cfg.configured)

    def test_enabled_without_key_rests_unconfigured(self):
        cfg = anchor.config_from_env({"NPC_ANCHOR_ENABLED": "1"})
        self.assertTrue(cfg.enabled)
        self.assertIsNone(cfg.private_key)
        self.assertIsNone(cfg.address)

    def test_owner_key_parses_and_address_derives(self):
        cfg = anchor.config_from_env(
            {"NPC_ANCHOR_ENABLED": "1",
             "NPC_ANCHOR_PRIVATE_KEY": OWNER_HEX})
        self.assertEqual(cfg.private_key, OWNER_KEY)
        self.assertEqual(cfg.address, OWNER_ADDRESS)
        self.assertEqual(cfg.address,
                         address_from_private_key(OWNER_KEY))

    def test_malformed_key_raises(self):
        for bad in ("0xzz", "0x1234", "not-a-key"):
            with self.assertRaises(anchor.AnchorConfigError):
                anchor.config_from_env(
                    {"NPC_ANCHOR_ENABLED": "1",
                     "NPC_ANCHOR_PRIVATE_KEY": bad})

    def test_signer_defaults_to_bayos_legacy_wallet(self):
        # The production default is the address Bayo supplied on
        # 2026-10-28, checksummed; an env value overrides it.
        from npc_verify.ethkeys import to_checksum_address
        self.assertEqual(to_checksum_address(LEGACY_SIGNER.lower()),
                         anchor.DEFAULT_SIGNER_ADDRESS)
        cfg = anchor.config_from_env({})
        self.assertEqual(cfg.signer_address,
                         anchor.DEFAULT_SIGNER_ADDRESS)
        cfg = anchor.config_from_env(
            {"NPC_ANCHOR_SIGNER_ADDRESS": SIGNER_ADDRESS.lower()})
        self.assertEqual(cfg.signer_address, SIGNER_ADDRESS)
        with self.assertRaises(anchor.AnchorConfigError):
            anchor.config_from_env(
                {"NPC_ANCHOR_SIGNER_ADDRESS": "0x1234"})


# -- the authority layer ---------------------------------------------------------

class CommitmentTest(unittest.TestCase):
    def test_commitment_message_is_the_metamask_statement(self):
        msg = anchor.batch_commitment_message("anchor_x1", "ab" * 32)
        self.assertEqual(
            msg.decode("utf-8"),
            "NPC Verify anchor batch\n"
            "Batch: anchor_x1\n"
            "Merkle root: " + "ab" * 32 + "\n"
            "Chain: Base (8453)")

    def test_signer_signature_verifies_and_binds_the_batch(self):
        root = "ab" * 32
        sig = _signer_signature("anchor_x1", root)
        self.assertEqual(
            anchor.verify_batch_commitment("anchor_x1", root, sig),
            SIGNER_ADDRESS)
        # Another batch or another root: the signature does not
        # speak for them.
        self.assertNotEqual(
            anchor.verify_batch_commitment("anchor_x2", root, sig),
            SIGNER_ADDRESS)
        self.assertNotEqual(
            anchor.verify_batch_commitment(
                "anchor_x1", "cd" * 32, sig), SIGNER_ADDRESS)
        # The owner wallet's signature is not the signer's.
        owner_sig = _signer_signature("anchor_x1", root, key=OWNER_KEY)
        self.assertEqual(
            anchor.verify_batch_commitment(
                "anchor_x1", root, owner_sig), OWNER_ADDRESS)

    def test_malformed_commitment_signature_recovers_nothing(self):
        self.assertIsNone(anchor.verify_batch_commitment(
            "anchor_x1", "ab" * 32, "0x1234"))
        self.assertIsNone(anchor.verify_batch_commitment(
            "anchor_x1", "ab" * 32, None))


class SignerRotationTest(unittest.TestCase):
    def _notice(self, signer=OWNER_KEY, from_signer=SIGNER_ADDRESS,
                to_signer=NEW_SIGNER):
        return anchor.build_signer_rotation(
            signer, from_signer, to_signer, NOW)

    def test_owner_signed_rotation_verifies(self):
        notice = self._notice()
        self.assertTrue(anchor.verify_signer_rotation(
            notice, OWNER_ADDRESS))
        self.assertEqual(anchor.rotation_notice_id(notice),
                         anchor.rotation_notice_id(dict(notice)))

    def test_only_the_owner_can_rotate(self):
        # Signed by the signer itself: a compromised signer cannot
        # install its own successor. That is the point of the role
        # split.
        notice = self._notice(signer=SIGNER_KEY)
        self.assertFalse(anchor.verify_signer_rotation(
            notice, OWNER_ADDRESS))
        notice = self._notice(signer=9)
        self.assertFalse(anchor.verify_signer_rotation(
            notice, OWNER_ADDRESS))
        notice = self._notice()
        self.assertFalse(anchor.verify_signer_rotation(
            notice, SIGNER_ADDRESS))
        self.assertFalse(anchor.verify_signer_rotation(
            notice, None))

    def test_tampered_or_noop_rotation_fails(self):
        notice = self._notice()
        notice["to_signer"] = SIGNER_ADDRESS
        self.assertFalse(anchor.verify_signer_rotation(
            notice, OWNER_ADDRESS))
        noop = self._notice(to_signer=SIGNER_ADDRESS)
        self.assertFalse(anchor.verify_signer_rotation(
            noop, OWNER_ADDRESS))
        broken = self._notice()
        broken["signature"] = "0x" + "00" * 65
        self.assertFalse(anchor.verify_signer_rotation(
            broken, OWNER_ADDRESS))
        self.assertFalse(anchor.verify_signer_rotation(
            {"type": "npc.anchor.signer_rotation"}, OWNER_ADDRESS))

    def test_store_round_trip_both_backends(self):
        tmp = tempfile.mkdtemp(prefix="npc_anchor_rot_")
        sqlite_store = Store(os.path.join(tmp, "t.db"))
        import boto3 as fake_boto3
        from npc_verify.ddb_store import DynamoDBStore
        ddb_store = DynamoDBStore(
            table=fake_boto3.FakeTable("npc-verify-store-test"))
        notice = self._notice()
        nid = anchor.rotation_notice_id(notice)
        for store in (sqlite_store, ddb_store):
            self.assertTrue(store.add_anchor_rotation(
                nid, notice, NOW))
            self.assertFalse(store.add_anchor_rotation(
                nid, notice, NOW))
            self.assertEqual(store.list_anchor_rotations(), [notice])
            # The authorized signer follows the newest notice.
            self.assertEqual(
                anchor.authorized_signer(store, _cfg()), NEW_SIGNER)
        sqlite_store.close()

    def test_authorized_signer_defaults_to_config(self):
        tmp = tempfile.mkdtemp(prefix="npc_anchor_auth_")
        store = Store(os.path.join(tmp, "t.db"))
        try:
            self.assertEqual(anchor.authorized_signer(store, _cfg()),
                             SIGNER_ADDRESS)
        finally:
            store.close()


# -- the engine, on the SQLite store ----------------------------------------------

# -- calldata pricing ---------------------------------------------------------

class CalldataGasTest(unittest.TestCase):
    def test_calldata_gas_prices_the_eip7623_floor(self):
        # All non-zero data: the floor (10 gas per token, 4 tokens
        # per non-zero byte = 40 per byte) binds over the Istanbul
        # schedule (16 per byte). 133 non-zero bytes is this
        # engine's own anchor payload shape.
        self.assertEqual(anchor.calldata_gas(b"\x01" * 133), 5320)
        # Zero bytes price at the floor too (10 per byte, not 4).
        self.assertEqual(anchor.calldata_gas(b"\x00" * 10), 100)
        # Mixed data takes the higher schedule.
        self.assertEqual(
            anchor.calldata_gas(b"\x00\x01"), max(4 + 16, 10 + 40))


class EngineSqliteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="npc_anchor_test_")
        self.store = Store(os.path.join(self.tmp, "t.db"))
        self.chain = FakeChain()
        self.cfg = _cfg()

    def tearDown(self):
        self.store.close()

    def add(self, *record_ids):
        for i, rid in enumerate(record_ids):
            self.store.add_registration(
                _record(rid, "2026-10-28T10:0%d:00+00:00" % i),
                "maker@example.com", "203.0.113.9")

    def pass_once(self):
        return anchor.run_anchor_pass(
            self.store, self.chain, self.cfg, NOW, sleep=_no_sleep)

    def prepare_and_sign(self, key=SIGNER_KEY):
        """One pass (prepares the batch, which then awaits its
        signature) plus the signer's signature recorded."""
        out = self.pass_once()
        self.assertEqual(out["status"], "awaiting_signature", out)
        batch = self.store.open_anchor_batch()
        self.assertIsNotNone(batch)
        signed = anchor.record_batch_signature(
            self.store, self.cfg, batch["batch_id"],
            _signer_signature(batch["batch_id"],
                              batch["merkle_root"], key=key))
        self.assertEqual(signed["status"], "signed", signed)
        return batch

    def test_happy_path_signs_then_anchors_and_proves(self):
        self.add("reg_a", "reg_b", "reg_c")
        out = self.pass_once()
        # Nothing can move before the signer signs: no broadcast,
        # and the summary carries the exact statement to sign.
        self.assertEqual(out["status"], "awaiting_signature")
        self.assertEqual(len(self.chain.sent_raws), 0)
        batch = self.store.open_anchor_batch()
        self.assertEqual(out["batch_id"], batch["batch_id"])
        self.assertEqual(
            out["commitment_message"],
            anchor.batch_commitment_message(
                batch["batch_id"], batch["merkle_root"]
            ).decode("utf-8"))
        self.assertEqual(out["signer_address"], SIGNER_ADDRESS)
        # A signature from the wrong wallet records nothing.
        refused = anchor.record_batch_signature(
            self.store, self.cfg, batch["batch_id"],
            _signer_signature(batch["batch_id"],
                              batch["merkle_root"], key=OWNER_KEY))
        self.assertEqual(refused["status"], "signer_not_authorized")
        self.assertIsNone(
            self.store.get_anchor_batch(batch["batch_id"])
            ["batch_sig"])
        refused = anchor.record_batch_signature(
            self.store, self.cfg, batch["batch_id"], "0x1234")
        self.assertEqual(refused["status"], "invalid_signature")
        # The signer's signature lands, and the next pass anchors.
        signed = anchor.record_batch_signature(
            self.store, self.cfg, batch["batch_id"],
            _signer_signature(batch["batch_id"],
                              batch["merkle_root"]))
        self.assertEqual(signed["status"], "signed")
        out = self.pass_once()
        self.assertEqual(out["status"], "anchored")
        self.assertEqual(out["records"], 3)
        self.assertEqual(out["owner_wallet"], OWNER_ADDRESS)
        self.assertEqual(len(self.chain.sent_raws), 1)
        self.assertIsNone(self.store.open_anchor_batch())
        # The transaction on the (fake) chain carries the root AND
        # the signer's signature; its sender is the owner wallet.
        raw = self.chain.sent_raws[0]
        fields, _ = _rlp_decode(raw, 1)
        self.assertEqual(anchor.root_from_calldata(fields[7]),
                         out["merkle_root"])
        onchain_sig = anchor.signer_signature_from_calldata(fields[7])
        self.assertEqual(
            anchor.verify_batch_commitment(
                out["batch_id"], out["merkle_root"], onchain_sig),
            SIGNER_ADDRESS)
        # Every record: proof walks from its leaf to the batch root.
        for rid in ("reg_a", "reg_b", "reg_c"):
            row = self.store.get_record_anchor(rid)
            self.assertIsNotNone(row)
            rec = self.store.get_registration(rid)
            self.assertEqual(row["leaf_hash"],
                             anchor.record_leaf_hash(rec))
            self.assertTrue(anchor.verify_proof(
                row["leaf_hash"], row["proof"], out["merkle_root"]))
        self.assertEqual(self.store.count_anchored_records(), 3)
        # A second pass is a no-op: idle, no new broadcast.
        out2 = self.pass_once()
        self.assertEqual(out2["status"], "idle")
        self.assertEqual(len(self.chain.sent_raws), 1)

    def test_unfunded_batch_waits_then_anchors_as_prepared(self):
        self.chain.balance = 0
        self.add("reg_a")
        batch = self.prepare_and_sign()
        root_before = batch["merkle_root"]
        out = self.pass_once()
        self.assertEqual(out["status"], "unfunded")
        self.assertEqual(out["owner_wallet"], OWNER_ADDRESS)
        self.assertEqual(len(self.chain.sent_raws), 0)
        waiting = self.store.open_anchor_batch()
        self.assertEqual(waiting["status"], "prepared")
        self.chain.balance = 10 ** 17
        out = self.pass_once()
        self.assertEqual(out["status"], "anchored")
        self.assertEqual(out["merkle_root"], root_before)
        self.assertEqual(len(self.chain.sent_raws), 1)

    def test_crash_after_broadcast_finalizes_without_resending(self):
        self.chain.hold_receipts = True
        self.add("reg_a", "reg_b")
        self.prepare_and_sign()
        out = self.pass_once()
        self.assertEqual(out["status"], "submitted")
        self.assertEqual(len(self.chain.sent_raws), 1)
        batch = self.store.open_anchor_batch()
        self.assertEqual(batch["status"], "submitted")
        self.assertTrue(batch["tx_hash"])
        self.assertTrue(batch["raw_tx"])
        # The receipt lands; the next pass settles the same batch.
        self.chain.hold_receipts = False
        tx_hash = batch["tx_hash"]
        self.chain.receipts[tx_hash] = {
            "status": 1, "block_number": self.chain.block_no}
        out = self.pass_once()
        self.assertEqual(out["status"], "anchored")
        self.assertEqual(out["tx_hash"], tx_hash)
        self.assertEqual(len(self.chain.sent_raws), 1)

    def test_visible_transaction_waits_for_its_receipt(self):
        self.chain.hide_txs = True
        self.add("reg_a")
        self.prepare_and_sign()
        out = self.pass_once()
        self.assertEqual(out["status"], "submitted")
        first_raw = self.chain.sent_raws[0]
        # The node now shows the transaction (mempool view returns)
        # but still no receipt: the next pass must not resend, it
        # waits. Then receipts land and it finalizes.
        tx_hash = "0x" + keccak256(first_raw).hex()
        self.chain.txs[tx_hash] = {"hash": tx_hash}
        self.chain.nonce = 1
        out = self.pass_once()
        self.assertEqual(out["status"], "submitted")
        self.assertEqual(len(self.chain.sent_raws), 1)
        self.chain.receipts[tx_hash] = {
            "status": 1, "block_number": self.chain.block_no}
        out = self.pass_once()
        self.assertEqual(out["status"], "anchored")
        self.assertEqual(len(self.chain.sent_raws), 1)

    def test_vanished_transaction_rebroadcasts_same_raw(self):
        self.chain.hide_txs = True
        self.chain.hold_receipts = True
        self.add("reg_a")
        self.prepare_and_sign()
        out = self.pass_once()
        self.assertEqual(out["status"], "submitted")
        first_raw = self.chain.sent_raws[0]
        # The transaction vanishes entirely (never landed, nonce
        # still free): recovery rebroadcasts the identical signed
        # bytes, so the hash, and the batch, are unchanged.
        self.chain.hide_txs = False
        self.chain.hold_receipts = False
        out = self.pass_once()
        self.assertEqual(len(self.chain.sent_raws), 2)
        self.assertEqual(self.chain.sent_raws[1], first_raw)
        self.assertEqual(out["status"], "anchored")

    def test_intrinsically_rejected_transaction_rebuilds(self):
        # A batch whose stored transaction was built with a gas
        # limit below the chain's intrinsic floor (the pre-EIP-7623
        # schedule) can never be rebroadcast: the node rejects the
        # identical bytes forever. The pass must clear the stored
        # transaction and build a fresh one at the current schedule;
        # the batch, its root and its signature carry over, so the
        # signer never has to sign again.
        self.add("reg_a", "reg_b")
        batch = self.prepare_and_sign()
        batch = self.store.open_anchor_batch()
        data = anchor.anchor_calldata(
            batch["merkle_root"], batch["batch_id"],
            batch["batch_sig"])
        raw, tx_hash = anchor.sign_anchor_transaction(
            OWNER_KEY, chain_id=anchor.CHAIN_ID, nonce=0,
            max_priority_fee=self.chain.priority,
            max_fee=2 * self.chain.base_fee + self.chain.priority,
            gas_limit=21000, to_address=OWNER_ADDRESS, data=data)
        self.store.update_anchor_batch(batch["batch_id"], {
            "nonce": 0, "tx_hash": tx_hash, "raw_tx": raw.hex()})
        poisoned = raw

        class RejectingChain(FakeChain):
            def send_raw(self, candidate):
                if candidate == poisoned:
                    raise anchor.ChainError(
                        "RPC eth_sendRawTransaction answered an "
                        "error: {'code': -32000, 'message': "
                        "'intrinsic gas too low'}")
                return super().send_raw(candidate)

        self.chain = RejectingChain()
        out = self.pass_once()
        self.assertEqual(out["status"], "anchored")
        self.assertNotEqual(out["tx_hash"], tx_hash)
        self.assertEqual(len(self.chain.sent_raws), 1)
        self.assertNotEqual(self.chain.sent_raws[0], poisoned)
        self.assertEqual(self.store.count_anchored_records(), 2)

    def test_failed_transaction_releases_records_for_rebatch(self):
        self.chain.fail_next_receipt = True
        self.add("reg_a", "reg_b")
        self.prepare_and_sign()
        out = self.pass_once()
        self.assertEqual(out["status"], "failed")
        self.assertEqual(self.store.count_anchored_records(), 0)
        self.assertEqual(
            len(self.store.unanchored_registrations(10)), 2)
        # The rebatch is a new batch: it needs a fresh signature.
        self.prepare_and_sign()
        out = self.pass_once()
        self.assertEqual(out["status"], "anchored")
        self.assertEqual(self.store.count_anchored_records(), 2)
        counts = self.store.count_anchor_batches()
        self.assertEqual(counts.get("failed"), 1)
        self.assertEqual(counts.get("confirmed"), 1)

    def test_signature_locks_once_submitted(self):
        self.chain.hold_receipts = True
        self.add("reg_a")
        batch = self.prepare_and_sign()
        out = self.pass_once()
        self.assertEqual(out["status"], "submitted")
        locked = anchor.record_batch_signature(
            self.store, self.cfg, batch["batch_id"],
            _signer_signature(batch["batch_id"],
                              batch["merkle_root"]))
        self.assertEqual(locked["status"], "batch_locked")
        unknown = anchor.record_batch_signature(
            self.store, self.cfg, "anchor_nope", "0x" + "11" * 65)
        self.assertEqual(unknown["status"], "unknown_batch")

    def test_disabled_and_unconfigured_rest(self):
        self.add("reg_a")
        out = anchor.run_anchor_pass(
            self.store, self.chain, _cfg(enabled=False), NOW,
            sleep=_no_sleep)
        self.assertEqual(out["status"], "disabled")
        out = anchor.run_anchor_pass(
            self.store, self.chain, _cfg(private_key=None), NOW,
            sleep=_no_sleep)
        self.assertEqual(out["status"], "not_configured")
        self.assertEqual(len(self.chain.sent_raws), 0)
        self.assertIsNone(self.store.open_anchor_batch())


# -- the engine, on the DynamoDB store (parity) --------------------------------------

class EngineDynamoTest(unittest.TestCase):
    def setUp(self):
        import boto3 as fake_boto3
        from npc_verify.ddb_store import DynamoDBStore
        self.store = DynamoDBStore(
            table=fake_boto3.FakeTable("npc-verify-store-test"))
        self.chain = FakeChain()
        self.cfg = _cfg()

    def _sign_open_batch(self):
        batch = self.store.open_anchor_batch()
        out = anchor.record_batch_signature(
            self.store, self.cfg, batch["batch_id"],
            _signer_signature(batch["batch_id"],
                              batch["merkle_root"]))
        self.assertEqual(out["status"], "signed", out)
        return batch

    def test_anchor_round_trip(self):
        for i, rid in enumerate(("reg_x", "reg_y")):
            self.store.add_registration(
                _record(rid, "2026-10-28T10:0%d:00+00:00" % i),
                "maker@example.com", "203.0.113.9")
        out = anchor.run_anchor_pass(
            self.store, self.chain, self.cfg, NOW, sleep=_no_sleep)
        self.assertEqual(out["status"], "awaiting_signature")
        self.assertEqual(len(self.chain.sent_raws), 0)
        self._sign_open_batch()
        out = anchor.run_anchor_pass(
            self.store, self.chain, self.cfg, NOW, sleep=_no_sleep)
        self.assertEqual(out["status"], "anchored")
        self.assertEqual(self.store.count_anchored_records(), 2)
        self.assertEqual(self.store.unanchored_registrations(10), [])
        row = self.store.get_record_anchor("reg_x")
        self.assertTrue(anchor.verify_proof(
            row["leaf_hash"], row["proof"], out["merkle_root"]))

    def test_release_and_rebatch(self):
        self.chain.fail_next_receipt = True
        self.store.add_registration(
            _record("reg_x"), "maker@example.com", "203.0.113.9")
        anchor.run_anchor_pass(
            self.store, self.chain, self.cfg, NOW, sleep=_no_sleep)
        self._sign_open_batch()
        out = anchor.run_anchor_pass(
            self.store, self.chain, self.cfg, NOW, sleep=_no_sleep)
        self.assertEqual(out["status"], "failed")
        self.assertIsNone(self.store.get_record_anchor("reg_x"))
        self.assertEqual(
            len(self.store.unanchored_registrations(10)), 1)


# -- HTTP surface -----------------------------------------------------------------------

class _HttpBase(unittest.TestCase):
    """Shared server plumbing for the anchor HTTP classes."""

    ENV_KEYS = ("NPC_ANCHOR_ENABLED", "NPC_ANCHOR_PRIVATE_KEY",
                "NPC_ANCHOR_SIGNER_ADDRESS")
    ENV = {"NPC_ANCHOR_ENABLED": "1",
           "NPC_ANCHOR_PRIVATE_KEY": OWNER_HEX,
           "NPC_ANCHOR_SIGNER_ADDRESS": SIGNER_ADDRESS}

    @classmethod
    def setUpClass(cls):
        from npc_verify.server import create_app, Handler
        from npc_verify.seed import seed_all
        from http.server import ThreadingHTTPServer
        cls._old_env = {k: os.environ.get(k) for k in cls.ENV_KEYS}
        for k in cls.ENV_KEYS:
            os.environ.pop(k, None)
        os.environ.update(cls.ENV)
        cls.tmp = tempfile.mkdtemp(prefix="npc_anchor_http_")
        cls.chain = FakeChain()
        cls.app = create_app(os.path.join(cls.tmp, "t.db"),
                             os.path.join(cls.tmp, "keys"),
                             anchor_chain=cls.chain)
        seeded = seed_all(cls.app.store, cls.app.keys)
        cls.issuer_key = seeded["issuer_key"]
        cls.verifier_key = seeded["verifier_key"]
        Handler.app = cls.app
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.app.store.close()
        for k, v in cls._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def request(self, method, path, body=None, key=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port,
                                          timeout=10)
        hdrs = {}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        if key:
            hdrs["Authorization"] = "Bearer " + key
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else {}


class AnchorHttpTest(_HttpBase):
    """The full loop over HTTP: register, prepare, the signer signs
    (here with the test key standing in for MetaMask), the owner
    submits, and the public record answers with its anchor section.
    The proof AND the authorship both verify from the response
    alone: the public recipe."""

    def test_full_loop_and_public_recipe(self):
        status, rec = self.request("POST", "/v1/register/content", {
            "title": "Anchor me", "kind": "text",
            "locator": "ab" * 32,
            "creator_name": "Maker",
            "creator_email": "maker@example.com"})
        self.assertEqual(status, 201, rec)
        rid = rec["record_id"]

        status, body = self.request("GET", "/v1/records/" + rid)
        self.assertEqual(status, 200)
        self.assertEqual(body["anchor"]["status"], "not_anchored")
        self.assertEqual(body["anchor"]["owner_wallet"],
                         OWNER_ADDRESS)
        self.assertEqual(body["status"],
                         "registered_checks_pending")

        # The run and sign endpoints are issuer-only.
        status, _ = self.request("POST", "/v1/internal/anchor/run")
        self.assertIn(status, (401, 403))
        status, _ = self.request(
            "POST", "/v1/internal/anchor/run", key=self.verifier_key)
        self.assertIn(status, (401, 403))

        # Pass one prepares the batch and stops: awaiting the
        # signer's signature, with the statement to sign.
        status, out = self.request(
            "POST", "/v1/internal/anchor/run", key=self.issuer_key)
        self.assertEqual(status, 200, out)
        self.assertEqual(out["status"], "awaiting_signature")
        self.assertEqual(out["owner_wallet"], OWNER_ADDRESS)
        batch_id = out["batch_id"]
        root = out["merkle_root"]
        self.assertEqual(
            out["commitment_message"],
            anchor.batch_commitment_message(batch_id, root)
            .decode("utf-8"))
        self.assertEqual(len(self.chain.sent_raws), 0)

        # A signature from the owner wallet itself is refused: the
        # owner submits, it does not sign batches.
        status, out = self.request(
            "POST", "/v1/internal/anchor/sign",
            body={"batch_id": batch_id,
                  "signature": _signer_signature(
                      batch_id, root, key=OWNER_KEY)},
            key=self.issuer_key)
        self.assertEqual(status, 400, out)
        self.assertEqual(out["error"], "signer_not_authorized")
        # The signer's signature records.
        status, out = self.request(
            "POST", "/v1/internal/anchor/sign",
            body={"batch_id": batch_id,
                  "signature": _signer_signature(batch_id, root)},
            key=self.issuer_key)
        self.assertEqual(status, 200, out)
        self.assertEqual(out["status"], "signed")
        self.assertEqual(out["signer_address"], SIGNER_ADDRESS)

        # Pass two submits from the owner wallet and anchors.
        status, out = self.request(
            "POST", "/v1/internal/anchor/run", key=self.issuer_key)
        self.assertEqual(status, 200, out)
        self.assertEqual(out["status"], "anchored")
        tx_hash = out["tx_hash"]

        status, body = self.request("GET", "/v1/records/" + rid)
        self.assertEqual(status, 200)
        section = body["anchor"]
        self.assertEqual(section["status"], "anchored")
        self.assertEqual(section["chain"], "base")
        self.assertEqual(section["chain_id"], 8453)
        self.assertEqual(section["tx_hash"], tx_hash)
        self.assertEqual(
            section["explorer_url"],
            "https://basescan.org/tx/" + tx_hash)
        # The record's own status is untouched by anchoring.
        self.assertEqual(body["status"],
                         "registered_checks_pending")
        # The public recipe, from the response alone: drop the
        # read-time anchor section, canonicalize, hash, walk.
        public_body = {k: v for k, v in body.items() if k != "anchor"}
        leaf = hashlib.sha256(canonicalize(public_body)).hexdigest()
        self.assertEqual(leaf, section["leaf_hash"])
        self.assertTrue(anchor.verify_proof(
            leaf, section["proof"], section["merkle_root"]))
        # Authorship, from the response alone: rebuild the
        # commitment statement from the section and verify the
        # published signature against the signer wallet.
        self.assertEqual(section["signer_wallet"], SIGNER_ADDRESS)
        self.assertEqual(section["owner_wallet"], OWNER_ADDRESS)
        signer = verify_personal_signature(
            anchor.batch_commitment_message(
                section["batch_id"], section["merkle_root"]),
            bytes.fromhex(section["batch_signature"][2:]))
        self.assertEqual(signer, SIGNER_ADDRESS)

        status, st = self.request(
            "GET", "/v1/internal/anchor/status", key=self.issuer_key)
        self.assertEqual(status, 200)
        self.assertEqual(st["records_anchored"], 1)
        self.assertEqual(st["owner_wallet"], OWNER_ADDRESS)
        self.assertEqual(st["wallet_balance_wei"], 10 ** 17)
        self.assertEqual(st["signer_configured"], SIGNER_ADDRESS)
        self.assertEqual(st["authorized_signer"], SIGNER_ADDRESS)
        self.assertEqual(st["rotations_recorded"], 0)

        # The authority statement is public and inspectable.
        status, auth = self.request("GET", "/v1/anchor/authority")
        self.assertEqual(status, 200, auth)
        self.assertEqual(auth["owner_wallet"], OWNER_ADDRESS)
        self.assertEqual(auth["authorized_signer"], SIGNER_ADDRESS)
        self.assertEqual(auth["signer_rotations"], [])

    def test_rotation_flow(self):
        # The owner rotates the signer; the recorded notice is
        # owner-signed and inspectable, and the old signer's
        # signatures stop recording from that moment.
        status, out = self.request(
            "POST", "/v1/internal/anchor/rotate-signer",
            body={"to_signer_address": NEW_SIGNER},
            key=self.issuer_key)
        self.assertEqual(status, 200, out)
        self.assertEqual(out["status"], "recorded")
        self.assertEqual(out["authorized_signer"], NEW_SIGNER)
        notice = out["notice"]
        self.assertTrue(anchor.verify_signer_rotation(
            notice, OWNER_ADDRESS))
        self.assertEqual(notice["from_signer"], SIGNER_ADDRESS)
        self.assertEqual(notice["to_signer"], NEW_SIGNER)
        # Rotation is issuer-only, and a no-op rotation is refused.
        status, _ = self.request(
            "POST", "/v1/internal/anchor/rotate-signer",
            body={"to_signer_address": SIGNER_ADDRESS})
        self.assertIn(status, (401, 403))
        status, out = self.request(
            "POST", "/v1/internal/anchor/rotate-signer",
            body={"to_signer_address": NEW_SIGNER},
            key=self.issuer_key)
        self.assertEqual(status, 400, out)

        status, st = self.request(
            "GET", "/v1/internal/anchor/status", key=self.issuer_key)
        self.assertEqual(st["rotations_recorded"], 1)
        self.assertEqual(st["authorized_signer"], NEW_SIGNER)
        status, auth = self.request("GET", "/v1/anchor/authority")
        self.assertEqual(len(auth["signer_rotations"]), 1)
        self.assertEqual(auth["authorized_signer"], NEW_SIGNER)

        # A new batch now answers only to the new signer.
        status, rec = self.request("POST", "/v1/register/content", {
            "title": "Post rotation", "kind": "text",
            "locator": "cd" * 32,
            "creator_name": "Maker",
            "creator_email": "maker@example.com"})
        self.assertEqual(status, 201, rec)
        status, out = self.request(
            "POST", "/v1/internal/anchor/run", key=self.issuer_key)
        self.assertEqual(out["status"], "awaiting_signature")
        self.assertEqual(out["signer_address"], NEW_SIGNER)
        batch_id, root = out["batch_id"], out["merkle_root"]
        status, out = self.request(
            "POST", "/v1/internal/anchor/sign",
            body={"batch_id": batch_id,
                  "signature": _signer_signature(batch_id, root)},
            key=self.issuer_key)
        self.assertEqual(status, 400, out)
        self.assertEqual(out["error"], "signer_not_authorized")
        status, out = self.request(
            "POST", "/v1/internal/anchor/sign",
            body={"batch_id": batch_id,
                  "signature": _signer_signature(
                      batch_id, root, key=4)},
            key=self.issuer_key)
        self.assertEqual(status, 200, out)
        self.assertEqual(out["signer_address"], NEW_SIGNER)
        status, out = self.request(
            "POST", "/v1/internal/anchor/run", key=self.issuer_key)
        self.assertEqual(out["status"], "anchored")


class AnchorRotateUnconfiguredTest(_HttpBase):
    """With no owner key configured, rotation cannot be signed, so
    the endpoint refuses honestly (409) and records nothing."""

    ENV = {"NPC_ANCHOR_ENABLED": "1",
           "NPC_ANCHOR_SIGNER_ADDRESS": SIGNER_ADDRESS}

    def test_rotate_refused_without_owner_key(self):
        status, out = self.request(
            "POST", "/v1/internal/anchor/rotate-signer",
            body={"to_signer_address": NEW_SIGNER},
            key=self.issuer_key)
        self.assertEqual(status, 409, out)
        self.assertEqual(out["error"], "owner_not_configured")
        self.assertEqual(self.app.store.list_anchor_rotations(), [])


class AnchorAuthorityOffTest(_HttpBase):
    """With the lane off, the public authority endpoint fails
    closed, and record payloads carry no anchor section."""

    ENV = {}

    def test_authority_off_and_record_byte_identity(self):
        status, _ = self.request("GET", "/v1/anchor/authority")
        self.assertEqual(status, 404)
        rec = _record("reg_off")
        self.app.store.add_registration(rec, "maker@example.com",
                                        "203.0.113.9")
        section = anchor.anchor_section(
            self.app.store, "reg_off",
            self.app.anchor_config.enabled,
            cfg=self.app.anchor_config)
        self.assertIsNone(section)


if __name__ == "__main__":
    unittest.main()
