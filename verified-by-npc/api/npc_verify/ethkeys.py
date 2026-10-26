"""Ethereum primitives for the identity linking service.

Standard library only, like the rest of this API. SIWE (EIP-4361)
verification needs two things Python's hashlib does not provide:
Keccak-256 (Ethereum's hash; NOT the finalized SHA3-256, which pads
differently) and secp256k1 public key recovery from an ECDSA
signature. Both are implemented here in pure Python. The code paths
are small and constant-shape; the test suite pins them against the
well-known Keccak vectors and the address of private key 1.

Nothing here holds keys for NPC. These functions only VERIFY
signatures a wallet made elsewhere (and, for tests, produce them).
"""
import hashlib
import hmac as _hmac

# -- Keccak-256 ---------------------------------------------------------------
_KECCAK_RATE = 136  # bytes, for a 256-bit output (capacity 512)
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# Rotation offsets r[x][y] and the pi permutation targets, in the
# lane order state[x + 5*y].
_KECCAK_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_MASK64 = (1 << 64) - 1


def _rotl64(value, shift):
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state):
    """One Keccak-f[1600] permutation over 25 64-bit lanes."""
    for rc in _KECCAK_RC:
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15]
             ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1)
             for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    state[x + 5 * y], _KECCAK_ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ (
                    (~b[(x + 1) % 5 + 5 * y] & _MASK64)
                    & b[(x + 2) % 5 + 5 * y])
        # iota
        state[0] ^= rc
    return state


def keccak256(data: bytes) -> bytes:
    """Keccak-256 as Ethereum uses it (legacy 0x01 domain suffix)."""
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _KECCAK_RATE:
        padded.append(0x00)
    padded[-1] |= 0x80
    for off in range(0, len(padded), _KECCAK_RATE):
        block = padded[off:off + _KECCAK_RATE]
        for i in range(_KECCAK_RATE // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8],
                                       "little")
        _keccak_f1600(state)
    out = bytearray()
    for i in range(_KECCAK_RATE // 8):
        out += state[i].to_bytes(8, "little")
    return bytes(out[:32])


# -- secp256k1 ------------------------------------------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, _P) % _P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % _P, -1, _P) % _P
    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _point_neg(point):
    if point is None:
        return None
    return (point[0], (-point[1]) % _P)


def to_checksum_address(address: str) -> str:
    """EIP-55 checksum encoding of a 0x-prefixed address."""
    hex_part = address.lower()
    if hex_part.startswith("0x"):
        hex_part = hex_part[2:]
    digest = keccak256(hex_part.encode("ascii")).hex()
    out = []
    for i, ch in enumerate(hex_part):
        if ch in "abcdef" and int(digest[i], 16) >= 8:
            out.append(ch.upper())
        else:
            out.append(ch)
    return "0x" + "".join(out)


def is_valid_address(address) -> bool:
    """True for a well-formed address; a mixed-case address must
    also carry a valid EIP-55 checksum."""
    if not isinstance(address, str):
        return False
    if len(address) != 42 or not address.startswith("0x"):
        return False
    hex_part = address[2:]
    if any(c not in "0123456789abcdefABCDEF" for c in hex_part):
        return False
    if hex_part == hex_part.lower() or hex_part == hex_part.upper():
        return True
    return to_checksum_address(address) == address


def address_from_public_key(point) -> str:
    x, y = point
    raw = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return to_checksum_address(
        "0x" + keccak256(raw)[-20:].hex())


def address_from_private_key(private_key: int) -> str:
    return address_from_public_key(_point_mul(private_key, _G))


def recover_address(digest: bytes, r: int, s: int, recid: int):
    """Recover the signer's address from an ECDSA signature over a
    32-byte digest. Returns None when recovery is impossible."""
    if not (1 <= r < _N and 1 <= s < _N and recid in (0, 1, 2, 3)):
        return None
    x = r + (recid >> 1) * _N
    if x >= _P:
        return None
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if (y * y) % _P != y_sq:
        return None
    if (y & 1) != (recid & 1):
        y = _P - y
    point_r = (x, y)
    if _point_mul(_N, point_r) is not None:
        return None
    z = int.from_bytes(digest, "big") % _N
    r_inv = pow(r, -1, _N)
    q = _point_mul(r_inv, _point_add(
        _point_mul(s, point_r), _point_neg(_point_mul(z, _G))))
    if q is None:
        return None
    return address_from_public_key(q)


def personal_sign_digest(message: bytes) -> bytes:
    """The EIP-191 digest a wallet signs for a text message."""
    prefix = b"\x19Ethereum Signed Message:\n" + str(
        len(message)).encode("ascii")
    return keccak256(prefix + message)


def verify_personal_signature(message: bytes, signature: bytes):
    """Recover the signer address of an EIP-191 signature over
    `message`, or None when the signature is malformed."""
    if len(signature) != 65:
        return None
    r = int.from_bytes(signature[0:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    if v >= 27:
        recid = v - 27
    else:
        recid = v
    if recid not in (0, 1):
        return None
    return recover_address(personal_sign_digest(message), r, s, recid)


def _rfc6979_nonce(private_key: int, digest: bytes) -> int:
    """Deterministic per-signature nonce (RFC 6979, HMAC-SHA256)."""
    x = private_key.to_bytes(32, "big")
    h1 = (int.from_bytes(digest, "big") % _N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = _hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = _hmac.new(k, v, hashlib.sha256).digest()
    k = _hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = _hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = _hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < _N:
            return candidate
        k = _hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = _hmac.new(k, v, hashlib.sha256).digest()


def sign_personal(private_key: int, message: bytes) -> bytes:
    """Sign a text message the way a wallet would (EIP-191).

    Used by the test suite to stand in for a wallet, and available
    to any local tooling that needs a fixture signature. NPC never
    signs on a customer's behalf in production flows.
    """
    digest = personal_sign_digest(message)
    z = int.from_bytes(digest, "big")
    k = _rfc6979_nonce(private_key, digest)
    point_r = _point_mul(k, _G)
    r = point_r[0] % _N
    recid = (point_r[1] & 1) | (2 if point_r[0] >= _N else 0)
    s = (pow(k, -1, _N) * (z + r * private_key)) % _N
    if s > _N // 2:  # low-s normalization flips the recovery parity
        s = _N - s
        recid ^= 1
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") \
        + bytes([27 + recid])
