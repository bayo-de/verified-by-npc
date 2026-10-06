"""Pure-Python Ed25519 (RFC 8032), djb reference structure.

Bundled with the Verified by NPC API reference implementation so the
Verification API shares the exact same signing primitive as the NPC
agent attestation flow. No third-party crypto libraries are used anywhere
in this program; the primitive is implemented directly from the RFC.

Sign/verify take ~50-150ms in pure Python - fine for an API that signs
one response per request.

Run `python3 ed25519.py` to execute the RFC 8032 test vectors.
"""
import hashlib

b = 256
q = (1 << 255) - 19
l = (1 << 252) + 27742317777372353535851937790883648493


def H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def expmod(base, e, m):
    if e == 0:
        return 1
    t = expmod(base, e // 2, m) ** 2 % m
    if e & 1:
        t = (t * base) % m
    return t


def inv(x):
    return expmod(x, q - 2, q)


d = (-121665 * inv(121666)) % q
I = expmod(2, (q - 1) // 4, q)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1) % q
    x = expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = (4 * inv(5)) % q
Bx = xrecover(By)
B = (Bx, By)  # base point


def edwards_add(P, Q):
    # Twisted Edwards addition for a = -1 (Ed25519):
    # x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
    # y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2) % q
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2) % q
    return (x3, y3)


# --- extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, x*y = T/Z ---
# Point addition/doubling need NO modular inversions here (Hisil-Wong-
# Carter-Dawson, twisted Edwards a = -1), so scalar multiplication costs
# one inversion total instead of two per addition. ~100x faster than the
# affine double-and-add above; the affine edwards_add is kept only as a
# readable reference for the curve arithmetic.
def _to_ext(P):
    x, y = P
    return (x, y, 1, x * y % q)


def _ext_add(P, Q):
    (X1, Y1, Z1, T1), (X2, Y2, Z2, T2) = P, Q
    A = (Y1 - X1) * (Y2 - X2) % q
    B = (Y1 + X1) * (Y2 + X2) % q
    C = T1 * (2 * d % q) % q * T2 % q
    D = (2 * Z1 % q) * Z2 % q
    E = (B - A) % q
    F = (D - C) % q
    G = (D + C) % q
    H = (B + A) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


_IDENTITY_EXT = (0, 1, 1, 0)


def _ext_to_affine(P):
    X, Y, Z, _T = P
    zi = inv(Z)
    return (X * zi % q, Y * zi % q)


def scalarmult(P, e):
    if e == 0:
        return (0, 1)
    Pe = _to_ext(P)
    Q = _IDENTITY_EXT
    for i in range(e.bit_length() - 1, -1, -1):
        Q = _ext_add(Q, Q)
        if (e >> i) & 1:
            Q = _ext_add(Q, Pe)
    return _ext_to_affine(Q)


def encodepoint(P) -> bytes:
    x, y = P
    bits = (y & ((1 << 255) - 1)) | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def decodepoint(s: bytes):
    if len(s) != 32:
        raise ValueError("bad point encoding length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = (s[31] >> 7) & 1
    x = xrecover(y)
    if (x & 1) != sign:
        x = q - x
    if ((-x * x + y * y - 1 - d * x * x * y * y) % q) != 0:
        raise ValueError("point not on curve")
    return (x, y)


def _clamp(h32: bytes) -> int:
    a = int.from_bytes(h32, "little")
    a &= (1 << 254) - 8   # clear lowest 3 bits
    a &= ~(1 << 255)      # clear bit 255
    a |= (1 << 254)       # set bit 254
    return a


def publickey(seed: bytes) -> bytes:
    """32-byte public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a = _clamp(H(seed)[:32])
    return encodepoint(scalarmult(B, a))


def sign(seed: bytes, msg: bytes) -> bytes:
    """64-byte signature."""
    h = H(seed)
    a = _clamp(h[:32])
    prefix = h[32:]
    A = encodepoint(scalarmult(B, a))
    r = int.from_bytes(H(prefix + msg), "little") % l
    R = encodepoint(scalarmult(B, r))
    k = int.from_bytes(H(R + A + msg), "little") % l
    S = (r + k * a) % l
    return R + S.to_bytes(32, "little")


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pk) != 32 or len(sig) != 64:
        return False
    R, S = sig[:32], int.from_bytes(sig[32:], "little")
    if S >= l:
        return False
    try:
        A_pt = decodepoint(pk)
        R_pt = decodepoint(R)
    except ValueError:
        return False
    k = int.from_bytes(H(R + pk + msg), "little") % l
    lhs = scalarmult(B, S)
    kA = scalarmult(A_pt, k)
    rhs = _ext_to_affine(_ext_add(_to_ext(R_pt), _to_ext(kA)))
    return encodepoint(lhs) == encodepoint(rhs)


def self_test():
    # RFC 8032 section 7.1, TEST 1 (empty message) and TEST 2 (1 byte).
    def tv(sk_hex, pk_hex, msg_hex, sig_hex):
        sk = bytes.fromhex(sk_hex)
        pk = bytes.fromhex(pk_hex)
        msg = bytes.fromhex(msg_hex)
        sig = bytes.fromhex(sig_hex)
        assert publickey(sk) == pk, "publickey vector failed"
        assert sign(sk, msg) == sig, "sign vector failed"
        assert verify(pk, msg, sig), "verify vector failed"
        assert not verify(pk, msg + b"\x00", sig), "tamper not detected"

    tv("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
       "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
       "",
       "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
       "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    tv("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
       "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
       "72",
       "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
       "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    # roundtrip with fresh key
    import os
    seed = os.urandom(32)
    pk2 = publickey(seed)
    m2 = b"npc attestation roundtrip"
    s2 = sign(seed, m2)
    assert verify(pk2, m2, s2), "roundtrip failed"
    assert not verify(pk2, m2 + b".", s2), "roundtrip tamper not detected"
    print("ed25519 self-test: RFC 8032 vectors (TEST 1+2) + roundtrip OK")


if __name__ == "__main__":
    self_test()
