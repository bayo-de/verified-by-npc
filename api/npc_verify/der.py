"""Minimal ASN.1 DER reader + X.509 certificate facts (stdlib only).

Just enough to answer, for a C2PA signing certificate carried in a
COSE x5chain: who does the certificate SAY the signer is (subject +
issuer distinguished names), which algorithm and public key does it
carry, and when is it valid. This module parses; it renders NO trust
verdict. Trust decisions belong to a trust list, and none is
configured in this codebase today: callers report the signer exactly
as presented in the certificate.

Never raises on malformed input: parsers return None / partial facts.
"""
import base64
import binascii

# -- OIDs ----------------------------------------------------------------
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_ED448 = "1.3.101.113"
OID_CURVES = {
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
}
OID_ATTRS = {
    "2.5.4.3": "CN",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "1.2.840.113549.1.9.1": "emailAddress",
}
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_SHA384_RSA = "1.2.840.113549.1.1.12"
OID_SHA512_RSA = "1.2.840.113549.1.1.13"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4"


class DerError(ValueError):
    """Raised internally when DER bytes do not parse; caught here."""


def read_tlv(data, off):
    """Read one DER TLV at off. Returns (tag, content_bytes, raw_tlv,
    next_off). Raises DerError on truncation or indefinite lengths."""
    if off + 2 > len(data):
        raise DerError("truncated")
    tag = data[off]
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tags unsupported")
    lb = data[off + 1]
    hdr = 2
    if lb & 0x80:
        n = lb & 0x7F
        if n == 0 or n > 4 or off + 2 + n > len(data):
            raise DerError("bad length")
        length = int.from_bytes(data[off + 2:off + 2 + n], "big")
        hdr = 2 + n
    else:
        length = lb
    end = off + hdr + length
    if end > len(data):
        raise DerError("content overruns buffer")
    return tag, data[off + hdr:end], data[off:end], end


def children(content):
    """Yield (tag, content, raw) for each TLV inside a constructed
    value's content bytes."""
    off = 0
    while off < len(content):
        tag, body, raw, off = read_tlv(content, off)
        yield tag, body, raw


def decode_oid(content):
    if not content:
        raise DerError("empty oid")
    parts = [content[0] // 40, content[0] % 40]
    val = 0
    for b in content[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    if content[-1] & 0x80:
        raise DerError("truncated oid arc")
    return ".".join(str(p) for p in parts)


def decode_string(tag, content):
    """Decode a DN string value (PrintableString / UTF8String /
    TeletexString / IA5String / BMPString) to text, best effort."""
    try:
        if tag == 0x1E:  # BMPString: UTF-16BE
            return content.decode("utf-16-be", "replace")
        if tag == 0x14:  # TeletexString: latin-1 stands close enough
            return content.decode("latin-1", "replace")
        return content.decode("utf-8", "replace")
    except Exception:
        return ""


def format_name(content):
    """Format an X.501 Name (SEQUENCE of RDN SETs of {oid, value}) as
    a single line: "CN=..., O=..., C=...". Order preserved."""
    parts = []
    try:
        for tag, rdn, _raw in children(content):
            if tag != 0x31:
                continue
            for atag, atv, _r in children(rdn):
                if atag != 0x30:
                    continue
                fields = list(children(atv))
                if len(fields) != 2:
                    continue
                oid = decode_oid(fields[0][1])
                label = OID_ATTRS.get(oid, oid)
                value = decode_string(fields[1][0], fields[1][1])
                if value:
                    parts.append("%s=%s" % (label, value))
    except DerError:
        return ""
    return ", ".join(parts)


def decode_time(tag, content):
    """UTCTime (0x17) / GeneralizedTime (0x18) -> ISO-8601 text."""
    try:
        text = content.decode("ascii", "strict").strip()
    except Exception:
        return None
    import re
    m = re.match(r"^(\d{2,4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?"
                 r"(Z|[+-]\d{4})?$", text)
    if not m:
        return None
    year = m.group(1)
    if tag == 0x17 and len(year) == 2:
        year = ("20" if int(year) < 50 else "19") + year
    return "%s-%s-%sT%s:%s:%sZ" % (
        year, m.group(2), m.group(3), m.group(4), m.group(5),
        m.group(6) or "00")


def pem_to_der(pem):
    """Extract the DER bytes from a PEM certificate (or raw DER)."""
    if isinstance(pem, str):
        pem = pem.encode("ascii", "ignore")
    if b"-----BEGIN" not in pem:
        return bytes(pem)
    body = []
    inside = False
    for line in pem.splitlines():
        if line.startswith(b"-----BEGIN"):
            inside = True
            continue
        if line.startswith(b"-----END"):
            break
        if inside:
            body.append(line.strip())
    try:
        return base64.b64decode(b"".join(body))
    except (binascii.Error, ValueError):
        return b""


def parse_certificate(der_bytes):
    """Parse a DER X.509 certificate into a small facts dict:

      {subject, issuer, not_before, not_after, key_algorithm,
       ec_curve (when EC), public_key: {..raw components..},
       signature_algorithm (OID text), tbs_der, signature (bytes)}

    Public key components: RSA -> {n, e} ints; EC -> {x, y} ints and
    curve name; Ed25519 -> {raw} bytes. Returns None when the bytes
    are not a parseable certificate.
    """
    try:
        tag, cert, _raw, _ = read_tlv(der_bytes, 0)
        if tag != 0x30:
            return None
        parts = list(children(cert))
        if len(parts) != 3:
            return None
        tbs_raw = parts[0][2]
        tbs = parts[0][1]
        sig_alg_oid = None
        try:
            alg_fields = list(children(parts[1][1]))
            if alg_fields:
                sig_alg_oid = decode_oid(alg_fields[0][1])
        except DerError:
            pass
        signature = parts[2][1]
        if signature[:1] == b"\x00":  # BIT STRING unused-bits byte
            signature = signature[1:]

        fields = list(children(tbs))
        idx = 0
        if fields and fields[0][0] == 0xA0:  # [0] version
            idx = 1
        # serial (idx), signature alg (idx+1), issuer (idx+2),
        # validity (idx+3), subject (idx+4), SPKI (idx+5)
        if len(fields) < idx + 6:
            return None
        issuer = format_name(fields[idx + 2][1])
        validity = list(children(fields[idx + 3][1]))
        not_before = decode_time(validity[0][0], validity[0][1]) \
            if len(validity) > 0 else None
        not_after = decode_time(validity[1][0], validity[1][1]) \
            if len(validity) > 1 else None
        subject = format_name(fields[idx + 4][1])

        spki = list(children(fields[idx + 5][1]))
        if len(spki) != 2:
            return None
        alg_fields = list(children(spki[0][1]))
        key_oid = decode_oid(alg_fields[0][1])
        key_bits = spki[1][1]
        if key_bits[:1] == b"\x00":
            key_bits = key_bits[1:]
        facts = {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "signature_algorithm": sig_alg_oid,
            "tbs_der": tbs_raw,
            "signature": signature,
        }
        if key_oid == OID_RSA_ENCRYPTION:
            ktag, kcontent, _r, _n = read_tlv(key_bits, 0)
            if ktag != 0x30:
                return None
            ints = list(children(kcontent))
            if len(ints) != 2:
                return None
            facts["key_algorithm"] = "rsa"
            facts["public_key"] = {
                "n": int.from_bytes(ints[0][1], "big"),
                "e": int.from_bytes(ints[1][1], "big"),
            }
        elif key_oid == OID_EC_PUBLIC_KEY:
            curve = None
            if len(alg_fields) > 1 and alg_fields[1][0] == 0x06:
                curve = OID_CURVES.get(decode_oid(alg_fields[1][1]))
            if curve is None or not key_bits or key_bits[0] != 0x04:
                facts["key_algorithm"] = "ec_unsupported"
                return facts
            size = {"P-256": 32, "P-384": 48, "P-521": 66}[curve]
            if len(key_bits) != 1 + 2 * size:
                facts["key_algorithm"] = "ec_unsupported"
                return facts
            facts["key_algorithm"] = "ec"
            facts["ec_curve"] = curve
            facts["public_key"] = {
                "x": int.from_bytes(key_bits[1:1 + size], "big"),
                "y": int.from_bytes(key_bits[1 + size:], "big"),
            }
        elif key_oid in (OID_ED25519, OID_ED448):
            facts["key_algorithm"] = "ed25519" if key_oid == OID_ED25519 \
                else "ed448"
            facts["public_key"] = {"raw": key_bits}
        else:
            facts["key_algorithm"] = "unknown"
        return facts
    except (DerError, IndexError, ValueError, OverflowError):
        return None
