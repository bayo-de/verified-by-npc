"""C2PA Content Credentials: structural parse, server side.

A faithful port of the Chrome extension's staging forensics parser
(plugins v1.1 forensics.js): extract the JUMBF manifest store from a
JPEG (APP11 JPEG XT packets) or a PNG (caBX chunk), walk the box tree,
decode the claim (CBOR), and report what the file declares: claim
generator, declared digital source type, assertion labels, instance ID.

STRUCTURAL ONLY. Nothing here validates the claim signature, the
assertion hashes, timestamps, or the signing certificate chain. A
present credential is reported with the standing honesty label
"present_not_cryptographically_validated" and validated: False.
Presence is a fact about the file's structure, never a verdict about
the content.

Never raises: unreadable input returns None or an empty result.
"""
import struct

# IPTC digital source type -> plain label (ported from forensics.js).
_SOURCE_TYPE_LABELS = {
    "trainedalgorithmicmedia": "AI-generated",
    "algorithmicmedia": "AI-generated",
    "compositewithtrainedalgorithmicmedia": "AI-generated composite",
    "digitalcapture": "Digital capture",
    "datadrivenmedia": "Data-driven media",
    "composite": "Composite",
    "compositecapture": "Composite capture",
    "humanedits": "Human-edited",
    "humanedited": "Human-edited",
    "virtualrecording": "Virtual recording",
    "negativefilm": "Film scan (negative)",
    "positivefilm": "Film scan (positive)",
    "print": "Print scan",
}


def map_digital_source_type(raw):
    """Map an IPTC digital source type URI or code to a plain label."""
    if not raw or not isinstance(raw, str):
        return None
    code = raw.strip().split("/")[-1].strip()
    if not code:
        return None
    key = "".join(c for c in code.lower() if c.isalnum())
    if key in _SOURCE_TYPE_LABELS:
        return _SOURCE_TYPE_LABELS[key]
    # Unknown code: hand back the code itself, humanized, never invented.
    pretty = []
    for i, c in enumerate(code):
        if i and c.isupper() and (code[i - 1].islower()
                                  or code[i - 1].isdigit()):
            pretty.append(" ")
        pretty.append(c)
    pretty = "".join(pretty).lower()
    return pretty[:1].upper() + pretty[1:]


# -- minimal CBOR decoder (RFC 8949 subset, ported from forensics.js) ------
class _CborError(Exception):
    pass


def _cbor_decode(data, pos=0):
    """Decode one CBOR item. Returns (value, next_pos). Raises _CborError."""
    end = len(data)

    def need(n):
        if pos + n > end:
            raise _CborError("cbor truncated")

    def read_u8():
        nonlocal pos
        need(1)
        v = data[pos]
        pos += 1
        return v

    def read_arg(ai):
        nonlocal pos
        if ai < 24:
            return ai
        if ai == 24:
            return read_u8()
        if ai == 25:
            need(2)
            v = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 2
            return v
        if ai == 26:
            need(4)
            v = struct.unpack(">I", data[pos:pos + 4])[0]
            pos += 4
            return v
        if ai == 27:
            need(8)
            v = struct.unpack(">Q", data[pos:pos + 8])[0]
            pos += 8
            return v
        if ai == 31:
            return -1  # indefinite-length marker
        raise _CborError("cbor reserved additional info")

    def is_break():
        nonlocal pos
        if pos < end and data[pos] == 0xFF:
            pos += 1
            return True
        return False

    def decode(depth):
        nonlocal pos
        if depth > 48:
            raise _CborError("cbor too deep")
        if pos >= end:
            raise _CborError("cbor truncated")
        ib = data[pos]
        pos += 1
        major = ib >> 5
        ai = ib & 31
        if major == 6:  # tag: discard the tag number, decode the value
            if ai == 31:
                raise _CborError("cbor bad tag")
            read_arg(ai)
            return decode(depth + 1)
        if major == 7:
            if ai < 20:
                return ai
            if ai == 20:
                return False
            if ai == 21:
                return True
            if ai == 22:
                return None
            if ai == 23:
                return None
            if ai == 24:
                v = read_u8()
                if v == 20:
                    return False
                if v == 21:
                    return True
                if v in (22, 23):
                    return None
                return v
            if ai == 25:
                need(2)
                u = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += 2
                return _half_to_float(u)
            if ai == 26:
                need(4)
                v = struct.unpack(">f", data[pos:pos + 4])[0]
                pos += 4
                return v
            if ai == 27:
                need(8)
                v = struct.unpack(">d", data[pos:pos + 8])[0]
                pos += 8
                return v
            raise _CborError("cbor bad simple value")
        arg = read_arg(ai)
        if major == 0:
            if arg < 0:
                raise _CborError("cbor bad uint")
            return arg
        if major == 1:
            if arg < 0:
                raise _CborError("cbor bad int")
            return -1 - arg
        if major in (2, 3):
            parts = []
            if arg < 0:  # indefinite: a run of definite chunks
                while not is_break():
                    if pos >= end or (data[pos] >> 5) != major:
                        raise _CborError("cbor bad chunk")
                    parts.append(decode(depth + 1))
            else:
                if arg > end - pos:
                    raise _CborError("cbor length out of range")
                chunk = data[pos:pos + arg]
                pos += arg
                parts.append(chunk if major == 2
                             else chunk.decode("utf-8", "replace"))
            if major == 3:
                return "".join(parts)
            return b"".join(parts)
        if major == 4:
            out = []
            if arg < 0:
                while not is_break():
                    out.append(decode(depth + 1))
            else:
                if arg > end - pos:
                    raise _CborError("cbor length out of range")
                for _ in range(arg):
                    out.append(decode(depth + 1))
            return out
        # major == 5: map
        out = {}
        pairs = arg
        if arg >= 0 and arg > end - pos:
            raise _CborError("cbor length out of range")
        i = 0
        while pairs < 0 or i < pairs:
            if pairs < 0 and is_break():
                break
            k = decode(depth + 1)
            v = decode(depth + 1)
            if isinstance(k, str):
                key = k
            elif isinstance(k, (int, bool)):
                key = str(k)
            elif isinstance(k, bytes):
                key = k.decode("latin-1")
            else:
                key = None
            if key is not None:
                out[key] = v
            i += 1
        return out

    value = decode(0)
    return value, pos


def _half_to_float(u):
    """IEEE 754 half-precision bits -> Python float."""
    sign = -1.0 if (u >> 15) else 1.0
    exp = (u >> 10) & 0x1F
    frac = u & 0x3FF
    if exp == 0:
        return sign * (frac / 1024.0) * (2 ** -14)
    if exp == 31:
        return sign * float("inf") if frac == 0 else float("nan")
    return sign * (1.0 + frac / 1024.0) * (2 ** (exp - 15))


# -- minimal CBOR encoder (deterministic form, for COSE Sig_structure) ----
def _cbor_head(major, arg):
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 256:
        return bytes([(major << 5) | 24, arg])
    if arg < 65536:
        return bytes([(major << 5) | 25]) + struct.pack(">H", arg)
    if arg < 4294967296:
        return bytes([(major << 5) | 26]) + struct.pack(">I", arg)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", arg)


def _cbor_encode(value):
    """Encode a small CBOR value deterministically (RFC 8949 core):
    ints, byte/text strings, arrays, maps with int or text keys,
    bool, None, and ("tag", n, value) tuples. Used to rebuild the
    COSE Sig_structure whose signature is being verified; never
    raises on the shapes this codebase feeds it."""
    if isinstance(value, tuple) and len(value) == 3 and value[0] == "tag":
        return _cbor_head(6, value[1]) + _cbor_encode(value[2])
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _cbor_head(0, value)
        return _cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _cbor_head(4, len(value)) + b"".join(
            _cbor_encode(v) for v in value)
    if isinstance(value, dict):
        items = sorted(value.items(),
                       key=lambda kv: _cbor_encode(kv[0]))
        out = [_cbor_head(5, len(items))]
        for k, v in items:
            out.append(_cbor_encode(k))
            out.append(_cbor_encode(v))
        return b"".join(out)
    raise _CborError("cannot encode %r" % type(value))


def _map_get(mapping, key, default=None):
    """Fetch a key from a decoded CBOR map. The decoder above turns
    int keys into their decimal text form, so look up both forms."""
    if not isinstance(mapping, dict):
        return default
    if key in mapping:
        return mapping[key]
    return mapping.get(str(key), default)


# -- JUMBF box tree (ISO/IEC 19566-5) ---------------------------------------
def _boxes(data, start, end):
    """Yield (type, content_start, content_end) for one box level.

    LBox/TBox pairs; the 64-bit (LBox == 1) and extends-to-end
    (LBox == 0) forms are handled. A malformed box ends the level.
    """
    out = []
    off = start
    while off + 8 <= end:
        lbox = struct.unpack(">I", data[off:off + 4])[0]
        btype = data[off + 4:off + 8].decode("latin-1")
        header = 8
        if lbox == 1:
            if off + 16 > end:
                break
            size = struct.unpack(">Q", data[off + 8:off + 16])[0]
            header = 16
        elif lbox == 0:
            size = end - off
        else:
            size = lbox
        if size < header or off + size > end:
            break
        out.append((btype, off + header, off + size))
        off += size
    return out


def _jumd_label(data, content_start, content_end):
    """The label in a jumd box: 16-byte UUID, toggles byte, label text."""
    p = content_start + 16
    if p >= content_end:
        return None
    if data[p] < 0x20:  # toggles byte is optional in some writers
        p += 1
    if p >= content_end:
        return None
    raw = data[p:content_end]
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    label = raw.decode("utf-8", "replace").strip()
    return label or None


def _visit(data, start, end, depth, ctx):
    """Walk the box tree collecting assertion labels and leaf payloads."""
    if depth > 24 or start >= end:
        return
    boxes = _boxes(data, start, end)
    my_label = None
    if boxes and boxes[0][0] == "jumd":
        my_label = _jumd_label(data, boxes[0][1], boxes[0][2])
        if my_label and my_label.startswith("c2pa.") \
                and my_label != "c2pa.assertions" \
                and my_label not in ctx["assertion_labels"]:
            ctx["assertion_labels"].append(my_label)
    for btype, cs, ce in boxes:
        if btype == "jumd":
            continue
        if btype in ("jumb", "c2pa"):
            _visit(data, cs, ce, depth + 1, ctx)
        else:
            # box_start/box_end: the content span of the enclosing
            # labeled box (this level's start..end). The claim's
            # assertion hashes are computed over exactly that span
            # (description box + content box, headers included).
            ctx["leaves"].append({"label": my_label, "type": btype,
                                  "start": cs, "end": ce,
                                  "box_start": start, "box_end": end})


def _find_digital_source_type(node, depth=0):
    if depth > 12:
        return None
    if isinstance(node, list):
        for item in node:
            hit = _find_digital_source_type(item, depth + 1)
            if hit:
                return hit
        return None
    if isinstance(node, dict):
        v = node.get("digitalSourceType")
        if isinstance(v, str) and v:
            return v
        for item in node.values():
            hit = _find_digital_source_type(item, depth + 1)
            if hit:
                return hit
    return None


# -- container extraction -----------------------------------------------------
def _jumbf_from_jpeg(data):
    """Reassemble the JUMBF stream from JPEG APP11 (JPEG XT) packets."""
    if len(data) < 4 or data[0:2] != b"\xff\xd8":
        return None
    packets = []
    off = 2
    while off + 4 < len(data):
        if data[off] != 0xFF:
            break
        marker = data[off + 1]
        if marker in (0xDA, 0xD9):  # SOS / EOI: image data follows
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            off += 2
            continue
        seg_len = struct.unpack(">H", data[off + 2:off + 4])[0]
        if seg_len < 2 or off + 2 + seg_len > len(data):
            break
        seg_end = off + 2 + seg_len
        if marker == 0xEB:  # APP11 (JPEG XT)
            if seg_len >= 10 and data[off + 4:off + 6] == b"JP":
                # The layout real C2PA signers write: "JP" common
                # identifier, a 2-byte packet field, then a 4-byte
                # packet sequence number; box bytes follow (8-byte
                # payload header).
                seq = struct.unpack(">I", data[off + 8:off + 12])[0]
                if seg_end > off + 12:
                    packets.append((seq, data[off + 12:seg_end]))
            elif seg_len >= 8 and data[off + 4:off + 8] == b"JUMB":
                # Staging-era layout: "JUMB" + 2-byte sequence number.
                seq = struct.unpack(">H", data[off + 8:off + 10])[0]
                if seg_end > off + 10:
                    packets.append((seq, data[off + 10:seg_end]))
        off += 2 + seg_len
    if not packets:
        return None
    packets.sort(key=lambda p: p[0])
    return b"".join(p[1] for p in packets)


def _jumbf_from_png(data):
    """The caBX chunk content is the raw JUMBF stream, no packet headers."""
    sig = bytes([137, 80, 78, 71, 13, 10, 26, 10])
    if len(data) < 8 or data[:8] != sig:
        return None
    off = 8
    while off + 8 < len(data):
        chunk_len = struct.unpack(">I", data[off:off + 4])[0]
        ctype = data[off + 4:off + 8].decode("latin-1")
        if chunk_len > len(data):
            break
        if ctype == "caBX" and chunk_len > 0:
            return data[off + 8:off + 8 + chunk_len]
        if ctype == "IEND":
            break
        off += 12 + chunk_len
    return None


# The BMFF (MP4/MOV) C2PA manifest box: a top-level uuid box whose
# 16-byte user type is this UUID; the JUMBF stream follows it.
_BMFF_C2PA_USERTYPE = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")


def _jumbf_from_bmff(data):
    """The JUMBF stream from an ISO BMFF file's C2PA uuid box."""
    if len(data) < 16 or data[4:8] != b"ftyp":
        return None
    off = 0
    while off + 8 <= len(data):
        size = struct.unpack(">I", data[off:off + 4])[0]
        btype = data[off + 4:off + 8]
        header = 8
        if size == 1:
            if off + 16 > len(data):
                return None
            size = struct.unpack(">Q", data[off + 8:off + 16])[0]
            header = 16
        elif size == 0:
            size = len(data) - off
        if size < header or off + size > len(data):
            return None
        if btype == b"uuid" and size >= header + 16 and \
                data[off + header:off + header + 16] == \
                _BMFF_C2PA_USERTYPE:
            content = data[off + header + 16:off + size]
            # The uuid payload frames each manifest (a label field
            # precedes the JUMBF box; 21 bytes in files written by
            # the reference SDK). Scan a short window for the jumb
            # box whose length lands exactly on the payload end.
            for k in range(0, min(64, len(content) - 8) + 1):
                if content[k + 4:k + 8] == b"jumb":
                    lbox = struct.unpack(
                        ">I", content[k:k + 4])[0]
                    if lbox >= 8 and k + lbox == len(content):
                        return content[k:k + lbox]
            return None
        off += size
    return None


def extract_jumbf(data):
    """Pull the JUMBF manifest-store bytes out of a JPEG, PNG, or
    BMFF (MP4/MOV) file, or None."""
    if not data:
        return None
    if data[:2] == b"\xff\xd8":
        return _jumbf_from_jpeg(data)
    if data[:8] == bytes([137, 80, 78, 71, 13, 10, 26, 10]):
        return _jumbf_from_png(data)
    if len(data) >= 8 and data[4:8] == b"ftyp":
        return _jumbf_from_bmff(data)
    return None


def extract_manifest(data):
    """Internal: pull a manifest's working parts out of an asset.

    Returns None when no JUMBF store is present, else a dict:
      {jumbf, assertion_labels,
       leaves: [{label, type, bytes, data (decoded, when readable)}],
       claim: the decoded claim dict or None,
       claim_raw: the claim box's exact stored bytes or None,
       claim_leaf: the leaf the claim came from or None}

    The claim is recognized by its dedicated box type (c2cl), by a
    claim label (c2pa.claim / c2pa.claim.v2), or, as before, by the
    claim-shaped CBOR payload some writers use. The cryptographic
    validator (c2pa_validate) consumes this; the structural parser
    below renders its public summary from the same parts. Never
    raises.
    """
    try:
        jumbf = extract_jumbf(data)
        if not jumbf or len(jumbf) < 8:
            return None
        ctx = {"leaves": [], "assertion_labels": []}
        _visit(jumbf, 0, len(jumbf), 0, ctx)
        leaves = []
        claims = []
        shaped = []

        def _is_claim_shaped(d):
            return isinstance(d, dict) and (
                isinstance(d.get("claim_generator"), str)
                or d.get("claim_generator_info")
                or isinstance(d.get("instanceID"), str))

        for leaf in ctx["leaves"]:
            chunk = jumbf[leaf["start"]:leaf["end"]]
            entry = {"label": leaf["label"], "type": leaf["type"],
                     "bytes": chunk,
                     "box_bytes": jumbf[leaf["box_start"]:
                                        leaf["box_end"]],
                     "data": None}
            decoded = None
            if leaf["type"] in ("c2cl", "cbor"):
                try:
                    value, _ = _cbor_decode(chunk)
                    if isinstance(value, (dict, list)):
                        decoded = value
                except _CborError:
                    pass  # unreadable payload: skip it
            elif leaf["type"] == "json":
                try:
                    import json as _json
                    value = _json.loads(chunk.decode("utf-8"))
                    if isinstance(value, (dict, list)):
                        decoded = value
                except Exception:
                    pass
            entry["data"] = decoded
            leaves.append(entry)
            if isinstance(decoded, dict) and (
                    leaf["type"] == "c2cl"
                    or leaf["label"] in ("c2pa.claim", "c2pa.claim.v2")):
                claims.append({"claim": decoded, "claim_raw": chunk,
                               "leaf": entry})
            elif _is_claim_shaped(decoded):
                shaped.append({"claim": decoded, "claim_raw": chunk,
                               "leaf": entry})
        claims.extend(shaped)
        first = claims[0] if claims else None
        return {"jumbf": jumbf,
                "assertion_labels": ctx["assertion_labels"],
                "leaves": leaves,
                "claims": claims,
                "claim": first["claim"] if first else None,
                "claim_raw": first["claim_raw"] if first else None,
                "claim_leaf": first["leaf"] if first else None}
    except Exception:
        return None


def parse_credentials(data):
    """Structural parse of an image's C2PA Content Credentials.

    Returns the declared credential facts, or None when no readable
    claim is present. Structural only: the result always carries
    status "present_not_cryptographically_validated" and
    validated: False. Cryptographic validation lives in
    c2pa_validate.validate_credentials, which runs separately.
    Never raises.
    """
    try:
        manifest = extract_manifest(data)
        if manifest is None:
            return None
        claim = manifest["claim"]
        if claim is None:
            return None
        payloads = [{"label": e["label"], "data": e["data"]}
                    for e in manifest["leaves"]
                    if isinstance(e["data"], (dict, list))]

        generator = None
        cg = claim.get("claim_generator")
        if isinstance(cg, str) and cg.strip():
            generator = cg.strip()
        elif claim.get("claim_generator_info"):
            info = claim["claim_generator_info"]
            if isinstance(info, list):
                info = info[0] if info else None
            if isinstance(info, dict) and isinstance(info.get("name"), str) \
                    and info["name"].strip():
                generator = info["name"].strip()
                ver = info.get("version")
                if isinstance(ver, str) and ver.strip() \
                        and ver.strip() not in generator:
                    generator += " " + ver.strip()

        dst_raw = None
        for p in payloads:
            if p["label"] == "c2pa.actions":
                dst_raw = _find_digital_source_type(p["data"])
                if dst_raw:
                    break
        if not dst_raw:
            for p in payloads:
                dst_raw = _find_digital_source_type(p["data"])
                if dst_raw:
                    break
        if not dst_raw:
            dst_raw = _find_digital_source_type(claim)

        instance_id = None
        for key in ("instanceID", "instanceId"):
            if isinstance(claim.get(key), str) and claim[key]:
                instance_id = claim[key]
                break

        return {
            "present": True,
            "status": "present_not_cryptographically_validated",
            "validated": False,
            "generator": generator,
            "digital_source_type": map_digital_source_type(dst_raw),
            "digital_source_type_raw": dst_raw,
            "assertions": manifest["assertion_labels"],
            "instance_id": instance_id,
        }
    except Exception:
        return None
