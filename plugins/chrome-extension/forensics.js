/* NPC Verify: client-side image forensics.
 *
 * Vanilla JS, no dependencies. Parses only what the file itself declares:
 * JPEG EXIF (Software / Make / Model / DateTime), PNG tEXt chunks, and
 * uncompressed PNG iTXt chunks. Matches embedded strings against known
 * generator markers.
 *
 * v1.1.0 adds two on-device provenance reads, both structural only:
 *   - C2PA Content Credentials: the JUMBF manifest store is walked
 *     (JPEG APP11 JPEG XT packets, reassembled in sequence order; PNG
 *     caBX chunk) and the active manifest's claim is decoded from CBOR.
 *     What the credential declares is reported (generator, source type,
 *     assertion labels). The credential's cryptographic signature is
 *     NOT checked in this version, and no result here ever claims it
 *     was: every credential result carries validated: false and the
 *     status "present_not_cryptographically_validated".
 *   - IPTC DigitalSourceType: read from the XMP packet wherever it
 *     rides (JPEG APP1 XMP segment, PNG iTXt "XML:com.adobe.xmp")
 *     and mapped to plain labels.
 *
 * What it never does: claim an image is AI-generated or human-made from
 * these signals alone. Markers can be stripped or faked, credentials
 * and tags can be edited or forged, and absence of any of them proves
 * nothing. Findings are reported; conclusions are not drawn.
 * Malformed or truncated structures degrade to "nothing found" and
 * never throw.
 */

const NPC_KNOWN_MARKERS = [
  { match: "dall", label: "DALL-E (OpenAI)" },
  { match: "midjourney", label: "Midjourney" },
  { match: "stable diffusion", label: "Stable Diffusion" },
  { match: "firefly", label: "Adobe Firefly" },
  { match: "ideogram", label: "Ideogram" },
  { match: "c2pa", label: "C2PA Content Credentials" },
  { match: "jumbf", label: "JUMBF container (Content Credentials)" },
  { match: "content credentials", label: "Content Credentials claim" },
  { match: "synthid", label: "SynthID watermark (Google)" },
  { match: "photoshop", label: "Adobe Photoshop (edited, not necessarily generated)" },
  { match: "gimp", label: "GIMP (edited, not necessarily generated)" }
];

function npcReadAscii(view, offset, length) {
  let s = "";
  for (let i = 0; i < length; i++) {
    const c = view.getUint8(offset + i);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function npcReadBytes(view, offset, length) {
  let s = "";
  for (let i = 0; i < length; i++) {
    s += String.fromCharCode(view.getUint8(offset + i));
  }
  return s;
}

function npcParseExif(buffer) {
  // Expects the TIFF header at the start of the buffer (after "Exif\0\0").
  const view = new DataView(buffer);
  const byteOrder = view.getUint16(0, false);
  const little = byteOrder === 0x4949;
  if (!little && byteOrder !== 0x4D4D) return null;
  if (view.getUint16(2, little) !== 42) return null;
  const ifdOffset = view.getUint32(4, little);
  const count = view.getUint16(ifdOffset, little);
  const out = {};
  const WANT = { 0x010F: "make", 0x0110: "model", 0x0131: "software", 0x0132: "datetime" };
  for (let i = 0; i < count; i++) {
    const e = ifdOffset + 2 + i * 12;
    const tag = view.getUint16(e, little);
    const type = view.getUint16(e + 2, little);
    const num = view.getUint32(e + 4, little);
    if (!WANT[tag] || type !== 2 || num === 0 || num > 512) continue;
    let val;
    if (num <= 4) {
      val = npcReadAscii(view, e + 8, num);
    } else {
      const vOff = view.getUint32(e + 8, little);
      if (vOff + num > view.byteLength) continue;
      val = npcReadAscii(view, vOff, num);
    }
    out[WANT[tag]] = val.trim();
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Minimal CBOR decoder (RFC 8949): major types 0-5, tags (skipped),  */
/* and simple/float values in major type 7. Byte strings decode to    */
/* Uint8Array, text strings to string, maps to plain objects.         */
/* Throws on anything malformed or truncated; callers catch.          */
/* ------------------------------------------------------------------ */

function npcCborHalfToFloat(u) {
  const sign = (u & 0x8000) ? -1 : 1;
  const exp = (u >> 10) & 0x1F;
  const frac = u & 0x03FF;
  if (exp === 0) return sign * Math.pow(2, -14) * (frac / 1024);
  if (exp === 31) return frac ? NaN : sign * Infinity;
  return sign * Math.pow(2, exp - 15) * (1 + frac / 1024);
}

function npcCborDecode(bytes, start) {
  let pos = start || 0;
  const end = bytes.length;
  function need(n) { if (pos + n > end) throw new Error("cbor truncated"); }
  function readU8() { need(1); return bytes[pos++]; }
  function readArg(ai) {
    if (ai < 24) return ai;
    if (ai === 24) return readU8();
    if (ai === 25) { need(2); const v = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2; return v; }
    if (ai === 26) {
      need(4);
      const v = new DataView(bytes.buffer, bytes.byteOffset + pos, 4).getUint32(0, false);
      pos += 4; return v;
    }
    if (ai === 27) {
      need(8);
      const dv = new DataView(bytes.buffer, bytes.byteOffset + pos, 8);
      const v = dv.getUint32(0, false) * 4294967296 + dv.getUint32(4, false);
      pos += 8; return v;
    }
    if (ai === 31) return -1; // indefinite-length marker
    throw new Error("cbor reserved additional info");
  }
  function isBreak() {
    if (pos < end && bytes[pos] === 0xFF) { pos++; return true; }
    return false;
  }
  function decode(depth) {
    if (depth > 48) throw new Error("cbor too deep");
    if (pos >= end) throw new Error("cbor truncated");
    const ib = bytes[pos++];
    const major = ib >> 5;
    const ai = ib & 31;
    if (major === 6) { // tag: read and discard the tag number, decode the value
      if (ai === 31) throw new Error("cbor bad tag");
      readArg(ai);
      return decode(depth + 1);
    }
    if (major === 7) {
      if (ai < 20) return ai;
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 23) return undefined;
      if (ai === 24) {
        const v = readU8();
        if (v === 20) return false;
        if (v === 21) return true;
        if (v === 22) return null;
        if (v === 23) return undefined;
        return v;
      }
      if (ai === 25) { need(2); const u = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2; return npcCborHalfToFloat(u); }
      if (ai === 26) {
        need(4);
        const v = new DataView(bytes.buffer, bytes.byteOffset + pos, 4).getFloat32(0, false);
        pos += 4; return v;
      }
      if (ai === 27) {
        need(8);
        const v = new DataView(bytes.buffer, bytes.byteOffset + pos, 8).getFloat64(0, false);
        pos += 8; return v;
      }
      throw new Error("cbor bad simple value"); // includes stray break (31)
    }
    const arg = readArg(ai);
    if (major === 0) {
      if (arg < 0) throw new Error("cbor bad uint");
      return arg;
    }
    if (major === 1) {
      if (arg < 0) throw new Error("cbor bad int");
      return -1 - arg;
    }
    if (major === 2 || major === 3) {
      const parts = [];
      if (arg < 0) { // indefinite: a run of definite chunks of the same major
        while (!isBreak()) {
          if (pos >= end || (bytes[pos] >> 5) !== major) throw new Error("cbor bad chunk");
          parts.push(decode(depth + 1));
        }
      } else {
        if (arg > end - pos) throw new Error("cbor length out of range");
        if (major === 2) {
          parts.push(bytes.subarray(pos, pos + arg));
          pos += arg;
        } else {
          parts.push(new TextDecoder("utf-8").decode(bytes.subarray(pos, pos + arg)));
          pos += arg;
        }
      }
      if (major === 3) return parts.join("");
      let total = 0;
      for (const p of parts) total += p.length;
      const out = new Uint8Array(total);
      let o = 0;
      for (const p of parts) { out.set(p, o); o += p.length; }
      return out;
    }
    if (major === 4) {
      const out = [];
      if (arg < 0) {
        while (!isBreak()) out.push(decode(depth + 1));
      } else {
        if (arg > end - pos) throw new Error("cbor length out of range");
        for (let i = 0; i < arg; i++) out.push(decode(depth + 1));
      }
      return out;
    }
    // major === 5: map
    const out = {};
    const pairs = (arg < 0) ? Infinity : arg;
    if (arg >= 0 && arg > end - pos) throw new Error("cbor length out of range");
    for (let i = 0; i < pairs; i++) {
      if (arg < 0 && isBreak()) break;
      const k = decode(depth + 1);
      const v = decode(depth + 1);
      let key = null;
      if (typeof k === "string") key = k;
      else if (typeof k === "number" || typeof k === "boolean") key = String(k);
      else if (k instanceof Uint8Array) key = npcReadBytes(new DataView(k.buffer, k.byteOffset, k.byteLength), 0, k.length);
      if (key !== null) out[key] = v;
    }
    return out;
  }
  const value = decode(0);
  return { value, next: pos };
}

/* ------------------------------------------------------------------ */
/* JUMBF box tree (ISO/IEC 19566-5): LBox/TBox pairs, with the 64-bit */
/* (LBox == 1) and extends-to-end (LBox == 0) forms handled. Any      */
/* malformed box simply ends the walk at that level.                 */
/* ------------------------------------------------------------------ */

function npcJumbfBoxes(bytes, start, end) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out = [];
  let off = start;
  while (off + 8 <= end) {
    const lbox = view.getUint32(off, false);
    const type = npcReadAscii(view, off + 4, 4);
    let header = 8;
    let size;
    if (lbox === 1) {
      if (off + 16 > end) break;
      const hi = view.getUint32(off + 8, false);
      const lo = view.getUint32(off + 12, false);
      size = hi * 4294967296 + lo;
      header = 16;
    } else if (lbox === 0) {
      size = end - off;
    } else {
      size = lbox;
    }
    if (size < header || off + size > end) break;
    out.push({ type, start: off + header, end: off + size });
    off += size;
  }
  return out;
}

function npcJumdLabel(bytes, box) {
  // jumd content: 16-byte UUID, one toggles byte, then a null-terminated
  // label. The toggles byte is optional in some writers, so a leading
  // control byte is skipped and anything printable is taken as label.
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let p = box.start + 16;
  if (p >= box.end) return null;
  if (view.getUint8(p) < 0x20) p++;
  if (p >= box.end) return null;
  const label = npcReadAscii(view, p, box.end - p).trim();
  return label || null;
}

/* Walk the box tree collecting the manifest claim, assertion payloads,
 * and assertion labels. ctx.leaves entries: { label, type, start, end }
 * where label is the enclosing container's jumd label. */
function npcVisitJumbf(bytes, start, end, depth, ctx) {
  if (depth > 24 || start >= end) return;
  const boxes = npcJumbfBoxes(bytes, start, end);
  let myLabel = null;
  if (boxes.length && boxes[0].type === "jumd") {
    myLabel = npcJumdLabel(bytes, boxes[0]);
    if (myLabel && /^c2pa\./.test(myLabel) && myLabel !== "c2pa.assertions"
        && !ctx.assertionLabels.includes(myLabel)) {
      ctx.assertionLabels.push(myLabel);
    }
  }
  for (const box of boxes) {
    if (box.type === "jumd") continue;
    if (box.type === "jumb" || box.type === "c2pa") {
      npcVisitJumbf(bytes, box.start, box.end, depth + 1, ctx);
    } else {
      ctx.leaves.push({ label: myLabel, type: box.type, start: box.start, end: box.end });
    }
  }
}

function npcFindDigitalSourceType(node, depth) {
  if (!node || typeof node !== "object" || depth > 12) return null;
  if (Array.isArray(node)) {
    for (const item of node) {
      const hit = npcFindDigitalSourceType(item, depth + 1);
      if (hit) return hit;
    }
    return null;
  }
  if (node instanceof Uint8Array) return null;
  if (typeof node.digitalSourceType === "string" && node.digitalSourceType) {
    return node.digitalSourceType;
  }
  for (const k of Object.keys(node)) {
    const hit = npcFindDigitalSourceType(node[k], depth + 1);
    if (hit) return hit;
  }
  return null;
}

/* Map an IPTC digital source type URI or bare code to a plain label. */
function npcMapDigitalSourceType(raw) {
  if (!raw || typeof raw !== "string") return null;
  const code = raw.trim().split("/").pop().trim();
  if (!code) return null;
  const key = code.toLowerCase().replace(/[^a-z0-9]/g, "");
  const MAP = {
    trainedalgorithmicmedia: "AI-generated",
    algorithmicmedia: "AI-generated",
    compositewithtrainedalgorithmicmedia: "AI-generated composite",
    digitalcapture: "Digital capture",
    datadrivenmedia: "Data-driven media",
    composite: "Composite",
    compositecapture: "Composite capture",
    humanedits: "Human-edited",
    humanedited: "Human-edited",
    virtualrecording: "Virtual recording",
    negativefilm: "Film scan (negative)",
    positivefilm: "Film scan (positive)",
    print: "Print scan"
  };
  if (MAP[key]) return MAP[key];
  // Unknown code: hand back the code itself, humanized, never invented.
  const pretty = code.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase();
  return pretty.charAt(0).toUpperCase() + pretty.slice(1);
}

/* Parse a reassembled JUMBF stream (from JPEG APP11 packets or a PNG
 * caBX chunk) and return the declared credential facts, or null when
 * no readable claim is present. Structural only: the returned object
 * always carries validated: false. Never throws. */
function npcExtractCredentials(jumbfBytes) {
  try {
    if (!jumbfBytes || jumbfBytes.length < 8) return null;
    const ctx = { leaves: [], assertionLabels: [] };
    npcVisitJumbf(jumbfBytes, 0, jumbfBytes.length, 0, ctx);
    let claim = null;
    const payloads = [];
    for (const leaf of ctx.leaves) {
      const slice = jumbfBytes.subarray(leaf.start, leaf.end);
      if (leaf.type === "c2cl") {
        if (!claim) {
          try {
            const dec = npcCborDecode(slice, 0);
            if (dec.value && typeof dec.value === "object" && !Array.isArray(dec.value)
                && !(dec.value instanceof Uint8Array)) {
              claim = dec.value;
            }
          } catch (e) { /* corrupt claim: degrade to no credentials */ }
        }
      } else if (leaf.type === "cbor") {
        try {
          const dec = npcCborDecode(slice, 0);
          if (dec.value && typeof dec.value === "object") {
            payloads.push({ label: leaf.label, data: dec.value });
          }
        } catch (e) { /* unreadable assertion payload: skip it */ }
      } else if (leaf.type === "json") {
        try {
          const data = JSON.parse(new TextDecoder("utf-8").decode(slice));
          if (data && typeof data === "object") payloads.push({ label: leaf.label, data });
        } catch (e) { /* skip */ }
      }
    }
    if (!claim) {
      // Some writers carry the claim in a generic CBOR content box.
      for (const p of payloads) {
        if (p.data && (typeof p.data.claim_generator === "string"
            || p.data.claim_generator_info || typeof p.data.instanceID === "string")) {
          claim = p.data;
          break;
        }
      }
    }
    if (!claim) return null;

    let generator = null;
    if (typeof claim.claim_generator === "string" && claim.claim_generator.trim()) {
      generator = claim.claim_generator.trim();
    } else if (claim.claim_generator_info) {
      const info = Array.isArray(claim.claim_generator_info)
        ? claim.claim_generator_info[0] : claim.claim_generator_info;
      if (info && typeof info.name === "string" && info.name.trim()) {
        generator = info.name.trim()
          + (typeof info.version === "string" && info.version.trim()
             && !info.name.includes(info.version) ? " " + info.version.trim() : "");
      }
    }

    let dstRaw = null;
    for (const p of payloads) {
      if (p.label === "c2pa.actions") {
        dstRaw = npcFindDigitalSourceType(p.data, 0);
        if (dstRaw) break;
      }
    }
    if (!dstRaw) {
      for (const p of payloads) {
        dstRaw = npcFindDigitalSourceType(p.data, 0);
        if (dstRaw) break;
      }
    }
    if (!dstRaw) dstRaw = npcFindDigitalSourceType(claim, 0);

    const instanceID = (typeof claim.instanceID === "string" && claim.instanceID)
      || (typeof claim.instanceId === "string" && claim.instanceId) || null;

    return {
      present: true,
      status: "present_not_cryptographically_validated",
      validated: false,
      generator,
      digitalSourceType: dstRaw ? npcMapDigitalSourceType(dstRaw) : null,
      digitalSourceTypeRaw: dstRaw || null,
      assertions: ctx.assertionLabels.slice(),
      instanceID
    };
  } catch (e) {
    return null;
  }
}

/* Extract the IPTC DigitalSourceType from an XMP packet, in either
 * attribute form (Iptc4xmpExt:DigitalSourceType="...") or element
 * form (<Iptc4xmpExt:DigitalSourceType>...</...>). Plain label or null. */
function npcExtractXmpSourceType(xmp) {
  if (!xmp || typeof xmp !== "string") return null;
  let m = xmp.match(/DigitalSourceType\s*=\s*"([^"]+)"/)
       || xmp.match(/DigitalSourceType\s*=\s*'([^']+)'/)
       || xmp.match(/<[^>]*DigitalSourceType[^>]*>([^<]+)</);
  if (!m) return null;
  return npcMapDigitalSourceType(m[1]);
}

/* ------------------------------------------------------------------ */
/* Container parsers                                                  */
/* ------------------------------------------------------------------ */

function npcParseJpeg(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 4 || view.getUint16(0, false) !== 0xFFD8) return { ok: false };
  let off = 2;
  const found = {};
  let xmp = null;
  const app11 = [];
  while (off + 4 < bytes.length) {
    if (view.getUint8(off) !== 0xFF) break;
    const marker = view.getUint8(off + 1);
    if (marker === 0xDA || marker === 0xD9) break; // SOS / EOI: image data follows
    if (marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) { off += 2; continue; }
    const len = view.getUint16(off + 2, false);
    if (len < 2 || off + 2 + len > bytes.length) break;
    const segEnd = off + 2 + len;
    if (marker === 0xE1) { // APP1: EXIF or XMP
      const head = npcReadAscii(view, off + 4, 6);
      if (head === "Exif") {
        const exif = npcParseExif(bytes.buffer.slice(bytes.byteOffset + off + 10, bytes.byteOffset + off + 2 + len));
        if (exif) Object.assign(found, exif);
      } else if (npcReadAscii(view, off + 4, 28) === "http://ns.adobe.com/xap/1.0/"
                 && off + 4 + 29 <= segEnd) {
        xmp = new TextDecoder("utf-8").decode(bytes.subarray(off + 4 + 29, segEnd));
      }
    } else if (marker === 0xEB) { // APP11: JPEG XT packet carrying JUMBF
      // Per the task spec: the segment payload starts with "JUMB", then
      // a 2-byte packet sequence number, then box bytes.
      if (len >= 8 && npcReadAscii(view, off + 4, 4) === "JUMB") {
        const seq = view.getUint16(off + 8, false);
        if (segEnd > off + 10) app11.push({ seq, data: bytes.slice(off + 10, segEnd) });
      }
    }
    off += 2 + len;
  }
  let jumbf = null;
  if (app11.length) {
    app11.sort((a, b) => a.seq - b.seq);
    let total = 0;
    for (const p of app11) total += p.data.length;
    jumbf = new Uint8Array(total);
    let o = 0;
    for (const p of app11) { jumbf.set(p.data, o); o += p.data.length; }
  }
  return { ok: true, exif: Object.keys(found).length ? found : null, xmp, jumbf };
}

function npcParsePng(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const SIG = [137, 80, 78, 71, 13, 10, 26, 10];
  for (let i = 0; i < 8; i++) if (view.getUint8(i) !== SIG[i]) return { ok: false };
  let off = 8;
  const text = {};
  let xmp = null;
  let cabx = null;
  while (off + 8 < bytes.length) {
    const len = view.getUint32(off, false);
    const type = npcReadAscii(view, off + 4, 4);
    if (len > bytes.length) break;
    if (type === "tEXt") {
      const raw = npcReadBytes(view, off + 8, len);
      const z = raw.indexOf("\0");
      if (z > 0) {
        const key = raw.slice(0, z).trim();
        text[key] = raw.slice(z + 1).slice(0, 300).trim();
        if (key === "XML:com.adobe.xmp" && !xmp) xmp = raw.slice(z + 1);
      }
    } else if (type === "iTXt") {
      // iTXt: keyword \0 compression-flag compression-method language
      // \0 translated \0 text. Only the uncompressed form (flag 0) is
      // read; compressed iTXt and zTXt are not parsed, and the report
      // does not claim otherwise.
      const start = off + 8;
      const end = start + len;
      const kwEnd = bytes.indexOf(0, start);
      if (kwEnd > 0 && kwEnd + 3 < end && view.getUint8(kwEnd + 1) === 0) {
        let p = kwEnd + 3; // skip flag + method bytes
        const langEnd = bytes.indexOf(0, p);
        if (langEnd > 0 && langEnd < end) {
          const trEnd = bytes.indexOf(0, langEnd + 1);
          if (trEnd > 0 && trEnd < end) {
            const keyword = npcReadBytes(view, start, kwEnd - start).trim();
            const fullValue = new TextDecoder("utf-8").decode(bytes.subarray(trEnd + 1, end));
            const value = fullValue.slice(0, 300).trim();
            if (keyword) text[keyword] = value;
            if (keyword === "XML:com.adobe.xmp" && !xmp) xmp = fullValue;
          }
        }
      }
    } else if (type === "caBX") {
      // The chunk content is the raw JUMBF stream, no packet headers.
      if (!cabx && len > 0) cabx = bytes.slice(off + 8, off + 8 + len);
    }
    if (type === "IEND") break;
    off += 12 + len;
  }
  return { ok: true, text: Object.keys(text).length ? text : null, xmp, cabx };
}

function npcFindMarkers(haystacks) {
  const hits = [];
  const blob = haystacks.filter(Boolean).join("\n").toLowerCase();
  for (const m of NPC_KNOWN_MARKERS) {
    if (blob.includes(m.match) && !hits.includes(m.label)) hits.push(m.label);
  }
  return hits;
}

async function npcSha256Hex(str) {
  const dig = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(dig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/* SHA-256 of the image bytes themselves. This is the identity the
 * free-check dedupe keys on: the same file, at any address, hashes
 * the same. Returns null when the digest cannot be computed. */
async function npcContentHashHex(bytes) {
  try {
    const dig = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(dig)).map(b => b.toString(16).padStart(2, "0")).join("");
  } catch (e) {
    return null;
  }
}

/* Analyze image bytes already in hand. Pure: no fetching, never throws. */
function npcAnalyzeImageBytes(bytes, src, naturalW, naturalH) {
  const report = {
    src,
    format: (src.split("?")[0].match(/\.([a-z0-9]{2,5})$/i) || [])[1] || "unknown",
    dimensions: naturalW && naturalH ? naturalW + " x " + naturalH : "unknown",
    bytesRead: true,
    byteSize: bytes.length,
    exif: null,
    pngText: null,
    markers: [],
    notes: [],
    credentials: null,
    iptcSourceType: null,
    contentHash: null
  };
  const isJpeg = bytes[0] === 0xFF && bytes[1] === 0xD8;
  const isPng = bytes[0] === 0x89 && bytes[1] === 0x50;
  if (isJpeg) {
    report.format = "jpeg";
    const r = npcParseJpeg(bytes);
    report.exif = r.exif;
    if (!r.exif) report.notes.push("no_exif");
    if (r.jumbf) report.credentials = npcExtractCredentials(r.jumbf);
    if (r.xmp) report.iptcSourceType = npcExtractXmpSourceType(r.xmp);
  } else if (isPng) {
    report.format = "png";
    const r = npcParsePng(bytes);
    report.pngText = r.text;
    if (!r.text) report.notes.push("no_text_chunks");
    if (r.cabx) report.credentials = npcExtractCredentials(r.cabx);
    if (r.xmp) report.iptcSourceType = npcExtractXmpSourceType(r.xmp);
  } else {
    report.notes.push("format_not_parsed");
  }
  const hay = [];
  if (report.exif) hay.push(report.exif.software, report.exif.make, report.exif.model);
  if (report.pngText) hay.push(...Object.entries(report.pngText).map(([k, v]) => k + " " + v));
  report.markers = npcFindMarkers(hay);
  return report;
}

/* Fetch an image's bytes from the extension context. Returns a
 * Uint8Array or null. Works only where the host serves the file with
 * CORS approval (or a matching host permission); the caller in
 * background.js first tries a page-context fetch, which covers the
 * far more common case of a page loading its own images. */
async function npcFetchImageBytes(src) {
  try {
    const res = await fetch(src, { mode: "cors", credentials: "omit" });
    if (!res.ok) return null;
    const buf = await res.arrayBuffer();
    if (buf.byteLength > 26214400) return null; // 25 MB sanity cap
    return new Uint8Array(buf);
  } catch (e) {
    return null;
  }
}

/* Main entry for callers that only have a URL. Never throws;
 * failures are data (bytesRead: false, note "bytes_unreadable"). */
async function npcAnalyzeImage(src, naturalW, naturalH) {
  const bytes = await npcFetchImageBytes(src);
  if (!bytes) {
    return {
      src,
      format: (src.split("?")[0].match(/\.([a-z0-9]{2,5})$/i) || [])[1] || "unknown",
      dimensions: naturalW && naturalH ? naturalW + " x " + naturalH : "unknown",
      bytesRead: false,
      byteSize: null,
      exif: null,
      pngText: null,
      markers: [],
      notes: ["bytes_unreadable"],
      credentials: null,
      iptcSourceType: null,
      contentHash: null
    };
  }
  const report = npcAnalyzeImageBytes(bytes, src, naturalW, naturalH);
  report.contentHash = await npcContentHashHex(bytes);
  return report;
}
