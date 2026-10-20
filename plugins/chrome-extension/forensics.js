/* NPC Verify: client-side image forensics.
 *
 * Vanilla JS, no dependencies. Parses only what the file itself declares:
 * JPEG EXIF (Software / Make / Model / DateTime), PNG tEXt chunks, and
 * uncompressed PNG iTXt chunks. Matches embedded strings against known
 * generator markers.
 *
 * What it never does: claim an image is AI-generated or human-made from
 * these signals alone. Markers can be stripped or faked, and absence of a
 * marker proves nothing. Findings are reported; conclusions are not drawn.
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

function npcParseJpeg(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 4 || view.getUint16(0, false) !== 0xFFD8) return { ok: false };
  let off = 2;
  const found = {};
  while (off + 4 < bytes.length) {
    if (view.getUint8(off) !== 0xFF) break;
    const marker = view.getUint8(off + 1);
    if (marker === 0xDA || marker === 0xD9) break; // SOS / EOI: image data follows
    if (marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) { off += 2; continue; }
    const len = view.getUint16(off + 2, false);
    if (len < 2 || off + 2 + len > bytes.length) break;
    if (marker === 0xE1) { // APP1: EXIF or XMP
      const head = npcReadAscii(view, off + 4, 6);
      if (head === "Exif") {
        const exif = npcParseExif(bytes.buffer.slice(bytes.byteOffset + off + 10, bytes.byteOffset + off + 2 + len));
        if (exif) Object.assign(found, exif);
      }
    }
    off += 2 + len;
  }
  return { ok: true, exif: Object.keys(found).length ? found : null };
}

function npcParsePng(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const SIG = [137, 80, 78, 71, 13, 10, 26, 10];
  for (let i = 0; i < 8; i++) if (view.getUint8(i) !== SIG[i]) return { ok: false };
  let off = 8;
  const text = {};
  while (off + 8 < bytes.length) {
    const len = view.getUint32(off, false);
    const type = npcReadAscii(view, off + 4, 4);
    if (len > bytes.length) break;
    if (type === "tEXt") {
      const raw = npcReadBytes(view, off + 8, len);
      const z = raw.indexOf("\0");
      if (z > 0) text[raw.slice(0, z).trim()] = raw.slice(z + 1).slice(0, 300).trim();
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
            const value = new TextDecoder("utf-8")
              .decode(bytes.subarray(trEnd + 1, end)).slice(0, 300).trim();
            if (keyword) text[keyword] = value;
          }
        }
      }
    }
    if (type === "IEND") break;
    off += 12 + len;
  }
  return { ok: true, text: Object.keys(text).length ? text : null };
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
    notes: []
  };
  const isJpeg = bytes[0] === 0xFF && bytes[1] === 0xD8;
  const isPng = bytes[0] === 0x89 && bytes[1] === 0x50;
  if (isJpeg) {
    report.format = "jpeg";
    const r = npcParseJpeg(bytes);
    report.exif = r.exif;
    if (!r.exif) report.notes.push("no_exif");
  } else if (isPng) {
    report.format = "png";
    const r = npcParsePng(bytes);
    report.pngText = r.text;
    if (!r.text) report.notes.push("no_text_chunks");
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
      notes: ["bytes_unreadable"]
    };
  }
  return npcAnalyzeImageBytes(bytes, src, naturalW, naturalH);
}
