/* NPC Verify: background service worker.
 *
 * Runs the layered check for one image:
 *   Layer 1 (provenance): hash the image URL, ask the verification API.
 *             A matched answer is only trusted after its Ed25519
 *             response signature verifies against NPC's published keys
 *             (NPC-JCS-v1 canonical body, X-NPC-Signature header), the
 *             same check the public dashboard performs. A failed or
 *             unverifiable signature fails closed: no verdict is shown
 *             from an answer we cannot trust.
 *   Layer 2 (forensics):  client-side file analysis (forensics.js).
 *             Bytes are fetched in the page's own context when possible
 *             (the page already loaded the image), falling back to a
 *             direct fetch where the host allows it.
 *   Layer 3 (AI judgment): stubbed. The hosted Fleet backend adds a
 *             probabilistic read here later. This scaffold never guesses.
 *
 * Verdicts are only ever: "verified", "no_record", "not_checked",
 * "api_unreachable". We never claim more than we checked.
 */

importScripts("config.js", "forensics.js");

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "NPC_CHECK") {
    runCheck(msg.image, msg.tabId).then(sendResponse).catch(err =>
      sendResponse({ error: "pipeline_failed", detail: String(err && err.message || err) })
    );
    return true; // async response
  }
  if (msg.type === "NPC_CHECKS_USED") {
    chrome.storage.local.get(["npc_checks_used"]).then(s =>
      sendResponse({ used: s.npc_checks_used || 0 })
    );
    return true;
  }
});

/* ------------------------------------------------------------------ */
/* NPC-JCS-v1 canonical JSON + Ed25519 response-signature verification */
/* ------------------------------------------------------------------ */

/* Reproduces api/npc_verify/canonical.py: keys sorted lexicographically,
 * no insignificant whitespace, UTF-8. API bodies carry strings, booleans,
 * integers and nulls; floats are serialized with the shortest round-trip
 * form, matching Python for every value the API emits today. */
function npcCanonicalJson(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    return String(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(npcCanonicalJson).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map(k =>
      JSON.stringify(k) + ":" + npcCanonicalJson(value[k])).join(",") + "}";
  }
  throw new Error("uncanonical type " + t);
}

function npcB64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let npcKeysCache = { base: null, promise: null };

function npcFetchPublishedKeys(apiBase) {
  if (npcKeysCache.base === apiBase && npcKeysCache.promise) {
    return npcKeysCache.promise;
  }
  const p = (async () => {
    const res = await fetch(apiBase + "/keys");
    if (!res.ok) throw new Error("keys http " + res.status);
    return res.json();
  })();
  npcKeysCache = { base: apiBase, promise: p };
  p.catch(() => {
    if (npcKeysCache.promise === p) npcKeysCache = { base: null, promise: null };
  });
  return p;
}

function npcFindSigningKey(keysDoc, keyId) {
  const signing = keysDoc && keysDoc.api_signing;
  if (!signing) return null;
  if (signing.current && signing.current.key_id === keyId) {
    return signing.current.public_key;
  }
  for (const h of signing.history || []) {
    if (h.key_id === keyId) return h.public_key;
  }
  return null;
}

/* Returns "valid", "invalid", or "unavailable" (keys unreachable, or
 * this browser cannot do Ed25519). Anything but "valid" fails closed. */
async function npcVerifyResponseSignature(apiBase, body, sigB64, keyId) {
  if (!sigB64 || !keyId) return "invalid";
  let keysDoc;
  try {
    keysDoc = await npcFetchPublishedKeys(apiBase);
  } catch (e) {
    return "unavailable";
  }
  const pubB64 = npcFindSigningKey(keysDoc, keyId);
  if (!pubB64) return "invalid";
  let key;
  try {
    key = await crypto.subtle.importKey(
      "raw", npcB64ToBytes(pubB64), { name: "Ed25519" }, false, ["verify"]);
  } catch (e) {
    return (e && e.name === "NotSupportedError") ? "unavailable" : "invalid";
  }
  try {
    const msg = new TextEncoder().encode(npcCanonicalJson(body));
    const ok = await crypto.subtle.verify(
      { name: "Ed25519" }, key, npcB64ToBytes(sigB64), msg);
    return ok ? "valid" : "invalid";
  } catch (e) {
    return "invalid";
  }
}

/* ------------------------------------------------------------------ */
/* Layer 1: provenance                                                  */
/* ------------------------------------------------------------------ */

async function checkProvenance(src, cfg) {
  if (!cfg.apiKey) return { status: "not_configured" };
  let hash;
  try {
    hash = await npcSha256Hex(src);
  } catch (e) {
    return { status: "error", detail: "hash_failed" };
  }
  let res;
  try {
    res = await fetch(cfg.apiBase + "/claims/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + cfg.apiKey
      },
      body: JSON.stringify({ claim_hash: hash })
    });
  } catch (e) {
    return { status: "unreachable" };
  }
  if (res.status === 401 || res.status === 403) return { status: "unauthorized" };
  if (res.status !== 200 && res.status !== 404) {
    return { status: "error", detail: "http_" + res.status };
  }
  let data;
  try {
    data = await res.json();
  } catch (e) {
    return { status: "error", detail: "bad_response" };
  }
  const sigState = await npcVerifyResponseSignature(
    cfg.apiBase, data,
    res.headers.get("X-NPC-Signature"), res.headers.get("X-NPC-Key-ID"));
  if (sigState !== "valid") {
    return { status: "signature_failed", detail: sigState };
  }
  if (res.status === 404 || !data || !data.matched) {
    return { status: "unknown", sigVerified: true };
  }
  const a = data.attestation || {};
  return {
    status: "matched",
    sigVerified: true,
    creator: a.creator_name || a.holder_name || "Registered creator",
    recordedAt: a.tested_at || a.created_at || null,
    attVerdict: a.verdict || "verified",
    findings: a.findings_summary || null,
    scope: (a.scope && a.scope.domain) || null,
    attestationId: a.id || null
  };
}

/* ------------------------------------------------------------------ */
/* Layer 2: forensics                                                   */
/* ------------------------------------------------------------------ */

/* Self-contained on purpose: chrome.scripting serializes this function
 * into the page, where the fetch runs with the page's own access to a
 * file it already loaded. Returns base64, or null when the bytes
 * cannot be read there either. */
async function npcPageFetchImageBase64(src) {
  try {
    const res = await fetch(src, { credentials: "omit" });
    if (!res.ok) return null;
    const buf = await res.arrayBuffer();
    if (buf.byteLength > 26214400) return null; // 25 MB sanity cap
    const bytes = new Uint8Array(buf);
    let bin = "";
    const CHUNK = 32768;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(bin);
  } catch (e) {
    return null;
  }
}

async function runForensics(image, tabId) {
  if (tabId) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        func: npcPageFetchImageBase64,
        args: [image.src]
      });
      const b64 = results && results[0] && results[0].result;
      if (b64) {
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return npcAnalyzeImageBytes(bytes, image.src, image.w, image.h);
      }
    } catch (e) {
      // Restricted page or injection refused: fall through to direct fetch.
    }
  }
  return npcAnalyzeImage(image.src, image.w, image.h);
}

/* ------------------------------------------------------------------ */
/* The check                                                            */
/* ------------------------------------------------------------------ */

async function runCheck(image, tabId) {
  const cfg = await npcGetConfig();
  const started = Date.now();

  const forensics = await runForensics(image, tabId);
  const provenance = await checkProvenance(image.src, cfg);

  let verdict, verdictWord, verdictSub, showMark = false;
  const pv = provenance.status;
  if (pv === "matched" && provenance.attVerdict === "verified") {
    verdict = "verified";
    verdictWord = "Verified";
    showMark = true;
    verdictSub = "Registered with NPC. Signature checked against NPC's published keys."
      + " Creator: " + provenance.creator + "."
      + (provenance.recordedAt ? " Recorded " + provenance.recordedAt.slice(0, 10) + "." : "");
  } else if (pv === "matched" && provenance.attVerdict === "verified_with_caveats") {
    verdict = "verified";
    verdictWord = "Verified with caveats";
    showMark = true;
    verdictSub = "Registered with NPC. Signature checked against NPC's published keys, and the record carries caveats."
      + (provenance.findings ? " " + provenance.findings : "");
  } else if (pv === "matched") {
    verdict = "not_checked";
    verdictWord = "Not checked";
    verdictSub = "A record matched this image, but its standing is \""
      + provenance.attVerdict + "\", so we do not present it as verified.";
  } else if (pv === "signature_failed") {
    verdict = "not_checked";
    verdictWord = "Not checked";
    verdictSub = "The API answered, but its NPC signature did not verify, so the answer is not trusted and no registry result is shown. The file checks below still ran on your device.";
  } else if (pv === "unknown") {
    verdict = "no_record";
    verdictWord = "No record found";
    verdictSub = "Nobody has registered this image with NPC yet. That is not the same as fake.";
  } else if (pv === "not_configured" || pv === "unauthorized") {
    verdict = "not_checked";
    verdictWord = "Not checked";
    verdictSub = "The registry was not checked. Point the extension at a verification API to enable provenance. The file checks below still ran on your device.";
  } else if (pv === "error") {
    verdict = "api_unreachable";
    verdictWord = "API unreachable";
    verdictSub = "The verification API answered with an error, so the registry could not be read. The file checks below still ran on your device.";
  } else {
    verdict = "api_unreachable";
    verdictWord = "API unreachable";
    verdictSub = "We could not reach the verification API, so the registry was not checked. The file checks below still ran on your device.";
  }

  const store = await chrome.storage.local.get(["npc_checks_used"]);
  const used = (store.npc_checks_used || 0) + 1;
  await chrome.storage.local.set({ npc_checks_used: used });

  return {
    image,
    verdict,
    verdictWord,
    showMark,
    verdictSub,
    provenance,
    forensics,
    ai: {
      status: "unavailable",
      note: "The hosted Fleet backend will add a probabilistic read here, with its confidence stated. This version does not guess."
    },
    nudge: verdict === "no_record",
    nudgeUrl: cfg.getVerifiedUrl,
    fullReportUrl: cfg.fullReportUrl,
    checksUsed: used,
    checksTotal: cfg.freeChecksTotal,
    elapsedMs: Date.now() - started,
    checkedAt: new Date().toISOString()
  };
}
