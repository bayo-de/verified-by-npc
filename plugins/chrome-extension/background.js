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
 *   Layer 3 (AI judgment): on request only, from the AI judgment
 *             section of the panel. The worker sends the image to the
 *             verification API,
 *             which asks Sightengine from the server side (no
 *             detection credentials ever ship in client code) and
 *             returns the score inside its signed response, verified
 *             here like every other answer. Never automatic, and a
 *             failed or unverifiable check shows no result.
 *
 * Verdicts are only ever: "verified", "no_record", "not_checked",
 * "api_unreachable". We never claim more than we checked.
 */

importScripts("config.js", "forensics.js", "api-client.js");

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "NPC_CHECK") {
    runCheck(msg.image, msg.tabId).then(sendResponse).catch(err =>
      sendResponse({ error: "pipeline_failed", detail: String(err && err.message || err) })
    );
    return true; // async response
  }
  if (msg.type === "NPC_AI_CHECK") {
    runAiCheck(msg.image, msg.tabId).then(sendResponse).catch(err =>
      sendResponse({ status: "error", detail: String(err && err.message || err) })
    );
    return true; // async response
  }
  if (msg.type === "NPC_CHECKS_USED") {
    chrome.storage.local.get(["npc_checks_used"]).then(s =>
      sendResponse({ used: s.npc_checks_used || 0 })
    );
    return true;
  }
  if (msg.type === "NPC_HISTORY") {
    npcLoadHistory().then(entries =>
      sendResponse({ entries: entries.map(npcHistorySummary) })
    );
    return true;
  }
  if (msg.type === "NPC_CHAT_SEND") {
    (async () => {
      const cfg = await npcGetConfig();
      sendResponse(await npcChatSend(
        cfg, msg.threadId || null, String(msg.message || ""), "extension"));
    })().catch(() => sendResponse({ state: "error" }));
    return true;
  }
  if (msg.type === "NPC_CHAT_FEEDBACK") {
    (async () => {
      const cfg = await npcGetConfig();
      sendResponse(await npcChatFeedback(
        cfg, msg.threadId || null, msg.turn, msg.rating));
    })().catch(() => sendResponse({ recorded: false }));
    return true;
  }
  if (msg.type === "NPC_CREDIT_BALANCE") {
    (async () => {
      const cfg = await npcGetConfig();
      sendResponse(await npcCreditSummary(cfg));
    })().catch(() => sendResponse({ state: "unknown" }));
    return true;
  }
  if (msg.type === "NPC_CREDIT_REDEEM") {
    (async () => {
      const cfg = await npcGetConfig();
      sendResponse(await npcCreditRedeem(String(msg.code || ""), cfg));
    })().catch(() => sendResponse({ state: "unknown" }));
    return true;
  }
  if (msg.type === "NPC_CREDIT_PACKS") {
    (async () => {
      const cfg = await npcGetConfig();
      sendResponse(await npcCreditPacks(cfg));
    })().catch(() => sendResponse({ state: "unknown", packs: [] }));
    return true;
  }
  if (msg.type === "NPC_AV_CHECK") {
    runAvCheck(msg.kind, msg.url).then(sendResponse).catch(err =>
      sendResponse({ status: "error", detail: String(err && err.message || err) })
    );
    return true;
  }
});

/* ------------------------------------------------------------------ */
/* Check history + free-check dedupe                                    */
/* ------------------------------------------------------------------ */

/* Completed checks are remembered locally, keyed by the image's
 * identity: the SHA-256 of its bytes when the bytes could be read,
 * the SHA-256 of its address when they could not. Checking the same
 * image again returns the remembered result and does not consume
 * another free check. Only signature-verified registry outcomes are
 * remembered (a record matched, or a signed no-record answer): an
 * error or an unreachable API is never cached, so a retry always
 * runs the real check. History lives only in this browser's local
 * storage; nothing about it leaves the device. */
const NPC_HISTORY_KEY = "npc_check_history";
const NPC_HISTORY_MAX = 20;

async function npcLoadHistory() {
  const s = await chrome.storage.local.get([NPC_HISTORY_KEY]);
  return Array.isArray(s[NPC_HISTORY_KEY]) ? s[NPC_HISTORY_KEY] : [];
}

function npcHistorySummary(entry) {
  return {
    id: entry.id,
    src: entry.src,
    verdictWord: entry.verdictWord,
    checkedAt: entry.checkedAt
  };
}

async function npcRememberCheck(identity, result) {
  const entries = await npcLoadHistory();
  const kept = entries.filter(e => e.id !== identity);
  kept.unshift({
    id: identity,
    src: result.image && result.image.src,
    verdictWord: result.verdictWord,
    checkedAt: result.checkedAt,
    result
  });
  await chrome.storage.local.set({
    [NPC_HISTORY_KEY]: kept.slice(0, NPC_HISTORY_MAX)
  });
}

/* ------------------------------------------------------------------ */
/* Credits: the paid tier behind the free checks                        */
/* ------------------------------------------------------------------ */

/* Per the credits integration spec (2026-10-28). A buyer's code is a
 * bearer credential and lives in local storage only, the same
 * treatment the extension already gives its API key. No balance is
 * ever trusted from storage: balances always come from the API,
 * through the signature-verified client in api-client.js.
 *
 * Two codes can be held at once, in draw order: the primary key
 * holds a Verifier Pass code (pack kind "access"), the pack key a
 * one-time pack code. Draw order for a paid check: an active Pass
 * first (standard checks are covered by the Pass and draw no pool;
 * AI checks draw its AI sub-allowance), then the pack code. */
const NPC_CREDIT_CODE_KEY = "npc_credit_code";
const NPC_CREDIT_PACK_KEY = "npc_credit_code_pack";

async function npcStoredCreditCodes() {
  const s = await chrome.storage.local.get(
    [NPC_CREDIT_CODE_KEY, NPC_CREDIT_PACK_KEY]);
  return {
    primary: s[NPC_CREDIT_CODE_KEY] || null,
    pack: s[NPC_CREDIT_PACK_KEY] || null
  };
}

/* Balance for one stored code. States: "ok" (with the ledger body),
 * "none" (no code in this slot), "invalid" (the API says the code is
 * gone or revoked; a 404 also clears the slot, per the spec),
 * "unknown" (unreachable, unverified, or error: treated as no
 * answer, and nothing is cleared or charged on it). */
async function npcCreditBalanceFor(code, slotKey, cfg) {
  if (!code) return { state: "none" };
  const r = await npcCreditCall(cfg, "/credits/balance", { code });
  if (r.status !== "http") return { state: "unknown" };
  if (r.httpStatus === 200 && r.data) {
    return {
      state: "ok",
      balance: r.data.balance,
      creditsTotal: r.data.credits_total,
      creditsUsed: r.data.credits_used,
      grantBalance: r.data.grant_balance || 0,
      aiBalance: typeof r.data.ai_balance === "number"
        ? r.data.ai_balance : r.data.balance,
      packId: r.data.pack_id,
      codeStatus: r.data.status,
      subscriptionStatus: r.data.subscription_status || null,
      registryUnlimited: !!r.data.registry_unlimited
    };
  }
  if (r.httpStatus === 404) {
    await chrome.storage.local.remove([slotKey]);
    return { state: "invalid" };
  }
  if (r.httpStatus === 403) return { state: "invalid" };
  return { state: "unknown" };
}

/* Both slots, in draw order, for the popup's usage display. */
async function npcCreditSummary(cfg) {
  const codes = await npcStoredCreditCodes();
  if (!codes.primary && !codes.pack) return { state: "none" };
  const primary = await npcCreditBalanceFor(
    codes.primary, NPC_CREDIT_CODE_KEY, cfg);
  const pack = await npcCreditBalanceFor(
    codes.pack, NPC_CREDIT_PACK_KEY, cfg);
  const anyOk = primary.state === "ok" || pack.state === "ok";
  const anyUnknown = primary.state === "unknown" || pack.state === "unknown";
  return {
    state: anyOk ? "ok" : (anyUnknown ? "unknown" : "invalid"),
    primary,
    pack
  };
}

/* Redeem a code the buyer pasted. On success the code is stored in
 * the slot its pack kind owns: an access (Pass) code in the primary
 * slot, a one-time pack code in the pack slot, each replacing only
 * its own kind. The kind is read off the packs list by pack_id. */
async function npcCreditRedeem(code, cfg) {
  code = String(code || "").trim();
  if (!code) return { state: "unknown" };
  const r = await npcCreditCall(cfg, "/credits/redeem", { code });
  if (r.status !== "http") return { state: "unknown" };
  if (r.httpStatus === 404) return { state: "not_found" };
  if (r.httpStatus === 403) return { state: "revoked" };
  if (r.httpStatus !== 200 || !r.data) return { state: "unknown" };
  let kind = "pack";
  const packs = await npcCreditPacks(cfg);
  if (packs.state === "ok") {
    const entry = packs.packs.find(p => p.id === r.data.pack_id);
    if (entry && entry.kind) kind = entry.kind;
  }
  const slotKey = kind === "access"
    ? NPC_CREDIT_CODE_KEY : NPC_CREDIT_PACK_KEY;
  await chrome.storage.local.set({ [slotKey]: code });
  return {
    state: "ok",
    kind,
    balance: r.data.balance,
    aiBalance: typeof r.data.ai_balance === "number"
      ? r.data.ai_balance : r.data.balance,
    packId: r.data.pack_id,
    subscriptionStatus: r.data.subscription_status || null,
    registryUnlimited: !!r.data.registry_unlimited
  };
}

/* Pick the credit source for one paid check, in draw order.
 * checkKind is "standard" or "ai". Returns one of:
 *   {mode: "pass", slotKey, code, balance}   active Pass covers it
 *   {mode: "credit", slotKey, code, balance} a finite balance pays
 *   {mode: "none", reason}                   nothing can pay
 *   {mode: "unknown"}                        a balance read failed
 * For "ai", the figure that must be positive is aiBalance (the
 * server already counts the Pass sub-allowance, then bonus grants,
 * then pack counters in that one number). */
async function npcPickCreditSource(cfg, checkKind) {
  const codes = await npcStoredCreditCodes();
  const slots = [
    { code: codes.primary, slotKey: NPC_CREDIT_CODE_KEY },
    { code: codes.pack, slotKey: NPC_CREDIT_PACK_KEY }
  ];
  let sawCode = false;
  let sawUnknown = false;
  let sawExhausted = false;
  for (const slot of slots) {
    if (!slot.code) continue;
    sawCode = true;
    const bal = await npcCreditBalanceFor(slot.code, slot.slotKey, cfg);
    if (bal.state === "unknown") { sawUnknown = true; continue; }
    if (bal.state !== "ok") continue;
    if (checkKind === "standard" && bal.registryUnlimited
        && bal.subscriptionStatus === "active") {
      return { mode: "pass", slotKey: slot.slotKey, code: slot.code, bal };
    }
    const spendable = checkKind === "ai" ? bal.aiBalance : bal.balance;
    if (spendable > 0) {
      return { mode: "credit", slotKey: slot.slotKey, code: slot.code, bal };
    }
    sawExhausted = true;
  }
  if (sawUnknown) return { mode: "unknown" };
  if (!sawCode) return { mode: "none", reason: "no_code" };
  return {
    mode: "none",
    reason: sawExhausted
      ? (checkKind === "ai" ? "no_ai_credits" : "exhausted")
      : "invalid"
  };
}

/* Consume one check against a picked source. Mirrors the spec's
 * outcomes: charged, duplicate (already paid, never charged twice),
 * exhausted (the balance moved between read and consume), or
 * unrecorded (the call failed or did not verify, so nothing was
 * charged server-side either). */
async function npcConsumeCredit(cfg, source, identity, claimHash, kind) {
  const payload = { code: source.code, image_identity: identity, kind };
  if (claimHash) payload.claim_hash = claimHash;
  const r = await npcCreditCall(cfg, "/credits/consume", payload);
  if (r.status !== "http") return { charged: false, unrecorded: true };
  if (r.httpStatus === 200 && r.data) {
    if (r.data.duplicate) {
      return { charged: false, duplicate: true, balance: r.data.balance };
    }
    return { charged: !!r.data.charged, balance: r.data.balance };
  }
  if (r.httpStatus === 402) {
    return {
      charged: false,
      exhausted: true,
      noAiCredits: !!(r.data && r.data.error === "no_ai_credits"),
      balance: r.data ? r.data.balance : 0
    };
  }
  return { charged: false, unrecorded: true };
}

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
    return { status: "unknown", sigVerified: true, claimHash: hash };
  }
  const a = data.attestation || {};
  return {
    status: "matched",
    sigVerified: true,
    claimHash: hash,
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
        const report = npcAnalyzeImageBytes(bytes, image.src, image.w, image.h);
        report.contentHash = await npcContentHashHex(bytes);
        return report;
      }
    } catch (e) {
      // Restricted page or injection refused: fall through to direct fetch.
    }
  }
  return npcAnalyzeImage(image.src, image.w, image.h);
}

/* ------------------------------------------------------------------ */
/* Layer 3: AI generation check (explicit user action only)             */
/* ------------------------------------------------------------------ */

/* Largest image sent as bytes; bigger files go by URL instead. The
 * API caps decoded bytes at 750 KB (base64 stays under its body cap). */
const NPC_AI_MAX_BYTES = 750 * 1000;

function npcBytesToBase64(bytes) {
  let bin = "";
  const CHUNK = 32768;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

/* The image bytes for the check: page context first (same path the
 * forensics layer uses), then a direct fetch. Null when neither works;
 * the caller falls back to sending the image URL. */
async function npcFetchImageBytesForCheck(image, tabId) {
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
        return bytes;
      }
    } catch (e) {
      // Restricted page or injection refused: fall through to direct fetch.
    }
  }
  return npcFetchImageBytes(image.src);
}

/* Runs only when the user presses the button in the AI judgment
 * section. The image goes to the NPC verification API, never to the detection
 * service from here: the API holds the Sightengine credentials and
 * answers inside its signed envelope, verified before any result is
 * shown. Every failure returns an honest status, never a guess. */
/* The paid-tier gate for AI generation checks (image, video, and
 * audio alike), per credits spec section 6.3. In the free tier an
 * AI check is part of a check's panel and consumes nothing. Past
 * the free tier it draws on a code: a Pass code's AI sub-allowance
 * first, then bonus grants, then pack counters, which is exactly
 * the order the server's ai_balance figure already reflects.
 * Returns {mode: "free"} | {mode: "paid", source} |
 * {mode: "unknown"} (balance unreadable: run the check, charge
 * nothing) | {mode: "blocked", reason} (do not run it). */
async function npcAiGate(cfg) {
  const store = await chrome.storage.local.get(["npc_checks_used"]);
  const freeLeft = Math.max(
    0, cfg.freeChecksTotal - (store.npc_checks_used || 0));
  if (freeLeft > 0) return { mode: "free" };
  const pick = await npcPickCreditSource(cfg, "ai");
  if (pick.mode === "unknown") return { mode: "unknown" };
  if (pick.mode === "none") return { mode: "blocked", reason: pick.reason };
  return { mode: "paid", source: pick };
}

async function runAiCheck(image, tabId) {
  const cfg = await npcGetConfig();
  if (!cfg.apiKey) return { status: "not_configured" };
  const gate = await npcAiGate(cfg);
  if (gate.mode === "blocked") {
    return { status: "no_ai_credits", reason: gate.reason };
  }
  const bytes = await npcFetchImageBytesForCheck(image, tabId);
  let payload;
  if (bytes && bytes.length <= NPC_AI_MAX_BYTES) {
    payload = { image_base64: npcBytesToBase64(bytes) };
  } else {
    // Bytes unreadable here, or too large to send: the API passes
    // the image URL to the detection service instead.
    payload = { image_url: image.src };
  }
  let res;
  try {
    res = await fetch(cfg.apiBase + "/images/ai-check", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + cfg.apiKey
      },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    return { status: "unreachable" };
  }
  if (res.status === 401 || res.status === 403) {
    return { status: "unauthorized" };
  }
  let data;
  try {
    data = await res.json();
  } catch (e) {
    return { status: "error", detail: "bad_response" };
  }
  if (res.status !== 200) {
    if (data && data.error === "detector_unavailable") {
      return { status: "unavailable" };
    }
    return { status: "error", detail: "http_" + res.status };
  }
  const sigState = await npcVerifyResponseSignature(
    cfg.apiBase, data,
    res.headers.get("X-NPC-Signature"), res.headers.get("X-NPC-Key-ID"));
  if (sigState !== "valid") {
    return { status: "signature_failed", detail: sigState };
  }
  const out = {
    status: "ok",
    sigVerified: true,
    percent: data.ai_generated_percent,
    provider: data.provider,
    model: data.model,
    checkedAt: data.checked_at
  };
  /* Paid tier: the consume fires only now, after the answer's
   * signature verified, never on a failed or unreachable check. */
  if (gate.mode === "paid") {
    let identity = null;
    try {
      identity = bytes
        ? "sha256:" + (await npcContentHashHex(bytes))
        : "url-sha256:" + (await npcSha256Hex(image.src));
    } catch (e) {
      identity = null;
    }
    out.credits = identity
      ? await npcConsumeCredit(
          cfg, gate.source, identity + ":ai", null, "ai")
      : { charged: false, unrecorded: true };
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Video and audio AI checks (explicit user action only)                */
/* ------------------------------------------------------------------ */

/* Runs only when the user picks a video or audio file on the page
 * and presses its check button. The media address goes to the NPC
 * API, which fetches and analyzes the file server-side; the answer
 * returns inside the signed envelope and is verified by the client
 * in api-client.js before anything is shown. The production API
 * does not serve these routes yet (they live in the detector-av
 * staging prototype), so until it does the honest answer here is
 * "not_available", never a guessed score. Paid-tier funding follows
 * the same AI gate as the image check. */
async function runAvCheck(kind, url) {
  const cfg = await npcGetConfig();
  if (!cfg.apiKey) return { status: "not_configured" };
  if (kind !== "video" && kind !== "audio") {
    return { status: "error", detail: "bad_kind" };
  }
  if (!url || !/^https?:/.test(url)) {
    return { status: "error", detail: "bad_url" };
  }
  const gate = await npcAiGate(cfg);
  if (gate.mode === "blocked") {
    return { status: "no_ai_credits", reason: gate.reason };
  }
  const out = await npcAvCheck(cfg, kind, url);
  if (out.status === "ok" && gate.mode === "paid") {
    let identity = null;
    try {
      identity = "url-sha256:" + (await npcSha256Hex(url));
    } catch (e) {
      identity = null;
    }
    out.credits = identity
      ? await npcConsumeCredit(
          cfg, gate.source, identity + ":" + kind + "-ai", null, "ai")
      : { charged: false, unrecorded: true };
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* The check                                                            */
/* ------------------------------------------------------------------ */

async function runCheck(image, tabId) {
  const cfg = await npcGetConfig();
  const started = Date.now();

  const forensics = await runForensics(image, tabId);

  /* Dedupe: the same image checked before returns its remembered
   * result. No registry call is made and no free check is consumed.
   * The identity is the hash of the image bytes when they could be
   * read, and the hash of the image address when they could not. */
  let identity = null;
  if (forensics && forensics.contentHash) {
    identity = "sha256:" + forensics.contentHash;
  } else if (image && image.src) {
    try {
      identity = "url-sha256:" + (await npcSha256Hex(image.src));
    } catch (e) {
      identity = null;
    }
  }
  if (identity) {
    const prior = (await npcLoadHistory()).find(e => e.id === identity);
    if (prior && prior.result) {
      const cached = JSON.parse(JSON.stringify(prior.result));
      cached.image = image;
      cached.fromHistory = true;
      const store = await chrome.storage.local.get(["npc_checks_used"]);
      cached.checksUsed = store.npc_checks_used || 0;
      cached.verdictSub = cached.verdictSub
        + " You checked this image on " + String(cached.checkedAt || "").slice(0, 10)
        + ". Showing that result again did not use a free check.";
      return cached;
    }
  }

  /* Tier gate (credits spec section 2.4): history was consulted
   * above, so a repeat check is free in every tier. While free
   * checks remain, behavior is exactly the free tier. Past them, a
   * stored code pays: an active Verifier Pass covers standard
   * checks, a finite balance is consumed only after a
   * signature-verified registry answer, and with nothing able to
   * pay the popup is told needs_credits WITHOUT any registry call:
   * nobody gets a free answer past the free tier, and nobody is
   * charged for one either. */
  const storeBefore = await chrome.storage.local.get(["npc_checks_used"]);
  const freeUsed = storeBefore.npc_checks_used || 0;
  const freeLeft = Math.max(0, cfg.freeChecksTotal - freeUsed);
  let tier = "free";
  let creditSource = null;
  let gateUnknown = false;
  if (freeLeft === 0) {
    tier = "credit";
    const pick = await npcPickCreditSource(cfg, "standard");
    if (pick.mode === "none") {
      return { error: "needs_credits", reason: pick.reason, image };
    }
    if (pick.mode === "unknown") {
      gateUnknown = true;
    } else {
      creditSource = pick;
    }
  }

  const provenance = gateUnknown
    ? { status: "unreachable" }
    : await checkProvenance(image.src, cfg);

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

  /* The free counter moves only in the free tier. In the paid tier
   * the charge, when one is owed, is the consume call below: only a
   * signature-verified registry answer (matched or unknown) is
   * charged, mirroring the history rule exactly. */
  let used = freeUsed;
  if (tier === "free") {
    used = freeUsed + 1;
    await chrome.storage.local.set({ npc_checks_used: used });
  }
  let creditsNote = null;
  if (tier === "credit" && creditSource && identity
      && (pv === "matched" || pv === "unknown")) {
    creditsNote = await npcConsumeCredit(
      cfg, creditSource, identity, provenance.claimHash, "standard");
    if (creditSource.mode === "pass" && creditsNote.charged) {
      creditsNote.passCovered = true;
    }
  }

  const result = {
    image,
    verdict,
    verdictWord,
    showMark,
    verdictSub,
    provenance,
    forensics,
    ai: {
      status: "on_request",
      note: "The AI generation check runs only when you ask for it. It sends the image through the NPC API to an outside detection service, and states the score it returns. Nothing runs automatically."
    },
    nudge: verdict === "no_record",
    nudgeUrl: cfg.getVerifiedUrl,
    fullReportUrl: cfg.fullReportUrl,
    tier,
    credits: creditsNote,
    checksUsed: used,
    checksTotal: cfg.freeChecksTotal,
    elapsedMs: Date.now() - started,
    checkedAt: new Date().toISOString(),
    fromHistory: false
  };

  /* Remember the result for the history view and for dedupe, but
   * only when the registry answer was signature-verified (a match,
   * or a signed no-record). Errors are never remembered: a retry
   * must be free to reach a different answer. */
  if (identity && (pv === "matched" || pv === "unknown")) {
    try {
      await npcRememberCheck(identity, JSON.parse(JSON.stringify(result)));
    } catch (e) {
      // History is a convenience; a storage failure never fails a check.
    }
  }
  return result;
}
