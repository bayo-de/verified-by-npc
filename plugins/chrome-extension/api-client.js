/* NPC Verify: isolated API client.
 *
 * Every call the extension makes to the NPC API goes through this
 * module, so the endpoint contracts live in exactly one place:
 *
 *   Chat (biblo-chat-SPEC-2026-10-15.md):
 *     POST /v1/chat          {thread_id?, message, page}
 *       -> 200 {thread_id, reply, sources, state: "ok" | "off"}
 *     POST /v1/chat/feedback {thread_id, turn, rating, comment?}
 *       -> 200 {recorded}
 *     Chat is PUBLIC and UNSIGNED by design: chat answers are
 *     conversation, never records, so no signature is expected and
 *     none is checked. Chat never carries the API key.
 *
 *   Credits (extension-credits-integration-spec-2026-10-28.md):
 *     GET  /v1/credits/packs
 *     POST /v1/credits/redeem  {code}
 *     POST /v1/credits/balance {code}
 *     POST /v1/credits/consume {code, image_identity, claim_hash?, kind?}
 *     Signed envelope, verified here like every registry answer. An
 *     unverified credits answer is treated as no answer.
 *
 *   Media AI checks (detector-av plan, 2026-10-14):
 *     POST /v1/images/ai-check  (existing, lives in background.js)
 *     POST /v1/videos/ai-check  {video_url, interval_seconds?}
 *       -> 200 {check, provider, model, ai_generated_percent,
 *               ai_generated_percent_peak, frames_analyzed,
 *               frames_flagged, interval_ms, video_sha256, source,
 *               vendor_operations, checked_at}
 *     POST /v1/audio/ai-check   {audio_url}
 *       -> 200 {check, provider, model, ai_generated_percent,
 *               audio_sha256, source, checked_at}
 *     Signed envelope, verifier role, verified here. NOTE: the video
 *     and audio routes exist today only in the staging prototype
 *     (detector-av/prototype/av_routes.py); they are not registered
 *     in the production API yet. A 404 from either route is reported
 *     as "not_available", honestly, never as a result.
 *
 * This file is loaded in the service worker only (importScripts in
 * background.js, after config.js). It relies on two worker globals:
 * npcGetConfig (config.js) and npcVerifyResponseSignature
 * (background.js). The popup never calls the API directly; it asks
 * the worker through runtime messages, as it always has.
 */

/* One signed POST. Returns one of:
 *   {status: "http", httpStatus, data}   signature verified
 *   {status: "unreachable"}              network failure
 *   {status: "signature_failed"}         answer not trusted
 *   {status: "error", detail}            unparseable answer
 * Callers treat anything but "http" as no answer. */
async function npcSignedCall(cfg, path, payload, options) {
  const opts = options || {};
  let res;
  try {
    res = await fetch(cfg.apiBase + path, {
      method: opts.method || "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + cfg.apiKey
      },
      body: payload === undefined ? undefined : JSON.stringify(payload)
    });
  } catch (e) {
    return { status: "unreachable" };
  }
  let data;
  try {
    data = await res.json();
  } catch (e) {
    return { status: "error", detail: "bad_response" };
  }
  const sig = await npcVerifyResponseSignature(
    cfg.apiBase, data,
    res.headers.get("X-NPC-Signature"), res.headers.get("X-NPC-Key-ID"));
  if (sig !== "valid") return { status: "signature_failed" };
  return { status: "http", httpStatus: res.status, data };
}

/* One public, unsigned POST (chat only). Same result shape minus the
 * signature state: chat answers are not records and are not signed. */
async function npcPublicCall(cfg, path, payload) {
  let res;
  try {
    res = await fetch(cfg.apiBase + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    return { status: "unreachable" };
  }
  let data;
  try {
    data = await res.json();
  } catch (e) {
    return { status: "error", detail: "bad_response" };
  }
  return { status: "http", httpStatus: res.status, data };
}

/* ------------------------------------------------------------------ */
/* Biblo chat                                                           */
/* ------------------------------------------------------------------ */

/* Send one chat message. threadId is null on the first message; the
 * API mints the thread and returns it. The popup keeps the thread id
 * in memory only, per the chat spec: a popup reopen starts fresh. */
async function npcChatSend(cfg, threadId, message, page) {
  const payload = { message, page: page || "extension" };
  if (threadId) payload.thread_id = threadId;
  const r = await npcPublicCall(cfg, "/chat", payload);
  if (r.status !== "http") return { state: r.status };
  if (r.httpStatus === 429) return { state: "rate_limited" };
  if (r.httpStatus !== 200 || !r.data || typeof r.data.reply !== "string") {
    return { state: "error", detail: "http_" + r.httpStatus };
  }
  const sources = Array.isArray(r.data.sources) ? r.data.sources : [];
  return {
    state: r.data.state === "off" ? "off" : "ok",
    threadId: r.data.thread_id || threadId || null,
    reply: r.data.reply,
    // The service returns sources as {title, path}; the spec's wire
    // sketch showed plain paths. Accept both, render paths only.
    sources: sources.map(s =>
      typeof s === "string" ? s : (s && s.path) || "").filter(Boolean)
  };
}

/* Thumbs feedback on one chat turn. Best effort by design: the API
 * answers quietly either way, and so does this helper. */
async function npcChatFeedback(cfg, threadId, turn, rating) {
  if (!threadId) return { recorded: false };
  const r = await npcPublicCall(cfg, "/chat/feedback",
    { thread_id: threadId, turn, rating });
  return { recorded: !!(r.status === "http" && r.data && r.data.recorded) };
}

/* ------------------------------------------------------------------ */
/* Credits                                                              */
/* ------------------------------------------------------------------ */

async function npcCreditCall(cfg, path, payload) {
  return npcSignedCall(cfg, path, payload);
}

async function npcCreditPacks(cfg) {
  const r = await npcSignedCall(cfg, "/credits/packs", undefined,
    { method: "GET" });
  if (r.status !== "http" || r.httpStatus !== 200 || !r.data) {
    return { state: "unknown" };
  }
  return {
    state: "ok",
    packs: Array.isArray(r.data.packs) ? r.data.packs : [],
    checkoutAvailable: !!r.data.checkout_available
  };
}

/* ------------------------------------------------------------------ */
/* Video and audio AI checks                                            */
/* ------------------------------------------------------------------ */

/* kind is "video" or "audio"; url is the media address on the page.
 * The API fetches the media itself (its body cap rules out sending
 * media bytes from here), exactly as the AV contract specifies. */
async function npcAvCheck(cfg, kind, url) {
  const isVideo = kind === "video";
  const path = isVideo ? "/videos/ai-check" : "/audio/ai-check";
  const payload = isVideo ? { video_url: url } : { audio_url: url };
  const r = await npcSignedCall(cfg, path, payload);
  if (r.status !== "http") return { status: r.status };
  if (r.httpStatus === 404) return { status: "not_available" };
  if (r.httpStatus === 401 || r.httpStatus === 403) {
    return { status: "unauthorized" };
  }
  if (r.httpStatus !== 200) {
    if (r.data && r.data.error === "detector_unavailable") {
      return { status: "unavailable" };
    }
    return { status: "error", detail: "http_" + r.httpStatus };
  }
  const d = r.data || {};
  if (typeof d.ai_generated_percent !== "number") {
    return { status: "error", detail: "bad_response" };
  }
  const out = {
    status: "ok",
    sigVerified: true,
    kind,
    percent: d.ai_generated_percent,
    provider: d.provider || null,
    model: d.model || null,
    checkedAt: d.checked_at || null,
    mediaSha256: (isVideo ? d.video_sha256 : d.audio_sha256) || null
  };
  if (isVideo) {
    out.percentPeak = typeof d.ai_generated_percent_peak === "number"
      ? d.ai_generated_percent_peak : null;
    out.framesAnalyzed = d.frames_analyzed || 0;
    out.framesFlagged = d.frames_flagged || 0;
    out.intervalMs = d.interval_ms || null;
  }
  return out;
}
