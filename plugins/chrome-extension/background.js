/* NPC Verify: background service worker.
 *
 * Runs the layered check for one image:
 *   Layer 1 (provenance): hash the image URL, ask the verification API.
 *   Layer 2 (forensics):  client-side file analysis (forensics.js).
 *   Layer 3 (AI judgment): stubbed. The hosted Fleet backend adds a
 *             probabilistic read here later. This scaffold never guesses.
 *
 * Verdicts are only ever: "verified", "no_record", "not_checked",
 * "api_unreachable". We never claim more than we checked.
 */

importScripts("config.js", "forensics.js");

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "NPC_CHECK") {
    runCheck(msg.image).then(sendResponse).catch(err =>
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
  if (res.status === 404) return { status: "unknown" };
  if (res.status === 401 || res.status === 403) return { status: "unauthorized" };
  if (!res.ok) return { status: "error", detail: "http_" + res.status };
  let data;
  try {
    data = await res.json();
  } catch (e) {
    return { status: "error", detail: "bad_response" };
  }
  if (data && data.matched) {
    const a = data.attestation || {};
    return {
      status: "matched",
      creator: a.creator_name || a.holder_name || "Registered creator",
      recordedAt: a.tested_at || a.created_at || null,
      verdict: a.verdict || "verified",
      scope: (a.scope && a.scope.domain) || null
    };
  }
  return { status: "unknown" };
}

async function runCheck(image) {
  const cfg = await npcGetConfig();
  const started = Date.now();

  const forensics = await npcAnalyzeImage(image.src, image.w, image.h);
  const provenance = await checkProvenance(image.src, cfg);

  let verdict, verdictSub;
  if (provenance.status === "matched") {
    verdict = "verified";
    verdictSub = "Registered with NPC."
      + (provenance.creator ? " Creator: " + provenance.creator + "." : "")
      + (provenance.recordedAt ? " Recorded " + provenance.recordedAt.slice(0, 10) + "." : "");
  } else if (provenance.status === "unknown") {
    verdict = "no_record";
    verdictSub = "Nobody has registered this image with NPC yet. That is not the same as fake.";
  } else if (provenance.status === "not_configured" || provenance.status === "unauthorized") {
    verdict = "not_checked";
    verdictSub = "The registry was not checked. Point the extension at a verification API to enable provenance. The file checks below still ran on your device.";
  } else {
    verdict = "api_unreachable";
    verdictSub = "We could not reach the verification API, so the registry was not checked. The file checks below still ran on your device.";
  }

  const store = await chrome.storage.local.get(["npc_checks_used"]);
  const used = (store.npc_checks_used || 0) + 1;
  await chrome.storage.local.set({ npc_checks_used: used });

  return {
    image,
    verdict,
    verdictSub,
    provenance,
    forensics,
    ai: {
      status: "unavailable",
      note: "The hosted Fleet backend will add a probabilistic read here, with its confidence stated. This version does not guess."
    },
    nudge: verdict === "no_record" || verdict === "not_checked",
    nudgeUrl: cfg.getVerifiedUrl,
    fullReportUrl: cfg.fullReportUrl,
    checksUsed: used,
    checksTotal: cfg.freeChecksTotal,
    elapsedMs: Date.now() - started,
    checkedAt: new Date().toISOString()
  };
}
