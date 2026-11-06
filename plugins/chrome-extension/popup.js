/* NPC Verify: popup logic. UI only; the check runs in background.js. */

const $ = id => document.getElementById(id);

function show(viewId) {
  for (const v of document.querySelectorAll(".view")) v.classList.add("hidden");
  $(viewId).classList.remove("hidden");
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

let IMAGES = [];
let SELECTED = 0;
let TAB_ID = null;
let AI_CONTEXT = null; // image + tab of the verdict currently on screen

async function init() {
  show("view-loading");
  updateChecksLine();
  const tab = await activeTab();
  if (!tab || !tab.id || !/^https?:/.test(tab.url || "")) {
    show("view-empty");
    return;
  }
  TAB_ID = tab.id;
  let resp;
  try {
    resp = await chrome.tabs.sendMessage(tab.id, { type: "NPC_COLLECT_IMAGES" });
  } catch (e) {
    resp = null;
  }
  if (!resp && chrome.scripting) {
    // Tab was open before install: inject the collector and retry once.
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
      resp = await chrome.tabs.sendMessage(tab.id, { type: "NPC_COLLECT_IMAGES" });
    } catch (e2) {
      resp = null;
    }
  }
  IMAGES = (resp && resp.images) || [];
  if (!IMAGES.length) {
    show("view-empty");
    return;
  }
  SELECTED = 0;
  renderPicker();
  show("view-pick");
}

function renderPicker() {
  const img = IMAGES[SELECTED];
  const sel = $("selected-img");
  sel.src = img.src;
  sel.alt = img.alt || "Selected image";
  const thumbs = $("thumbs");
  thumbs.innerHTML = "";
  IMAGES.forEach((im, i) => {
    const t = document.createElement("img");
    t.src = im.src;
    t.alt = im.alt || "Image " + (i + 1);
    t.className = i === SELECTED ? "sel" : "";
    t.addEventListener("click", () => { SELECTED = i; renderPicker(); });
    thumbs.appendChild(t);
  });
  updateChecksLine();
}

async function updateChecksLine() {
  const cfg = await npcGetConfig();
  const used = await new Promise(res =>
    chrome.runtime.sendMessage({ type: "NPC_CHECKS_USED" }, r => res((r && r.used) || 0))
  );
  const remaining = Math.max(0, cfg.freeChecksTotal - used);
  $("checks-line").textContent = remaining + " of " + cfg.freeChecksTotal + " free checks left";
  const btn = $("check-btn");
  if (btn) {
    if (remaining <= 0) {
      btn.disabled = true;
      btn.textContent = "Free checks used up";
    } else {
      btn.disabled = false;
      btn.textContent = "Check this image";
    }
  }
}

async function runCheck() {
  show("view-checking");
  AI_CONTEXT = { image: IMAGES[SELECTED], tabId: TAB_ID };
  let result;
  try {
    result = await chrome.runtime.sendMessage({ type: "NPC_CHECK", image: IMAGES[SELECTED], tabId: TAB_ID });
  } catch (e) {
    result = { error: "pipeline_failed" };
  }
  if (!result || result.error) {
    $("verdict-word").textContent = "Check failed";
    $("verdict-sub").textContent = "Something went wrong running the check. Try again.";
    $("verdict-mark").classList.add("hidden");
    setLayer("prov", "", "");
    setLayer("for", "", "");
    setLayer("ai", "", "");
    $("body-prov").innerHTML = "<p>The check did not complete.</p>";
    $("body-for").innerHTML = "";
    $("body-ai").innerHTML = "";
    $("nudge").classList.add("hidden");
    show("view-verdict");
    return;
  }
  renderVerdict(result);
  updateChecksLine();
}

/* The AI generation check button in the AI judgment layer. Sends the
 * image from the verdict on screen to the background worker, which
 * asks the NPC API. Nothing about this runs until it is pressed. */
async function runAiCheckFromPopup() {
  const btn = $("ai-check-btn");
  const out = $("ai-check-result");
  if (!btn || !out || !AI_CONTEXT) return;
  btn.disabled = true;
  btn.textContent = "Checking...";
  out.innerHTML = "";
  let r;
  try {
    r = await chrome.runtime.sendMessage(
      { type: "NPC_AI_CHECK", image: AI_CONTEXT.image, tabId: AI_CONTEXT.tabId });
  } catch (e) {
    r = { status: "error" };
  }
  btn.disabled = false;
  btn.textContent = "Check this image for AI generation";
  renderAiResult(r || { status: "error" }, out);
}

function renderAiResult(r, out) {
  if (r.status === "ok") {
    const p = r.percent;
    let lead;
    if (p >= 75) lead = "Signals strongly suggest AI generation.";
    else if (p >= 40) lead = "The signals are mixed, and this read does not settle the question.";
    else lead = "No AI-generation signals found.";
    out.innerHTML = "<p><span class='k'>" + esc(lead) + "</span> AI generation analysis scored this image "
      + esc(p) + " out of 100 for AI generation.</p>"
      + "<p>The score is one detection service's read of the image itself, stated with its number. It is a signal, not proof.</p>"
      + "<p>Answer signed by NPC. Signature verified against the published keys.</p>";
  } else if (r.status === "signature_failed") {
    out.innerHTML = "<p>The API answered, but the answer's NPC signature did not verify against the published keys, so this result is not shown.</p>";
  } else if (r.status === "not_configured") {
    out.innerHTML = "<p>This check was not run. This copy of the extension has no API key set. See the README to connect one.</p>";
  } else if (r.status === "unauthorized") {
    out.innerHTML = "<p>The API rejected the configured key, so this check was not run.</p>";
  } else if (r.status === "unavailable") {
    out.innerHTML = "<p>The detection service did not complete the check, so there is no result to show. NPC does not guess.</p>";
  } else {
    out.innerHTML = "<p>The AI generation check could not be completed, so there is no result to show. NPC does not guess.</p>";
  }
}

function setLayer(which, stateText, stateClass) {
  const el = $("state-" + which);
  el.textContent = stateText;
  el.className = "layer-state" + (stateClass ? " " + stateClass : "");
}

function fmtBytes(n) {
  if (n == null) return "unknown";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(2) + " MB";
}

function renderVerdict(r) {
  const word = $("verdict-word");
  const sub = $("verdict-sub");
  const mark = $("verdict-mark");
  mark.classList.add("hidden");

  if (r.verdictWord) {
    word.textContent = r.verdictWord;
  } else if (r.verdict === "verified") {
    word.textContent = "Verified";
  } else if (r.verdict === "no_record") {
    word.textContent = "No record found";
  } else if (r.verdict === "not_checked") {
    word.textContent = "Not checked";
  } else {
    word.textContent = "API unreachable";
  }
  // The mark appears only when the worker verified a signed, positive
  // verdict. It is never decoration.
  if (r.showMark) mark.classList.remove("hidden");
  sub.textContent = r.verdictSub;

  // Layer 1: provenance
  const p = r.provenance || {};
  if (p.status === "matched" && r.showMark) {
    setLayer("prov", p.attVerdict === "verified_with_caveats" ? "registered, with caveats" : "registered", "hit");
    $("body-prov").innerHTML =
      "<p><span class='k'>Registered.</span> " + esc(p.creator || "A creator") + " put this on record"
      + (p.recordedAt ? " on " + esc(p.recordedAt.slice(0, 10)) : "") + "."
      + (p.scope ? " Scope: " + esc(p.scope) + "." : "") + "</p>"
      + (p.findings ? "<p><span class='k'>On record:</span> " + esc(p.findings) + "</p>" : "")
      + "<p>Answer signed by NPC. Signature verified against the published keys.</p>"
      + "<p><a href='" + esc(r.fullReportUrl) + "' target='_blank' rel='noopener'>See the full record</a></p>";
  } else if (p.status === "matched") {
    setLayer("prov", "record found", "miss");
    $("body-prov").innerHTML =
      "<p>A record matched this image, with standing \"" + esc(p.attVerdict || "unknown")
      + "\". That standing is not a verified one, so no verdict is shown from it.</p>"
      + "<p>Answer signed by NPC. Signature verified against the published keys.</p>";
  } else if (p.status === "signature_failed") {
    setLayer("prov", "signature failed", "miss");
    $("body-prov").innerHTML = "<p>The API answered, but the answer's NPC signature did not verify against the published keys. An answer we cannot verify is not shown as a result.</p>";
  } else if (p.status === "unknown") {
    setLayer("prov", "no record", "miss");
    $("body-prov").innerHTML = "<p>No NPC record matches this image. That means nobody has registered it here, nothing more.</p>"
      + "<p>Answer signed by NPC. Signature verified against the published keys.</p>";
  } else if (p.status === "not_configured") {
    setLayer("prov", "not connected", "miss");
    $("body-prov").innerHTML = "<p>The registry was not checked. This copy of the extension has no API key set. See the README to connect one.</p>";
  } else if (p.status === "unauthorized") {
    setLayer("prov", "key rejected", "miss");
    $("body-prov").innerHTML = "<p>The API rejected the configured key. Check that it is a verifier-role key.</p>";
  } else if (p.status === "error") {
    setLayer("prov", "api error", "miss");
    $("body-prov").innerHTML = "<p>The verification API answered with an error, so the registry could not be read.</p>";
  } else {
    setLayer("prov", "unreachable", "miss");
    $("body-prov").innerHTML = "<p>We could not reach the verification API, so the registry was not checked.</p>";
  }

  // Layer 2: forensics
  const f = r.forensics || {};
  setLayer("for", f.bytesRead ? "file read" : "limited", f.bytesRead ? "hit" : "miss");
  let fh = "";
  fh += "<p><span class='k'>Format:</span> " + esc(f.format || "unknown")
    + " &nbsp;<span class='k'>Size:</span> " + esc(fmtBytes(f.byteSize))
    + " &nbsp;<span class='k'>Dimensions:</span> " + esc(f.dimensions || "unknown") + "</p>";
  if (!f.bytesRead) {
    fh += "<p>We could not read the file's bytes. The site blocks cross-origin reads, so embedded metadata could not be inspected.</p>";
  } else {
    if (f.exif && (f.exif.software || f.exif.make || f.exif.model)) {
      fh += "<p><span class='k'>Embedded tags:</span> "
        + esc([f.exif.software, f.exif.make, f.exif.model].filter(Boolean).join(" / ")) + "</p>";
    } else if (f.pngText) {
      const keys = Object.keys(f.pngText).slice(0, 4);
      fh += "<p><span class='k'>Embedded text:</span> " + esc(keys.join(", ")) + "</p>";
    } else {
      fh += "<p>No embedded software tags found. That is normal. Most images carry none.</p>";
    }
    if (f.markers && f.markers.length) {
      fh += "<p><span class='k'>Marker found:</span> " + esc(f.markers.join(", "))
        + ". This suggests the named tool touched the file. Markers can be stripped or faked, so this is a hint, not proof.</p>";
    } else {
      fh += "<p>No known generator markers found. Absence of a marker proves nothing either way.</p>";
    }
    if (f.credentials && f.credentials.present) {
      let cs = "Content Credentials are attached.";
      if (f.credentials.generator) {
        cs += " The credential says this image was made with " + esc(f.credentials.generator);
        cs += f.credentials.digitalSourceType
          ? " and labels it " + esc(f.credentials.digitalSourceType) + "." : ".";
      } else if (f.credentials.digitalSourceType) {
        cs += " The credential labels this image " + esc(f.credentials.digitalSourceType) + ".";
      }
      cs += " NPC has not cryptographically checked the credential in this version.";
      fh += "<p>" + cs + "</p>";
    }
    if (f.iptcSourceType) {
      fh += "<p><span class='k'>Source type tag:</span> " + esc(f.iptcSourceType)
        + ". This tag is written into the file by software and can be edited, so treat it as a claim by the file, not proof.</p>";
    }
  }
  const lens = "https://lens.google.com/uploadbyurl?url=" + encodeURIComponent(f.src || "");
  const tineye = "https://tineye.com/search?url=" + encodeURIComponent(f.src || "");
  fh += "<p>See where else this image appears: "
    + "<a href='" + lens + "' target='_blank' rel='noopener'>Google Lens</a> · "
    + "<a href='" + tineye + "' target='_blank' rel='noopener'>TinEye</a></p>";
  $("body-for").innerHTML = fh;

  // Layer 3: AI judgment. The request control, its explanation, and
  // its result all live in this layer. Explicit user action only,
  // never automatic, and the disclosure sits next to the button.
  setLayer("ai", "on request", "miss");
  $("body-ai").innerHTML =
    "<p><span class='k'>AI generation check.</span> The checks above read what the file declares about itself. This one looks at the image itself.</p>"
    + "<p>" + esc((r.ai && r.ai.note) || "The AI generation check runs only when you ask for it. It sends the image through the NPC API to an outside detection service, and states the score it returns. Nothing runs automatically.") + "</p>"
    + "<div class='ai-check'>"
    + "<button id='ai-check-btn' class='ghost-btn' type='button'>Check this image for AI generation</button>"
    + "<p class='fineprint'>This check sends the image to an outside detection service.</p>"
    + "<div id='ai-check-result'></div>"
    + "</div>";
  const aiBtn = $("ai-check-btn");
  if (aiBtn) aiBtn.addEventListener("click", runAiCheckFromPopup);

  // Nudge
  const nudge = $("nudge");
  if (r.nudge) {
    nudge.classList.remove("hidden");
    $("nudge-link").textContent = r.nudgeUrl;
    $("nudge-copy").onclick = async () => {
      try {
        await navigator.clipboard.writeText(r.nudgeUrl);
        $("nudge-copy").textContent = "Copied";
        setTimeout(() => { $("nudge-copy").textContent = "Copy invite link"; }, 1600);
      } catch (e) {
        $("nudge-copy").textContent = "Copy failed";
      }
    };
  } else {
    nudge.classList.add("hidden");
  }

  show("view-verdict");
}

/* Past checks: the worker keeps this browser's own check history in
 * local storage. The view lists each checked image with its verdict
 * and when it was checked. Checking an image already listed returns
 * its earlier result and uses no free check. */
async function openHistory() {
  show("view-history");
  const list = $("history-list");
  list.innerHTML = "<p class='quiet'>Loading…</p>";
  let entries = [];
  try {
    const r = await chrome.runtime.sendMessage({ type: "NPC_HISTORY" });
    entries = (r && r.entries) || [];
  } catch (e) {
    entries = [];
  }
  if (!entries.length) {
    list.innerHTML = "<p class='quiet'>No checks yet. Images you check will be listed here.</p>";
    return;
  }
  list.innerHTML = entries.map(e => {
    let where = "";
    try { where = new URL(e.src).hostname; } catch (err) { where = ""; }
    const short = String(e.id || "").replace(/^(sha256|url-sha256):/, "").slice(0, 12);
    const thumb = e.src
      ? "<img class='hist-thumb' src='" + esc(e.src) + "' alt=''>"
      : "";
    return "<div class='hist-row'>"
      + thumb
      + "<div class='hist-text'>"
      + "<p class='hist-verdict'>" + esc(e.verdictWord || "Checked") + "</p>"
      + "<p class='hist-meta'>" + esc(String(e.checkedAt || "").slice(0, 10))
      + (where ? " · " + esc(where) : "")
      + (short ? " · image " + esc(short) + "…" : "")
      + "</p></div></div>";
  }).join("");
  /* A thumbnail that cannot load (hotlink protection, a dead address)
   * is dropped, leaving the plain text row. The error listener is
   * attached here rather than inline: the popup's CSP, like every
   * MV3 extension page, forbids inline handlers. */
  for (const img of list.querySelectorAll(".hist-thumb")) {
    if (img.complete && img.naturalWidth === 0) img.remove();
    else img.addEventListener("error", () => img.remove());
  }
}

$("check-btn").addEventListener("click", runCheck);
$("again-btn").addEventListener("click", () => { renderPicker(); show("view-pick"); });
for (const b of document.querySelectorAll(".history-open")) {
  b.addEventListener("click", openHistory);
}
$("history-back").addEventListener("click", () => {
  if (IMAGES.length) { renderPicker(); show("view-pick"); }
  else show("view-empty");
});

document.addEventListener("DOMContentLoaded", init);
