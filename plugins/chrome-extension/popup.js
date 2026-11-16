/* NPC Verify: popup logic. UI only; the check runs in background.js. */

const $ = id => document.getElementById(id);

let LAST_VERIFY_VIEW = "view-pick";

function setActiveTab(name) {
  for (const n of ["verify", "biblo", "usage"]) {
    $("tab-" + n).classList.toggle("active", n === name);
  }
}

function show(viewId) {
  for (const v of document.querySelectorAll(".view")) v.classList.add("hidden");
  $(viewId).classList.remove("hidden");
  if (viewId === "view-biblo") setActiveTab("biblo");
  else if (viewId === "view-usage") setActiveTab("usage");
  else { LAST_VERIFY_VIEW = viewId; setActiveTab("verify"); }
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
let MEDIA = [];
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
  MEDIA = (resp && resp.media) || [];
  if (!IMAGES.length && !MEDIA.length) {
    show("view-empty");
    return;
  }
  SELECTED = 0;
  renderPicker();
  show("view-pick");
}

function renderPicker() {
  const hasImages = IMAGES.length > 0;
  document.querySelector(".selected-wrap").classList.toggle("hidden", !hasImages);
  $("thumbs").classList.toggle("hidden", !hasImages);
  $("check-btn").classList.toggle("hidden", !hasImages);
  if (hasImages) {
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
  }
  renderMedia();
  updateChecksLine();
}

function fmtDuration(sec) {
  if (sec == null) return "";
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return m + ":" + String(s).padStart(2, "0");
}

/* Video and audio found on the page, each with its own AI
 * generation check. The check sends the file's address to the NPC
 * API; the file itself is read by the API, not by this page. */
function renderMedia() {
  const block = $("media-block");
  const list = $("media-list");
  if (!MEDIA.length) {
    block.classList.add("hidden");
    return;
  }
  block.classList.remove("hidden");
  list.innerHTML = "";
  MEDIA.forEach((m, i) => {
    const row = document.createElement("div");
    row.className = "media-row";
    const kind = document.createElement("span");
    kind.className = "media-kind";
    kind.textContent = m.kind === "video" ? "Video" : "Audio";
    const meta = document.createElement("span");
    meta.className = "media-meta";
    let host = "";
    try { host = new URL(m.src).hostname; } catch (e) { host = ""; }
    meta.textContent = (m.title || host)
      + (m.duration ? " · " + fmtDuration(m.duration) : "");
    const btn = document.createElement("button");
    btn.className = "ghost-btn";
    btn.type = "button";
    btn.textContent = "Check for AI generation";
    btn.addEventListener("click", () => runAvCheck(i));
    row.appendChild(kind);
    row.appendChild(meta);
    row.appendChild(btn);
    list.appendChild(row);
  });
}

async function runAvCheck(i) {
  const m = MEDIA[i];
  if (!m) return;
  show("view-checking");
  let r;
  try {
    r = await chrome.runtime.sendMessage(
      { type: "NPC_AV_CHECK", kind: m.kind, url: m.src });
  } catch (e) {
    r = { status: "error" };
  }
  renderAvResult(m, r || { status: "error" });
}

function aiLead(percent) {
  if (percent >= 75) return "Signals strongly suggest AI generation.";
  if (percent >= 40) return "The signals are mixed, and this read does not settle the question.";
  return "No AI-generation signals found.";
}

function creditsNoteText(c) {
  if (!c) return "";
  if (c.passCovered) return " Covered by your Verifier Pass. No check was spent.";
  if (c.charged) return " Paid with 1 check from your code."
    + (typeof c.balance === "number" ? " " + c.balance + " left." : "");
  if (c.duplicate) return " This was already paid for on your code, so no check was spent.";
  if (c.exhausted) return " Your code is now out of checks.";
  if (c.unrecorded) return " The check could not be recorded against your code, so no check was spent.";
  return "";
}

function renderAvResult(m, r) {
  const word = $("av-word");
  const sub = $("av-sub");
  const detail = $("av-detail");
  const label = m.kind === "video" ? "Video" : "Audio";
  if (r.status === "ok") {
    word.textContent = label + " check";
    sub.textContent = aiLead(r.percent) + " AI generation analysis scored this "
      + m.kind + " " + r.percent + " out of 100 for AI generation.";
    let h = "<p>The score is one detection service's read of the file itself, stated with its number. It is a signal, not proof.</p>";
    if (m.kind === "video") {
      h += "<p><span class='k'>Frames read:</span> " + esc(r.framesAnalyzed || 0)
        + " · <span class='k'>Frames flagged:</span> " + esc(r.framesFlagged || 0)
        + (r.percentPeak != null
          ? " · <span class='k'>Strongest frame:</span> " + esc(r.percentPeak) + " out of 100" : "")
        + "</p>";
    } else {
      h += "<p>This read is strongest on music without vocals. Singing can blur it, so weigh it as one signal among others.</p>";
    }
    h += "<p>Answer signed by NPC. Signature verified against the published keys.</p>";
    const note = creditsNoteText(r.credits);
    if (note) h += "<p>" + esc(note.trim()) + "</p>";
    detail.innerHTML = h;
  } else if (r.status === "not_available") {
    word.textContent = "Not live yet";
    sub.textContent = "Video and audio checks are built into this update, but the NPC API does not serve them yet, so there is no result to show. NPC does not guess.";
    detail.innerHTML = "";
  } else if (r.status === "no_ai_credits") {
    word.textContent = "AI checks used up";
    sub.textContent = "The AI generation checks your code can fund are used up for now. Registry checks are not affected.";
    detail.innerHTML = "";
  } else if (r.status === "signature_failed") {
    word.textContent = "Not checked";
    sub.textContent = "The API answered, but the answer's NPC signature did not verify against the published keys, so this result is not shown.";
    detail.innerHTML = "";
  } else if (r.status === "not_configured") {
    word.textContent = "Not checked";
    sub.textContent = "This copy of the extension has no API key set. See the README to connect one.";
    detail.innerHTML = "";
  } else if (r.status === "unauthorized") {
    word.textContent = "Not checked";
    sub.textContent = "The API rejected the configured key, so this check was not run.";
    detail.innerHTML = "";
  } else if (r.status === "unavailable") {
    word.textContent = "No result";
    sub.textContent = "The detection service did not complete the check, so there is no result to show. NPC does not guess.";
    detail.innerHTML = "";
  } else {
    word.textContent = "No result";
    sub.textContent = "We could not complete this check, so there is no result to show. NPC does not guess.";
    detail.innerHTML = "";
  }
  show("view-av");
}

function sendMsg(msg) {
  return new Promise(res => {
    try {
      chrome.runtime.sendMessage(msg, r => res(r || null));
    } catch (e) {
      res(null);
    }
  });
}

async function fetchCreditSummary() {
  const r = await sendMsg({ type: "NPC_CREDIT_BALANCE" });
  return r || { state: "unknown" };
}

function fmtPrice(cents, currency) {
  const sym = currency === "usd" ? "$" : "";
  const v = (cents / 100).toFixed(2).replace(/\.00$/, "");
  return sym + v;
}

/* The upsell, rendered from the packs endpoint (prices are never
 * written into this file): the Verifier Pass first as best value,
 * then the one-time packs. Quiet by design: it renders only where a
 * zero state or the Usage view asks for it. */
async function renderUpsell(container) {
  if (!container) return;
  container.innerHTML = "";
  const cfg = await npcGetConfig();
  const r = await sendMsg({ type: "NPC_CREDIT_PACKS" });
  const packs = (r && r.state === "ok" ? r.packs : [])
    .filter(p => p.on_sale !== false);
  packs.sort((a, b) => (a.kind === "access" ? 0 : 1) - (b.kind === "access" ? 0 : 1));
  for (const p of packs) {
    const a = document.createElement("a");
    a.className = "upsell-item" + (p.kind === "access" ? " best" : "");
    a.href = cfg.creditsPurchaseUrl;
    a.target = "_blank";
    a.rel = "noopener";
    const name = document.createElement("p");
    name.className = "upsell-name";
    name.textContent = p.label;
    const desc = document.createElement("p");
    desc.className = "upsell-desc";
    if (p.kind === "access") {
      desc.textContent = fmtPrice(p.price_cents, p.currency) + " a month. "
        + "Unlimited registry checks, including " + (p.ai_checks || 0)
        + " AI generation checks a month.";
    } else {
      desc.textContent = fmtPrice(p.price_cents, p.currency)
        + " one payment for " + p.checks + " checks.";
    }
    a.appendChild(name);
    a.appendChild(desc);
    container.appendChild(a);
  }
}

/* The checks line and the check button, in every state the credits
 * spec names: free remaining, code balance, active Pass, canceled
 * Pass with checks still live, and the zero state with its upsell. */
async function updateChecksLine() {
  const cfg = await npcGetConfig();
  const used = await new Promise(res =>
    chrome.runtime.sendMessage({ type: "NPC_CHECKS_USED" }, r => res((r && r.used) || 0))
  );
  const remaining = Math.max(0, cfg.freeChecksTotal - used);
  const btn = $("check-btn");
  const cta = $("credits-cta");
  const enable = label => {
    if (btn) { btn.disabled = false; btn.textContent = label; }
    if (cta) cta.classList.add("hidden");
  };
  if (remaining > 0) {
    let line = remaining + " of " + cfg.freeChecksTotal + " free checks left";
    const credit = await fetchCreditSummary();
    const okSlot = [credit.primary, credit.pack]
      .find(s => s && s.state === "ok");
    if (okSlot) line += " · " + okSlot.balance + " checks on your code";
    $("checks-line").textContent = line;
    enable("Check this image");
    return;
  }
  const credit = await fetchCreditSummary();
  const prim = credit.primary || { state: "none" };
  const pack = credit.pack || { state: "none" };
  if (prim.state === "ok" && prim.registryUnlimited
      && prim.subscriptionStatus === "active") {
    $("checks-line").textContent = "Free checks used up · Unlimited registry "
      + "checks on your Verifier Pass · " + prim.aiBalance
      + " AI checks left this month";
    enable("Check this image");
    return;
  }
  if (prim.state === "ok" && prim.subscriptionStatus === "canceled"
      && prim.balance > 0) {
    $("checks-line").textContent = "Pass canceled · Free checks used up · "
      + prim.balance + " checks left on your Verifier Pass this cycle · "
      + prim.aiBalance + " AI checks left";
    enable("Check this image");
    return;
  }
  const payer = [prim, pack].find(s => s.state === "ok" && s.balance > 0);
  if (payer) {
    $("checks-line").textContent = "Free checks used up · "
      + payer.balance + " checks left on your code";
    enable("Check this image");
    return;
  }
  $("checks-line").textContent = "Free checks used up";
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Free checks used up";
  }
  if (cta) {
    cta.classList.remove("hidden");
    $("buy-checks-btn").href = cfg.creditsPurchaseUrl;
    $("credits-cta-text").textContent = credit.state === "invalid"
      ? "Your saved code is no longer valid. Get more checks, or apply a new code below."
      : "Your free checks are used up.";
    renderUpsell($("upsell-list"));
  }
}

/* One redeem flow behind both code fields (picker and Usage view),
 * with the spec's plain outcome lines. */
async function redeemCredit(input, msg) {
  const code = (input.value || "").trim();
  if (!code) { msg.textContent = "Paste your code first."; return; }
  msg.textContent = "Checking the code...";
  const r = await sendMsg({ type: "NPC_CREDIT_REDEEM", code });
  if (r && r.state === "ok") {
    msg.textContent = r.registryUnlimited
      ? "Code applied. Your Verifier Pass is active: registry checks are unlimited, with "
        + r.aiBalance + " AI checks a month."
      : "Code applied. " + r.balance + " checks available.";
    input.value = "";
    updateChecksLine();
    if (!$("view-usage").classList.contains("hidden")) renderUsage();
  } else if (r && r.state === "not_found") {
    msg.textContent = "That code was not found. Check it and try again.";
  } else if (r && r.state === "revoked") {
    msg.textContent = "That code is no longer active.";
  } else {
    msg.textContent = "We could not check the code just now. Nothing was changed. Try again in a moment.";
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
  if (result && result.error === "needs_credits") {
    // Paid tier with nothing able to pay: back to the picker, where
    // updateChecksLine reveals the credits block with the upsell.
    renderPicker();
    show("view-pick");
    updateChecksLine();
    return;
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
  if (r.status === "no_ai_credits") {
    out.innerHTML = "<p>The AI generation checks your code can fund are used up for now. Registry checks are not affected.</p>";
    return;
  }
  if (r.status === "ok") {
    const p = r.percent;
    let lead;
    if (p >= 75) lead = "Signals strongly suggest AI generation.";
    else if (p >= 40) lead = "The signals are mixed, and this read does not settle the question.";
    else lead = "No AI-generation signals found.";
    out.innerHTML = "<p><span class='k'>" + esc(lead) + "</span> AI generation analysis scored this image "
      + esc(p) + " out of 100 for AI generation.</p>"
      + "<p>The score is one detection service's read of the image itself, stated with its number. It is a signal, not proof.</p>"
      + "<p>Answer signed by NPC. Signature verified against the published keys.</p>"
      + (creditsNoteText(r.credits)
        ? "<p>" + esc(creditsNoteText(r.credits).trim()) + "</p>" : "");
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
  // Paid tier: the charge note rides the verdict sub in the same
  // plain style as the history note (credits spec section 4.4).
  if (r.tier === "credit" && r.credits) {
    const note = creditsNoteText(r.credits);
    if (note) sub.textContent += note;
  }

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

/* ------------------------------------------------------------------ */
/* Usage view                                                           */
/* ------------------------------------------------------------------ */

/* The same meter the desktop app and dashboard read: free checks
 * counted locally, paid balances read live from the ledger through
 * the worker. Numbers shown are the ledger's own; a balance that
 * cannot be read is shown as unread, never guessed. */
async function renderUsage() {
  const body = $("usage-body");
  body.innerHTML = "<p class='quiet'>Loading…</p>";
  const cfg = await npcGetConfig();
  const used = await new Promise(res =>
    chrome.runtime.sendMessage({ type: "NPC_CHECKS_USED" }, r => res((r && r.used) || 0))
  );
  const remaining = Math.max(0, cfg.freeChecksTotal - used);
  const credit = await fetchCreditSummary();
  const rows = [];
  rows.push(["Free checks", used + " of " + cfg.freeChecksTotal
    + " used · " + remaining + " left"]);
  const prim = credit.primary || { state: "none" };
  const pack = credit.pack || { state: "none" };
  if (prim.state === "ok" && prim.registryUnlimited
      && prim.subscriptionStatus === "active") {
    rows.push(["Verifier Pass", "Active"]);
    rows.push(["Registry checks", "Unlimited on your Pass"]);
    rows.push(["AI checks left this month", String(prim.aiBalance)]);
  } else if (prim.state === "ok") {
    rows.push([prim.subscriptionStatus === "canceled"
      ? "Verifier Pass (canceled)" : "Checks on your Pass code",
      prim.balance + " left"]);
    rows.push(["AI checks left", String(prim.aiBalance)]);
  }
  if (pack.state === "ok") {
    rows.push(["Checks on your pack code", pack.balance + " left"]);
    rows.push(["AI checks left on pack", String(pack.aiBalance)]);
  }
  if (credit.state === "none") {
    rows.push(["Checks code", "None added yet"]);
  } else if (credit.state === "unknown") {
    rows.push(["Code balance", "Could not be read just now"]);
  } else if (credit.state === "invalid"
      && prim.state !== "ok" && pack.state !== "ok") {
    rows.push(["Checks code", "No longer valid"]);
  }
  body.innerHTML = rows.map(([k, v]) =>
    "<div class='usage-row'><span class='u-k'>" + esc(k)
    + "</span><span class='u-v'>" + esc(v) + "</span></div>").join("");
  // The upsell lives here only in the zero state: present when it is
  // the way forward, quiet otherwise.
  const upsell = $("usage-upsell");
  const canPay = [prim, pack].some(s => s.state === "ok"
    && (s.balance > 0 || (s.registryUnlimited
      && s.subscriptionStatus === "active")));
  if (remaining === 0 && !canPay) {
    renderUpsell(upsell);
  } else {
    upsell.innerHTML = "";
  }
}

/* ------------------------------------------------------------------ */
/* Biblo chat                                                           */
/* ------------------------------------------------------------------ */

/* Chat is conversation, never a record: no verdict is ever rendered
 * from it, and the thread id lives in this popup's memory only, so
 * closing the popup starts a fresh conversation (chat spec). */
let CHAT_THREAD = null;
let CHAT_TURN = 0;
let CHAT_GREETED = false;

function initChat() {
  if (CHAT_GREETED) return;
  CHAT_GREETED = true;
  addChatMsg("biblo",
    "Hello. I am Biblo, the assistant here at NPC Labs. Ask me about "
    + "records, registering your own work or an agent, what the checks "
    + "mean, or where the plugins stand. If I do not know, I will say so.",
    null, 0);
}

function addChatMsg(who, text, sources, turn) {
  const log = $("chat-log");
  const wrap = document.createElement("div");
  const bubble = document.createElement("div");
  bubble.className = "chat-msg " + (who === "biblo" ? "biblo" : "you");
  bubble.textContent = text;
  wrap.appendChild(bubble);
  if (who === "biblo" && sources && sources.length) {
    const src = document.createElement("p");
    src.className = "chat-sources";
    src.textContent = "From: " + sources.join(", ");
    wrap.appendChild(src);
  }
  if (who === "biblo" && turn > 0) {
    const fb = document.createElement("div");
    fb.className = "chat-fb";
    for (const [label, rating] of [["Helpful", "up"], ["Not helpful", "down"]]) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = label;
      b.addEventListener("click", async () => {
        for (const x of fb.querySelectorAll("button")) x.classList.remove("picked");
        b.classList.add("picked");
        await sendMsg({ type: "NPC_CHAT_FEEDBACK",
          threadId: CHAT_THREAD, turn, rating });
      });
      fb.appendChild(b);
    }
    wrap.appendChild(fb);
  }
  log.appendChild(wrap);
  log.scrollTop = log.scrollHeight;
}

async function sendChat(text) {
  text = (text || "").trim();
  if (!text) return;
  initChat();
  $("chat-starters").classList.add("hidden");
  addChatMsg("you", text, null, 0);
  const input = $("chat-input");
  input.value = "";
  const btn = $("chat-send");
  btn.disabled = true;
  CHAT_TURN += 1;
  const myTurn = CHAT_TURN;
  const r = await sendMsg({ type: "NPC_CHAT_SEND",
    threadId: CHAT_THREAD, message: text });
  btn.disabled = false;
  if (r && r.threadId) CHAT_THREAD = r.threadId;
  if (r && (r.state === "ok" || r.state === "off")) {
    addChatMsg("biblo", r.reply, r.sources, myTurn);
  } else if (r && r.state === "rate_limited") {
    addChatMsg("biblo",
      "That is a lot of questions for now. Please try again in a "
      + "little while, or write to hello@npclabs.xyz.", null, 0);
  } else {
    addChatMsg("biblo",
      "Biblo could not answer just now. Please try again in a moment, "
      + "or write to hello@npclabs.xyz.", null, 0);
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

$("tab-verify").addEventListener("click", () => show(LAST_VERIFY_VIEW));
$("tab-biblo").addEventListener("click", () => { initChat(); show("view-biblo"); });
$("tab-usage").addEventListener("click", () => { show("view-usage"); renderUsage(); });

$("chat-send").addEventListener("click", () => sendChat($("chat-input").value));
$("chat-input").addEventListener("keydown", e => {
  if (e.key === "Enter") sendChat($("chat-input").value);
});
for (const chip of document.querySelectorAll("#chat-starters .chip")) {
  chip.addEventListener("click", () => sendChat(chip.getAttribute("data-q")));
}

$("credit-redeem-btn").addEventListener("click", () =>
  redeemCredit($("credit-code-input"), $("credit-msg")));
$("usage-redeem-btn").addEventListener("click", () =>
  redeemCredit($("usage-code-input"), $("usage-msg")));

$("av-back").addEventListener("click", () => {
  renderPicker();
  show("view-pick");
});

document.addEventListener("DOMContentLoaded", init);
