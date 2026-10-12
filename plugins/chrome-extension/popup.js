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

async function init() {
  show("view-loading");
  updateChecksLine();
  const tab = await activeTab();
  if (!tab || !tab.id || !/^https?:/.test(tab.url || "")) {
    show("view-empty");
    return;
  }
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
  let result;
  try {
    result = await chrome.runtime.sendMessage({ type: "NPC_CHECK", image: IMAGES[SELECTED] });
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

  if (r.verdict === "verified") {
    word.textContent = "Verified";
    mark.classList.remove("hidden");
  } else if (r.verdict === "no_record") {
    word.textContent = "No record found";
  } else if (r.verdict === "not_checked") {
    word.textContent = "Not checked";
  } else {
    word.textContent = "API unreachable";
  }
  sub.textContent = r.verdictSub;

  // Layer 1: provenance
  const p = r.provenance || {};
  if (p.status === "matched") {
    setLayer("prov", "registered", "hit");
    $("body-prov").innerHTML =
      "<p><span class='k'>Registered.</span> " + esc(p.creator || "A creator") + " put this on record"
      + (p.recordedAt ? " on " + esc(p.recordedAt.slice(0, 10)) : "") + "."
      + (p.scope ? " Scope: " + esc(p.scope) + "." : "") + "</p>"
      + "<p><a href='" + esc(r.fullReportUrl) + "' target='_blank' rel='noopener'>See the full record</a></p>";
  } else if (p.status === "unknown") {
    setLayer("prov", "no record", "miss");
    $("body-prov").innerHTML = "<p>No NPC record matches this image. That means nobody has registered it here, nothing more.</p>";
  } else if (p.status === "not_configured") {
    setLayer("prov", "not connected", "miss");
    $("body-prov").innerHTML = "<p>The registry was not checked. This copy of the extension has no API key set. See the README to connect one.</p>";
  } else if (p.status === "unauthorized") {
    setLayer("prov", "key rejected", "miss");
    $("body-prov").innerHTML = "<p>The API rejected the configured key. Check that it is a verifier-role key.</p>";
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
  }
  const lens = "https://lens.google.com/uploadbyurl?url=" + encodeURIComponent(f.src || "");
  const tineye = "https://tineye.com/search?url=" + encodeURIComponent(f.src || "");
  fh += "<p>See where else this image appears: "
    + "<a href='" + lens + "' target='_blank' rel='noopener'>Google Lens</a> · "
    + "<a href='" + tineye + "' target='_blank' rel='noopener'>TinEye</a></p>";
  $("body-for").innerHTML = fh;

  // Layer 3: AI judgment (stubbed, honestly)
  setLayer("ai", "coming soon", "miss");
  $("body-ai").innerHTML = "<p>" + esc((r.ai && r.ai.note) || "Not available in this version.") + "</p>";

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

$("check-btn").addEventListener("click", runCheck);
$("again-btn").addEventListener("click", () => { renderPicker(); show("view-pick"); });

document.addEventListener("DOMContentLoaded", init);
