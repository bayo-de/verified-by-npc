/* NPC Verify: content script.
 * Collects the page's images so the popup can offer them for checking.
 * Reads the DOM only. Sends nothing anywhere.
 */

function npcCollectImages() {
  const seen = new Set();
  const out = [];
  for (const img of document.images) {
    const src = img.currentSrc || img.src;
    if (!src || !src.startsWith("http") || seen.has(src)) continue;
    const w = img.naturalWidth || img.width || 0;
    const h = img.naturalHeight || img.height || 0;
    if (w < 160 || h < 160) continue; // skip icons, pixels, spacers
    seen.add(src);
    out.push({ src, alt: (img.alt || "").slice(0, 120), w, h, area: w * h });
  }
  out.sort((a, b) => b.area - a.area);
  return out.slice(0, 8);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "NPC_COLLECT_IMAGES") {
    try {
      sendResponse({ images: npcCollectImages() });
    } catch (e) {
      sendResponse({ images: [], error: String(e && e.message || e) });
    }
  }
  return false;
});
