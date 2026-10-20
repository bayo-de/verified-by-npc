/* NPC Verify: configuration.
 *
 * The shipped default is the production verification API. Both values
 * can be overridden at runtime via chrome.storage.local keys
 * "npc_api_base" and "npc_api_key" (developer use: point the base at
 * the local demo API from the verified-by-npc repo, api/README.md).
 *
 * API_KEY must be a verifier-role key. With no key set, provenance
 * checks are skipped honestly and every other layer still runs.
 */

const NPC_CONFIG_DEFAULTS = {
  apiBase: "https://api.npclabs.xyz/v1",
  apiKey: "npc_demo_HNL8-qoMjLTVvDCYog1scIZm4JgrganOI2RRFoTFI-E",
  getVerifiedUrl: "https://verify.npclabs.xyz/get-verified",
  fullReportUrl: "https://verify.npclabs.xyz",
  freeChecksTotal: 10
};

async function npcGetConfig() {
  const stored = await chrome.storage.local.get(["npc_api_base", "npc_api_key"]);
  return {
    apiBase: (stored.npc_api_base || NPC_CONFIG_DEFAULTS.apiBase).replace(/\/$/, ""),
    apiKey: stored.npc_api_key || NPC_CONFIG_DEFAULTS.apiKey,
    getVerifiedUrl: NPC_CONFIG_DEFAULTS.getVerifiedUrl,
    fullReportUrl: NPC_CONFIG_DEFAULTS.fullReportUrl,
    freeChecksTotal: NPC_CONFIG_DEFAULTS.freeChecksTotal
  };
}
