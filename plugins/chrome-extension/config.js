/* NPC Verify: configuration.
 *
 * Point API_BASE at the hosted verification API when it is live.
 * API_KEY must be a verifier-role key. Both can also be overridden at
 * runtime via chrome.storage.local keys "npc_api_base" and "npc_api_key".
 *
 * Defaults target the local demo API from the verified-by-npc repo
 * (api/README.md). With no key set, provenance checks are skipped
 * honestly and every other layer still runs.
 */

const NPC_CONFIG_DEFAULTS = {
  apiBase: "http://127.0.0.1:8787/v1",
  apiKey: "",
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
