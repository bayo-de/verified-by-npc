/* End-to-end driver for the .npc "Register a file" flow.
 *
 * Runs the exact logic the Verify yours page runs, against the
 * throwaway local stack from npc_e2e_stack.py:
 *   1. write a small test file,
 *   2. hash it in chunks with the shared module's incremental
 *      SHA-256 (the module the page inlines),
 *   3. register the fingerprint with the API, by hash only,
 *   4. build the .npc credential with the shared module and write
 *      it out under the name the page would give the download,
 *   5. leave a manifest for npc_e2e_validate.py.
 *
 * Usage: NPC_E2E_DIR=/tmp/npc-e2e node npc_e2e_driver.mjs
 */
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const NPC = require(path.join(here, "..", "npc_credential.js"));

const API = "http://127.0.0.1:8799";
const SITE = "http://127.0.0.1:8790";
const work = process.env.NPC_E2E_DIR || "/tmp/npc-e2e";
mkdirSync(work, { recursive: true });

// 1. a small test file, a few MB so the chunked read path matters
const testFile = path.join(work, "e2e-test-tone.wav");
const payload = Buffer.concat([
  Buffer.from("NPC e2e test tone, not music. ", "utf8"),
  randomBytes(3 * 1024 * 1024 + 12345),
]);
writeFileSync(testFile, payload);

// 2. chunked hash with the page's own hasher, 1 MiB slices
const data = readFileSync(testFile);
const hasher = new NPC.Sha256();
const CHUNK = 1024 * 1024;
for (let off = 0; off < data.length; off += CHUNK) {
  hasher.update(data.subarray(off, off + CHUNK));
}
const hex = hasher.digestHex();
console.log("file:", testFile, "bytes:", data.length);
console.log("sha256 (module, chunked):", hex);

// 3. register by hash, the exact payload the page sends
const regRes = await fetch(API + "/v1/register/content", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    title: "E2E Test Tone",
    kind: NPC.inferKind("e2e-test-tone.wav", "audio/wav"),
    locator: "sha256:" + hex,
    creator_name: "E2E Driver",
    creator_email: "e2e@npclabs.xyz",
  }),
});
const record = await regRes.json();
if (!regRes.ok || !record.record_id) {
  console.error("registration failed:", regRes.status, record);
  process.exit(1);
}
console.log("registered:", record.record_id,
            "status:", record.status_label);

// 4. build the .npc exactly as the page's Download button does
const recordUrl = SITE + "/search?id=" +
  encodeURIComponent(record.record_id);
const envelope = NPC.buildCredential({
  record, recordUrl, contentSha256: hex,
});
const npcName = NPC.credentialFilename(record.title, hex);
const npcPath = path.join(work, npcName);
writeFileSync(npcPath, NPC.serialize(envelope));
console.log("wrote .npc:", npcPath);

// 5. manifest for the validator
writeFileSync(path.join(work, "e2e-manifest.json"), JSON.stringify({
  testFile, npcPath, npcName, sha256: hex,
  recordId: record.record_id, api: API, site: SITE,
}, null, 2));
console.log("manifest written");
