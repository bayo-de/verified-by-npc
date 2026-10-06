# Verified by NPC 1.0.0 - Release Notes

**Public launch.** The Verified by NPC ChatGPT plugin answers the question
"is this real?" inside the conversation.

## What it does

Five operations, all read-only, against the NPC Verification API v1:

- **Verify a product** - check a smart tag for authenticity, with the public
  provenance chain.
- **Verify a credential** - check whether a certificate or credential is
  valid, revoked, or expired.
- **Verify a claim** - check a statement against NPC Labs attestation
  records.
- **Verify an AI agent** - check an agent's verification status, with scope
  and time bounds.
- **Explain verification** - a plain-language explainer for what a
  verification result means.

## Trust properties

- Every API answer is cryptographically signed by NPC Labs and the plugin
  checks the signature before trusting it. Public keys are published at
  `https://api.npclabs.xyz/v1/keys`.
- When NPC Labs has no record of the subject, the answer is **unknown**.
  Unknown is never a guess, and it is never a claim that something is false.
- The plugin verifies only. It cannot issue attestations, and it never
  explains its checking methodology.

## Reviewer notes

- No sign-in required. The API is public and read-only.
- Demo fixtures for testing: product tag `demo-tag-001`, credential
  `demo-cred-001`, agent `demo-agent-001`.
- Demo data is fictional and labeled `demo-`.
