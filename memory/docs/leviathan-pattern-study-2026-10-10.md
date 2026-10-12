# Leviathan pattern study — trust-layer persistent memory v1
Date: 2026-10-10 · Source: elstongun/leviathan (Apache-2.0, verified) · Fleet flywheel ADOPTED

## What it is
Single static Rust binary that turns records (JSONL/CSV/SQLite/DB exports) into a ranked
full-text index (SQLite FTS5 + BM25). Agents query in plain words and get short cited
result cards: ~450 tokens per answer at any dataset size (99.0% top-5 at 1M records,
33ms median). Ships CLI + agent skill + MCP (4 read-only stdio tools: search,
resolve_group, get, describe). Optional read/write memory: `remember` one claim at a
time, keyed writes replace stale values, `recall` is token-budgeted, session-start
briefing under 1K tokens after 300 sessions (vs 33K for a markdown MEMORY.md).

## Patterns to steal for trust-layer persistent memory v1
1. **Cited result cards, not raw dumps.** Every answer reports "shown N of M" so the
   agent can tell "no match" from "no data." Our memory reads should carry the same
   honesty: provenance on every recalled claim.
2. **Keyed writes replace, never contradict.** `memory remember --key X` overwrites the
   old value. This is the stale-memory killer (their benchmark: 0% stale in context
   vs 73.8% for whole-file markdown memory). Our v1 should enforce keyed slots for
   anything that can change.
3. **Ambiguity-refusing resolution.** `resolve_group` lists candidates and exits 3 on
   ambiguity — never guesses. Matches our honesty creed; adopt as a rule for any
   entity resolution in the memory layer.
4. **Token-budgeted recall + session briefing.** `recall` returns only what fits a
   budget; sessions start with a short briefing. This is the shape our agent
   context-injection should take.
5. **MCP surface is 4 read-only tools.** Small, auditable tool surface. Our memory MCP
   should be equally minimal; writes go through a separate, permissioned path.
6. **Secrets refused at write time.** Leviathan refuses to store secrets. Our memory
   layer must do the same (attestation-relevant: never persist credentials).

## What we are NOT doing
- Not installing the binary, not depending on the Rust crate. This is a
  documentation-first pattern adoption (kevin-liao principle): we take the design,
  we build our own.
- License is Apache-2.0 so pattern reuse is clean regardless.

## Next step
When trust-layer memory v1 is next touched, implement keyed-write slots,
shown-N-of-M recall cards, and the ambiguity-refusal rule as the v1.1 spec delta.
