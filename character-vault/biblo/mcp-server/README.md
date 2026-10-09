# biblo-character MCP server v0.1.0 — INTERNAL DRAFT

The Biblo character IP as an MCP server (the anabology pattern: character IP
as MCP server + skill + canon). Three tools, pure standard library, no
network calls, stdio transport.

## Tools

- `get_canon` — returns Biblo's character canon (CANON.md) and its version.
- `speak` — applies Biblo's mechanical voice rules to a draft (em-dash
  removal, owl-emoji removal, performative-opener stripping). First pass
  only; judgment-level voice work still needs an agent reading the canon.
- `voice_check` — scores a text against the checkable voice rules and lists
  every violation with an excerpt and a suggestion.

## Run

```sh
python3 -m biblo_character_mcp
```

The server reads `../CANON.md` relative to the package (the character vault
root). It must run from inside the vault.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

All tests must pass before any change ships. The canon is versioned; bump
`CANON_VERSION` in `biblo_character_mcp/canon.py` together with CANON.md.

## Status

Internal draft. Not published, not licensed. Publication or licensing needs
an explicit decision from Bayode Okusanya.
