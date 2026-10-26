"""Vendored signing primitives for standalone installs.

Byte-identical copies of api/npc_verify/canonical.py and
api/npc_verify/ed25519.py. The MCP client prefers the API package
itself when the repo tree is present; these copies exist so a PyPI
install works with no repo checkout. tests/test_vendor_sync.py
asserts byte equality whenever the API tree is present.
"""
