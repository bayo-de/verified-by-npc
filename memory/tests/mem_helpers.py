"""Shared fixtures for memory tests (fictional data only)."""
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_BASE = os.path.join(os.path.dirname(BASE), "api")
for p in (BASE, API_BASE):
    if p not in sys.path:
        sys.path.insert(0, p)

from npc_memory import AgentIdentity, MemoryClient, MemoryStore, Scope  # noqa: E402


class Clock:
    """Deterministic ISO-8601 clock for tests."""

    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return f"2026-10-06T00:00:{self.n:02d}+00:00"


def make_client(agent_id="test_agent", company_id="test_co",
                team_id="test_team", clock=None):
    store = MemoryStore.open(":memory:")
    ident = AgentIdentity.generate(agent_id)
    scope = Scope(company_id=company_id, team_id=team_id, agent_id=agent_id)
    client = MemoryClient(store, ident, scope, clock=clock or Clock())
    client.register_self()
    return client, store, ident


class MemoryTestCase(unittest.TestCase):
    def setUp(self):
        self.client, self.store, self.ident = make_client()
