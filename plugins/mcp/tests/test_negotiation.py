"""Protocol-version negotiation tests for initialize.

The server once hard-coded 2024-11-05. Current MCP clients (including
hosted connector stacks) negotiate at 2025-03-26 or 2025-06-18, so
initialize now honors the client's requested version when it is in
the supported set and otherwise answers with the newest supported
version. The stdio session shape is unchanged; only the negotiated
protocolVersion value is new.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import McpTestCase  # noqa: E402
from npc_verify_mcp.server import (  # noqa: E402
    SUPPORTED_PROTOCOL_VERSIONS, negotiate_protocol_version)


def _initialize(mcp, requested, include_version=True):
    params = {"capabilities": {},
              "clientInfo": {"name": "negotiation-test", "version": "0"}}
    if include_version:
        params["protocolVersion"] = requested
    reply = mcp.handle({"jsonrpc": "2.0", "id": 1,
                        "method": "initialize", "params": params})
    return reply["result"]["protocolVersion"]


class TestNegotiation(McpTestCase):
    def test_supported_versions_are_honored(self):
        for version in SUPPORTED_PROTOCOL_VERSIONS:
            self.assertEqual(_initialize(self.mcp, version), version)

    def test_current_client_versions(self):
        # The versions current hosted clients actually negotiate at.
        self.assertEqual(_initialize(self.mcp, "2025-06-18"), "2025-06-18")
        self.assertEqual(_initialize(self.mcp, "2025-03-26"), "2025-03-26")
        self.assertEqual(_initialize(self.mcp, "2024-11-05"), "2024-11-05")

    def test_unknown_version_gets_newest_supported(self):
        self.assertEqual(_initialize(self.mcp, "2099-01-01"),
                         SUPPORTED_PROTOCOL_VERSIONS[0])
        self.assertEqual(_initialize(self.mcp, "2020-01-01"),
                         SUPPORTED_PROTOCOL_VERSIONS[0])

    def test_missing_version_gets_newest_supported(self):
        self.assertEqual(
            _initialize(self.mcp, None, include_version=False),
            SUPPORTED_PROTOCOL_VERSIONS[0])

    def test_negotiate_helper(self):
        self.assertEqual(negotiate_protocol_version("2025-03-26"),
                         "2025-03-26")
        self.assertEqual(negotiate_protocol_version(None),
                         SUPPORTED_PROTOCOL_VERSIONS[0])
        self.assertEqual(negotiate_protocol_version(""),
                         SUPPORTED_PROTOCOL_VERSIONS[0])
