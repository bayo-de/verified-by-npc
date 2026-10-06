"""MCP JSON-RPC 2.0 transport over stdio (no third-party dependencies).

Implements the message shapes an MCP client needs from a tools-only server:
initialize, notifications/initialized, tools/list, tools/call.
"""
import json
import sys
import traceback

from . import __version__
from .api_client import VerifiedClient, ApiError
from .tools import TOOLS, TOOL_MAP

SERVER_NAME = "npc-verify"
PROTOCOL_VERSION = "2024-11-05"


def _log(msg):
    sys.stderr.write(f"[{SERVER_NAME}] {msg}\n")
    sys.stderr.flush()


class McpServer:
    def __init__(self, client=None):
        self.client = client or VerifiedClient()

    # -- JSON-RPC plumbing ---------------------------------------------
    def _result(self, msg_id, result):
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _error(self, msg_id, code, message, data=None):
        err = {"jsonrpc": "2.0", "id": msg_id,
               "error": {"code": code, "message": message}}
        if data is not None:
            err["error"]["data"] = data
        return err

    def handle(self, msg):
        """Handle one decoded JSON-RPC message. Returns the reply dict,
        or None for notifications (no reply)."""
        if not isinstance(msg, dict):
            return self._error(None, -32600, "invalid request")
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            return self._result(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME,
                               "version": __version__},
            })
        if method and method.startswith("notifications/"):
            return None  # notifications get no reply
        if method == "tools/list":
            return self._result(msg_id, {"tools": [
                {"name": t["name"], "description": t["description"],
                 "inputSchema": t["inputSchema"]} for t in TOOLS]})
        if method == "tools/call":
            return self._tools_call(msg_id, params)
        if method == "ping":
            return self._result(msg_id, {})
        return self._error(msg_id, -32601, f"method not found: {method}")

    def _tools_call(self, msg_id, params):
        name = params.get("name")
        arguments = params.get("arguments") or {}
        tool = TOOL_MAP.get(name)
        if tool is None:
            return self._error(msg_id, -32602, f"unknown tool: {name}")
        if not isinstance(arguments, dict):
            return self._error(msg_id, -32602,
                               "arguments must be an object")
        try:
            is_error, text = tool["handler"](self.client, arguments)
        except ApiError as exc:  # belt and suspenders: never leak a traceback
            return self._result(msg_id, {
                "content": [{"type": "text",
                             "text": f"Verification failed: {exc}"}],
                "isError": True})
        except Exception as exc:  # noqa: BLE001 - transport must not crash
            _log(f"tool {name} raised: {exc}\n{traceback.format_exc()}")
            return self._result(msg_id, {
                "content": [{"type": "text",
                             "text": "Verification failed: internal error"}],
                "isError": True})
        out = {"content": [{"type": "text", "text": text}]}
        if is_error:
            out["isError"] = True
        return self._result(msg_id, out)

    def serve(self, stdin=None, stdout=None):
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                stdout.write(json.dumps(
                    self._error(None, -32700, "parse error")) + "\n")
                stdout.flush()
                continue
            try:
                reply = self.handle(msg)
            except Exception as exc:  # noqa: BLE001
                _log(f"handle raised: {exc}\n{traceback.format_exc()}")
                reply = self._error(msg.get("id") if isinstance(msg, dict)
                                    else None, -32603, "internal error")
            if reply is not None:
                stdout.write(json.dumps(reply) + "\n")
                stdout.flush()
