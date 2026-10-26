"""Console entry point: npc-verify-mcp."""
import os
import sys


def main():
    from .server import McpServer, _log
    if not os.environ.get("NPC_VERIFY_API_KEY"):
        _log("NPC_VERIFY_API_KEY is not set - using the bundled public "
             "read-only verifier key. Set NPC_VERIFY_API_KEY to use "
             "your own key.")
    McpServer().serve()


if __name__ == "__main__":
    sys.exit(main())
