"""Console entry point: npc-verify-mcp."""
import os
import sys


def main():
    from .server import McpServer, _log
    if not os.environ.get("NPC_VERIFY_API_KEY"):
        _log("WARNING: NPC_VERIFY_API_KEY is not set — authenticated tools "
             "will report a configuration error until it is.")
    McpServer().serve()


if __name__ == "__main__":
    sys.exit(main())
