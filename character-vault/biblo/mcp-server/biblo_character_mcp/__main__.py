"""Console entry point: biblo-character-mcp."""
import sys


def main():
    from .server import McpServer
    McpServer().serve()


if __name__ == "__main__":
    sys.exit(main())
