"""``python -m themob.mcp``: serve themob's tools over the Model Context
Protocol, on stdio."""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m themob.mcp",
        description="Serve themob's tools over the Model Context Protocol (stdio).")
    parser.add_argument("--home", default="",
                        help="the themob project store to serve "
                             "(default: $THEMOB_HOME or ~/.themob)")
    args = parser.parse_args(argv)

    try:
        from .server import main as serve
    except ImportError:
        print('the MCP server needs the MCP SDK: pip install "themob[mcp]"',
              file=sys.stderr)
        return 2
    return serve(args.home or None)


if __name__ == "__main__":
    sys.exit(main())
