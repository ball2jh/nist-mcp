"""CLI entry point for the scraper.

Usage::

    python -m scraper -o nist_mcp.db
    python -m scraper --quick -o /tmp/test.db
"""

import argparse

from scraper.build_db import build_database


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build NIST MCP database index",
    )
    parser.add_argument(
        "-o", "--output",
        default="nist_mcp.db",
        help="Output database file path (default: nist_mcp.db)",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip slow operations (detail page scraping)",
    )
    args = parser.parse_args()
    build_database(args.output, quick=args.quick)


if __name__ == "__main__":
    main()
