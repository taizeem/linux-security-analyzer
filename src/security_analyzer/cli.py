import argparse
import sys
from typing import Optional, Sequence

from security_analyzer import __app_name__, __version__


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog=__app_name__,
        description=(
            "Defensive Linux authentication log analyzer for inspecting SSH "
            "and sudo security events."
        ),
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI application and return an OS exit status code."""
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
