import argparse
import logging
import sys
from typing import Optional, Sequence

from security_analyzer import __app_name__, __version__
from security_analyzer.config import AppConfig, load_config
from security_analyzer.database import DatabaseManager
from security_analyzer.logger import get_logger


logger = get_logger(__name__)


def _resolve_config_and_db(args: argparse.Namespace) -> tuple[AppConfig, DatabaseManager]:
    """Load AppConfig and initialize DatabaseManager with optional CLI overrides."""
    app_config = load_config(args.config)
    db_path = args.db if args.db else app_config.db_path
    db = DatabaseManager(db_path)
    db.initialize()
    return app_config, db


def _handle_analyze(args: argparse.Namespace) -> int:
    """Placeholder handler for 'analyze' (implemented in Checkpoint 6.2)."""
    print(f"analyze command registered (file={args.file})")
    return 0


def _handle_events(args: argparse.Namespace) -> int:
    """Placeholder handler for 'events' (implemented in Checkpoint 6.3)."""
    print(f"events command registered (limit={args.limit})")
    return 0


def _handle_alerts(args: argparse.Namespace) -> int:
    """Placeholder handler for 'alerts' (implemented in Checkpoint 6.4)."""
    print(f"alerts command registered (limit={args.limit})")
    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Placeholder handler for 'stats' (implemented in Checkpoint 6.5)."""
    print(f"stats command registered (top={args.top})")
    return 0


def _handle_report(args: argparse.Namespace) -> int:
    """Placeholder handler for 'report' (implemented in Phase 7)."""
    print(f"report command registered (format={args.format})")
    return 0


def _build_common_parser() -> argparse.ArgumentParser:
    """Build shared options accepted both before and after subcommands."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-c",
        "--config",
        default=None,
        help="Path to JSON configuration file (defaults to built-in settings).",
    )
    common.add_argument(
        "--db",
        default=None,
        help="Override SQLite database path.",
    )
    common.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override application logging verbosity.",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the top-level argument parser and all subcommands."""
    common = _build_common_parser()

    parser = argparse.ArgumentParser(
        prog=__app_name__,
        parents=[common],
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

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        metavar="<command>",
    )

    # 1. analyze
    analyze_parser = subparsers.add_parser(
        "analyze",
        parents=[common],
        help="Parse an authentication log file, run detection rules, and store results.",
    )
    analyze_parser.add_argument(
        "-f",
        "--file",
        default=None,
        help="Path to authentication log file (defaults to config default_path).",
    )
    analyze_parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Reference year for legacy BSD syslog timestamps (e.g., 2026).",
    )
    analyze_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output scan summary as JSON.",
    )
    analyze_parser.set_defaults(handler=_handle_analyze)

    # 2. events
    events_parser = subparsers.add_parser(
        "events",
        parents=[common],
        help="Query stored authentication events from SQLite.",
    )
    events_parser.add_argument("--ip", dest="source_ip", default=None, help="Filter by source IP.")
    events_parser.add_argument("--user", dest="username", default=None, help="Filter by username.")
    events_parser.add_argument("--event-type", default=None, help="Filter by event type.")
    events_parser.add_argument("--service", default=None, help="Filter by service (e.g., sshd, sudo).")
    events_parser.add_argument("--since", default=None, help="Filter events at or after ISO-8601 timestamp.")
    events_parser.add_argument("--until", default=None, help="Filter events at or before ISO-8601 timestamp.")
    events_parser.add_argument("--limit", type=int, default=50, help="Maximum rows to display (default: 50).")
    events_parser.add_argument("--json", action="store_true", dest="as_json", help="Output events as JSON.")
    events_parser.set_defaults(handler=_handle_events)

    # 3. alerts
    alerts_parser = subparsers.add_parser(
        "alerts",
        parents=[common],
        help="Query generated security alerts from SQLite.",
    )
    alerts_parser.add_argument(
        "--severity",
        default=None,
        help="Filter by severity (low, medium, high, critical).",
    )
    alerts_parser.add_argument("--rule-id", default=None, help="Filter by detection rule ID.")
    alerts_parser.add_argument("--ip", dest="source_ip", default=None, help="Filter by source IP.")
    alerts_parser.add_argument("--user", dest="username", default=None, help="Filter by username.")
    alerts_parser.add_argument("--limit", type=int, default=50, help="Maximum alerts to display (default: 50).")
    alerts_parser.add_argument(
        "--show-evidence",
        action="store_true",
        help="Include underlying log evidence lines for each alert.",
    )
    alerts_parser.add_argument("--json", action="store_true", dest="as_json", help="Output alerts as JSON.")
    alerts_parser.set_defaults(handler=_handle_alerts)

    # 4. stats
    stats_parser = subparsers.add_parser(
        "stats",
        parents=[common],
        help="Display aggregated authentication and alert statistics.",
    )
    stats_parser.add_argument("--top", type=int, default=10, help="Number of top IPs/users to show (default: 10).")
    stats_parser.add_argument("--json", action="store_true", dest="as_json", help="Output stats as JSON.")
    stats_parser.set_defaults(handler=_handle_stats)

    # 5. report
    report_parser = subparsers.add_parser(
        "report",
        parents=[common],
        help="Generate a terminal or JSON security report from stored history.",
    )
    report_parser.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Report output format (default: terminal).",
    )
    report_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional output file path to save the report.",
    )
    report_parser.add_argument("--top", type=int, default=10, help="Number of top IPs/users to include.")
    report_parser.set_defaults(handler=_handle_report)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI application and return an OS exit status code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.log_level:
        logging.getLogger("security_analyzer").setLevel(
            getattr(logging, args.log_level)
        )

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0

    try:
        return int(handler(args))
    except (FileNotFoundError, IsADirectoryError, PermissionError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        logger.exception("Unexpected error while executing '%s'", args.command)
        print(f"Fatal error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())