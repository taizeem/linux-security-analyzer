import argparse
from datetime import datetime
import json
import logging
import sys
from typing import Optional, Sequence

from security_analyzer import __app_name__, __version__
from security_analyzer.config import AppConfig, load_config
from security_analyzer.database import DatabaseManager
from security_analyzer.detector import DetectionEngine
from security_analyzer.logger import get_logger
from security_analyzer.models import VALID_SEVERITIES
from security_analyzer.parser import parse_log_file, validate_ip_address
from security_analyzer.reporter import (
    build_report_data,
    render_terminal_report,
    write_report_file,
)

logger = get_logger(__name__)

VALID_EVENT_TYPES = frozenset(
    {
        "ssh_failed_login",
        "ssh_successful_login",
        "ssh_invalid_user",
        "sudo_command",
        "sudo_auth_failure",
        "session_opened",
        "session_closed",
        "other",
    }
)


def _validate_positive_int(value: int, flag_name: str, max_value: int) -> int:
    """Ensure an integer CLI option falls within [1, max_value]."""
    if value < 1 or value > max_value:
        raise ValueError(
            f"{flag_name} must be between 1 and {max_value} (got {value})."
        )
    return value


def _validate_ip_filter(ip_value: Optional[str]) -> Optional[str]:
    """Validate and canonicalize an optional --ip filter."""
    if ip_value is None:
        return None
    canonical = validate_ip_address(ip_value)
    if canonical is None:
        raise ValueError(f"Invalid IP address for --ip: '{ip_value}'.")
    return canonical


def _validate_severity_filter(severity: Optional[str]) -> Optional[str]:
    """Validate an optional --severity filter."""
    if severity is None:
        return None
    normalized = severity.strip().lower()
    if normalized not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. "
            f"Choose from: {', '.join(sorted(VALID_SEVERITIES))}."
        )
    return normalized


def _validate_event_type_filter(event_type: Optional[str]) -> Optional[str]:
    """Validate an optional --event-type filter."""
    if event_type is None:
        return None
    normalized = event_type.strip().lower()
    if normalized not in VALID_EVENT_TYPES:
        raise ValueError(
            f"Invalid event type '{event_type}'. "
            f"Choose from: {', '.join(sorted(VALID_EVENT_TYPES))}."
        )
    return normalized


def _validate_iso_bound(value: Optional[str], flag_name: str) -> Optional[str]:
    """Validate an ISO-8601 date or timestamp string for --since / --until."""
    if value is None:
        return None
    raw = value.strip()
    iso_candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        datetime.fromisoformat(iso_candidate)
    except ValueError as exc:
        raise ValueError(
            f"Invalid ISO-8601 timestamp for {flag_name}: '{value}'. "
            "Example: 2026-11-18T08:00:00+05:30 or 2026-11-18."
        ) from exc
    return raw


def _validate_year(year: Optional[int]) -> Optional[int]:
    """Validate optional --year reference parameter."""
    if year is None:
        return None
    if year < 1970 or year > 2100:
        raise ValueError(f"--year must be between 1970 and 2100 (got {year}).")
    return year


def _resolve_config_and_db(args: argparse.Namespace) -> tuple[AppConfig, DatabaseManager]:
    """Load AppConfig and initialize DatabaseManager with optional CLI overrides."""
    app_config = load_config(args.config)
    db_path = args.db if args.db else app_config.db_path
    db = DatabaseManager(db_path)
    db.initialize()
    return app_config, db


def _handle_analyze(args: argparse.Namespace) -> int:
    """Ingest a log file, run detection rules, persist results, and print summary."""
    reference_year = _validate_year(args.year)
    app_config, db = _resolve_config_and_db(args)
    target_file = args.file if args.file else app_config.default_log_path

    parse_result = parse_log_file(target_file, reference_year=reference_year)
    engine = DetectionEngine.from_config(app_config)
    alerts = engine.evaluate(parse_result.events)
    persistence = db.persist_scan_results(parse_result, alerts)

    summary = {
        "scan_run_id": persistence["scan_run_id"],
        "source_path": parse_result.source_path,
        "db_path": str(db.db_path),
        "total_lines": parse_result.total_lines,
        "valid_events": parse_result.valid_events,
        "malformed_lines": parse_result.malformed_lines,
        "new_events_stored": persistence["new_events"],
        "duplicate_events_skipped": persistence["duplicate_events"],
        "alerts_detected": len(alerts),
        "new_alerts_stored": persistence["new_alerts"],
        "duplicate_alerts_skipped": persistence["duplicate_alerts"],
        "alerts": [alert.to_dict() for alert in alerts],
    }

    if args.as_json:
        print(json.dumps(summary, indent=2))
        return 0

    print(f"Scan Run #{summary['scan_run_id']} completed")
    print(f"  Source file:      {summary['source_path']}")
    print(f"  Database:         {summary['db_path']}")
    print(
        f"  Lines parsed:     {summary['total_lines']} "
        f"(valid: {summary['valid_events']}, malformed: {summary['malformed_lines']})"
    )
    print(
        f"  Events stored:    {summary['new_events_stored']} new, "
        f"{summary['duplicate_events_skipped']} duplicates skipped"
    )
    print(
        f"  Alerts detected:  {summary['alerts_detected']} "
        f"({summary['new_alerts_stored']} new, "
        f"{summary['duplicate_alerts_skipped']} duplicates skipped)"
    )

    if alerts:
        print("\nDetected Alerts:")
        for alert in alerts:
            target = alert.source_ip or alert.username or "host"
            print(
                f"  [{alert.severity.upper():<8}] {alert.rule_id} | "
                f"{target} | {alert.title}"
            )
    else:
        print("\nDetected Alerts: None")

    return 0

def _truncate(text: Optional[str], max_len: int) -> str:
    """Truncate long terminal fields cleanly with an ellipsis."""
    if not text:
        return "-"
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _handle_events(args: argparse.Namespace) -> int:
    """Query and display stored authentication events."""
    source_ip = _validate_ip_filter(args.source_ip)
    event_type = _validate_event_type_filter(args.event_type)
    since = _validate_iso_bound(args.since, "--since")
    until = _validate_iso_bound(args.until, "--until")
    if since and until and since > until:
        raise ValueError("--since must be earlier than or equal to --until.")
    limit = _validate_positive_int(args.limit, "--limit", max_value=10000)

    _, db = _resolve_config_and_db(args)
    events = db.query_events(
        event_type=event_type,
        username=args.username,
        source_ip=source_ip,
        service=args.service,
        since=since,
        until=until,
        limit=limit,
    )

    if args.as_json:
        print(json.dumps(events, indent=2))
        return 0

    if not events:
        print("No matching authentication events found.")
        return 0

    header = (
        f"{'TIMESTAMP':<26} {'SERVICE':<8} {'EVENT TYPE':<22} "
        f"{'USER':<12} {'SOURCE IP':<26} {'MESSAGE'}"
    )
    print(header)
    print("-" * 110)
    for ev in events:
        ts = _truncate(str(ev["timestamp"])[:25], 25)
        svc = _truncate(ev["service"], 8)
        ev_type = _truncate(ev["event_type"], 22)
        user = _truncate(ev["username"], 12)
        ip_addr = _truncate(ev["source_ip"], 26)
        msg = _truncate(ev["message"], 55)
        print(f"{ts:<26} {svc:<8} {ev_type:<22} {user:<12} {ip_addr:<26} {msg}")

    print(f"\nShowing {len(events)} event(s).")
    return 0


def _handle_alerts(args: argparse.Namespace) -> int:
    """Query and display stored security alerts with optional evidence drill-down."""
    severity = _validate_severity_filter(args.severity)
    source_ip = _validate_ip_filter(args.source_ip)
    limit = _validate_positive_int(args.limit, "--limit", max_value=10000)

    _, db = _resolve_config_and_db(args)
    alerts = db.query_alerts(
        severity=severity,
        rule_id=args.rule_id,
        source_ip=source_ip,
        username=args.username,
        limit=limit,
    )

    if args.as_json:
        print(json.dumps(alerts, indent=2))
        return 0

    if not alerts:
        print("No matching security alerts found.")
        return 0

    for idx, alert in enumerate(alerts, start=1):
        target = alert["source_ip"] or alert["username"] or "host"
        print(
            f"{idx}. [{alert['severity'].upper():<8}] {alert['rule_id']} | "
            f"{alert['title']}"
        )
        print(
            f"   Target: {target} | Events: {alert['event_count']} | "
            f"Window: {alert['first_seen']} -> {alert['last_seen']}"
        )
        print(f"   Summary: {alert['description']}")

        if args.show_evidence and alert.get("evidence"):
            print("   Evidence:")
            for item in alert["evidence"]:
                print(
                    f"     - line {item['line_number']} | "
                    f"{item['timestamp']} | {item['message']}"
                )
        print()

    print(f"Showing {len(alerts)} alert(s).")
    return 0

def _handle_stats(args: argparse.Namespace) -> int:
    """Display aggregated authentication and alert statistics from SQLite."""
    top_n = _validate_positive_int(args.top, "--top", max_value=500)
    _, db = _resolve_config_and_db(args)
    stats = db.get_statistics(top_n=top_n)

    if args.as_json:
        print(json.dumps(stats, indent=2))
        return 0

    print("Authentication Security Statistics")
    print("=" * 42)
    print(f"Total stored events:       {stats['total_events']}")
    print(f"Successful SSH logins:     {stats['total_successful_logins']}")
    print(f"Failed SSH logins:         {stats['total_failed_logins']}")
    print(f"Invalid username probes:   {stats['total_invalid_users']}")
    print(f"Sudo activity events:      {stats['total_sudo_events']}")
    print(f"Total generated alerts:    {stats['total_alerts']}")

    sev = stats["alerts_by_severity"]
    print("\nAlerts by Severity:")
    print(
        f"  CRITICAL: {sev['critical']} | HIGH: {sev['high']} | "
        f"MEDIUM: {sev['medium']} | LOW: {sev['low']}"
    )

    print(f"\nTop Source IP Addresses (limit {top_n}):")
    if stats["top_source_ips"]:
        for entry in stats["top_source_ips"]:
            print(f"  {entry['source_ip']:<30} {entry['count']} event(s)")
    else:
        print("  None recorded")

    print(f"\nMost Targeted Usernames (limit {top_n}):")
    if stats["top_targeted_usernames"]:
        for entry in stats["top_targeted_usernames"]:
            print(f"  {entry['username']:<20} {entry['count']} failed/invalid event(s)")
    else:
        print("  None recorded")

    print("\nRecent Scan Runs:")
    if stats["recent_scan_runs"]:
        for run in stats["recent_scan_runs"]:
            print(
                f"  Run #{run['id']} | {run['started_at']} | "
                f"new_events={run['new_events_stored']} "
                f"new_alerts={run['alerts_generated']} | {run['source_path']}"
            )
    else:
        print("  No scans recorded yet")

    return 0


def _handle_report(args: argparse.Namespace) -> int:
    """Generate a terminal or JSON security report from stored SQLite data."""
    top_n = _validate_positive_int(args.top, "--top", max_value=500)
    _, db = _resolve_config_and_db(args)
    report_data = build_report_data(db, top_n=top_n)

    if args.format == "json":
        rendered = json.dumps(report_data, indent=2)
    else:
        rendered = render_terminal_report(report_data)

    if args.output:
        saved_path = write_report_file(rendered, args.output)
        print(f"Report written to {saved_path}")
    else:
        print(rendered)

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