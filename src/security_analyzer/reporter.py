from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Union

from security_analyzer import __app_name__, __version__
from security_analyzer.database import DatabaseManager


def build_report_data(
    db: DatabaseManager,
    top_n: int = 10,
    alert_limit: int = 50,
) -> Dict[str, Any]:
    """Assemble a canonical security report payload from SQLite."""
    stats = db.get_statistics(top_n=top_n)
    alerts = db.query_alerts(limit=alert_limit)

    return {
        "metadata": {
            "app_name": __app_name__,
            "app_version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "database_path": str(db.db_path),
        },
        "summary": {
            "total_events": stats["total_events"],
            "total_successful_logins": stats["total_successful_logins"],
            "total_failed_logins": stats["total_failed_logins"],
            "total_invalid_users": stats["total_invalid_users"],
            "total_sudo_events": stats["total_sudo_events"],
            "total_alerts": stats["total_alerts"],
            "alerts_by_severity": stats["alerts_by_severity"],
        },
        "top_source_ips": stats["top_source_ips"],
        "top_targeted_usernames": stats["top_targeted_usernames"],
        "alerts": alerts,
        "scan_runs": stats["recent_scan_runs"],
    }


def render_terminal_report(
    report_data: Dict[str, Any],
    max_evidence_per_alert: int = 5,
) -> str:
    """Render a structured, human-readable terminal security report."""
    meta = report_data["metadata"]
    summary = report_data["summary"]
    sev = summary["alerts_by_severity"]
    lines: List[str] = []

    lines.append("=" * 72)
    lines.append("LINUX SECURITY LOG ANALYZER — SECURITY REPORT")
    lines.append("=" * 72)
    lines.append(f"Generated At: {meta['generated_at']}")
    lines.append(f"Tool Version: {meta['app_name']} {meta['app_version']}")
    lines.append(f"Database:     {meta['database_path']}")
    lines.append("")

    lines.append("1. AUTHENTICATION SUMMARY")
    lines.append("-" * 72)
    lines.append(f"  Total Events Analyzed:     {summary['total_events']}")
    lines.append(f"  Total Successful Logins:   {summary['total_successful_logins']}")
    lines.append(f"  Total Failed Logins:       {summary['total_failed_logins']}")
    lines.append(f"  Invalid Username Probes:   {summary['total_invalid_users']}")
    lines.append(f"  Sudo Events Observed:      {summary['total_sudo_events']}")
    lines.append(f"  Total Alerts Generated:    {summary['total_alerts']}")
    lines.append(
        f"  Alerts by Severity:        "
        f"CRITICAL={sev['critical']}  HIGH={sev['high']}  "
        f"MEDIUM={sev['medium']}  LOW={sev['low']}"
    )
    lines.append("")

    lines.append("2. FREQUENTLY OBSERVED SOURCE IP ADDRESSES")
    lines.append("-" * 72)
    if report_data["top_source_ips"]:
        for item in report_data["top_source_ips"]:
            lines.append(f"  {item['source_ip']:<36} {item['count']:>6} event(s)")
    else:
        lines.append("  No source IP activity recorded.")
    lines.append("")

    lines.append("3. MOST TARGETED USERNAMES")
    lines.append("-" * 72)
    if report_data["top_targeted_usernames"]:
        for item in report_data["top_targeted_usernames"]:
            lines.append(
                f"  {item['username']:<24} {item['count']:>6} failed/invalid event(s)"
            )
    else:
        lines.append("  No failed or invalid username activity recorded.")
    lines.append("")

    lines.append("4. DETECTED ALERTS & EVIDENCE")
    lines.append("-" * 72)
    alerts = report_data["alerts"]
    if not alerts:
        lines.append("  No security alerts generated.")
    else:
        for idx, alert in enumerate(alerts, start=1):
            target = alert["source_ip"] or alert["username"] or "host"
            lines.append(
                f"  [{idx}] [{alert['severity'].upper():<8}] {alert['rule_id']} — {alert['title']}"
            )
            lines.append(
                f"      Target: {target} | Events: {alert['event_count']} | "
                f"Window: {alert['first_seen']} -> {alert['last_seen']}"
            )
            lines.append(f"      Details: {alert['description']}")

            evidence = alert.get("evidence", [])
            if evidence:
                lines.append("      Evidence:")
                shown = evidence[:max_evidence_per_alert]
                for ev in shown:
                    lines.append(
                        f"        - line {ev['line_number']} | "
                        f"{ev['timestamp']} | {ev['message']}"
                    )
                remaining = len(evidence) - len(shown)
                if remaining > 0:
                    lines.append(f"        ... ({remaining} additional evidence line(s) omitted)")
            lines.append("")

    lines.append("5. SCAN EXECUTION HISTORY")
    lines.append("-" * 72)
    if report_data["scan_runs"]:
        for run in report_data["scan_runs"]:
            lines.append(
                f"  Run #{run['id']} | {run['started_at']} | "
                f"lines={run['total_lines']} valid={run['valid_events']} "
                f"malformed={run['malformed_lines']} "
                f"new_events={run['new_events_stored']} "
                f"new_alerts={run['alerts_generated']}"
            )
            lines.append(f"    Source: {run['source_path']}")
    else:
        lines.append("  No scan runs recorded.")

    lines.append("=" * 72)
    return "\n".join(lines)


def write_report_file(content: str, output_path: Union[str, Path]) -> Path:
    """Write rendered report content to disk, creating parent directories if needed."""
    destination = Path(output_path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content + "\n", encoding="utf-8")
    return destination